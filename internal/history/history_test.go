package history

import (
	"context"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/pratikbin/opensecretmask/internal/store"
)

func newStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "osm.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.InitCrypto(context.Background(), "test-pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestCaptureTruncatesAndClones(t *testing.T) {
	src := make([]byte, MaxBody+1024)
	for i := range src {
		src[i] = 'a'
	}
	got := Capture(src)
	if len(got) != MaxBody {
		t.Fatalf("len = %d, want %d", len(got), MaxBody)
	}
	// The clone must not alias the read buffer: the proxy reuses and releases
	// multi-megabyte buffers, and a captured body outlives the request.
	src[0] = 'z'
	if got[0] != 'a' {
		t.Error("Capture aliased its input")
	}
	if cap(got) >= cap(src) {
		t.Errorf("cap(got) = %d, cap(src) = %d — the large buffer is still retained", cap(got), cap(src))
	}
}

func TestCaptureShortBodyIsCopied(t *testing.T) {
	src := []byte("hello")
	got := Capture(src)
	src[0] = 'j'
	if string(got) != "hello" {
		t.Fatalf("got %q, want %q", got, "hello")
	}
}

func TestCaptureNilStaysNil(t *testing.T) {
	if got := Capture(nil); len(got) != 0 {
		t.Fatalf("Capture(nil) = %q, want empty", got)
	}
}

func TestRecordPersistsExchange(t *testing.T) {
	st := newStore(t)
	r := NewRecorder(Config{Store: st})

	r.Record(Exchange{
		Provider: "anthropic", Host: "api.anthropic.com", Method: "POST",
		Path: "/v1/messages", Status: 200, Masked: 1,
		Duration: 1500 * time.Millisecond, ReqBody: []byte("masked-req"),
		RespBody: []byte("masked-resp"),
	})
	r.Close() // drains in-flight writes

	rows, err := st.ListRequests(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	if rows[0].Host != "api.anthropic.com" || rows[0].Status != 200 {
		t.Fatalf("row = %+v, want the recorded exchange", rows[0])
	}
}

func TestRecordDropsAndCountsWhenSaturated(t *testing.T) {
	st := newStore(t)
	r := NewRecorder(Config{Store: st})
	defer r.Close()

	// Saturate admission deterministically: fill every slot, so Record takes
	// the drop branch instead of racing real writes.
	for range cap(r.sem) {
		r.sem <- struct{}{}
	}

	r.Record(Exchange{Host: "api.anthropic.com", Path: "/v1/messages"})
	r.Record(Exchange{Host: "api.anthropic.com", Path: "/v1/messages"})
	if got := r.Dropped(); got != 2 {
		t.Fatalf("Dropped = %d, want 2", got)
	}

	// Freeing a slot lets the next record through.
	<-r.sem
	r.Record(Exchange{Host: "api.anthropic.com", Path: "/v1/messages"})
	if got := r.Dropped(); got != 2 {
		t.Fatalf("Dropped = %d after a slot freed, want 2", got)
	}
	for range cap(r.sem) - 1 {
		<-r.sem
	}
}

func TestRecordWithoutStoreIsANoOp(t *testing.T) {
	r := NewRecorder(Config{})
	defer r.Close()
	r.Record(Exchange{Host: "api.anthropic.com"})
	if got := r.Dropped(); got != 0 {
		t.Fatalf("Dropped = %d, want 0 — a store-less recorder discards silently", got)
	}
}

func TestNilRecorderIsSafe(t *testing.T) {
	var r *Recorder
	r.Record(Exchange{Host: "api.anthropic.com"})
	if got := r.Dropped(); got != 0 {
		t.Fatalf("Dropped = %d, want 0", got)
	}
	r.Close()
}

func TestPurgeOnceDeletesExpiredRequests(t *testing.T) {
	st := newStore(t)
	if _, err := st.LogRequest(context.Background(), store.RequestRecord{
		Provider: "anthropic", Host: "api.anthropic.com", Method: "POST",
		Path: "/v1/messages", Status: 200,
	}, nil); err != nil {
		t.Fatalf("LogRequest: %v", err)
	}

	r := NewRecorder(Config{Store: st})
	defer r.Close()
	// A negative retention puts the cutoff in the future, so ts < cutoff
	// holds for the just-inserted row regardless of the store's millisecond
	// timestamp precision — no sleep needed.
	r.purgeOnce(-time.Second)

	rows, err := st.ListRequests(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("rows = %d after purge, want 0", len(rows))
	}
}

func TestCloseStopsThePurgeLoop(t *testing.T) {
	r := NewRecorder(Config{Store: newStore(t), Retention: time.Hour})
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return — the purge loop is still running")
	}
	// Close is idempotent: the runtime may call it on more than one teardown
	// path.
	r.Close()
}

func TestRecordConcurrentWithCloseDoesNotPanic(t *testing.T) {
	// goproxy's MITM loop runs in a detached goroutine that
	// http.Server.Shutdown does not wait for, so a final Record can race
	// Close at daemon teardown. Unserialized, when the last in-flight write
	// drains the WaitGroup counter to zero, a Record's wg.Go landing before
	// the parked Wait has resumed panics the sync runtime — and goproxy's
	// goroutine has no recover. len(r.sem) returning to zero marks that
	// drain instant (the write goroutine has released its slot but not yet
	// called wg.Done), so pouncing there hits the window with high
	// probability per iteration if Record and Close are ever unserialized
	// again.
	st := newStore(t)
	for range 300 {
		r := NewRecorder(Config{Store: st})
		r.Record(Exchange{Host: "api.anthropic.com", Path: "/v1/messages"})
		closed := make(chan struct{})
		go func() {
			r.Close()
			close(closed)
		}()
		for len(r.sem) != 0 {
			runtime.Gosched()
		}
		r.Record(Exchange{Host: "api.anthropic.com", Path: "/v1/messages"})
		<-closed
	}
}

func TestRetentionZeroDisablesPurging(t *testing.T) {
	st := newStore(t)
	if _, err := st.LogRequest(context.Background(), store.RequestRecord{
		Provider: "anthropic", Host: "api.anthropic.com", Method: "POST",
		Path: "/v1/messages", Status: 200,
	}, nil); err != nil {
		t.Fatalf("LogRequest: %v", err)
	}
	r := NewRecorder(Config{Store: st, Retention: 0})
	r.Close()

	rows, err := st.ListRequests(context.Background(), 10)
	if err != nil {
		t.Fatalf("ListRequests: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1 — retention 0 must not purge", len(rows))
	}
}
