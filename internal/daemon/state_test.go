package daemon

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestPublishReadRoundTrip(t *testing.T) {
	f := installFake(t)
	home := "/home"
	in := Info{
		PID: 99, ProxyAddr: "127.0.0.1:8787", DashAddr: "127.0.0.1:8788",
		StartedAt:     time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC),
		Extra:         []string{"api.acme.com"},
		Entropy:       true,
		LogLevel:      "debug",
		AllowExternal: true,
	}
	if err := Publish(home, in); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	got, err := readState(home)
	if err != nil {
		t.Fatalf("readState: %v", err)
	}
	if got.PID != in.PID || got.ProxyAddr != in.ProxyAddr || got.DashAddr != in.DashAddr ||
		!got.StartedAt.Equal(in.StartedAt) || got.Entropy != in.Entropy ||
		got.LogLevel != in.LogLevel || got.AllowExternal != in.AllowExternal ||
		!slices.Equal(got.Extra, in.Extra) {
		t.Fatalf("readState = %+v, want %+v", *got, in)
	}
	// Publication must be atomic: the temp file is written, then renamed onto
	// the real path, so a concurrent reader never sees a half-written record.
	ev := f.events()
	if !slices.Equal(ev, []string{"write:" + statePath(home) + ".tmp", "rename:" + statePath(home)}) {
		t.Fatalf("events = %v, want temp write then rename", ev)
	}
}

func TestPublishUsesStableJSONFieldNames(t *testing.T) {
	f := installFake(t)
	if err := Publish("/home", Info{PID: 7, ProxyAddr: "a:1", DashAddr: "b:2"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	f.mu.Lock()
	raw := string(f.files[statePath("/home")])
	f.mu.Unlock()
	for _, want := range []string{`"pid"`, `"proxy_addr"`, `"dash_addr"`, `"started_at"`} {
		if !strings.Contains(raw, want) {
			t.Errorf("record %s missing field %s", raw, want)
		}
	}
}

func TestReadStateRejectsAbsentAndMalformed(t *testing.T) {
	f := installFake(t)
	home := "/home"

	if _, err := readState(home); !os.IsNotExist(err) {
		t.Errorf("readState(absent) = %v, want IsNotExist", err)
	}

	f.writeRaw(home, []byte("{not json"))
	if _, err := readState(home); err == nil {
		t.Error("readState(garbage) = nil error, want parse error")
	}

	// Present but useless: discovery needs both a PID and an address.
	f.writeState(home, Info{PID: 0, ProxyAddr: "127.0.0.1:1"})
	if _, err := readState(home); err == nil {
		t.Error("readState(pid=0) = nil error, want malformed error")
	}
	f.writeState(home, Info{PID: 5, ProxyAddr: ""})
	if _, err := readState(home); err == nil {
		t.Error("readState(no addr) = nil error, want malformed error")
	}
}

func TestUnpublishIsIdempotent(t *testing.T) {
	f := installFake(t)
	home := "/home"
	f.writeState(home, Info{PID: 3, ProxyAddr: "a:1"})
	if err := Unpublish(home); err != nil {
		t.Fatalf("Unpublish: %v", err)
	}
	if f.hasState(home) {
		t.Fatal("record still present after Unpublish")
	}
	if err := Unpublish(home); err != nil {
		t.Fatalf("Unpublish(absent) = %v, want nil", err)
	}
}
