package daemon

import (
	"context"
	"sync"
	"testing"
	"time"
)

// recorder collects Watch's log lines and the ordering events the drain test
// asserts on.
type recorder struct {
	mu    sync.Mutex
	lines []string
}

func (r *recorder) logf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lines = append(r.lines, format)
}

func (r *recorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

func TestWatchEmptyKeyReturnsImmediately(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		Watch(context.Background(), home, "", (&recorder{}).logf)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return with an empty key")
	}
}

func TestWatchNoRecordReturnsImmediately(t *testing.T) {
	installFake(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		Watch(context.Background(), home, "pass", (&recorder{}).logf)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return with no record to watch")
	}
}

func TestWatchReturnsOnCancelWhileHealthy(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787", DashAddr: "127.0.0.1:8788"})
	f.setAlive(10, true)
	f.setOpen("127.0.0.1:8787", true)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Watch(ctx, home, "pass", (&recorder{}).logf)
	}()

	f.tickNow() // one probe of a healthy daemon
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not return after cancellation")
	}
	if s := f.spawns(); len(s) != 0 {
		t.Fatalf("Watch respawned a healthy daemon: %+v", s)
	}
}

func TestWatchRespawnsDeadDaemonOnRecordedAddresses(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{
		PID: 10, ProxyAddr: "127.0.0.1:8787", DashAddr: "127.0.0.1:8788",
		Extra: []string{"api.acme.com"}, Entropy: true, LogLevel: "debug",
	})
	// PID 10 was never marked alive: the daemon is already gone.

	respawned := make(chan struct{})
	f.setSpawnFn(func(f *fakeSys, cfg SpawnConfig) error {
		f.publishFrom(cfg, 4242)
		close(respawned)
		return nil
	})

	rec := &recorder{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		Watch(ctx, home, "pass", rec.logf)
	}()

	f.tickNow()
	select {
	case <-respawned:
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not respawn a dead daemon")
	}
	cancel()
	<-done

	got := f.spawns()
	if len(got) != 1 {
		t.Fatalf("spawns = %d, want 1", len(got))
	}
	if got[0].Listen != "127.0.0.1:8787" || got[0].Dash != "127.0.0.1:8788" ||
		got[0].Key != "pass" || !got[0].Entropy || got[0].LogLevel != "debug" {
		t.Fatalf("respawn lost the recorded configuration: %+v", got[0])
	}
	if lines := rec.snapshot(); len(lines) == 0 {
		t.Fatal("Watch logged nothing while respawning a dead daemon")
	}
}

// TestWatchDrainsInFlightRespawnBeforeReturning is the contract the caller
// depends on: after Watch returns, no goroutine of its making is still holding
// the daemon lock. The spawn seam blocks until the test releases it; if Watch
// returned without draining, "watch-returned" would be recorded before
// "spawn-finished".
func TestWatchDrainsInFlightRespawnBeforeReturning(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787", DashAddr: "127.0.0.1:8788"})

	var mu sync.Mutex
	var order []string
	note := func(s string) {
		mu.Lock()
		defer mu.Unlock()
		order = append(order, s)
	}

	entered := make(chan struct{})
	release := make(chan struct{})
	f.setSpawnFn(func(f *fakeSys, cfg SpawnConfig) error {
		close(entered)
		<-release
		note("spawn-finished")
		f.publishFrom(cfg, 4242)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		Watch(ctx, home, "pass", (&recorder{}).logf)
		note("watch-returned")
		close(done)
	}()

	f.tickNow()
	<-entered
	cancel()
	// Give a cancelled-but-undrained Watch a window to return early. Without
	// the drain this sleep is where the bug shows up; with it, Watch is still
	// blocked in spawnWg.Wait().
	time.Sleep(20 * time.Millisecond)
	close(release)
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 || order[0] != "spawn-finished" || order[1] != "watch-returned" {
		t.Fatalf("order = %v, want [spawn-finished watch-returned]", order)
	}
}

func TestWatchDoesNotStackConcurrentRespawns(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787", DashAddr: "127.0.0.1:8788"})

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	f.setSpawnFn(func(f *fakeSys, cfg SpawnConfig) error {
		once.Do(func() { close(entered) })
		<-release
		f.publishFrom(cfg, 4242)
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		Watch(ctx, home, "pass", (&recorder{}).logf)
	}()

	f.tickNow()
	<-entered
	// A second tick while the first respawn is still in flight must be a no-op.
	f.tickNow()
	time.Sleep(20 * time.Millisecond)
	close(release)
	cancel()
	<-done

	if got := f.spawns(); len(got) != 1 {
		t.Fatalf("spawns = %d, want 1 — a second tick stacked a respawn", len(got))
	}
}
