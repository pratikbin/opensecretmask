package main

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

// TestWatchDaemonEmptyKeyReturnsImmediately verifies the short-circuit path:
// with no OSM_KEY, the watchdog cannot respawn the daemon, so the function
// must return at once rather than spin and burn ticker fires.
func TestWatchDaemonEmptyKeyReturnsImmediately(t *testing.T) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchDaemon(context.Background(), t.TempDir(),
			&pidInfo{PID: 1, ProxyAddr: "127.0.0.1:1"}, "", daemonOpts{})
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchDaemon did not return when osmKey was empty")
	}
}

// TestWatchDaemonReturnsOnCtxCancel exercises the steady-state cancellation
// path: with a healthy daemon, the watchdog polls forever; cancelling the
// context must unblock the select and the function must return.
//
// The "daemon" is a local TCP listener bound to an ephemeral port. The pidfile
// records the current process PID so daemonHealthy returns true.
func TestWatchDaemonReturnsOnCtxCancel(t *testing.T) {
	home := t.TempDir()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	p := pidInfo{
		PID:       os.Getpid(),
		ProxyAddr: ln.Addr().String(),
		DashAddr:  "127.0.0.1:0",
	}
	b, _ := json.Marshal(p)
	if err := os.WriteFile(filepath.Join(home, pidFileName), b, 0o600); err != nil {
		t.Fatalf("write pidfile: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		watchDaemon(ctx, home, &p, "test-key", daemonOpts{})
	}()

	// Let the watchdog tick at least once so it observes the healthy
	// daemon before we cancel.
	time.Sleep(watchdogInterval + 100*time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("watchDaemon did not return after ctx cancel")
	}
}

// TestWatchDaemonDrainsRespawnGoroutine guarantees the spawn-drain
// contract: when a respawn goroutine is in flight at cancellation time,
// watchDaemon must wait for it before returning. Without spawnWg.Wait(),
// the goroutine would outlive the function and the caller's wg.Wait()
// would race with an orphan that still holds the daemon flock.
//
// Setup: home has no pidfile, so daemonHealthy returns false on the first
// tick → watchDaemon enters the spawn branch. ensureDaemon will attempt to
// fork-exec the test binary as 'osm proxy' and either fail fast or hit the
// 10s daemonStartTimeout. We cancel mid-spawn and assert watchDaemon does
// not return until the spawn goroutine finishes.
func TestWatchDaemonDrainsRespawnGoroutine(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only fork-exec assumptions")
	}
	home := t.TempDir()
	p := pidInfo{
		PID:       1, // not us; daemonHealthy → false
		ProxyAddr: "127.0.0.1:1",
		DashAddr:  "127.0.0.1:1",
	}

	// Detect respawn-goroutine completion via the fmt.Fprintf to stderr,
	// but we can't intercept stderr easily here. Instead, monitor through
	// a side channel: wrap watchDaemon to record whether spawnWg has
	// fully drained at the moment of return.
	//
	// Implementation: a wrapper goroutine starts watchDaemon, then we
	// cancel after a tick. We can't directly observe spawnWg, but we can
	// assert that the returned-time vs the time the spawn must take are
	// consistent: spawn must call ensureDaemon → flock → spawnDaemon →
	// poll up to daemonStartTimeout. So the elapsed return time should be
	// at least ~daemonPollInterval, never sub-millisecond.
	var done atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		watchDaemon(ctx, home, &p, "test-key", daemonOpts{})
		done.Store(true)
	}()

	// Wait for the first tick — watchDaemon must enter the spawn branch.
	time.Sleep(watchdogInterval + 200*time.Millisecond)
	cancel()

	// watchDaemon should NOT return instantly: the spawn goroutine is
	// blocked in ensureDaemon (either flock or the readiness poll). The
	// drain ensures we wait for it.
	time.Sleep(50 * time.Millisecond)
	if done.Load() {
		t.Fatal("watchDaemon returned before draining in-flight spawn goroutine")
	}

	// Eventually the spawn will fail (test binary cannot serve 'osm proxy'
	// inside the test process) and watchDaemon will return. Bound by
	// daemonStartTimeout + slack.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if done.Load() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("watchDaemon never returned after spawn drain window")
}
