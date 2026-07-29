package daemon

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
)

// watchInterval is how often Watch probes the daemon. Short enough that a
// silent SIGKILL costs the supervised child roughly one retry's worth of
// failed requests before the listener is back on the same address.
const watchInterval = 2 * time.Second

// Watch keeps the daemon alive for as long as ctx runs, respawning it on the
// recorded addresses and configuration if it disappears — silent SIGKILL, host
// sleep, manual kill. The addresses must be preserved: a supervised child
// already holds HTTPS_PROXY pointing at the old one.
//
// Watch returns when ctx is done, and only after any in-flight respawn has
// finished, so the caller can exit without racing a goroutine that still holds
// the daemon lock.
//
// Two conditions make watching a no-op. An empty key means a respawned daemon
// could not unlock the store and would exit at once, looping forever; adapters
// warn about that themselves. No readable record means there is nothing to
// reproduce. logf receives one-line progress messages.
func Watch(ctx context.Context, home, key string, logf func(format string, args ...any)) {
	if key == "" {
		return
	}
	in, err := readState(home)
	if err != nil {
		return
	}
	cfg := spawnConfigFrom(home, in, key)

	var inflight atomic.Bool
	// spawnWg drains an in-flight respawn before Watch returns.
	var spawnWg sync.WaitGroup
	defer spawnWg.Wait()

	tick, stop := sys.newTicker(watchInterval)
	defer stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick:
		}
		if _, ok := Status(home); ok {
			continue
		}
		// CompareAndSwap so a slow respawn does not stack a second attempt.
		if !inflight.CompareAndSwap(false, true) {
			continue
		}
		// Recheck cancellation after winning the CAS: it may have arrived
		// during the probe, and forking during shutdown is wasted work.
		select {
		case <-ctx.Done():
			inflight.Store(false)
			return
		default:
		}
		spawnWg.Go(func() {
			defer inflight.Store(false)
			logf("osm: daemon died — respawning on %s", cfg.Listen)
			np, _, err := Ensure(cfg)
			if err != nil {
				logf("osm: respawn failed: %v", err)
				return
			}
			logf("osm: daemon respawned pid=%d", np.PID)
		})
	}
}
