package daemon

import (
	"fmt"
	"path/filepath"
	"time"
)

// SpawnConfig is everything needed to start a daemon. Key is the store
// passphrase, handed to the spawned process via $OSM_KEY: this package never
// prompts, so adapters resolve it from the environment or a terminal first.
type SpawnConfig struct {
	Home          string
	Listen        string
	Dash          string
	Key           string
	Extra         []string
	Entropy       bool
	LogLevel      string
	AllowExternal bool
}

// args renders the 'osm proxy' argv for this configuration. An empty LogLevel
// falls back to info: a record written by an older binary may not carry one,
// and 'osm proxy' rejects an empty --log-level.
func (c SpawnConfig) args() []string {
	logLevel := c.LogLevel
	if logLevel == "" {
		logLevel = "info"
	}
	args := []string{"proxy", "--listen", c.Listen, "--dashboard", c.Dash, "--log-level", logLevel}
	for _, p := range c.Extra {
		args = append(args, "--provider", p)
	}
	if c.Entropy {
		args = append(args, "--detect-entropy")
	}
	if c.AllowExternal {
		args = append(args, "--allow-external-bind")
	}
	return args
}

const (
	// startTimeout bounds how long Ensure waits for a spawned daemon to
	// publish its record and accept a connection.
	startTimeout = 10 * time.Second
	// probeTimeout bounds a single liveness dial.
	probeTimeout = 500 * time.Millisecond
	// pollInterval is the gap between readiness and exit observations.
	pollInterval = 100 * time.Millisecond
)

// spawnConfigFrom rebuilds the configuration a recorded daemon was started
// with, so a respawn lands on the same addresses with the same behaviour. The
// addresses matter: a child process already holds HTTPS_PROXY pointing at
// ProxyAddr and cannot be told about a new one.
//
//nolint:unused // consumed starting in Task 4 (Restart)
func spawnConfigFrom(home string, in *Info, key string) SpawnConfig {
	return SpawnConfig{
		Home: home, Listen: in.ProxyAddr, Dash: in.DashAddr, Key: key,
		Extra: in.Extra, Entropy: in.Entropy, LogLevel: in.LogLevel,
		AllowExternal: in.AllowExternal,
	}
}

// Status reports the recorded daemon and whether it is usable. Info is nil
// when there is no readable record. Health requires both a live PID and a
// reachable listener: after a reboot an unrelated process can inherit the
// recorded PID, and it will not be bound to the recorded address.
func Status(home string) (*Info, bool) {
	in, err := readState(home)
	if err != nil {
		return nil, false
	}
	return in, healthy(in)
}

func healthy(in *Info) bool {
	return in != nil && sys.alive(in.PID) && sys.dial(in.ProxyAddr, probeTimeout) == nil
}

// Ensure returns a healthy daemon, spawning one when the recorded daemon is
// missing or dead; spawned reports whether this call started it. Concurrent
// callers serialize on a lockfile and recheck health inside the lock, so two
// simultaneous 'osm run' invocations cannot produce two daemons.
func Ensure(cfg SpawnConfig) (*Info, bool, error) {
	if in, ok := Status(cfg.Home); ok {
		return in, false, nil
	}

	unlock, err := sys.lock(statePath(cfg.Home) + lockSuffix)
	if err != nil {
		return nil, false, err
	}
	defer unlock()

	// Recheck under the lock — another caller may have spawned while we waited.
	if in, ok := Status(cfg.Home); ok {
		return in, false, nil
	}
	// The record is stale by definition here; drop it so the readiness poll
	// below cannot mistake the dead daemon's entry for the new one.
	_ = Unpublish(cfg.Home)

	if err := sys.spawn(cfg); err != nil {
		return nil, false, err
	}

	// Readiness is "record published and listener accepting". Process liveness
	// is deliberately not part of it: the record is written by the daemon
	// itself, so its presence already implies the process ran.
	deadline := sys.now().Add(startTimeout)
	for sys.now().Before(deadline) {
		if in, rerr := readState(cfg.Home); rerr == nil && sys.dial(in.ProxyAddr, probeTimeout) == nil {
			return in, true, nil
		}
		sys.sleep(pollInterval)
	}
	return nil, false, fmt.Errorf("daemon did not become ready within %s — see %s",
		startTimeout, filepath.Join(cfg.Home, LogName))
}
