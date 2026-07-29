// Package daemon owns the complete lifecycle of the background 'osm proxy'
// process: the persisted record, health evaluation, serialized spawn,
// readiness and exit observation, supervision, restart, and publication.
//
// Callers state a goal — Status, Ensure, Stop, Restart, Watch — and the
// package derives current state from the record plus live probes on every
// call. There is no exported state machine and no exported seam: process,
// clock, filesystem, and socket adapters stay inside the package.
package daemon

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// keyEnv carries the store passphrase to a spawned daemon so it can unlock
// without a terminal. cmd/osm declares the same name for its own env handling;
// package main is not importable, so the constant is restated here.
const keyEnv = "OSM_KEY"

// system is every OS interaction the lifecycle performs, collected behind
// function fields. Production uses realSystem(); package-internal tests swap
// in a fake so state transitions are driven without fork-exec, real clocks,
// or real sockets.
type system struct {
	readFile  func(path string) ([]byte, error)
	writeFile func(path string, b []byte, perm os.FileMode) error
	rename    func(oldPath, newPath string) error
	remove    func(path string) error
	lock      func(path string) (unlock func(), err error)
	alive     func(pid int) bool
	signal    func(pid int, sig syscall.Signal) error
	dial      func(addr string, timeout time.Duration) error
	now       func() time.Time
	sleep     func(d time.Duration)
	newTicker func(d time.Duration) (<-chan time.Time, func())
	spawn     func(cfg SpawnConfig) error
}

// sys is unused until Task 3 adds the lifecycle operations that call through
// it; nolint is temporary and comes out with that task's first caller.
//
//nolint:unused // consumed starting in Task 3
var sys = realSystem()

func realSystem() system {
	return system{
		readFile:  os.ReadFile,
		writeFile: os.WriteFile,
		rename:    os.Rename,
		remove:    os.Remove,
		lock:      flockFile,
		alive:     processAlive,
		signal:    func(pid int, sig syscall.Signal) error { return syscall.Kill(pid, sig) },
		dial:      dialTCP,
		now:       time.Now,
		sleep:     time.Sleep,
		newTicker: func(d time.Duration) (<-chan time.Time, func()) {
			t := time.NewTicker(d)
			return t.C, t.Stop
		},
		spawn: spawnProcess,
	}
}

// flockFile takes an exclusive advisory lock and returns the release func.
// The fd is held for the lock's lifetime — closing it would drop the lock.
func flockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600) // #nosec G304 -- lockfile path is internal (under $OPENSECRETMASK_HOME)
	if err != nil {
		return nil, fmt.Errorf("open daemon lockfile: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil { // #nosec G115 -- fd uintptr fits in int on all supported platforms
		_ = f.Close()
		return nil, fmt.Errorf("flock daemon lockfile: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN) // #nosec G115 -- fd uintptr fits in int on all supported platforms
		_ = f.Close()
	}, nil
}

// processAlive reports whether pid is a running process. Signal 0 is a no-op
// liveness probe: it succeeds only if the process exists and is signalable.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return proc.Signal(syscall.Signal(0)) == nil
}

func dialTCP(addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	return conn.Close()
}

// spawnProcess fork-execs 'osm proxy' detached from the parent terminal: a new
// session via Setsid so SIGHUP from the parent shell does not reach it, and
// stdio redirected to a log file so the daemon survives parent exit.
func spawnProcess(cfg SpawnConfig) error {
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate osm binary: %w", err)
	}
	logF, err := os.OpenFile(filepath.Join(cfg.Home, LogName), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) // #nosec G304 -- daemon log path is internal (under $OPENSECRETMASK_HOME)
	if err != nil {
		return fmt.Errorf("open daemon log: %w", err)
	}
	cmd := exec.Command(self, cfg.args()...) // #nosec G204 -- self is os.Executable, args are internal
	cmd.Stdin = nil
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	env := os.Environ()
	if cfg.Key != "" {
		env = envWith(env, keyEnv, cfg.Key)
	}
	cmd.Env = env
	if err := cmd.Start(); err != nil {
		_ = logF.Close()
		return fmt.Errorf("spawn osm proxy: %w", err)
	}
	_ = cmd.Process.Release()
	_ = logF.Close()
	return nil
}

// envWith returns base with key set to val, dropping any pre-existing entry so
// the value is unambiguous. cmd/osm has its own withEnv for the child
// command's multi-key map; the few lines are restated here rather than making
// internal/daemon depend on package main, which cannot be imported.
func envWith(base []string, key, val string) []string {
	out := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if k, _, _ := strings.Cut(kv, "="); k == key {
			continue
		}
		out = append(out, kv)
	}
	return append(out, key+"="+val)
}
