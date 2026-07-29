package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

// fakeSys is a deterministic stand-in for every OS seam. Every field is
// guarded by mu because the watch tests run a supervision goroutine while the
// test body mutates state, and the suite runs under -race.
type fakeSys struct {
	mu       sync.Mutex
	files    map[string][]byte
	aliveSet map[int]bool
	openSet  map[string]bool
	clock    time.Time
	log      []string
	spawned  []SpawnConfig
	signals  []int
	tick     chan time.Time

	// spawnFn runs inside the spawn seam. The default simulates a daemon that
	// comes up cleanly: it publishes a record and starts accepting.
	spawnFn func(f *fakeSys, cfg SpawnConfig) error
}

// installFake swaps the package seam for the duration of the test. Tests using
// it must not call t.Parallel — sys is package state.
func installFake(t *testing.T) *fakeSys {
	t.Helper()
	f := &fakeSys{
		files:    map[string][]byte{},
		aliveSet: map[int]bool{},
		openSet:  map[string]bool{},
		clock:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		tick:     make(chan time.Time, 1),
	}
	f.spawnFn = func(f *fakeSys, cfg SpawnConfig) error {
		f.publishFrom(cfg, 4242)
		return nil
	}
	prev := sys
	sys = f.system()
	t.Cleanup(func() { sys = prev })
	return f
}

func (f *fakeSys) system() system {
	return system{
		readFile: func(path string) ([]byte, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			b, ok := f.files[path]
			if !ok {
				return nil, &fs.PathError{Op: "open", Path: path, Err: os.ErrNotExist}
			}
			return append([]byte(nil), b...), nil
		},
		writeFile: func(path string, b []byte, _ os.FileMode) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.files[path] = append([]byte(nil), b...)
			f.log = append(f.log, "write:"+path)
			return nil
		},
		rename: func(oldPath, newPath string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			b, ok := f.files[oldPath]
			if !ok {
				return &fs.PathError{Op: "rename", Path: oldPath, Err: os.ErrNotExist}
			}
			delete(f.files, oldPath)
			f.files[newPath] = b
			f.log = append(f.log, "rename:"+newPath)
			return nil
		},
		remove: func(path string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if _, ok := f.files[path]; !ok {
				return &fs.PathError{Op: "remove", Path: path, Err: os.ErrNotExist}
			}
			delete(f.files, path)
			f.log = append(f.log, "remove:"+path)
			return nil
		},
		lock: func(path string) (func(), error) {
			f.mu.Lock()
			f.log = append(f.log, "lock")
			f.mu.Unlock()
			return func() {
				f.mu.Lock()
				f.log = append(f.log, "unlock")
				f.mu.Unlock()
			}, nil
		},
		alive: func(pid int) bool {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.aliveSet[pid]
		},
		signal: func(pid int, _ syscall.Signal) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.signals = append(f.signals, pid)
			f.log = append(f.log, fmt.Sprintf("signal:%d", pid))
			return nil
		},
		dial: func(addr string, _ time.Duration) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			if !f.openSet[addr] {
				return errors.New("connection refused")
			}
			return nil
		},
		now: func() time.Time {
			f.mu.Lock()
			defer f.mu.Unlock()
			return f.clock
		},
		sleep: func(d time.Duration) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.clock = f.clock.Add(d)
		},
		newTicker: func(time.Duration) (<-chan time.Time, func()) {
			return f.tick, func() {}
		},
		spawn: func(cfg SpawnConfig) error {
			f.mu.Lock()
			f.spawned = append(f.spawned, cfg)
			f.log = append(f.log, "spawn")
			fn := f.spawnFn
			f.mu.Unlock()
			return fn(f, cfg)
		},
	}
}

// publishFrom simulates the proxy process coming up: it writes the record the
// daemon would publish and marks the process and listener live.
func (f *fakeSys) publishFrom(cfg SpawnConfig, pid int) {
	f.writeState(cfg.Home, Info{
		PID: pid, ProxyAddr: cfg.Listen, DashAddr: cfg.Dash,
		Extra: cfg.Extra, Entropy: cfg.Entropy, LogLevel: cfg.LogLevel,
		AllowExternal: cfg.AllowExternal,
	})
	f.setAlive(pid, true)
	f.setOpen(cfg.Listen, true)
}

func (f *fakeSys) writeState(home string, in Info) {
	b, err := json.Marshal(in)
	if err != nil {
		panic(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[statePath(home)] = b
}

func (f *fakeSys) writeRaw(home string, b []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[statePath(home)] = b
}

func (f *fakeSys) hasState(home string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.files[statePath(home)]
	return ok
}

func (f *fakeSys) setAlive(pid int, v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.aliveSet[pid] = v
}

func (f *fakeSys) setOpen(addr string, v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.openSet[addr] = v
}

func (f *fakeSys) events() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

// tickNow is unused until Task 5 adds the watch loop that calls it; nolint is
// temporary, same as the sys var in Task 1, and comes out with its first caller.

func (f *fakeSys) spawns() []SpawnConfig {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]SpawnConfig(nil), f.spawned...)
}

func (f *fakeSys) setSpawnFn(fn func(*fakeSys, SpawnConfig) error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.spawnFn = fn
}

// tickNow fires one supervision tick.
func (f *fakeSys) tickNow() { f.tick <- time.Time{} }
