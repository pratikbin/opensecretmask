package daemon

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

const home = "/osm-home"

func TestStatusAbsentRecord(t *testing.T) {
	installFake(t)
	in, ok := Status(home)
	if in != nil || ok {
		t.Fatalf("Status(absent) = (%v, %v), want (nil, false)", in, ok)
	}
}

func TestStatusHealthyRequiresProcessAndListener(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787"})

	// Dead PID, listener answering (something else took the port).
	f.setOpen("127.0.0.1:8787", true)
	if in, ok := Status(home); in == nil || ok {
		t.Errorf("Status(dead pid) = (%v, %v), want (record, false)", in, ok)
	}

	// Live PID, nothing listening — PID reuse after a reboot.
	f.setAlive(10, true)
	f.setOpen("127.0.0.1:8787", false)
	if _, ok := Status(home); ok {
		t.Error("Status(live pid, closed socket) = healthy, want unhealthy")
	}

	f.setOpen("127.0.0.1:8787", true)
	in, ok := Status(home)
	if !ok {
		t.Fatal("Status(live pid, open socket) = unhealthy, want healthy")
	}
	if in.PID != 10 {
		t.Fatalf("Status PID = %d, want 10", in.PID)
	}
}

func TestEnsureReusesHealthyDaemonWithoutLockOrSpawn(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787", DashAddr: "127.0.0.1:8788"})
	f.setAlive(10, true)
	f.setOpen("127.0.0.1:8787", true)

	in, spawned, err := Ensure(SpawnConfig{Home: home, Listen: "127.0.0.1:8787", Dash: "127.0.0.1:8788"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if spawned {
		t.Error("spawned = true, want false for a healthy daemon")
	}
	if in.PID != 10 {
		t.Errorf("PID = %d, want 10", in.PID)
	}
	if ev := f.events(); len(ev) != 0 {
		t.Errorf("fast path touched the OS: %v", ev)
	}
}

func TestEnsureSpawnsUnderLockAndClearsStaleRecord(t *testing.T) {
	f := installFake(t)
	// Stale: PID recorded but dead.
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787", DashAddr: "127.0.0.1:8788"})

	cfg := SpawnConfig{
		Home: home, Listen: "127.0.0.1:8787", Dash: "127.0.0.1:8788",
		Key: "pass", Extra: []string{"api.acme.com"}, Entropy: true,
		LogLevel: "debug", AllowExternal: true,
	}
	in, spawned, err := Ensure(cfg)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if !spawned {
		t.Error("spawned = false, want true")
	}
	if in.PID != 4242 {
		t.Errorf("PID = %d, want 4242 (the fake's spawned daemon)", in.PID)
	}

	ev := f.events()
	lockIdx := slices.Index(ev, "lock")
	removeIdx := slices.Index(ev, "remove:"+statePath(home))
	spawnIdx := slices.Index(ev, "spawn")
	unlockIdx := slices.Index(ev, "unlock")
	if lockIdx < 0 || removeIdx < 0 || spawnIdx < 0 || unlockIdx < 0 {
		t.Fatalf("events missing a phase: %v", ev)
	}
	if lockIdx >= removeIdx || removeIdx >= spawnIdx || spawnIdx >= unlockIdx {
		t.Fatalf("ordering wrong (want lock < remove < spawn < unlock): %v", ev)
	}

	got := f.spawns()
	if len(got) != 1 {
		t.Fatalf("spawns = %d, want 1", len(got))
	}
	if got[0].Key != "pass" || got[0].Listen != "127.0.0.1:8787" || !got[0].Entropy ||
		!got[0].AllowExternal || got[0].LogLevel != "debug" ||
		!slices.Equal(got[0].Extra, []string{"api.acme.com"}) {
		t.Fatalf("spawn config not passed through: %+v", got[0])
	}
}

func TestEnsureRechecksHealthAfterAcquiringLock(t *testing.T) {
	f := installFake(t)
	// No record at first: the fast path misses and Ensure takes the lock.
	// A competing caller "wins" while we wait — simulate by publishing a
	// healthy record from the lock seam.
	prev := sys.lock
	sys.lock = func(path string) (func(), error) {
		f.writeState(home, Info{PID: 77, ProxyAddr: "127.0.0.1:8787"})
		f.setAlive(77, true)
		f.setOpen("127.0.0.1:8787", true)
		return prev(path)
	}

	in, spawned, err := Ensure(SpawnConfig{Home: home, Listen: "127.0.0.1:8787", Dash: "127.0.0.1:8788"})
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}
	if spawned {
		t.Error("spawned = true, want false — the recheck must find the winner's daemon")
	}
	if in.PID != 77 {
		t.Errorf("PID = %d, want 77", in.PID)
	}
	if slices.Contains(f.events(), "spawn") {
		t.Error("Ensure spawned a second daemon after the recheck")
	}
}

func TestEnsurePropagatesSpawnFailure(t *testing.T) {
	f := installFake(t)
	f.setSpawnFn(func(*fakeSys, SpawnConfig) error { return errors.New("boom") })

	_, spawned, err := Ensure(SpawnConfig{Home: home, Listen: "a:1", Dash: "b:2"})
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("Ensure err = %v, want spawn failure", err)
	}
	if spawned {
		t.Error("spawned = true on a failed spawn")
	}
}

func TestEnsureReadinessTimeout(t *testing.T) {
	f := installFake(t)
	// A daemon that starts but never publishes or binds.
	f.setSpawnFn(func(*fakeSys, SpawnConfig) error { return nil })

	_, _, err := Ensure(SpawnConfig{Home: home, Listen: "a:1", Dash: "b:2"})
	if err == nil {
		t.Fatal("Ensure = nil error, want readiness timeout")
	}
	for _, want := range []string{"did not become ready", LogName} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err %q missing %q", err, want)
		}
	}
}

func TestStopIsIdempotent(t *testing.T) {
	f := installFake(t)

	// No record at all.
	if err := Stop(home); err != nil {
		t.Fatalf("Stop(absent) = %v, want nil", err)
	}

	// Record whose process is already gone: clear it, signal nothing.
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787"})
	if err := Stop(home); err != nil {
		t.Fatalf("Stop(dead) = %v, want nil", err)
	}
	if f.hasState(home) {
		t.Error("stale record survived Stop")
	}
	if slices.ContainsFunc(f.events(), func(e string) bool { return strings.HasPrefix(e, "signal:") }) {
		t.Error("Stop signalled a dead process")
	}
}

func TestStopDoesNotSignalUnhealthyRecord(t *testing.T) {
	f := installFake(t)
	// PID reused after a reboot: alive, but nothing is bound to the recorded
	// address, so healthy() (the same check Status/Ensure use) says no. Stop
	// must not signal a process it never started.
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787"})
	f.setAlive(10, true)

	if err := Stop(home); err != nil {
		t.Fatalf("Stop(unhealthy) = %v, want nil", err)
	}
	if f.hasState(home) {
		t.Error("stale record survived Stop")
	}
	if slices.ContainsFunc(f.events(), func(e string) bool { return strings.HasPrefix(e, "signal:") }) {
		t.Error("Stop signalled an unhealthy (reused-PID) record")
	}
}

func TestStopSignalsAndWaitsForFullExit(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787"})
	f.setAlive(10, true)
	f.setOpen("127.0.0.1:8787", true)

	// Model a clean SIGTERM: the daemon removes its own record, then exits.
	// The exit lands one poll after the record disappears, so the test proves
	// Stop waits for BOTH conditions rather than either one.
	prevSleep := sys.sleep
	step := 0
	sys.sleep = func(d time.Duration) {
		step++
		switch step {
		case 1:
			f.mu.Lock()
			delete(f.files, statePath(home))
			f.mu.Unlock()
		case 2:
			f.setAlive(10, false)
		}
		prevSleep(d)
	}

	if err := Stop(home); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if step < 2 {
		t.Fatalf("Stop returned after %d polls, want at least 2 (dead PID and absent record)", step)
	}
	if !slices.Contains(f.events(), "signal:10") {
		t.Error("Stop did not signal the daemon")
	}
}

func TestStopSignalsAndWaitsForFullExitPidFirst(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787"})
	f.setAlive(10, true)
	f.setOpen("127.0.0.1:8787", true)

	// Mirror of TestStopSignalsAndWaitsForFullExit with the orderings swapped:
	// the process dies first, the record disappears one poll later. Together
	// the two tests prove Stop waits for both conditions regardless of which
	// one settles first — neither an AND-of-either-order nor an OR shortcut
	// can pass both.
	prevSleep := sys.sleep
	step := 0
	sys.sleep = func(d time.Duration) {
		step++
		switch step {
		case 1:
			f.setAlive(10, false)
		case 2:
			f.mu.Lock()
			delete(f.files, statePath(home))
			f.mu.Unlock()
		}
		prevSleep(d)
	}

	if err := Stop(home); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if step < 2 {
		t.Fatalf("Stop returned after %d polls, want at least 2 (dead PID and absent record)", step)
	}
	if !slices.Contains(f.events(), "signal:10") {
		t.Error("Stop did not signal the daemon")
	}
}

func TestStopTimesOutOnHungDaemon(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{PID: 10, ProxyAddr: "127.0.0.1:8787"})
	f.setAlive(10, true)
	f.setOpen("127.0.0.1:8787", true) // healthy — signalled, but never dies

	err := Stop(home)
	if err == nil || !strings.Contains(err.Error(), "did not exit within") {
		t.Fatalf("Stop(hung) = %v, want timeout error", err)
	}
}

func TestRestartWithoutRecord(t *testing.T) {
	installFake(t)
	if _, err := Restart(home, "pass"); !errors.Is(err, ErrNoDaemon) {
		t.Fatalf("Restart(absent) = %v, want ErrNoDaemon", err)
	}
}

func TestRestartPreservesAddressesAndConfig(t *testing.T) {
	f := installFake(t)
	f.writeState(home, Info{
		PID: 10, ProxyAddr: "127.0.0.1:8787", DashAddr: "127.0.0.1:8788",
		Extra: []string{"api.acme.com"}, Entropy: true, LogLevel: "debug",
		AllowExternal: true,
	})
	// Dead PID — restart from a stale record is a supported path: Stop clears
	// the record and Ensure brings a fresh daemon up on the same addresses.

	np, err := Restart(home, "pass")
	if err != nil {
		t.Fatalf("Restart: %v", err)
	}
	if np.PID != 4242 {
		t.Errorf("PID = %d, want 4242", np.PID)
	}
	got := f.spawns()
	if len(got) != 1 {
		t.Fatalf("spawns = %d, want 1", len(got))
	}
	if got[0].Listen != "127.0.0.1:8787" || got[0].Dash != "127.0.0.1:8788" ||
		got[0].Key != "pass" || !got[0].Entropy || !got[0].AllowExternal ||
		got[0].LogLevel != "debug" || !slices.Equal(got[0].Extra, []string{"api.acme.com"}) {
		t.Fatalf("restart did not preserve configuration: %+v", got[0])
	}
}
