package daemon

import (
	"errors"
	"slices"
	"strings"
	"testing"
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
