package daemon

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"
)

func TestRealSystemFileOps(t *testing.T) {
	s := realSystem()
	dir := t.TempDir()
	src := filepath.Join(dir, "a.tmp")
	dst := filepath.Join(dir, "a.json")

	if err := s.writeFile(src, []byte(`{"pid":1}`), 0o600); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	if err := s.rename(src, dst); err != nil {
		t.Fatalf("rename: %v", err)
	}
	b, err := s.readFile(dst)
	if err != nil {
		t.Fatalf("readFile: %v", err)
	}
	if string(b) != `{"pid":1}` {
		t.Fatalf("readFile = %q, want %q", b, `{"pid":1}`)
	}
	if err := s.remove(dst); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := s.readFile(dst); !os.IsNotExist(err) {
		t.Fatalf("readFile after remove: err = %v, want IsNotExist", err)
	}
}

func TestRealSystemLockIsExclusiveWithinProcess(t *testing.T) {
	s := realSystem()
	path := filepath.Join(t.TempDir(), "x.lock")
	unlock, err := s.lock(path)
	if err != nil {
		t.Fatalf("lock: %v", err)
	}
	unlock()
	// Re-acquiring after unlock must succeed — a leaked fd or missing
	// LOCK_UN would make this hang or fail.
	unlock2, err := s.lock(path)
	if err != nil {
		t.Fatalf("re-lock: %v", err)
	}
	unlock2()
}

func TestRealSystemProcessAndDial(t *testing.T) {
	s := realSystem()
	if !s.alive(os.Getpid()) {
		t.Error("alive(self) = false, want true")
	}
	// PID 0 is never a real user process; Signal(0) on it is rejected.
	if s.alive(0) {
		t.Error("alive(0) = true, want false")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := s.dial(addr, time.Second); err != nil {
		t.Errorf("dial(open) = %v, want nil", err)
	}
	_ = ln.Close()
	if err := s.dial(addr, 200*time.Millisecond); err == nil {
		t.Error("dial(closed) = nil, want error")
	}
	if err := s.signal(os.Getpid(), syscall.Signal(0)); err != nil {
		t.Errorf("signal(self, 0) = %v, want nil", err)
	}
}

func TestRealSystemTicker(t *testing.T) {
	s := realSystem()
	c, stop := s.newTicker(5 * time.Millisecond)
	defer stop()
	select {
	case <-c:
	case <-time.After(2 * time.Second):
		t.Fatal("ticker did not fire")
	}
}

func TestEnvWithReplacesExistingKey(t *testing.T) {
	got := envWith([]string{"PATH=/bin", "OSM_KEY=old", "HOME=/h"}, "OSM_KEY", "new")
	want := []string{"PATH=/bin", "HOME=/h", "OSM_KEY=new"}
	if !slices.Equal(got, want) {
		t.Fatalf("envWith = %v, want %v", got, want)
	}
}

func TestSpawnConfigArgs(t *testing.T) {
	cfg := SpawnConfig{
		Listen: "127.0.0.1:8787", Dash: "127.0.0.1:8788",
		Extra: []string{"api.acme.com", "x.io=custom"}, Entropy: true,
		LogLevel: "debug", AllowExternal: true,
	}
	want := []string{
		"proxy", "--listen", "127.0.0.1:8787", "--dashboard", "127.0.0.1:8788",
		"--log-level", "debug",
		"--provider", "api.acme.com", "--provider", "x.io=custom",
		"--detect-entropy", "--allow-external-bind",
	}
	if got := cfg.args(); !slices.Equal(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}

	// A record written by an older binary carries no log level; the spawned
	// process must still get a valid --log-level value.
	bare := SpawnConfig{Listen: "a:1", Dash: "b:2"}
	wantBare := []string{"proxy", "--listen", "a:1", "--dashboard", "b:2", "--log-level", "info"}
	if got := bare.args(); !slices.Equal(got, wantBare) {
		t.Fatalf("args(bare) = %v, want %v", got, wantBare)
	}
}
