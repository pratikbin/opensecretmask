package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pratikbin/opensecretmask/internal/daemon"
)

func TestProxyCmdRejectsNonLoopbackListen(t *testing.T) {
	cmd := proxyCmd()
	cmd.SetArgs([]string{"--listen", "0.0.0.0:8787"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "not loopback") {
		t.Fatalf("proxyCmd --listen 0.0.0.0 = %v, want not-loopback error", err)
	}
}

func TestProxyCmdRejectsWildcardDashboard(t *testing.T) {
	cmd := proxyCmd()
	cmd.SetArgs([]string{"--dashboard", ":8788"})
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "every interface") {
		t.Fatalf("proxyCmd --dashboard :8788 = %v, want wildcard error", err)
	}
}

// The escape hatch must get past the guard. Execution then fails later (no
// CA in the temp home) — any error that is NOT a listen-address error proves
// the guard was bypassed.
func TestProxyCmdAllowExternalBindBypassesGuard(t *testing.T) {
	t.Setenv(homeEnv, t.TempDir())
	cmd := proxyCmd()
	cmd.SetArgs([]string{"--listen", "0.0.0.0:8787", "--allow-external-bind"})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("proxyCmd without CA should fail after the guard")
	}
	if strings.Contains(err.Error(), "not loopback") ||
		strings.Contains(err.Error(), "every interface") ||
		strings.Contains(err.Error(), "unresolved hostname") {
		t.Fatalf("guard fired despite --allow-external-bind: %v", err)
	}
}

// TestProxyCmdPublishesAllowExternalBind proves the write side of the
// --allow-external-bind policy: with the flag set, the running proxy records
// allow_external=true in the pidfile alongside its concrete bound addresses.
// The daemon package only tests respawn PRESERVING an already-set value, so
// nothing else in the repo guards this field actually being written.
func TestProxyCmdPublishesAllowExternalBind(t *testing.T) {
	home := t.TempDir()
	t.Setenv(homeEnv, home)
	t.Setenv(keyEnv, "test-passphrase")
	mustRunOSM(t, "init")

	cmd := proxyCmd()
	cmd.SetArgs([]string{
		"--allow-external-bind",
		"--listen", "127.0.0.1:0",
		"--dashboard", "127.0.0.1:0",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()

	type record struct {
		ProxyAddr     string `json:"proxy_addr"`
		DashAddr      string `json:"dash_addr"`
		AllowExternal bool   `json:"allow_external"`
	}
	var rec record
	pidPath := filepath.Join(home, daemon.PidFileName)
	deadline := time.Now().Add(5 * time.Second)
	for {
		select {
		case err := <-done:
			t.Fatalf("proxyCmd exited before publishing: %v", err)
		default:
		}
		b, err := os.ReadFile(pidPath)
		if err == nil {
			if jerr := json.Unmarshal(b, &rec); jerr != nil {
				t.Fatalf("parse pidfile: %v", jerr)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("pidfile did not appear within 5s")
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !rec.AllowExternal {
		t.Error("allow_external = false in pidfile, want true — the flag was not written to the daemon record")
	}
	for _, addr := range []string{rec.ProxyAddr, rec.DashAddr} {
		if addr == "" || strings.HasSuffix(addr, ":0") {
			t.Errorf("pidfile has non-concrete address %q, want a real bound port", addr)
		}
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatalf("proxyCmd after cancel: %v", err)
	}
	if _, err := os.Stat(pidPath); !os.IsNotExist(err) {
		t.Errorf("pidfile not removed after clean shutdown (stat err = %v)", err)
	}
}
