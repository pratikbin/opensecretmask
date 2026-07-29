package main

import (
	"strings"
	"testing"
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
