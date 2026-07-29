package proxyproc_test

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pratikbin/opensecretmask/internal/proxy"
	"github.com/pratikbin/opensecretmask/internal/proxyproc"
)

// baseConfig is a runnable configuration against home, with ephemeral ports
// and no daemon-state callbacks.
func baseConfig(home string) proxyproc.Config {
	return proxyproc.Config{
		Home:       home,
		Listen:     "127.0.0.1:0",
		Dash:       "127.0.0.1:0",
		Passphrase: func() (string, error) { return testPass, nil },
	}
}

func TestStartBindsBothListenersAndPublishes(t *testing.T) {
	home := newHome(t)
	cfg := baseConfig(home)

	var gotProxy, gotDash string
	cfg.Publish = func(proxyAddr, dashAddr string) error {
		gotProxy, gotDash = proxyAddr, dashAddr
		return nil
	}

	rt, err := proxyproc.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	// No teardown here: Serve arrives in the next task and owns cleanup. A
	// started-but-never-served runtime holds two loopback listeners and a
	// SQLite handle until the test binary exits, which is fine — every test
	// below binds its own ephemeral port.

	if rt.ProxyAddr() == "" || rt.ProxyAddr() == "127.0.0.1:0" {
		t.Fatalf("ProxyAddr = %q, want a concrete bound address", rt.ProxyAddr())
	}
	if gotProxy != rt.ProxyAddr() || gotDash != rt.DashAddr() {
		t.Fatalf("Publish got (%q, %q), want (%q, %q)", gotProxy, gotDash, rt.ProxyAddr(), rt.DashAddr())
	}
	// Publication must describe reality: both addresses accept connections.
	for _, addr := range []string{rt.ProxyAddr(), rt.DashAddr()} {
		c, derr := net.Dial("tcp", addr)
		if derr != nil {
			t.Fatalf("dial %s: %v", addr, derr)
		}
		_ = c.Close()
	}
}

func TestStartFailsBeforePromptingWhenCAMissing(t *testing.T) {
	home := newHome(t)
	if err := os.Remove(proxy.CertPath(home)); err != nil {
		t.Fatalf("remove CA: %v", err)
	}
	cfg := baseConfig(home)
	prompted := 0
	cfg.Passphrase = func() (string, error) { prompted++; return testPass, nil }

	_, err := proxyproc.Start(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "osm init") {
		t.Fatalf("Start = %v, want a load-CA error naming 'osm init'", err)
	}
	if prompted != 0 {
		t.Errorf("passphrase prompted %d times before the CA check; want 0", prompted)
	}
}

func TestStartFailsBeforePromptingWhenStoreUninitialized(t *testing.T) {
	home := newHome(t)
	if err := os.Remove(filepath.Join(home, "osm.db")); err != nil {
		t.Fatalf("remove store: %v", err)
	}
	cfg := baseConfig(home)
	prompted := 0
	cfg.Passphrase = func() (string, error) { prompted++; return testPass, nil }

	_, err := proxyproc.Start(context.Background(), cfg)
	if err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Fatalf("Start = %v, want a not-initialized error", err)
	}
	if prompted != 0 {
		t.Errorf("passphrase prompted %d times before the init check; want 0", prompted)
	}
}

func TestStartPropagatesPassphraseFailure(t *testing.T) {
	cfg := baseConfig(newHome(t))
	sentinel := errors.New("no terminal")
	cfg.Passphrase = func() (string, error) { return "", sentinel }

	_, err := proxyproc.Start(context.Background(), cfg)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Start = %v, want the passphrase error", err)
	}
}

func TestStartRejectsWrongPassphrase(t *testing.T) {
	cfg := baseConfig(newHome(t))
	cfg.Passphrase = func() (string, error) { return "wrong", nil }

	if _, err := proxyproc.Start(context.Background(), cfg); err == nil {
		t.Fatal("Start = nil error with a wrong passphrase")
	}
}

// TestStartReleasesProxyPortWhenDashboardBindFails is the rollback contract:
// a failure at bind step 2 must unwind bind step 1. It is proven by binding
// the same proxy address again — a leaked listener would make this fail with
// "address already in use".
func TestStartReleasesProxyPortWhenDashboardBindFails(t *testing.T) {
	home := newHome(t)
	proxyAddr := freePort(t)

	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	cfg := baseConfig(home)
	cfg.Listen = proxyAddr
	cfg.Dash = occupied.Addr().String()
	if _, err := proxyproc.Start(context.Background(), cfg); err == nil {
		t.Fatal("Start = nil error with an occupied dashboard address")
	}

	cfg.Dash = "127.0.0.1:0"
	if _, err := proxyproc.Start(context.Background(), cfg); err != nil {
		t.Fatalf("second Start on the same proxy address: %v — the failed Start leaked its listener", err)
	}
}

// TestStartDoesNotPublishWhenBindFails guards the daemon contract: an
// unreachable address must never be recorded.
func TestStartDoesNotPublishWhenBindFails(t *testing.T) {
	home := newHome(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = occupied.Close() }()

	cfg := baseConfig(home)
	cfg.Dash = occupied.Addr().String()
	published := 0
	cfg.Publish = func(string, string) error { published++; return nil }

	if _, err := proxyproc.Start(context.Background(), cfg); err == nil {
		t.Fatal("Start = nil error with an occupied dashboard address")
	}
	if published != 0 {
		t.Errorf("Publish called %d times after a bind failure; want 0", published)
	}
}

// TestStartRollsBackWhenPublishFails proves the last acquired resource is
// unwound too: the proxy address must be bindable again.
func TestStartRollsBackWhenPublishFails(t *testing.T) {
	home := newHome(t)
	proxyAddr := freePort(t)

	cfg := baseConfig(home)
	cfg.Listen = proxyAddr
	cfg.Publish = func(string, string) error { return errors.New("read-only home") }

	if _, err := proxyproc.Start(context.Background(), cfg); err == nil {
		t.Fatal("Start = nil error when Publish failed")
	}

	ln, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("rebind %s: %v — Start leaked its listener when Publish failed", proxyAddr, err)
	}
	_ = ln.Close()
}

func TestStartParsesExtraProviders(t *testing.T) {
	cfg := baseConfig(newHome(t))
	cfg.ExtraProviders = []string{"api.acme.com=openai", "bare.example.com"}

	rt, err := proxyproc.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	got := rt.Providers()
	last := got[len(got)-2:]
	if last[0].Host != "api.acme.com" || last[0].Dialect != "openai" {
		t.Errorf("provider[-2] = %+v, want api.acme.com/openai", last[0])
	}
	if last[1].Host != "bare.example.com" || last[1].Dialect != "custom" {
		t.Errorf("provider[-1] = %+v, want bare.example.com/custom", last[1])
	}
}

func TestStartRejectsNegativeRetention(t *testing.T) {
	cfg := baseConfig(newHome(t))
	cfg.HistoryRetention = -time.Hour
	if _, err := proxyproc.Start(context.Background(), cfg); err == nil {
		t.Fatal("Start = nil error with a negative retention")
	}
}
