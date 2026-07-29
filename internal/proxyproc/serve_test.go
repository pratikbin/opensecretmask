package proxyproc_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pratikbin/opensecretmask/internal/proxyproc"
)

// canceled is an already-cancelled context: Serve with it starts, immediately
// drains, and tears down — the shortest path to exercising cleanup.
func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestServeStopsOnCancelAndCleansUp(t *testing.T) {
	cfg := baseConfig(newHome(t))
	var unpublished atomic.Int32
	cfg.Unpublish = func() { unpublished.Add(1) }

	rt, err := proxyproc.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	proxyAddr, dashAddr := rt.ProxyAddr(), rt.DashAddr()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- rt.Serve(ctx) }()

	// Both servers answer before cancellation.
	for _, addr := range []string{proxyAddr, dashAddr} {
		c, derr := net.Dial("tcp", addr)
		if derr != nil {
			t.Fatalf("dial %s while serving: %v", addr, derr)
		}
		_ = c.Close()
	}

	cancel()
	select {
	case serr := <-done:
		if serr != nil {
			t.Fatalf("Serve = %v, want nil on cancellation", serr)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return after cancellation")
	}

	if got := unpublished.Load(); got != 1 {
		t.Errorf("Unpublish called %d times, want 1", got)
	}
	// Both ports are released: another process can take them.
	for _, addr := range []string{proxyAddr, dashAddr} {
		ln, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			t.Errorf("rebind %s after Serve: %v — the listener leaked", addr, lerr)
			continue
		}
		_ = ln.Close()
	}
}

func TestServeWithAlreadyCanceledContextCleansUp(t *testing.T) {
	cfg := baseConfig(newHome(t))
	var unpublished atomic.Int32
	cfg.Unpublish = func() { unpublished.Add(1) }

	rt, err := proxyproc.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if serr := rt.Serve(canceled()); serr != nil {
		t.Fatalf("Serve(canceled) = %v, want nil", serr)
	}
	if got := unpublished.Load(); got != 1 {
		t.Errorf("Unpublish called %d times, want 1", got)
	}
}

func TestServeIsUsableAfterStoreCloses(t *testing.T) {
	// Serve owns the store's lifetime: after it returns, the store is closed.
	// A second Serve must not panic or hang — it returns promptly.
	cfg := baseConfig(newHome(t))
	rt, err := proxyproc.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if serr := rt.Serve(canceled()); serr != nil {
		t.Fatalf("first Serve = %v", serr)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = rt.Serve(canceled())
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("second Serve hung")
	}
}
