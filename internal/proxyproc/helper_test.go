package proxyproc_test

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/proxy"
	"github.com/pratikbin/opensecretmask/internal/store"
)

const testPass = "correct-horse-battery-staple"

// newHome returns a temp state directory holding a real CA and an initialized,
// locked store — the same on-disk shape 'osm init' produces.
func newHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()

	ca, err := proxy.GenerateCA()
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := ca.Save(home); err != nil {
		t.Fatalf("save CA: %v", err)
	}

	st, err := store.Open(context.Background(), filepath.Join(home, "osm.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.InitCrypto(context.Background(), testPass); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("store.Close: %v", err)
	}
	return home
}

// freePort returns a loopback address that was bindable a moment ago. Used to
// prove a failed Start released the port it had taken.
func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return addr
}
