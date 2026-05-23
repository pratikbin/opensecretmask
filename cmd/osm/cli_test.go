package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/store"
)

func runOSM(t *testing.T, args ...string) error {
	t.Helper()
	c := rootCmd()
	c.SetArgs(args)
	c.SetOut(io.Discard)
	c.SetErr(io.Discard)
	return c.Execute()
}

func mustRunOSM(t *testing.T, args ...string) {
	t.Helper()
	if err := runOSM(t, args...); err != nil {
		t.Fatalf("osm %s: %v", strings.Join(args, " "), err)
	}
}

func openHomeStore(t *testing.T, home, pass string) *store.Store {
	t.Helper()
	st, err := store.Open(t.Context(), filepath.Join(home, "osm.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.Unlock(t.Context(),pass); err != nil {
		t.Fatalf("unlock store: %v", err)
	}
	return st
}

func TestCLIInitAddStatusDoctor(t *testing.T) {
	home := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", home)
	t.Setenv("OSM_KEY", "test-passphrase")

	mustRunOSM(t, "init", "--no-trust")
	for _, f := range []string{"ca-cert.pem", "ca-key.pem", "osm.db"} {
		if _, err := os.Stat(filepath.Join(home, f)); err != nil {
			t.Fatalf("init did not create %s: %v", f, err)
		}
	}
	if err := runOSM(t, "init", "--no-trust"); err == nil {
		t.Fatal("re-running init on an initialized home should fail")
	}

	mustRunOSM(t, "add", "ANTHROPIC_KEY=sk-ant-api03-secretvalue1234567890")

	st := openHomeStore(t, home, "test-passphrase")
	reg, err := st.RegisteredSecrets(t.Context())
	if err != nil {
		t.Fatalf("RegisteredSecrets: %v", err)
	}
	if len(reg) != 1 || reg[0].Name != "ANTHROPIC_KEY" {
		t.Fatalf("add did not register the secret: %+v", reg)
	}
	if reg[0].Mask == reg[0].Original || len(reg[0].Mask) != len(reg[0].Original) {
		t.Fatalf("registered secret not masked format-preservingly: %+v", reg[0])
	}

	mustRunOSM(t, "status")
	mustRunOSM(t, "doctor")
}

func TestCLIPreload(t *testing.T) {
	home := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", home)
	t.Setenv("OSM_KEY", "pass")
	mustRunOSM(t, "init", "--no-trust")

	envDir := t.TempDir()
	envContent := "API_KEY=sk-ant-api03-fromenvfile1234567\n" +
		"# a comment line\n" +
		"export DB_URL=postgres://user:pw@host/db\n" +
		"\n"
	if err := os.WriteFile(filepath.Join(envDir, ".env"), []byte(envContent), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	mustRunOSM(t, "preload", envDir)

	st := openHomeStore(t, home, "pass")
	reg, err := st.RegisteredSecrets(t.Context())
	if err != nil {
		t.Fatalf("RegisteredSecrets: %v", err)
	}
	if len(reg) != 2 {
		t.Fatalf("preload should register 2 values, got %d: %+v", len(reg), reg)
	}
}

func TestCLIRequiresInit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", home)
	t.Setenv("OSM_KEY", "pass")
	if err := runOSM(t, "add", "K=v"); err == nil {
		t.Fatal("'osm add' before 'osm init' should fail")
	}
}

func TestCLIRunRequiresInit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", home)
	if err := runOSM(t, "run", "echo", "hi"); err == nil {
		t.Fatal("'osm run' before 'osm init' should fail")
	}
}

func TestCLIRunSpawnsOwnProxy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", home)
	t.Setenv("OSM_KEY", "pass")
	mustRunOSM(t, "init", "--no-trust")
	// Port 1 is reliably refused — with no proxy to reuse, 'osm run' must
	// spawn its own ephemeral proxy and still run the command to completion.
	if err := runOSM(t, "run", "--listen", "127.0.0.1:1", "echo", "hi"); err != nil {
		t.Fatalf("'osm run' should spawn its own proxy and succeed: %v", err)
	}
}

