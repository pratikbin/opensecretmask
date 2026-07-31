package store_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"go.uber.org/goleak"

	"github.com/pratikbin/opensecretmask/internal/store"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(t.Context(), filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestInitAndUnlock(t *testing.T) {
	s := openTestStore(t)

	init, err := s.Initialized(t.Context())
	if err != nil || init {
		t.Fatalf("fresh db should be uninitialized: init=%v err=%v", init, err)
	}
	if err := s.InitCrypto(t.Context(), "master-pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	if !s.Unlocked() {
		t.Fatal("store should be unlocked after InitCrypto")
	}
	init, err = s.Initialized(t.Context())
	if err != nil || !init {
		t.Fatalf("db should be initialized after InitCrypto: init=%v err=%v", init, err)
	}
	if err := s.InitCrypto(t.Context(), "again"); err == nil {
		t.Fatal("InitCrypto on an initialized db should fail")
	}
}

func TestOpenCreatesFileMode0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file mode bits don't apply on windows")
	}
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = s.Close() }()

	// Includes the -wal/-shm sidecar files: SQLite creates them on first
	// write inheriting the main file's mode at that moment, so this also
	// guards the chmod-before-first-write ordering in store.Open.
	for _, suffix := range []string{"", "-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatalf("Stat(%s): %v", suffix, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s%s mode = %o, want 0600", path, suffix, got)
		}
	}
}

func TestUnlockWrongPassphrase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := s.InitCrypto(t.Context(), "right-pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	_ = s.Close()

	s2, err := store.Open(t.Context(), path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer func() { _ = s2.Close() }()
	if err := s2.Unlock(t.Context(), "wrong-pass"); !errors.Is(err, store.ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
	if err := s2.Unlock(t.Context(), "right-pass"); err != nil {
		t.Fatalf("Unlock with right pass: %v", err)
	}
	if !s2.Unlocked() {
		t.Fatal("store should be unlocked")
	}
}

func TestLockedRejectsSecretOps(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.PutSecret(t.Context(), store.Secret{Original: "x", Mask: "m"}); !errors.Is(err, store.ErrLocked) {
		t.Fatalf("expected ErrLocked from PutSecret on locked store, got %v", err)
	}
}

func TestPutGetSecret(t *testing.T) {
	s := openTestStore(t)
	if err := s.InitCrypto(t.Context(), "pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	sec := store.Secret{
		Name:     "ANTHROPIC_API_KEY",
		Source:   "registered",
		Original: "sk-ant-nrh80-gnililegs0110247876",
		Mask:     "sk-ant-awh17-qnqrlkRMZD1320637819",
		Shape:    "sk-ant-api03-{32}",
	}
	id, err := s.PutSecret(t.Context(), sec)
	if err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	got, err := s.SecretByMask(t.Context(), sec.Mask)
	if err != nil {
		t.Fatalf("SecretByMask: %v", err)
	}
	if got.Original != sec.Original {
		t.Fatalf("original mismatch: got %q want %q", got.Original, sec.Original)
	}
	if got.ID != id {
		t.Fatalf("id mismatch: got %d want %d", got.ID, id)
	}

	byOrig, err := s.SecretByOriginal(t.Context(), sec.Original)
	if err != nil {
		t.Fatalf("SecretByOriginal: %v", err)
	}
	if byOrig.Mask != sec.Mask {
		t.Fatalf("mask mismatch: got %q want %q", byOrig.Mask, sec.Mask)
	}
}

func TestPutSecretDedup(t *testing.T) {
	s := openTestStore(t)
	if err := s.InitCrypto(t.Context(), "pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	sec := store.Secret{
		Name: "K", Source: "registered",
		Original: "duplicate-secret-value",
		Mask:     "mask-aaaa", Shape: "{22}",
	}
	id1, err := s.PutSecret(t.Context(), sec)
	if err != nil {
		t.Fatalf("first PutSecret: %v", err)
	}
	sec.Mask = "mask-bbbb" // same Original — must dedup to the first row
	id2, err := s.PutSecret(t.Context(), sec)
	if err != nil {
		t.Fatalf("second PutSecret: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("dedup failed: ids %d and %d differ", id1, id2)
	}
}

func TestListRevealTouch(t *testing.T) {
	s := openTestStore(t)
	if err := s.InitCrypto(t.Context(), "pass"); err != nil {
		t.Fatalf("InitCrypto: %v", err)
	}
	id, err := s.PutSecret(t.Context(), store.Secret{
		Name: "K", Source: "registered",
		Original: "reveal-me", Mask: "m1", Shape: "{9}",
	})
	if err != nil {
		t.Fatalf("PutSecret: %v", err)
	}

	metas, err := s.ListSecrets(t.Context())
	if err != nil {
		t.Fatalf("ListSecrets: %v", err)
	}
	if len(metas) != 1 || metas[0].Mask != "m1" {
		t.Fatalf("unexpected ListSecrets result: %+v", metas)
	}

	got, err := s.RevealSecret(t.Context(), id)
	if err != nil || got != "reveal-me" {
		t.Fatalf("RevealSecret: got %q err %v", got, err)
	}

	if err := s.TouchSecret(t.Context(), id); err != nil {
		t.Fatalf("TouchSecret: %v", err)
	}
	metas, _ = s.ListSecrets(t.Context())
	if metas[0].Hits != 1 {
		t.Fatalf("expected hits=1 after touch, got %d", metas[0].Hits)
	}
}
