package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/term"

	"github.com/pratikbin/opensecretmask/internal/detect"
	"github.com/pratikbin/opensecretmask/internal/mask"
	"github.com/pratikbin/opensecretmask/internal/store"
)

const (
	homeEnv     = "OPENSECRETMASK_HOME"
	keyEnv      = "OSM_KEY"
	dbName      = "osm.db"
	proxyListen = "127.0.0.1:8787"
	dashListen  = "127.0.0.1:8788"
)

// homeDir returns the opensecretmask state directory, honoring
// $OPENSECRETMASK_HOME (used for tests) and defaulting to ~/.opensecretmask.
func homeDir() (string, error) {
	if h := os.Getenv(homeEnv); h != "" {
		return h, nil
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(u, ".opensecretmask"), nil
}

func dbPath(home string) string { return filepath.Join(home, dbName) }

// promptHidden reads a line from the terminal without echoing it.
func promptHidden(prompt string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(int(os.Stdin.Fd())) // #nosec G115 -- stdin fd is a small bounded value
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// passphrase returns $OSM_KEY if set, otherwise prompts once.
func passphrase() (string, error) {
	if k := os.Getenv(keyEnv); k != "" {
		return k, nil
	}
	p, err := promptHidden("opensecretmask passphrase: ")
	if err != nil {
		return "", err
	}
	if p == "" {
		return "", errors.New("empty passphrase")
	}
	return p, nil
}

// newPassphrase returns $OSM_KEY if set, otherwise prompts twice and confirms.
func newPassphrase() (string, error) {
	if k := os.Getenv(keyEnv); k != "" {
		return k, nil
	}
	p1, err := promptHidden("set a passphrase (encrypts the secret store): ")
	if err != nil {
		return "", err
	}
	if p1 == "" {
		return "", errors.New("empty passphrase")
	}
	p2, err := promptHidden("confirm passphrase: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("passphrases do not match")
	}
	return p1, nil
}

// openUnlocked opens the store and unlocks it, failing clearly when osm init
// has not been run.
func openUnlocked(ctx context.Context, home string) (*store.Store, error) {
	st, err := store.Open(ctx, dbPath(home))
	if err != nil {
		return nil, err
	}
	ok, err := st.Initialized(ctx)
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	if !ok {
		_ = st.Close()
		return nil, errors.New("not initialized — run 'osm init' first")
	}
	pass, err := passphrase()
	if err != nil {
		_ = st.Close()
		return nil, err
	}
	if err := st.Unlock(ctx, pass); err != nil {
		_ = st.Close()
		return nil, err
	}
	return st, nil
}

// newMasker builds a Masker over an unlocked store.
func newMasker(st *store.Store, entropy bool) (*mask.Masker, error) {
	det, err := detect.New(detect.Config{Entropy: entropy})
	if err != nil {
		return nil, err
	}
	return mask.NewMasker(st, det), nil
}

