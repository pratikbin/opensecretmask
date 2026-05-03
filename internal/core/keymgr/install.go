package keymgr

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const InstallKeyName = "install.key"
const installKeyLen = 32

var ErrKeyMissing = errors.New("opensecretmask: install.key not found; run `osm init`")
var ErrKeyBadMode = errors.New("opensecretmask: install.key has insecure permissions; want 0600")

func LoadOrError(dir string) ([]byte, error) {
	p := filepath.Join(dir, InstallKeyName)
	st, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrKeyMissing
	}
	if err != nil {
		return nil, fmt.Errorf("stat install.key: %w", err)
	}
	if st.Mode().Perm() != 0o600 {
		return nil, ErrKeyBadMode
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read install.key: %w", err)
	}
	if len(b) != installKeyLen {
		return nil, fmt.Errorf("install.key length=%d, want %d", len(b), installKeyLen)
	}
	return b, nil
}

func Generate(dir string) ([]byte, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	b := make([]byte, installKeyLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	p := filepath.Join(dir, InstallKeyName)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, fmt.Errorf("write install.key: %w", err)
	}
	return b, nil
}
