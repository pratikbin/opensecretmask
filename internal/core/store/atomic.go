package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// WriteAtomic writes data to path via tmp+fsync+rename. mode applied to final.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	rb := make([]byte, 4)
	if _, err := rand.Read(rb); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".tmp.%d.%s", os.Getpid(), hex.EncodeToString(rb)))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// CleanStaleTmp removes leftover .tmp.* files from crashes.
func CleanStaleTmp(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if len(n) > 5 && n[:5] == ".tmp." {
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
	return nil
}
