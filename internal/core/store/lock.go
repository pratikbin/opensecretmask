package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

type Lock struct {
	fl *flock.Flock
}

func OpenLock(root string) (*Lock, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(root, LockName)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		f, ferr := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o644)
		if ferr != nil {
			return nil, ferr
		}
		_ = f.Close()
	}
	return &Lock{fl: flock.New(p)}, nil
}

func (l *Lock) WithExclusive(timeout time.Duration, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	got, err := l.fl.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return fmt.Errorf("flock ex: %w", err)
	}
	if !got {
		return fmt.Errorf("flock ex: timeout after %s", timeout)
	}
	defer l.fl.Unlock()
	return fn()
}

func (l *Lock) WithShared(timeout time.Duration, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	got, err := l.fl.TryRLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return fmt.Errorf("flock sh: %w", err)
	}
	if !got {
		return fmt.Errorf("flock sh: timeout after %s", timeout)
	}
	defer l.fl.Unlock()
	return fn()
}
