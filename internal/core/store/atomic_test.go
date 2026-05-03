package store

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWriteAtomic_ContentAndMode(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	data := []byte("hello world")
	require.NoError(t, WriteAtomic(p, data, 0o600))

	got, err := os.ReadFile(p)
	require.NoError(t, err)
	require.Equal(t, data, got)

	if runtime.GOOS != "windows" {
		fi, err := os.Stat(p)
		require.NoError(t, err)
		require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
	}
}

func TestWriteAtomic_NoTmpLeft(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	require.NoError(t, WriteAtomic(p, []byte("x"), 0o644))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), ".tmp."), "leftover tmp: %s", e.Name())
	}
}

func TestCleanStaleTmp(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".tmp.foo"), []byte("a"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "regular.txt"), []byte("b"), 0o644))

	require.NoError(t, CleanStaleTmp(dir))

	_, err := os.Stat(filepath.Join(dir, ".tmp.foo"))
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(filepath.Join(dir, "regular.txt"))
	require.NoError(t, err)
}

func TestWriteAtomic_Concurrent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f.txt")
	const n = 10

	contents := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		contents[fmt.Sprintf("writer-%02d", i)] = struct{}{}
	}

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for c := range contents {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			if err := WriteAtomic(p, []byte(s), 0o644); err != nil {
				errs <- err
			}
		}(c)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}

	got, err := os.ReadFile(p)
	require.NoError(t, err)
	_, ok := contents[string(got)]
	require.True(t, ok, "final content %q not from any writer", string(got))

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	for _, e := range entries {
		require.False(t, strings.HasPrefix(e.Name(), ".tmp."), "leftover tmp: %s", e.Name())
	}
}
