package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/stretchr/testify/require"
)

func runInit(t *testing.T, args ...string) (*bytes.Buffer, error) {
	t.Helper()
	root := newRootCmd()
	root.SetArgs(append([]string{"init"}, args...))
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	return out, root.Execute()
}

func TestInit_FreshDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)

	_, err := runInit(t)
	require.NoError(t, err)

	st, err := os.Stat(filepath.Join(dir, keymgr.InstallKeyName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())

	dst, err := os.Stat(dir)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o700), dst.Mode().Perm())

	for _, name := range []string{store.ConfigName, store.SecretsName, store.MappingsName, store.AllowlistName} {
		_, err := os.Stat(filepath.Join(dir, name))
		require.NoErrorf(t, err, "expected %s to exist", name)
	}
}

func TestInit_ErrorsWhenAlreadyInitialized(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)

	_, err := runInit(t)
	require.NoError(t, err)

	_, err = runInit(t)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already initialized")

	_, err = runInit(t, "--force")
	require.NoError(t, err)
}

