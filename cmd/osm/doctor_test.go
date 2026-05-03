package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/stretchr/testify/require"
)

func runDoctor(t *testing.T, args ...string) (*bytes.Buffer, error) {
	t.Helper()
	root := newRootCmd()
	root.SetArgs(append([]string{"doctor"}, args...))
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	return out, root.Execute()
}

func TestDoctor_HealthyHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)

	_, err := runInit(t)
	require.NoError(t, err)

	out, err := runDoctor(t)
	require.NoError(t, err)
	require.Contains(t, out.String(), "PASS")
	require.NotContains(t, out.String(), "FAIL")
}

func TestDoctor_BrokenInstallKeyMode(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)

	_, err := runInit(t)
	require.NoError(t, err)

	keyPath := filepath.Join(dir, keymgr.InstallKeyName)
	require.NoError(t, os.Chmod(keyPath, 0o644))

	out, err := runDoctor(t)
	require.Error(t, err)
	require.Contains(t, out.String(), "install.key mode")
}

func TestDoctor_RepairModes(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)

	_, err := runInit(t)
	require.NoError(t, err)

	keyPath := filepath.Join(dir, keymgr.InstallKeyName)
	require.NoError(t, os.Chmod(keyPath, 0o644))

	_, err = runDoctor(t, "--repair-modes")
	require.NoError(t, err)

	st, err := os.Stat(keyPath)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}

func TestDoctor_OrphanMappings(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)

	_, err := runInit(t)
	require.NoError(t, err)

	mappingsPath := filepath.Join(dir, store.MappingsName)
	m := &store.Mappings{Version: 1, ByMask: map[string]string{"orphan_mask": "orphan_real"}}
	b, err := json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(mappingsPath, b, 0o600))

	out, err := runDoctor(t)
	require.Error(t, err)
	require.Contains(t, out.String(), "orphan masks")

	_, err = runDoctor(t, "--rebuild-mappings")
	require.NoError(t, err)

	got, err := store.LoadMappings(mappingsPath)
	require.NoError(t, err)
	_, exists := got.ByMask["orphan_mask"]
	require.False(t, exists)
}
