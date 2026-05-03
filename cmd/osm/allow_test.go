package main

import (
	"path/filepath"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/stretchr/testify/require"
)

func TestAllow_Value(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "allow", "myhostname.local")
	require.NoError(t, err)

	a, err := store.LoadAllowlist(filepath.Join(dir, store.AllowlistName))
	require.NoError(t, err)
	require.Contains(t, a.Values, "myhostname.local")
}

func TestAllow_Pattern(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "allow", "--pattern", "test_.*")
	require.NoError(t, err)

	a, err := store.LoadAllowlist(filepath.Join(dir, store.AllowlistName))
	require.NoError(t, err)
	require.Contains(t, a.Patterns, "test_.*")
}

func TestAllow_RuleDisable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "allow", "--rule", "jwt")
	require.NoError(t, err)

	a, err := store.LoadAllowlist(filepath.Join(dir, store.AllowlistName))
	require.NoError(t, err)
	require.Contains(t, a.RulesDisabled, "jwt")
}

func TestAllow_RefusesRegistered(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "add", "API=registeredvalue123")
	require.NoError(t, err)

	_, _, err = runOSM(t, "allow", "registeredvalue123")
	require.Error(t, err)
}

func TestAllow_ForceOverridesRegistered(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "add", "API=registeredvalue123")
	require.NoError(t, err)

	_, _, err = runOSM(t, "allow", "--force", "registeredvalue123")
	require.NoError(t, err)

	a, err := store.LoadAllowlist(filepath.Join(dir, store.AllowlistName))
	require.NoError(t, err)
	require.Contains(t, a.Values, "registeredvalue123")
}

func TestAllow_NoArgs(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "allow")
	require.Error(t, err)
}
