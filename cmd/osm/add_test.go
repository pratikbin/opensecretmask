package main

import (
	"path/filepath"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/stretchr/testify/require"
)

func TestAdd_NewSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	out, _, err := runOSM(t, "add", "API_KEY=supersecret123")
	require.NoError(t, err)
	require.Contains(t, out, "registered")

	m, err := store.LoadMappings(filepath.Join(dir, store.MappingsName))
	require.NoError(t, err)
	require.Len(t, m.ByMask, 1)

	s, err := store.LoadSecrets(filepath.Join(dir, store.SecretsName))
	require.NoError(t, err)
	require.Len(t, s.Secrets, 1)
	require.Equal(t, "API_KEY", s.Secrets[0].Label)
	require.Equal(t, "supersecret123", s.Secrets[0].Value)
	require.Equal(t, "manual", s.Secrets[0].Source)
}

func TestAdd_DuplicateValue(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "add", "K1=samevalue123456")
	require.NoError(t, err)
	_, _, err = runOSM(t, "add", "K2=samevalue123456")
	require.NoError(t, err)

	m, err := store.LoadMappings(filepath.Join(dir, store.MappingsName))
	require.NoError(t, err)
	require.Len(t, m.ByMask, 1, "duplicate value reused")
}

func TestAdd_BadFormat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "add", "NOEQUAL")
	require.Error(t, err)
}

func TestAdd_EmptyValue(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "add", "FOO=")
	require.Error(t, err)
}
