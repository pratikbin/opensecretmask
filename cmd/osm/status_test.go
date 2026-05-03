package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestStatus_Empty(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	out, _, err := runOSM(t, "status")
	require.NoError(t, err)
	require.Contains(t, out, "root:")
	require.Contains(t, out, "secrets: 0")
	require.Contains(t, out, "mappings: 0")
	require.Contains(t, out, "audit.log: (none)")
}

func TestStatus_AfterAdd(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	_, _, err = runOSM(t, "add", "API=somesecretvalue")
	require.NoError(t, err)

	out, _, err := runOSM(t, "status")
	require.NoError(t, err)
	require.Contains(t, out, "secrets: 1")
	require.Contains(t, out, "mappings: 1")
}
