package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func runOSM(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	out := &bytes.Buffer{}
	errOut := &bytes.Buffer{}
	root := newRootCmd()
	root.SetArgs(args)
	root.SetOut(out)
	root.SetErr(errOut)
	err := root.Execute()
	return out.String(), errOut.String(), err
}

func TestScan_StripeKeyMasked(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	input := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	fpath := filepath.Join(dir, "in.txt")
	require.NoError(t, os.WriteFile(fpath, []byte(input), 0o600))

	out, _, err := runOSM(t, "scan", fpath)
	require.NoError(t, err)
	require.Contains(t, out, "before ")
	require.Contains(t, out, " after")
	require.NotContains(t, out, "sk_live_4eC39HqLyjWDarjtT1zdp7dc")
	require.Contains(t, out, "sk_live_")
}

func TestScan_Determinism(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	input := "x sk_live_4eC39HqLyjWDarjtT1zdp7dc y"
	fpath := filepath.Join(dir, "in.txt")
	require.NoError(t, os.WriteFile(fpath, []byte(input), 0o600))

	out1, _, err := runOSM(t, "scan", fpath)
	require.NoError(t, err)
	out2, _, err := runOSM(t, "scan", fpath)
	require.NoError(t, err)
	require.Equal(t, out1, out2)
}

func TestScan_NoPersist(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, _, err := runOSM(t, "init")
	require.NoError(t, err)

	input := "x sk_live_4eC39HqLyjWDarjtT1zdp7dc y"
	fpath := filepath.Join(dir, "in.txt")
	require.NoError(t, os.WriteFile(fpath, []byte(input), 0o600))

	_, _, err = runOSM(t, "scan", "--no-persist", fpath)
	require.NoError(t, err)

	mappings, err := os.ReadFile(filepath.Join(dir, "mappings.json"))
	require.NoError(t, err)
	require.NotContains(t, string(mappings), "sk_live_")
}
