package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPreload_RegistersDotEnvSecret(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OPENSECRETMASK_HOME", dir)

	_, err := runInit(t)
	require.NoError(t, err)

	cwd := t.TempDir()
	envPath := filepath.Join(cwd, ".env")
	require.NoError(t, os.WriteFile(envPath, []byte("API_KEY=sk-ant-api03-"+strings.Repeat("Z", 90)+"-AA\n"), 0o600))

	root := newRootCmd()
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(out)
	root.SetArgs([]string{"preload", "--cwd", cwd})
	require.NoError(t, root.Execute())

	if !strings.Contains(out.String(), "preloaded ") {
		t.Fatalf("expected preload output, got: %s", out.String())
	}
}
