package detector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseEnvFile_Basic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	content := "# comment\n" +
		"KEY1=value1\n" +
		"export KEY2=value2\n" +
		"KEY3=\"quoted value\"\n" +
		"KEY4='single quoted'\n" +
		"\n" +
		"KEY5=\n" +
		"=broken\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	entries, err := ParseEnvFile(path)
	require.NoError(t, err)
	require.Len(t, entries, 5)

	got := map[string]string{}
	for _, e := range entries {
		got[e.Key] = e.Value
		require.Equal(t, path, e.SourcePath)
	}
	require.Equal(t, "value1", got["KEY1"])
	require.Equal(t, "value2", got["KEY2"])
	require.Equal(t, "quoted value", got["KEY3"])
	require.Equal(t, "single quoted", got["KEY4"])
	require.Equal(t, "", got["KEY5"])
}

func TestParseEnvFile_Missing(t *testing.T) {
	_, err := ParseEnvFile(filepath.Join(t.TempDir(), "nope.env"))
	require.Error(t, err)
}

func TestFindEnvFiles_FlatDir(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte("A=1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".envrc"), []byte("B=2"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "unrelated.txt"), []byte("x"), 0o644))
	// place a .git so walk stops here, not at filesystem root
	require.NoError(t, os.Mkdir(filepath.Join(dir, ".git"), 0o755))

	found, err := FindEnvFiles(dir, []string{".env", ".env.*", ".envrc"}, true)
	require.NoError(t, err)

	require.Contains(t, found, filepath.Join(dir, ".env"))
	require.Contains(t, found, filepath.Join(dir, ".envrc"))
	for _, p := range found {
		require.NotContains(t, p, "unrelated.txt")
	}
}

func TestFindEnvFiles_WalkUp(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(a, "b")
	require.NoError(t, os.MkdirAll(b, 0o755))
	require.NoError(t, os.Mkdir(filepath.Join(root, ".git"), 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(b, ".env"), []byte("x=1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(a, ".env"), []byte("x=1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(root, ".env"), []byte("x=1"), 0o644))

	found, err := FindEnvFiles(b, []string{".env"}, true)
	require.NoError(t, err)

	// glob runs at each dir BEFORE .git check, so root/.env IS included
	require.Contains(t, found, filepath.Join(b, ".env"))
	require.Contains(t, found, filepath.Join(a, ".env"))
	require.Contains(t, found, filepath.Join(root, ".env"))
}

func TestFindEnvFiles_NoGitWalk(t *testing.T) {
	root := t.TempDir()
	a := filepath.Join(root, "a")
	b := filepath.Join(a, "b")
	require.NoError(t, os.MkdirAll(b, 0o755))

	require.NoError(t, os.WriteFile(filepath.Join(b, ".env"), []byte("x=1"), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(a, ".env"), []byte("x=1"), 0o644))

	found, err := FindEnvFiles(b, []string{".env"}, true)
	require.NoError(t, err)

	require.Contains(t, found, filepath.Join(b, ".env"))
	require.Contains(t, found, filepath.Join(a, ".env"))
}
