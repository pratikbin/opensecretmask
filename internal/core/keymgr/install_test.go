package keymgr

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateAndLoad(t *testing.T) {
	d := t.TempDir()
	b, err := Generate(d)
	require.NoError(t, err)
	require.Len(t, b, 32)
	st, err := os.Stat(filepath.Join(d, InstallKeyName))
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	got, err := LoadOrError(d)
	require.NoError(t, err)
	require.Equal(t, b, got)
}

func TestLoadMissing(t *testing.T) {
	_, err := LoadOrError(t.TempDir())
	require.ErrorIs(t, err, ErrKeyMissing)
}

func TestLoadBadMode(t *testing.T) {
	d := t.TempDir()
	_, err := Generate(d)
	require.NoError(t, err)
	require.NoError(t, os.Chmod(filepath.Join(d, InstallKeyName), 0o644))
	_, err = LoadOrError(d)
	require.ErrorIs(t, err, ErrKeyBadMode)
}
