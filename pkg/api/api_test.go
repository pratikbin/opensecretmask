package api_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pratikbin/opensecretmask/internal/core/keymgr"
	"github.com/pratikbin/opensecretmask/internal/core/store"
	"github.com/pratikbin/opensecretmask/pkg/api"
	"github.com/stretchr/testify/require"
)

// initHome bootstraps a usable opensecretmask home in a tempdir.
func initHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	t.Setenv("OPENSECRETMASK_HOME", dir)
	_, err := keymgr.Generate(dir)
	require.NoError(t, err)
	cfg := store.DefaultConfig()
	// Note: cannot serialize via TOML easily without the cmd-side helper, but LoadConfig
	// returns defaults on missing file; so we just don't write config.toml at all.
	require.NoError(t, store.SaveSecrets(filepath.Join(dir, store.SecretsName), &store.Secrets{Version: 1}))
	require.NoError(t, store.SaveMappings(filepath.Join(dir, store.MappingsName), &store.Mappings{Version: 1, ByMask: map[string]string{}}))
	require.NoError(t, store.SaveAllowlist(filepath.Join(dir, store.AllowlistName), &store.Allowlist{Values: cfg.Detector.Allowlist.Values}))
	return dir
}

func TestNewMaskUnmaskRoundtrip(t *testing.T) {
	dir := initHome(t)
	m, err := api.New(api.Options{Home: dir})
	require.NoError(t, err)
	input := "before sk_live_4eC39HqLyjWDarjtT1zdp7dc after"
	masked, err := m.Mask(context.Background(), input)
	require.NoError(t, err)
	require.NotContains(t, masked, "sk_live_4eC39HqLyjWDarjtT1zdp7dc")
	require.True(t, strings.Contains(masked, "sk_live_"))
	unmasked, err := m.Unmask(masked)
	require.NoError(t, err)
	require.Equal(t, input, unmasked)
}

func TestDetect(t *testing.T) {
	dir := initHome(t)
	m, err := api.New(api.Options{Home: dir})
	require.NoError(t, err)
	hits := m.Detect("sk_live_4eC39HqLyjWDarjtT1zdp7dc")
	require.NotEmpty(t, hits)
	require.Equal(t, "stripe-live", hits[0].Rule)
}

func TestNew_MissingInstallKey(t *testing.T) {
	dir := t.TempDir()
	_, err := api.New(api.Options{Home: dir})
	require.Error(t, err)
}
