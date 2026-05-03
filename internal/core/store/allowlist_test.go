package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAllowlistRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "allowlist.json")

	a := &Allowlist{
		Values:        []string{"localhost", "true"},
		Patterns:      []string{`^test_.*$`},
		RulesDisabled: []string{"openai"},
	}
	require.NoError(t, SaveAllowlist(p, a))

	got, err := LoadAllowlist(p)
	require.NoError(t, err)
	require.Equal(t, a, got)
}

func TestAllowlist_LoadMissing(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadAllowlist(filepath.Join(dir, "nope.json"))
	require.NoError(t, err)
	require.Equal(t, &Allowlist{}, got)
}
