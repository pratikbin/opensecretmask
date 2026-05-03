package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMappings_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "mappings.json")

	m := &Mappings{Version: 1, ByMask: map[string]string{"sk_live_X9k1": "sk_live_4eC3"}}
	require.NoError(t, SaveMappings(p, m))

	got, err := LoadMappings(p)
	require.NoError(t, err)
	require.Equal(t, m.ByMask, got.ByMask)
	require.False(t, got.UpdatedAt.IsZero())
}

func TestAhoCorasickReplace_Single(t *testing.T) {
	m := &Mappings{Version: 1, ByMask: map[string]string{"sk_live_X9k1": "sk_live_4eC3"}}
	got := m.AhoCorasickReplace("use sk_live_X9k1 here")
	require.Equal(t, "use sk_live_4eC3 here", got)
}

func TestAhoCorasickReplace_Multi(t *testing.T) {
	m := &Mappings{Version: 1, ByMask: map[string]string{
		"AAAA": "1111",
		"BBBB": "2222",
	}}
	got := m.AhoCorasickReplace("xx AAAA yy BBBB zz")
	require.Equal(t, "xx 1111 yy 2222 zz", got)
}

func TestAhoCorasickReplace_NoMappings(t *testing.T) {
	m := &Mappings{Version: 1, ByMask: map[string]string{}}
	require.Equal(t, "unchanged", m.AhoCorasickReplace("unchanged"))
}

func TestAhoCorasickReplace_NonOverlapping(t *testing.T) {
	m := &Mappings{Version: 1, ByMask: map[string]string{"ABCD": "XXXX"}}
	got := m.AhoCorasickReplace("ABCDABCD")
	require.Equal(t, "XXXXXXXX", got)
}

func TestMappings_LoadMissing(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadMappings(filepath.Join(dir, "nope.json"))
	require.NoError(t, err)
	require.NotNil(t, got.ByMask)
	require.Equal(t, 1, got.Version)
}
