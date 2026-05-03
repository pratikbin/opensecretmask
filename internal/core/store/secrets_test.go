package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSecretsRoundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secrets.json")

	now := time.Now().UTC().Truncate(time.Second)
	s := &Secrets{
		Version: 1,
		Secrets: []SecretEntry{
			{
				ID:           "abc",
				Label:        "OPENAI_API_KEY",
				Source:       "env",
				SourcePath:   "/tmp/.env",
				Rule:         "openai",
				Value:        "sk_live_X9k1",
				Masked:       "sk_live_4eC3",
				RegisteredAt: now,
				LastSeenAt:   now,
			},
		},
	}
	require.NoError(t, SaveSecrets(p, s))

	got, err := LoadSecrets(p)
	require.NoError(t, err)
	require.Equal(t, s, got)
}

func TestSecrets_LoadMissing(t *testing.T) {
	dir := t.TempDir()
	got, err := LoadSecrets(filepath.Join(dir, "nope.json"))
	require.NoError(t, err)
	require.Equal(t, &Secrets{Version: 1}, got)
}

func TestUpsertById(t *testing.T) {
	s := &Secrets{Version: 1}
	s.Upsert(SecretEntry{ID: "x", Label: "v1"})
	require.Len(t, s.Secrets, 1)
	require.Equal(t, "v1", s.Secrets[0].Label)

	s.Upsert(SecretEntry{ID: "x", Label: "v2"})
	require.Len(t, s.Secrets, 1)
	require.Equal(t, "v2", s.Secrets[0].Label)
	require.False(t, s.Secrets[0].LastSeenAt.IsZero())
}

func TestFindByValue(t *testing.T) {
	s := &Secrets{Version: 1, Secrets: []SecretEntry{
		{ID: "a", Value: "alpha"},
		{ID: "b", Value: "beta"},
	}}
	got, ok := s.FindByValue("beta")
	require.True(t, ok)
	require.Equal(t, "b", got.ID)

	_, ok = s.FindByValue("nope")
	require.False(t, ok)
}
