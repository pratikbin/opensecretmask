package store

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
	"github.com/stretchr/testify/require"
)

func TestDefaultConfig(t *testing.T) {
	c := DefaultConfig()
	require.Equal(t, 1, c.Version)
	require.Equal(t, 8, c.Detector.MinSecretLength)
	require.Equal(t, 52428800, c.Hooks.MaxScanBytes)
	require.Equal(t, 1048576, c.Hooks.MaxContainerBytes)
	require.Equal(t, 12, c.Audit.TruncateMaskTo)
	require.Equal(t, "hmac-sha256", c.Crypto.Hash)
	require.Equal(t, "deny", c.Hooks.MaskOnError)
	require.Equal(t, "passthrough", c.Hooks.UnmaskOnError)
	require.Equal(t, "ask", c.Harness.Claudecode.Bash.DefaultDecision)
}

func TestValidate_OK(t *testing.T) {
	require.NoError(t, DefaultConfig().Validate())
}

func TestValidate_RejectsBadEnum(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"OnScanCap", func(c *Config) { c.Hooks.OnScanCap = "bogus" }},
		{"MaskOnError", func(c *Config) { c.Hooks.MaskOnError = "bogus" }},
		{"UnmaskOnError", func(c *Config) { c.Hooks.UnmaskOnError = "bogus" }},
		{"BashDefaultDecision", func(c *Config) { c.Harness.Claudecode.Bash.DefaultDecision = "bogus" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			tc.mut(c)
			require.Error(t, c.Validate())
		})
	}
}

func TestLoadConfig_Missing(t *testing.T) {
	dir := t.TempDir()
	c, err := LoadConfig(filepath.Join(dir, "nope.toml"))
	require.NoError(t, err)
	require.Equal(t, DefaultConfig(), c)
}

func TestLoadConfig_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "config.toml")

	def := DefaultConfig()
	var buf bytes.Buffer
	require.NoError(t, toml.NewEncoder(&buf).Encode(def))
	require.NoError(t, WriteAtomic(p, buf.Bytes(), 0o600))

	got, err := LoadConfig(p)
	require.NoError(t, err)
	require.Equal(t, def, got)
}
