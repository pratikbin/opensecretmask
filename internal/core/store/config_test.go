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
	require.Equal(t, 52428800, c.Engine.MaxScanBytes)
	require.Equal(t, 1048576, c.Engine.MaxContainerBytes)
	require.Equal(t, 12, c.Audit.TruncateMaskTo)
	require.Equal(t, "hmac-sha256", c.Crypto.Hash)
	require.Equal(t, "127.0.0.1:8787", c.Proxy.Bind)
	require.Equal(t, "https://api.anthropic.com", c.Proxy.UpstreamURL)
}

func TestValidate_OK(t *testing.T) {
	require.NoError(t, DefaultConfig().Validate())
}

func TestValidate_RejectsBadEnum(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Config)
	}{
		{"OnScanCap", func(c *Config) { c.Engine.OnScanCap = "bogus" }},
		{"zero MaxScanBytes", func(c *Config) { c.Engine.MaxScanBytes = 0 }},
		{"zero LockTimeoutMs", func(c *Config) { c.Engine.LockTimeoutMs = 0 }},
		{"zero MaxContainerBytes", func(c *Config) { c.Engine.MaxContainerBytes = 0 }},
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

