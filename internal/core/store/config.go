package store

import (
	"errors"
	"os"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Version  int            `toml:"version"`
	Detector DetectorConfig `toml:"detector"`
	Crypto   CryptoConfig   `toml:"crypto"`
	Engine   EngineConfig   `toml:"engine"`
	Proxy    ProxyConfig    `toml:"proxy"`
	Audit    AuditConfig    `toml:"audit"`
}

type DetectorConfig struct {
	MinSecretLength int             `toml:"min_secret_length"`
	Env             EnvConfig       `toml:"env"`
	Entropy         EntropyConfig   `toml:"entropy"`
	Allowlist       AllowlistConfig `toml:"allowlist"`
}

type EnvConfig struct {
	Enabled         bool     `toml:"enabled"`
	WalkUpToGitRoot bool     `toml:"walk_up_to_git_root"`
	Patterns        []string `toml:"patterns"`
	IgnoreKeys      []string `toml:"ignore_keys"`
}

type EntropyConfig struct {
	Enabled   bool    `toml:"enabled"`
	Threshold float64 `toml:"threshold"`
	MinLength int     `toml:"min_length"`
}

type AllowlistConfig struct {
	Values []string `toml:"values"`
}

type CryptoConfig struct {
	Hash string `toml:"hash"`
}

type EngineConfig struct {
	LockTimeoutMs     int    `toml:"lock_timeout_ms"`
	MaxScanBytes      int    `toml:"max_scan_bytes"`
	OnScanCap         string `toml:"on_scan_cap"`
	MaxContainerBytes int    `toml:"max_container_bytes"`
}

type ProxyConfig struct {
	Bind        string `toml:"bind"`
	UpstreamURL string `toml:"upstream_url"`
}

type AuditConfig struct {
	Enabled        bool `toml:"enabled"`
	TruncateMaskTo int  `toml:"truncate_mask_to"`
	MaxSizeMb      int  `toml:"max_size_mb"`
}

func DefaultConfig() *Config {
	return &Config{
		Version: 1,
		Detector: DetectorConfig{
			MinSecretLength: 8,
			Env: EnvConfig{
				Enabled:         true,
				WalkUpToGitRoot: true,
				Patterns:        []string{".env", ".env.*", ".envrc"},
				IgnoreKeys:      []string{"NODE_ENV", "PATH", "HOME"},
			},
			Entropy: EntropyConfig{
				Enabled:   false,
				Threshold: 4.5,
				MinLength: 24,
			},
			Allowlist: AllowlistConfig{
				Values: []string{"true", "false", "localhost", "127.0.0.1", "production", "staging", "development"},
			},
		},
		Crypto: CryptoConfig{Hash: "hmac-sha256"},
		Engine: EngineConfig{
			LockTimeoutMs:     5000,
			MaxScanBytes:      52428800,
			OnScanCap:         "truncate",
			MaxContainerBytes: 1048576,
		},
		Proxy: ProxyConfig{
			Bind:        "127.0.0.1:8787",
			UpstreamURL: "https://api.anthropic.com",
		},
		Audit: AuditConfig{
			Enabled:        true,
			TruncateMaskTo: 12,
			MaxSizeMb:      50,
		},
	}
}

func LoadConfig(path string) (*Config, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return DefaultConfig(), nil
		}
		return nil, err
	}
	c := &Config{}
	if _, err := toml.DecodeFile(path, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) Validate() error {
	if c.Engine.MaxScanBytes <= 0 {
		return errors.New("engine.max_scan_bytes must be > 0")
	}
	if c.Engine.LockTimeoutMs <= 0 {
		return errors.New("engine.lock_timeout_ms must be > 0")
	}
	if c.Engine.MaxContainerBytes <= 0 {
		return errors.New("engine.max_container_bytes must be > 0")
	}
	switch c.Engine.OnScanCap {
	case "truncate", "deny":
	default:
		return errors.New("engine.on_scan_cap must be truncate|deny")
	}
	return nil
}

