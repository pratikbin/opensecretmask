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
	Hooks    HooksConfig    `toml:"hooks"`
	Harness  HarnessConfig  `toml:"harness"`
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

type HooksConfig struct {
	MaskOnError       string         `toml:"mask_on_error"`
	UnmaskOnError     string         `toml:"unmask_on_error"`
	LockTimeoutMs     int            `toml:"lock_timeout_ms"`
	MaxScanBytes      int            `toml:"max_scan_bytes"`
	OnScanCap         string         `toml:"on_scan_cap"`
	MaxContainerBytes int            `toml:"max_container_bytes"`
	SkipExtensions    SkipExtensions `toml:"skip_extensions"`
}

type SkipExtensions struct {
	Default []string `toml:"default"`
	Read    []string `toml:"read"`
	Write   []string `toml:"write"`
}

type HarnessConfig struct {
	Claudecode ClaudecodeConfig `toml:"claudecode"`
}

type ClaudecodeConfig struct {
	PostToolUseMatch string     `toml:"posttooluse_match"`
	PreToolUseMatch  string     `toml:"pretooluse_match"`
	WarnOnPrompt     bool       `toml:"warn_on_prompt"`
	Bash             BashConfig `toml:"bash"`
}

type BashConfig struct {
	DefaultDecision     string   `toml:"default_decision"`
	EgressBlocklist     []string `toml:"egress_blocklist"`
	LocalAllowlist      []string `toml:"local_allowlist"`
	TreatPipeAsAsk      bool     `toml:"treat_pipe_as_ask"`
	TreatRedirectAsAsk  bool     `toml:"treat_redirect_as_ask"`
	TreatSubshellAsDeny bool     `toml:"treat_subshell_as_deny"`
}

type AuditConfig struct {
	Enabled        bool `toml:"enabled"`
	TruncateMaskTo int  `toml:"truncate_mask_to"`
	MaxSizeMb      int  `toml:"max_size_mb"`
}

// DefaultConfig returns spec §7.3 defaults.
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
		Hooks: HooksConfig{
			MaskOnError:       "deny",
			UnmaskOnError:     "passthrough",
			LockTimeoutMs:     5000,
			MaxScanBytes:      52428800,
			OnScanCap:         "truncate",
			MaxContainerBytes: 1048576,
			SkipExtensions: SkipExtensions{
				Default: []string{
					".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
					".pdf", ".zip", ".tar", ".gz",
					".woff", ".woff2", ".ttf", ".otf",
					".mp4", ".mp3", ".wav", ".mov", ".avi",
					".so", ".dylib", ".dll", ".o", ".a",
					".class", ".jar", ".exe",
				},
				Read:  []string{},
				Write: []string{},
			},
		},
		Harness: HarnessConfig{
			Claudecode: ClaudecodeConfig{
				PostToolUseMatch: ".*",
				PreToolUseMatch:  "Edit|Write|MultiEdit|Bash|NotebookEdit",
				WarnOnPrompt:     true,
				Bash: BashConfig{
					DefaultDecision: "ask",
					EgressBlocklist: []string{
						"curl", "wget", "http", "httpie", "xh", "nc", "ncat", "socat", "telnet",
						"ssh", "scp", "sftp", "rsync", "ftp", "openssl s_client",
						"git push", "git fetch", "git clone", "git pull", "git ls-remote",
						"gh", "glab",
						"aws", "gcloud", "az", "doctl", "fly", "vercel", "netlify", "heroku",
						"npm publish", "pnpm publish", "yarn publish", "cargo publish", "gem push", "twine upload",
						"docker push", "podman push", "helm push",
						"kubectl apply", "kubectl exec", "kubectl port-forward",
						"python -c", "node -e", "deno eval", "ruby -e", "perl -e",
					},
					LocalAllowlist: []string{
						"cat", "head", "tail", "grep", "rg", "ag", "awk", "sed", "sort", "uniq",
						"ls", "fd", "find", "stat", "file", "wc", "diff", "jq", "yq", "xq",
						"echo", "printf", "mkdir", "mv", "cp",
						"git status", "git diff", "git log", "git show", "git add", "git commit",
						"make", "just", "task",
						"npm install", "npm test", "npm run",
						"pnpm install", "pnpm test", "pnpm run",
						"bun install", "bun test", "bun run",
						"cargo build", "cargo test",
					},
					TreatPipeAsAsk:      true,
					TreatRedirectAsAsk:  true,
					TreatSubshellAsDeny: true,
				},
			},
		},
		Audit: AuditConfig{
			Enabled:        true,
			TruncateMaskTo: 12,
			MaxSizeMb:      50,
		},
	}
}

// LoadConfig reads TOML from path. Missing file → DefaultConfig().
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

// Validate enforces spec invariants.
func (c *Config) Validate() error {
	if c.Hooks.MaxScanBytes <= 0 {
		return errors.New("hooks.max_scan_bytes must be > 0")
	}
	if c.Hooks.LockTimeoutMs <= 0 {
		return errors.New("hooks.lock_timeout_ms must be > 0")
	}
	if c.Hooks.MaxContainerBytes <= 0 {
		return errors.New("hooks.max_container_bytes must be > 0")
	}
	switch c.Hooks.OnScanCap {
	case "truncate", "deny":
	default:
		return errors.New("hooks.on_scan_cap must be truncate|deny")
	}
	switch c.Hooks.MaskOnError {
	case "deny", "redact-all":
	default:
		return errors.New("hooks.mask_on_error must be deny|redact-all")
	}
	switch c.Hooks.UnmaskOnError {
	case "passthrough", "deny":
	default:
		return errors.New("hooks.unmask_on_error must be passthrough|deny")
	}
	switch c.Harness.Claudecode.Bash.DefaultDecision {
	case "ask", "allow", "deny":
	default:
		return errors.New("harness.claudecode.bash.default_decision must be ask|allow|deny")
	}
	return nil
}
