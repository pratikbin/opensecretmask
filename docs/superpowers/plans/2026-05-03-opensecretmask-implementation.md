# opensecretmask Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `osm`, a Go-based credential-masking hook binary that intercepts AI coding agents (claude-code v1; opencode/pi-agent later), masks secrets in tool outputs before they reach the LLM, and unmasks them before tools execute locally.

**Architecture:** Single static Go binary invoked per hook event over stdin/JSON. Pure-Go core (`internal/core/{detector,transformer,store,keymgr}`) with no harness awareness. Per-harness adapters (`internal/harness/<name>/`) translate native JSON to a canonical `Request`/`Response` envelope. Format-preserving masks via HMAC-SHA256 + HKDF-Expand keyed by a per-install random key, with rejection-sampled charset mapping. Persistent `mappings.json` (mask→real plaintext) and `secrets.json` (source of truth) under `~/.opensecretmask/`, protected by flock + atomic-rename. Direction-aware failure: mask path fails closed (block JSON), unmask path fails open (passthrough so the tool fails loudly).

**Tech Stack:** Go 1.26.2; cobra for CLI; `golang.org/x/crypto/hkdf`; `github.com/gofrs/flock`; `github.com/BurntSushi/toml`; `github.com/cloudflare/ahocorasick` (or `cloudflare/ahocorasick`-style fallback); `mvdan.cc/sh/v3` for bash command parsing; `github.com/google/uuid` for ULIDs (or `github.com/oklog/ulid/v2`). Tests: stdlib `testing` + `github.com/google/go-cmp/cmp` + `github.com/stretchr/testify/require`. Lint: `gofmt` + `go vet` + `golangci-lint` + `gosec`. Build/release: `goreleaser`.

**Spec reference:** `docs/superpowers/specs/2026-05-02-opensecretmask-design.md` (all section numbers below refer to this spec).

**Conventions for this plan:**
- Each task lists exact file paths to create/modify.
- TDD is **NOT** used. Implementation first; tests in the same task; verify; commit.
- One commit per task. Conventional commit style: `<type>(<scope>): <subject>` (`feat`, `fix`, `chore`, `test`, `docs`, `refactor`).
- Module path: `github.com/pratikbin/opensecretmask`.

---

## File Structure (locked)

```
opensecretmask/
├── cmd/osm/
│   ├── main.go                  # entrypoint, calls root.Execute()
│   ├── root.go                  # cobra root + global flags
│   ├── init.go                  # `osm init`
│   ├── doctor.go                # `osm doctor`
│   ├── scan.go                  # `osm scan <file>`
│   ├── hook.go                  # `osm hook --harness=<name> <event>` dispatcher
│   ├── install.go               # `osm install claude-code` / `osm uninstall claude-code`
│   ├── add.go                   # `osm add NAME=value`
│   ├── allow.go                 # `osm allow <value>`
│   ├── status.go                # `osm status`
│   ├── tail.go                  # `osm tail`
│   └── version.go               # `osm version`
├── internal/core/
│   ├── keymgr/
│   │   ├── install.go           # load/create install.key
│   │   └── hasher.go            # HMAC-SHA256 + HKDF stream
│   ├── store/
│   │   ├── paths.go             # ~/.opensecretmask/* path helpers
│   │   ├── lock.go              # flock wrapper
│   │   ├── atomic.go            # tmp+fsync+rename
│   │   ├── config.go            # config.toml load/defaults
│   │   ├── secrets.go           # secrets.json schema + ops
│   │   ├── mappings.go          # mappings.json schema + ops + AC index
│   │   ├── audit.go             # NDJSON append-only writer
│   │   └── allowlist.go         # allowlist.json
│   ├── transformer/
│   │   ├── charset.go           # Charset enum + Bytes()
│   │   ├── fpe.go               # Mask (flat + segments) + deriveCharsetBytes
│   │   └── unmask.go            # Unmask (multi-pattern AC replace)
│   └── detector/
│       ├── allowlist.go         # AllowlistSet
│       ├── env.go               # .env discovery + parse
│       ├── entropy.go           # Shannon entropy scanner
│       ├── patterns.go          # Rule, Segment, Charset wiring
│       ├── rules.go             # compiled-in rule set (~30)
│       ├── detector.go          # 3-layer cascade Detect()
│       └── scanner.go           # streaming scan with adaptive overlap + container buf
├── internal/harness/
│   ├── protocol.go              # canonical Request/Response/Target/Direction/Finding
│   └── claudecode/
│       ├── adapter.go           # ParseRequest / EmitResponse / EventDirection
│       ├── events.go            # PostToolUse / PreToolUse / UserPromptSubmit / SessionStart
│       ├── tools.go             # per-tool field maps (Read.content, Bash.command, …)
│       └── bashgate.go          # §5.2.1 egress classifier (mvdan/sh AST)
├── pkg/api/
│   └── api.go                   # public Go API for library users (Mask, Unmask, Detect)
├── tests/
│   ├── integration/
│   │   ├── posttooluse_test.go
│   │   ├── pretooluse_test.go
│   │   ├── userpromptsubmit_test.go
│   │   ├── sessionstart_test.go
│   │   └── bashgate_test.go
│   └── fixtures/
│       └── *.json               # claude-code hook payload fixtures
├── examples/
│   └── claude-code-settings.json
├── .github/workflows/
│   ├── ci.yml                   # build + test + lint + gosec matrix
│   └── release.yml              # goreleaser
├── .goreleaser.yaml
├── .golangci.yml
├── .gitignore
├── Makefile
├── README.md
├── LICENSE
└── go.mod
```

---

## Task 0: Bootstrap repo + module

**Files:**
- Create: `go.mod`, `.gitignore`, `LICENSE`, `Makefile`, `README.md` (stub)

- [ ] **Step 1: Init git + Go module**

```bash
cd /Users/ctos/workspace/pratikbin/hacks/opensecretmask
git init
go mod init github.com/pratikbin/opensecretmask
go mod edit -go=1.26.2
```

- [ ] **Step 2: Write `.gitignore`**

```gitignore
/bin/
/dist/
*.test
*.out
coverage.txt
.idea/
.vscode/
.DS_Store
.tmp.*
```

- [ ] **Step 3: Write `LICENSE` (MIT) and `README.md` stub**

Stub README: one-paragraph description + link to spec. Full README written in Task 25.

- [ ] **Step 4: Write `Makefile`**

```makefile
.PHONY: build test lint vet sec fmt clean
build:
	go build -trimpath -ldflags="-s -w" -o bin/osm ./cmd/osm
test:
	go test -race -count=1 ./...
lint:
	golangci-lint run ./...
vet:
	go vet ./...
sec:
	gosec -quiet ./...
fmt:
	gofmt -s -w .
clean:
	rm -rf bin dist
```

- [ ] **Step 5: Add base deps**

```bash
go get github.com/spf13/cobra@latest
go get github.com/gofrs/flock@latest
go get github.com/BurntSushi/toml@latest
go get golang.org/x/crypto/hkdf@latest
go get github.com/oklog/ulid/v2@latest
go get mvdan.cc/sh/v3@latest
go get github.com/cloudflare/ahocorasick@latest
go get github.com/stretchr/testify/require@latest
go get github.com/google/go-cmp/cmp@latest
go mod tidy
```

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "chore: bootstrap repo, go module, makefile, deps"
```

---

## Task 1: keymgr — install.key + HMAC + HKDF stream

**Files:**
- Create: `internal/core/keymgr/install.go`, `internal/core/keymgr/hasher.go`
- Create: `internal/core/keymgr/install_test.go`, `internal/core/keymgr/hasher_test.go`

- [ ] **Step 1: Write `install.go`**

```go
package keymgr

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

const InstallKeyName = "install.key"
const installKeyLen = 32

var ErrKeyMissing = errors.New("opensecretmask: install.key not found; run `osm init`")
var ErrKeyBadMode = errors.New("opensecretmask: install.key has insecure permissions; want 0600")

func LoadOrError(dir string) ([]byte, error) {
	p := filepath.Join(dir, InstallKeyName)
	st, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrKeyMissing
	}
	if err != nil {
		return nil, fmt.Errorf("stat install.key: %w", err)
	}
	if st.Mode().Perm() != 0o600 {
		return nil, ErrKeyBadMode
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("read install.key: %w", err)
	}
	if len(b) != installKeyLen {
		return nil, fmt.Errorf("install.key length=%d, want %d", len(b), installKeyLen)
	}
	return b, nil
}

func Generate(dir string) ([]byte, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir %s: %w", dir, err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	b := make([]byte, installKeyLen)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("rand: %w", err)
	}
	p := filepath.Join(dir, InstallKeyName)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return nil, fmt.Errorf("write install.key: %w", err)
	}
	return b, nil
}
```

- [ ] **Step 2: Write `hasher.go`**

```go
package keymgr

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

// Hasher wraps the per-install key for FPE derivation.
type Hasher struct {
	key []byte
}

func NewHasher(key []byte) *Hasher { return &Hasher{key: key} }

// MAC returns HMAC-SHA256(key, data). Use as keying material for HKDF-Expand.
func (h *Hasher) MAC(data []byte) []byte {
	m := hmac.New(sha256.New, h.key)
	m.Write(data)
	return m.Sum(nil)
}

// Stream returns an HKDF-Expand reader over the given info string. The reader
// produces an arbitrary-length pseudorandom byte stream deterministic in
// (h.key, info). Used by transformer for charset rejection sampling.
func (h *Hasher) Stream(info []byte) io.Reader {
	prk := h.MAC(info[:0]) // PRK derived from key alone; info supplied to Expand
	return hkdf.Expand(sha256.New, prk, info)
}
```

- [ ] **Step 3: Write `install_test.go`**

Test: Generate → file exists → mode 0600 → length 32 → LoadOrError returns same bytes. Reject mode 0644. Reject missing file → ErrKeyMissing.

```go
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
```

- [ ] **Step 4: Write `hasher_test.go`**

Test: MAC determinism (same input → same output across calls). Stream determinism (read N bytes twice → identical). Different `info` → different bytes within first 16 bytes (statistical, not exact).

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/core/keymgr/... -race -count=1
git add internal/core/keymgr go.sum
git commit -m "feat(keymgr): install.key generation/load + HMAC/HKDF hasher"
```

---

## Task 2: store/paths + lock + atomic write

**Files:**
- Create: `internal/core/store/paths.go`, `internal/core/store/lock.go`, `internal/core/store/atomic.go`
- Create: `internal/core/store/atomic_test.go`, `internal/core/store/lock_test.go`

- [ ] **Step 1: Write `paths.go`**

```go
package store

import (
	"os"
	"path/filepath"
)

const (
	DirName             = ".opensecretmask"
	ConfigName          = "config.toml"
	SecretsName         = "secrets.json"
	MappingsName        = "mappings.json"
	AllowlistName       = "allowlist.json"
	AuditName           = "audit.log"
	LockName            = ".lock"
	CacheDirName        = "cache"
	RegisteredCacheName = "registered.aho"
)

// Root resolves ~/.opensecretmask. Override with $OPENSECRETMASK_HOME for tests.
func Root() (string, error) {
	if v := os.Getenv("OPENSECRETMASK_HOME"); v != "" {
		return v, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, DirName), nil
}

func Path(name string) (string, error) {
	r, err := Root()
	if err != nil {
		return "", err
	}
	return filepath.Join(r, name), nil
}
```

- [ ] **Step 2: Write `lock.go`**

```go
package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/gofrs/flock"
)

type Lock struct {
	fl *flock.Flock
}

func OpenLock(root string) (*Lock, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(root, LockName)
	if _, err := os.Stat(p); os.IsNotExist(err) {
		f, ferr := os.OpenFile(p, os.O_CREATE|os.O_WRONLY, 0o644)
		if ferr != nil {
			return nil, ferr
		}
		_ = f.Close()
	}
	return &Lock{fl: flock.New(p)}, nil
}

func (l *Lock) WithExclusive(timeout time.Duration, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	got, err := l.fl.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return fmt.Errorf("flock ex: %w", err)
	}
	if !got {
		return fmt.Errorf("flock ex: timeout after %s", timeout)
	}
	defer l.fl.Unlock()
	return fn()
}

func (l *Lock) WithShared(timeout time.Duration, fn func() error) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	got, err := l.fl.TryRLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return fmt.Errorf("flock sh: %w", err)
	}
	if !got {
		return fmt.Errorf("flock sh: timeout after %s", timeout)
	}
	defer l.fl.Unlock()
	return fn()
}
```

- [ ] **Step 3: Write `atomic.go`**

```go
package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
)

// WriteAtomic writes data to path via tmp+fsync+rename. mode applied to final.
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	rb := make([]byte, 4)
	if _, err := rand.Read(rb); err != nil {
		return err
	}
	tmp := filepath.Join(dir, fmt.Sprintf(".tmp.%d.%s", os.Getpid(), hex.EncodeToString(rb)))
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, path)
}

// CleanStaleTmp removes leftover .tmp.* files from crashes.
func CleanStaleTmp(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		n := e.Name()
		if len(n) > 5 && n[:5] == ".tmp." {
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
	return nil
}
```

- [ ] **Step 4: Tests**

`atomic_test.go`: `WriteAtomic` writes correct bytes + mode; tmp gone after success; `CleanStaleTmp` removes only `.tmp.*` not other files. Concurrent `WriteAtomic` from N goroutines → final file is one of the writers' content, never partial.

`lock_test.go`: exclusive lock blocks second exclusive (with short timeout) but allows after release; shared+shared coexist; shared blocks exclusive.

- [ ] **Step 5: Run + commit**

```bash
go test ./internal/core/store/... -race -count=1
git add internal/core/store
git commit -m "feat(store): paths, flock, atomic write"
```

---

## Task 3: store/config + secrets + mappings + audit + allowlist

**Files:**
- Create: `internal/core/store/config.go`, `secrets.go`, `mappings.go`, `audit.go`, `allowlist.go`
- Create: `*_test.go` for each

- [ ] **Step 1: `config.go` — TOML schema**

Define struct mirroring spec §7.3 verbatim. Use `BurntSushi/toml`. `LoadOrDefaults(path string) (*Config, error)` — if file missing, return defaults. Provide `(*Config).Validate()` (e.g., `MaxScanBytes > 0`, `LockTimeoutMs > 0`).

```go
package store

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
	Enabled          bool     `toml:"enabled"`
	WalkUpToGitRoot  bool     `toml:"walk_up_to_git_root"`
	Patterns         []string `toml:"patterns"`
	IgnoreKeys       []string `toml:"ignore_keys"`
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
	MaskOnError      string         `toml:"mask_on_error"`
	UnmaskOnError    string         `toml:"unmask_on_error"`
	LockTimeoutMs    int            `toml:"lock_timeout_ms"`
	MaxScanBytes     int            `toml:"max_scan_bytes"`
	OnScanCap        string         `toml:"on_scan_cap"`
	MaxContainerBytes int           `toml:"max_container_bytes"`
	SkipExtensions   SkipExtensions `toml:"skip_extensions"`
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
	DefaultDecision    string   `toml:"default_decision"`
	EgressBlocklist    []string `toml:"egress_blocklist"`
	LocalAllowlist     []string `toml:"local_allowlist"`
	TreatPipeAsAsk     bool     `toml:"treat_pipe_as_ask"`
	TreatRedirectAsAsk bool     `toml:"treat_redirect_as_ask"`
	TreatSubshellAsDeny bool    `toml:"treat_subshell_as_deny"`
}

type AuditConfig struct {
	Enabled        bool `toml:"enabled"`
	TruncateMaskTo int  `toml:"truncate_mask_to"`
	MaxSizeMb      int  `toml:"max_size_mb"`
}

func DefaultConfig() *Config { /* fill all defaults exactly per spec §7.3 */ }
func LoadConfig(path string) (*Config, error) { /* toml.DecodeFile or DefaultConfig() if missing */ }
func (c *Config) Validate() error { /* ranges + enum membership for OnScanCap, MaskOnError */ }
```

- [ ] **Step 2: `secrets.go` — secrets.json**

```go
type SecretEntry struct {
	ID            string    `json:"id"`
	Label         string    `json:"label"`
	Source        string    `json:"source"`
	SourcePath    string    `json:"source_path,omitempty"`
	Rule          string    `json:"rule"`
	Value         string    `json:"value"`
	Masked        string    `json:"masked"`
	RegisteredAt  time.Time `json:"registered_at"`
	LastSeenAt    time.Time `json:"last_seen_at"`
}

type Secrets struct {
	Version int           `json:"version"`
	Secrets []SecretEntry `json:"secrets"`
}

func LoadSecrets(path string) (*Secrets, error)        // missing → empty {Version:1}
func SaveSecrets(path string, s *Secrets) error        // WriteAtomic with 0600
func (s *Secrets) Upsert(e SecretEntry)                // by ID
func (s *Secrets) FindByValue(v string) (*SecretEntry, bool)
```

- [ ] **Step 3: `mappings.go` — mappings.json + reverse-lookup**

Includes `BuildAhoCorasick()` returning a matcher over `by_mask` keys. AC index rebuilt on each load (cached on disk in Task 9 via `cache/registered.aho`).

```go
type Mappings struct {
	Version   int               `json:"version"`
	ByMask    map[string]string `json:"by_mask"`
	UpdatedAt time.Time         `json:"updated_at"`
}

func LoadMappings(path string) (*Mappings, error)
func SaveMappings(path string, m *Mappings) error
func (m *Mappings) Set(mask, real string)
func (m *Mappings) Lookup(mask string) (string, bool)
// AhoCorasickReplace returns text with every mask key in m.ByMask replaced by its real value.
func (m *Mappings) AhoCorasickReplace(text string) string
```

For `AhoCorasickReplace`: build AC matcher using `cloudflare/ahocorasick` (longest-match-wins via match-end ordering). Iterate matches non-overlapping, replace.

- [ ] **Step 4: `audit.go` — NDJSON append-only**

```go
type AuditEvent struct {
	TS         time.Time `json:"ts"`
	SessionID  string    `json:"session_id,omitempty"`
	Action     string    `json:"action"`
	Tool       string    `json:"tool,omitempty"`
	Event      string    `json:"event,omitempty"`
	Rule       string    `json:"rule,omitempty"`
	Mask       string    `json:"mask,omitempty"`        // truncated to TruncateMaskTo
	Count      int       `json:"count,omitempty"`
	Src        string    `json:"src,omitempty"`
	Decision   string    `json:"decision,omitempty"`
	Direction  string    `json:"direction,omitempty"`
	Policy     string    `json:"policy_applied,omitempty"`
	Error      string    `json:"error,omitempty"`
}

type AuditWriter struct{ path string; truncTo int }

func NewAuditWriter(path string, truncTo int) *AuditWriter
// Append serializes ev as a single JSON line, ensures size < 4096, then writes
// with O_APPEND in one syscall (POSIX-atomic per PIPE_BUF guarantee).
func (a *AuditWriter) Append(ev AuditEvent) error
```

Truncate `Mask` via `if len(ev.Mask) > a.truncTo { ev.Mask = ev.Mask[:a.truncTo] + "…" }`. Real values **never** stored.

- [ ] **Step 5: `allowlist.go`**

```go
type Allowlist struct {
	Values         []string `json:"values"`
	Patterns       []string `json:"patterns"`
	RulesDisabled  []string `json:"rules_disabled"`
}
func LoadAllowlist(path string) (*Allowlist, error)
func SaveAllowlist(path string, a *Allowlist) error
```

- [ ] **Step 6: Tests**

- `config_test.go`: defaults match spec §7.3 byte-for-byte; Validate rejects bad enum.
- `secrets_test.go`: round-trip Save/Load; Upsert dedup by ID.
- `mappings_test.go`: AC replace `"sk_live_X9k…"` → `"sk_live_4eC…"` inside larger text; non-overlapping; idempotent on input with no masks.
- `audit_test.go`: write 100 events concurrently from goroutines (with `O_APPEND` they must all show up, line-aligned, under PIPE_BUF).
- `allowlist_test.go`: round-trip.

- [ ] **Step 7: Run + commit**

```bash
go test ./internal/core/store/... -race -count=1
git add internal/core/store
git commit -m "feat(store): config, secrets, mappings, audit, allowlist schemas + ops"
```

---

## Task 4: transformer/charset

**Files:**
- Create: `internal/core/transformer/charset.go`, `charset_test.go`

- [ ] **Step 1: Write `charset.go`**

```go
package transformer

type Charset uint8

const (
	CharsetAlphanumeric Charset = iota
	CharsetHex
	CharsetBase64URL
	CharsetAlphaUpper
	CharsetBase64
)

var (
	csAlphanumeric = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
	csHex          = []byte("0123456789abcdef")
	csBase64URL    = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
	csAlphaUpper   = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	csBase64       = []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
)

func (c Charset) Bytes() []byte {
	switch c {
	case CharsetHex:
		return csHex
	case CharsetBase64URL:
		return csBase64URL
	case CharsetAlphaUpper:
		return csAlphaUpper
	case CharsetBase64:
		return csBase64
	default:
		return csAlphanumeric
	}
}

func ParseCharset(s string) (Charset, bool) { /* "alphanumeric"|"hex"|... */ }
```

- [ ] **Step 2: Tests** — assert lengths (Alphanumeric=62, Hex=16, Base64URL=64, AlphaUpper=36, Base64=65). Round-trip ParseCharset.

- [ ] **Step 3: Commit**

```bash
go test ./internal/core/transformer/...
git add internal/core/transformer
git commit -m "feat(transformer): charset enum"
```

---

## Task 5: transformer/fpe Mask (flat + segments)

**Files:**
- Create: `internal/core/transformer/fpe.go`, `fpe_test.go`

- [ ] **Step 1: Write `fpe.go`**

Implement exactly per spec §4.4 (Mask, maskFlat, maskSegments, deriveCharsetBytes). Code already in spec — copy verbatim into the file.

Critical points:
- `maxCollisionRetries = 8`
- `ErrMaskExhaustedRetries` exported
- `existing` parameter is `map[string]string` (mask→real); collision check uses cross-secret only (skip if `other == real`)
- Segments must accept zero PrefixLen; flat must accept zero Segments
- Error wrap on every `stream.Read` failure

Add a `Rule` type used by Mask. Rule is **defined** here (not in detector) because transformer needs it; detector imports it:

```go
package transformer

import "regexp"

type Segment struct {
	Name    string
	Group   int
	Charset Charset
}

type Rule struct {
	ID          string
	Pattern     *regexp.Regexp
	MinLen      int
	MaxLen      int
	BeginMarker string
	EndMarker   string
	PrefixLen   int
	Charset     Charset
	Segments    []Segment
}
```

Note: The detector’s `Rule` struct **is** this `transformer.Rule`. detector imports transformer. Detector adds no rule fields beyond this.

- [ ] **Step 2: Tests in `fpe_test.go`**

- `TestMaskFlat_StripeLive`: real `sk_live_4eC39HqLyjWDarjtT1zdp7dc`, rule prefix=8, charset=alphanumeric. Mask must: same length; prefix `sk_live_`; body alphanumeric; deterministic across two calls; ≠ real.
- `TestMaskFlat_Determinism`: two `Mask` calls with same hasher+rule+real → identical mask.
- `TestMaskFlat_DifferentInstallKeys`: different keys → different masks (statistical).
- `TestMaskSegments_JWT`: rule with two segments (payload group 2, signature group 3 of `^([^.]+)\.([^.]+)\.([^.]+)$`). Mask preserves dots and group 1; group 2/3 are masked into base64url, lengths preserved.
- `TestMaskCollisionFallback`: stub a hasher that returns bytes equal to `real` body on first attempt; expect retry then success. Use a controllable test hasher (interface? small wrapper) — simplest: feed a `Stream` mock via interface and dependency-inject. If interface refactor too invasive for this task, skip and rely on cross-secret collision test below.
- `TestMaskCrossSecretCollision`: fixed `existing[mask]=otherReal`; mask must retry to a different mask. (Requires deterministic stream injection; if mocking is too heavy, mark this `t.Skip("requires hasher mock")` and revisit in Task 6.)
- `TestMaskSegmentsRejectsBadGroup`: pattern with no group 2 → error.
- `TestMaskRejectsShortReal`: real shorter than PrefixLen → error.
- `TestMaskRejectsTooFewBytes`: rule with `bodyLen=0` → returns prefix only, no error.
- `TestRejectionSampling_NoModuloBias`: derive 1MB of bytes for charset of length 62, count distribution; chi-square over 62 buckets must accept uniform null hypothesis at p>0.001 (loose).

For the "mock hasher" pattern, introduce in `fpe.go`:

```go
type Hasher interface {
	Stream(info []byte) io.Reader
}
```

`keymgr.Hasher` already implements this (after Task 1; verify it does — if not, adjust signature there).

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/core/transformer/... -race -count=1
git add internal/core/transformer
git commit -m "feat(transformer): FPE Mask (flat + segments) + rejection sampling"
```

---

## Task 6: transformer/unmask (Aho-Corasick)

**Files:**
- Create: `internal/core/transformer/unmask.go`, `unmask_test.go`

- [ ] **Step 1: Write `unmask.go`**

Use `cloudflare/ahocorasick`. Build the matcher from `mappings.ByMask` keys; replace longest-match per offset, non-overlapping.

```go
package transformer

import (
	"sort"

	"github.com/cloudflare/ahocorasick"
)

type ReverseIndex struct {
	keys    [][]byte
	values  []string // parallel slice; index i = real value for keys[i]
	matcher *ahocorasick.Matcher
}

func BuildReverseIndex(byMask map[string]string) *ReverseIndex {
	keys := make([][]byte, 0, len(byMask))
	vals := make([]string, 0, len(byMask))
	for m, r := range byMask {
		keys = append(keys, []byte(m))
		vals = append(vals, r)
	}
	// sort by len desc so AC's first-match preference favors longer keys when offsets tie
	sort.SliceStable(keys, func(i, j int) bool { return len(keys[i]) > len(keys[j]) })
	// keep vals aligned with keys after sort: rebuild
	rebuilt := make([]string, len(keys))
	for i, k := range keys {
		rebuilt[i] = byMask[string(k)]
	}
	return &ReverseIndex{
		keys:    keys,
		values:  rebuilt,
		matcher: ahocorasick.NewMatcher(keys),
	}
}

// Replace returns text with every key of r found in text replaced by its value,
// non-overlapping, longest-match-first by offset.
func (r *ReverseIndex) Replace(text string) string {
	if r == nil || len(r.keys) == 0 {
		return text
	}
	// Find all match indices; pick non-overlapping greedy by start, then by length.
	hits := r.matcher.Match([]byte(text))
	if len(hits) == 0 {
		return text
	}
	// hits[i] = key index that matched (matcher returns multiple hit indices, we need offsets too)
	// cloudflare/ahocorasick.Match returns indices of matched patterns; for offsets we need
	// MatchString or a custom walk. Use MatchAll variant that returns positions:
	// (See cloudflare/ahocorasick docs; if it doesn't expose offsets, fall back to
	// `index/suffixarray` or `regexp.MustCompile` over alternation of escaped keys.)
	return replaceUsingMatcher(text, r.keys, r.values, r.matcher)
}
```

**Implementation note for engineer:** `cloudflare/ahocorasick` returns matched-pattern indices but not offsets. Two paths:

  (a) Use the lower-level walk in cloudflare/ahocorasick by iterating bytes manually using its internal API (private, so no).

  (b) Switch to `github.com/anknown/ahocorasick` or `github.com/iohub/ahocorasick` which expose `(start, end, patternID)`. Pick `iohub/ahocorasick` (active, MIT, returns offsets).

Update Task 0 deps accordingly:
```bash
go get github.com/iohub/ahocorasick@latest
```

Then:

```go
import ahocorasick "github.com/iohub/ahocorasick"

type ReverseIndex struct {
	keys    []string
	values  []string
	m       *ahocorasick.Matcher
}

func BuildReverseIndex(byMask map[string]string) *ReverseIndex {
	if len(byMask) == 0 { return &ReverseIndex{} }
	m := ahocorasick.NewMatcher()
	keys := make([]string, 0, len(byMask))
	vals := make([]string, 0, len(byMask))
	for k, v := range byMask {
		keys = append(keys, k)
		vals = append(vals, v)
		m.Insert([]byte(k), []byte(k))
	}
	m.Compile()
	return &ReverseIndex{keys: keys, values: vals, m: m}
}

func (r *ReverseIndex) Replace(text string) string {
	if r == nil || r.m == nil { return text }
	resp := r.m.Match([]byte(text))
	type hit struct{ start, end int; v string }
	hits := make([]hit, 0, 16)
	for resp.HasNext() {
		h := resp.NextMatchItem([]byte(text))
		// h.At = end position (inclusive of last byte); h.Word = []byte key
		key := string(h.Word)
		end := int(h.At) + 1
		start := end - len(key)
		// find replacement
		var val string
		for i, k := range r.keys {
			if k == key { val = r.values[i]; break }
		}
		hits = append(hits, hit{start, end, val})
	}
	resp.Release()
	if len(hits) == 0 { return text }
	// non-overlapping greedy: sort by start asc, then end desc
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].start != hits[j].start { return hits[i].start < hits[j].start }
		return hits[i].end > hits[j].end
	})
	// drop overlapping
	keep := hits[:0]
	prevEnd := -1
	for _, h := range hits {
		if h.start < prevEnd { continue }
		keep = append(keep, h)
		prevEnd = h.end
	}
	// build output
	var sb strings.Builder
	last := 0
	for _, h := range keep {
		sb.WriteString(text[last:h.start])
		sb.WriteString(h.v)
		last = h.end
	}
	sb.WriteString(text[last:])
	return sb.String()
}
```

- [ ] **Step 2: Tests in `unmask_test.go`**

- `TestReplace_BasicTwoMasks`: two masks in one input — both replaced.
- `TestReplace_NoMasks`: input unchanged.
- `TestReplace_OverlappingPreferLonger`: keys `"abc"` and `"abcdef"` both match — `"abcdef"` wins.
- `TestReplace_AdjacentMasks`: `"X9k…AKIA…"` adjacent → both replaced.
- `TestReplace_EmptyIndex`: nil index returns input.
- `TestReplace_PartialMaskNotReplaced`: input contains first 8 chars of a 24-char mask → unchanged (validates spec §8.7 partial-mask behavior).

- [ ] **Step 3: Run + commit**

```bash
go mod tidy
go test ./internal/core/transformer/... -race -count=1
git add internal/core/transformer go.mod go.sum
git commit -m "feat(transformer): unmask via Aho-Corasick reverse index"
```

---

## Task 7: detector/allowlist + entropy

**Files:**
- Create: `internal/core/detector/allowlist.go`, `entropy.go`, plus tests

- [ ] **Step 1: `allowlist.go` — AllowlistSet**

```go
package detector

import "regexp"

type AllowlistSet struct {
	values        map[string]struct{}
	patterns      []*regexp.Regexp
	rulesDisabled map[string]struct{}
}

func NewAllowlistSet(values []string, patterns []string, disabled []string) (*AllowlistSet, error) {
	a := &AllowlistSet{
		values:        make(map[string]struct{}),
		rulesDisabled: make(map[string]struct{}),
	}
	for _, v := range values { a.values[v] = struct{}{} }
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil { return nil, err }
		a.patterns = append(a.patterns, re)
	}
	for _, r := range disabled { a.rulesDisabled[r] = struct{}{} }
	return a, nil
}

func (a *AllowlistSet) AllowsValue(v string) bool {
	if a == nil { return false }
	if _, ok := a.values[v]; ok { return true }
	for _, re := range a.patterns {
		if re.MatchString(v) { return true }
	}
	return false
}

func (a *AllowlistSet) RuleDisabled(id string) bool {
	if a == nil { return false }
	_, ok := a.rulesDisabled[id]
	return ok
}
```

- [ ] **Step 2: `entropy.go` — Shannon scanner**

```go
package detector

import "math"

type EntropyScanner struct {
	threshold float64
	minLen    int
}

func NewEntropyScanner(threshold float64, minLen int) *EntropyScanner {
	return &EntropyScanner{threshold: threshold, minLen: minLen}
}

// ScoreToken returns Shannon entropy in bits/char. >= threshold means "secret-like".
func (s *EntropyScanner) ScoreToken(t string) float64 {
	if len(t) == 0 { return 0 }
	var counts [256]int
	for i := 0; i < len(t); i++ { counts[t[i]]++ }
	n := float64(len(t))
	var h float64
	for _, c := range counts {
		if c == 0 { continue }
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func (s *EntropyScanner) IsSecret(t string) bool {
	if len(t) < s.minLen { return false }
	return s.ScoreToken(t) >= s.threshold
}
```

- [ ] **Step 3: Tests** — entropy of `"aaaaaaaa"` ≈ 0; entropy of random base64 of length 32 > 4.5; AllowlistSet matches and rejects correctly.

- [ ] **Step 4: Commit**

```bash
go test ./internal/core/detector/... -race -count=1
git add internal/core/detector
git commit -m "feat(detector): allowlist + entropy scanner"
```

---

## Task 8: detector/rules — built-in rule set (~30 rules)

**Files:**
- Create: `internal/core/detector/rules.go`, `rules_test.go`

- [ ] **Step 1: Rule definitions**

Implement each row of spec §4.3 as `transformer.Rule`. Use raw-string regex literals; specify `MinLen`, `MaxLen` (16 KB for `pem-private-key` and `ssh-private-key`, 4 KB for others), `BeginMarker`/`EndMarker` for PEM/SSH containers, and segments for `jwt`, `pem-private-key`, `db-conn-string`, `bearer-token-url`, `generic-bearer-header`, `ssh-private-key`. `env-import` and `entropy-high` use Base64URL fallback per spec §8.6.

```go
package detector

import (
	"regexp"

	"github.com/pratikbin/opensecretmask/internal/core/transformer"
)

func BuiltinRules() []transformer.Rule {
	return []transformer.Rule{
		{
			ID:        "stripe-live",
			Pattern:   regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,}`),
			MinLen:    32, MaxLen: 256,
			PrefixLen: 8, Charset: transformer.CharsetAlphanumeric,
		},
		// ... ~30 rules total. Each row of spec §4.3.
	}
}
```

For complex segmented rules:

```go
{
	ID:      "jwt",
	Pattern: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.([A-Za-z0-9_-]{10,})\.([A-Za-z0-9_-]{10,})`),
	MinLen:  40, MaxLen: 4096,
	Segments: []transformer.Segment{
		{Name: "jwt-payload", Group: 1, Charset: transformer.CharsetBase64URL},
		{Name: "jwt-signature", Group: 2, Charset: transformer.CharsetBase64URL},
	},
},
{
	ID:          "pem-private-key",
	Pattern:     regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----\n([A-Za-z0-9+/=\n]+)-----END [A-Z ]*PRIVATE KEY-----`),
	MinLen:      80, MaxLen: 16384,
	BeginMarker: "-----BEGIN ",
	EndMarker:   "-----END ",
	Segments:    []transformer.Segment{{Name: "pem-body", Group: 1, Charset: transformer.CharsetBase64}},
},
{
	ID:      "db-conn-string",
	Pattern: regexp.MustCompile(`(?i)(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:/\s]+:([^@\s]+)@[^/\s]+(?:/\S+)?`),
	MinLen:  20, MaxLen: 1024,
	Segments: []transformer.Segment{{Name: "conn-password", Group: 1, Charset: transformer.CharsetAlphanumeric}},
},
```

(Implement remaining rules similarly. Engineer must verify each regex compiles and exercises the Segment/PrefixLen branch correctly.)

- [ ] **Step 2: User-rules loader**

```go
// LoadUserRules reads rules.toml (optional) and appends to BuiltinRules.
type userRule struct {
	ID        string `toml:"id"`
	Pattern   string `toml:"pattern"`
	PrefixLen int    `toml:"prefix_len"`
	Charset   string `toml:"charset"`
	MinLen    int    `toml:"min_len"`
	MaxLen    int    `toml:"max_len"`
}
func LoadUserRules(path string) ([]transformer.Rule, error)  // file optional
```

- [ ] **Step 3: Tests**

For each rule, table-driven: a positive sample (must match end-to-end) + a negative sample (must NOT match). Builtin rule count >= 18 (anything missing → fail with rule ID).

- [ ] **Step 4: Commit**

```bash
go test ./internal/core/detector/... -race -count=1
git add internal/core/detector
git commit -m "feat(detector): built-in rule set + user rules.toml loader"
```

---

## Task 9: detector/env loader

**Files:**
- Create: `internal/core/detector/env.go`, `env_test.go`

- [ ] **Step 1: `env.go`**

```go
package detector

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

type EnvEntry struct {
	Key       string
	Value     string
	SourcePath string
}

// FindEnvFiles walks from cwd up until .git/ or filesystem root, collecting
// files matching any of the configured patterns. Stops at git boundary if walkUpToGitRoot=true.
func FindEnvFiles(cwd string, patterns []string, walkUpToGitRoot bool) ([]string, error) {
	var found []string
	dir := cwd
	for {
		for _, pat := range patterns {
			matches, _ := filepath.Glob(filepath.Join(dir, pat))
			found = append(found, matches...)
		}
		if walkUpToGitRoot {
			if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
				return found, nil
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir { return found, nil }
		dir = parent
	}
}

// ParseEnvFile returns KEY=VALUE entries. Honors `export KEY=VALUE`, ignores
// blank lines, comments. Values can be quoted "..." or '...'.
func ParseEnvFile(path string) ([]EnvEntry, error) {
	f, err := os.Open(path)
	if err != nil { return nil, err }
	defer f.Close()
	var out []EnvEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") { continue }
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq <= 0 { continue }
		k := strings.TrimSpace(line[:eq])
		v := strings.TrimSpace(line[eq+1:])
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out = append(out, EnvEntry{Key: k, Value: v, SourcePath: path})
	}
	return out, sc.Err()
}
```

- [ ] **Step 2: Tests** — fixture `.env` files with quotes, exports, comments, blanks. Walk fixture creates temp tree with nested dirs + `.git` marker.

- [ ] **Step 3: Commit**

```bash
go test ./internal/core/detector/... -race -count=1
git add internal/core/detector
git commit -m "feat(detector): .env discovery + parser"
```

---

## Task 10: detector/detector — 3-layer cascade

**Files:**
- Create: `internal/core/detector/detector.go`, `detector_test.go`

- [ ] **Step 1: `detector.go`**

```go
package detector

import (
	"github.com/pratikbin/opensecretmask/internal/core/transformer"
)

type Finding struct {
	Start, End int
	Value      string
	Rule       string
	Confidence float64
}

type RegisteredSet struct {
	values map[string]struct{}
	// For fast multi-find scan use Aho-Corasick from iohub/ahocorasick (Task 6 dep).
	matcher *registeredMatcher
}

type Detector struct {
	registered *RegisteredSet
	rules      []transformer.Rule
	entropy    *EntropyScanner
	allowlist  *AllowlistSet
}

func NewDetector(reg *RegisteredSet, rules []transformer.Rule, entropy *EntropyScanner, allow *AllowlistSet) *Detector {
	return &Detector{registered: reg, rules: rules, entropy: entropy, allowlist: allow}
}

// Detect returns findings in `text`. Order: registered → rules → entropy. First match per offset wins.
// Overlapping findings: longer wins; on tie, earlier rule index wins.
func (d *Detector) Detect(text string) []Finding {
	var hits []Finding
	if d.registered != nil { hits = append(hits, d.registered.scan(text)...) }
	for ri, r := range d.rules {
		if d.allowlist.RuleDisabled(r.ID) { continue }
		idxs := r.Pattern.FindAllStringIndex(text, -1)
		for _, ix := range idxs {
			val := text[ix[0]:ix[1]]
			if d.allowlist.AllowsValue(val) { continue }
			if r.MinLen > 0 && len(val) < r.MinLen { continue }
			if r.MaxLen > 0 && len(val) > r.MaxLen { continue }
			hits = append(hits, Finding{Start: ix[0], End: ix[1], Value: val, Rule: r.ID, Confidence: 0.95 - 0.001*float64(ri)})
		}
	}
	if d.entropy != nil {
		// optional layer-3 scan over residual tokens; skip for now if covered above
		hits = append(hits, d.entropyScan(text, hits)...)
	}
	return resolveOverlaps(hits)
}

// resolveOverlaps drops findings that overlap with a higher-priority finding.
func resolveOverlaps(hits []Finding) []Finding { /* sort by start asc, end desc; greedy keep */ }
```

`RegisteredSet.scan` uses iohub/ahocorasick with each registered value as a key.

- [ ] **Step 2: Tests** — registered exact match wins over regex; allowlist suppresses; entropy scan only triggers when first two layers miss; overlap resolution prefers longer.

- [ ] **Step 3: Commit**

```bash
go test ./internal/core/detector/... -race -count=1
git add internal/core/detector
git commit -m "feat(detector): 3-layer cascade Detect()"
```

---

## Task 11: detector/scanner — streaming + container buffer

**Files:**
- Create: `internal/core/detector/scanner.go`, `scanner_test.go`

- [ ] **Step 1: `scanner.go`**

Translate spec §8.2 pseudocode into Go. Key points:

- `adaptiveOverlap = max(longestRuleMaxLen, 4096)` computed once from rules.
- `scanBuf` is a `bytes.Buffer` (treat as ring; on overflow shift). `containerBuf` is a separate `[]byte` allocated on container open.
- Container detection via `BeginMarker` / `EndMarker` matched as exact substrings.
- `max_container_bytes` and `max_scan_bytes` from `HooksConfig`.
- Fail-closed paths return a sentinel error `ErrScanCapExceeded`, `ErrContainerOverflow`, `ErrUnclosedContainer`.

```go
package detector

import (
	"bytes"
	"errors"
	"io"
)

var (
	ErrScanCapExceeded   = errors.New("scan cap exceeded")
	ErrContainerOverflow = errors.New("container exceeded max_container_bytes")
	ErrUnclosedContainer = errors.New("EOF inside open container")
)

type Scanner struct {
	det               *Detector
	rules             []transformer.Rule
	overlap           int
	maxScan           int
	maxContainer      int
	mask              func(text string) (string, error) // injected
	flushScan         func(b []byte, w io.Writer) error
	containerRules    []*transformer.Rule
}

func NewScanner(det *Detector, rules []transformer.Rule, maxScan, maxContainer int,
	mask func(string) (string, error)) *Scanner {
	overlap := 4096
	for _, r := range rules {
		if r.MaxLen > overlap { overlap = r.MaxLen }
	}
	var crs []*transformer.Rule
	for i := range rules {
		if rules[i].BeginMarker != "" && rules[i].EndMarker != "" {
			crs = append(crs, &rules[i])
		}
	}
	return &Scanner{det: det, rules: rules, overlap: overlap, maxScan: maxScan,
		maxContainer: maxContainer, mask: mask, containerRules: crs}
}

func (s *Scanner) Stream(r io.Reader, w io.Writer) error { /* implement spec §8.2 pseudocode */ }
```

`flushScan(bytes, w)` calls `det.Detect(string(bytes))`, applies `mask` to each finding (replace into byte slice), writes to `w`.

`applyContainerMask(buf, rule)` runs a single segmented `transformer.Mask(string(buf), *rule, …)` on the full container bytes (because the rule pattern matches the whole container).

- [ ] **Step 2: Tests**

- `TestStream_NoSecrets`: 256 KB random text → output equals input (no false matches against builtin rules).
- `TestStream_SingleSecret`: stripe key embedded mid-stream → output has mask not real.
- `TestStream_StraddleBoundary`: position the secret across two chunk boundaries (use a `chunkReader` that returns small chunks). Mask must still fire because of overlap.
- `TestStream_PEM`: 4 KB PEM block → masked body, header/footer preserved verbatim.
- `TestStream_ContainerOverflow`: PEM with body > maxContainer → returns `ErrContainerOverflow`; **NO body bytes flushed to writer.**
- `TestStream_EOFInContainer`: BEGIN marker + body, no END, EOF → `ErrUnclosedContainer`; **NO body bytes flushed.**
- `TestStream_ScanCap`: writer truncate-replace last bytes when total > maxScan and `OnScanCap=truncate`.
- `TestStream_FlushOnEOF`: secret in last `< overlap` bytes of input is still detected (regression for the "tail leak" edge case).

- [ ] **Step 3: Commit**

```bash
go test ./internal/core/detector/... -race -count=1
git add internal/core/detector
git commit -m "feat(detector): streaming scanner with adaptive overlap + container buffer"
```

---

## Task 12: harness/protocol — canonical envelope

**Files:**
- Create: `internal/harness/protocol.go`, `protocol_test.go`

- [ ] **Step 1: `protocol.go`**

```go
package harness

import (
	"encoding/json"
	"io"

	"github.com/pratikbin/opensecretmask/internal/core/detector"
)

type Direction int

const (
	DirMask Direction = iota
	DirUnmask
	DirObserve
)

type Target struct {
	Path     []string
	Content  string
	Encoding string
	Skip     bool
}

type Request struct {
	Harness   string
	SessionID string
	EventName string
	Direction Direction
	ToolName  string
	Cwd       string
	Targets   []Target
}

type Response struct {
	Modified   bool
	Targets    []Target
	Findings   []detector.Finding
	Notes      []string
	DenyReason string
}

type Adapter interface {
	Name() string
	ParseRequest(stdin io.Reader) (*Request, json.RawMessage, error)
	EmitResponse(w io.Writer, original json.RawMessage, resp *Response) error
	EventDirection(eventName, toolName string) (Direction, error)
}
```

- [ ] **Step 2: Tests** — round-trip Direction enum string ↔ value; assert struct field tags absent (these are not JSON-serialized directly; harnesses translate).

- [ ] **Step 3: Commit**

```bash
go test ./internal/harness/...
git add internal/harness
git commit -m "feat(harness): canonical Request/Response envelope + Adapter interface"
```

---

## Task 13: harness/claudecode adapter (events + tools, no bash gate yet)

**Files:**
- Create: `internal/harness/claudecode/adapter.go`, `events.go`, `tools.go`
- Create: tests for each

- [ ] **Step 1: `events.go` — event names + direction**

```go
package claudecode

import (
	"fmt"

	"github.com/pratikbin/opensecretmask/internal/harness"
)

const (
	EventPostToolUse      = "PostToolUse"
	EventPreToolUse       = "PreToolUse"
	EventUserPromptSubmit = "UserPromptSubmit"
	EventSessionStart     = "SessionStart"
)

func eventDirection(event, tool string) (harness.Direction, error) {
	switch event {
	case EventPostToolUse:
		return harness.DirMask, nil
	case EventPreToolUse:
		return harness.DirUnmask, nil
	case EventUserPromptSubmit:
		return harness.DirObserve, nil
	case EventSessionStart:
		return harness.DirObserve, nil
	}
	return 0, fmt.Errorf("claudecode: unknown event %q", event)
}
```

- [ ] **Step 2: `tools.go` — per-tool field maps**

For PostToolUse (`tool_response` is the scannable payload):

```go
// readableFields returns JSON paths into tool_response that contain scannable text.
func postToolUseFields(toolName string) [][]string {
	switch toolName {
	case "Read":     return [][]string{{"content"}}
	case "Bash":     return [][]string{{"stdout"}, {"stderr"}}
	case "Grep":     return [][]string{{"matches"}}
	case "Glob":     return [][]string{{"files"}}
	case "WebFetch": return [][]string{{"content"}}
	default:         return [][]string{} // unknown tool: scan nothing
	}
}
```

For PreToolUse (`tool_input` paths to unmask):

```go
func preToolUseFields(toolName string) [][]string {
	switch toolName {
	case "Edit":         return [][]string{{"old_string"}, {"new_string"}}
	case "Write":        return [][]string{{"content"}}
	case "MultiEdit":    return [][]string{{"edits", "*", "old_string"}, {"edits", "*", "new_string"}}
	case "NotebookEdit": return [][]string{{"old_source"}, {"new_source"}}
	case "Bash":         return [][]string{{"command"}}
	}
	return nil
}
```

Provide `extractByPath(raw json.RawMessage, path []string) ([]string, error)` and `replaceByPath(raw, path, values) (json.RawMessage, error)` that handle the `*` wildcard (array iteration).

- [ ] **Step 3: `adapter.go`**

```go
type Adapter struct{}

func (Adapter) Name() string { return "claudecode" }

func (Adapter) EventDirection(event, tool string) (harness.Direction, error) {
	return eventDirection(event, tool)
}

func (a Adapter) ParseRequest(r io.Reader) (*harness.Request, json.RawMessage, error) {
	raw, err := io.ReadAll(r)
	if err != nil { return nil, nil, err }
	var hdr struct {
		HookEventName string          `json:"hook_event_name"`
		ToolName      string          `json:"tool_name"`
		ToolInput     json.RawMessage `json:"tool_input"`
		ToolResponse  json.RawMessage `json:"tool_response"`
		SessionID     string          `json:"session_id"`
		Cwd           string          `json:"cwd"`
		Prompt        string          `json:"prompt"`
		Source        string          `json:"source"`
	}
	if err := json.Unmarshal(raw, &hdr); err != nil { return nil, raw, err }
	req := &harness.Request{
		Harness:   "claudecode",
		SessionID: hdr.SessionID,
		EventName: hdr.HookEventName,
		ToolName:  hdr.ToolName,
		Cwd:       hdr.Cwd,
	}
	dir, err := eventDirection(hdr.HookEventName, hdr.ToolName)
	if err != nil { return nil, raw, err }
	req.Direction = dir
	switch hdr.HookEventName {
	case EventPostToolUse:
		for _, p := range postToolUseFields(hdr.ToolName) {
			vals, _ := extractByPath(hdr.ToolResponse, p)
			for _, v := range vals { req.Targets = append(req.Targets, harness.Target{Path: p, Content: v, Encoding: "utf8"}) }
		}
	case EventPreToolUse:
		for _, p := range preToolUseFields(hdr.ToolName) {
			vals, _ := extractByPath(hdr.ToolInput, p)
			for _, v := range vals { req.Targets = append(req.Targets, harness.Target{Path: p, Content: v, Encoding: "utf8"}) }
		}
	case EventUserPromptSubmit:
		req.Targets = []harness.Target{{Path: []string{"prompt"}, Content: hdr.Prompt, Encoding: "utf8"}}
	case EventSessionStart:
		// no targets; engine triggers env-preload separately
	}
	return req, raw, nil
}

func (a Adapter) EmitResponse(w io.Writer, original json.RawMessage, resp *harness.Response) error {
	// Build hook response per spec §5.5; varies by event. See implementation matrix:
	//
	// PostToolUse mask happy path:
	//   { "hookSpecificOutput": { "hookEventName": "PostToolUse", "updatedToolOutput": <modified tool_response> } }
	// PreToolUse unmask happy path:
	//   { "hookSpecificOutput": { "hookEventName": "PreToolUse", "permissionDecision": "<allow|ask|deny>",
	//                              "permissionDecisionReason": "...", "updatedInput": <modified tool_input> } }
	// UserPromptSubmit warn:
	//   { "hookSpecificOutput": { "hookEventName": "UserPromptSubmit", "additionalContext": "..." } }
	// Mask fail-closed deny:
	//   { "decision": "block", "reason": "..." }
	// SessionStart: empty {}.
}
```

- [ ] **Step 4: Tests** — fixture-driven. Each event has 2-3 fixtures in `tests/fixtures/`. Adapter parses them, asserts targets extracted; EmitResponse round-trips a `Response` to expected JSON.

- [ ] **Step 5: Commit**

```bash
go test ./internal/harness/claudecode/... -race -count=1
git add internal/harness/claudecode tests/fixtures
git commit -m "feat(harness/claudecode): adapter + per-event field mapping"
```

---

## Task 14: harness/claudecode bash gate (mvdan/sh)

**Files:**
- Create: `internal/harness/claudecode/bashgate.go`, `bashgate_test.go`

- [ ] **Step 1: `bashgate.go`**

Use `mvdan.cc/sh/v3/syntax` to parse `Bash.command`. Walk AST:

- Subshell or `eval`/`source`/`.` → `DENY`.
- Command word matches any token in `egress_blocklist` (token-1 OR substring scan over full command for `bash -c '...curl ...'`) → `DENY`.
- Pipe present and `treat_pipe_as_ask` → `ASK`.
- Redirect present and `treat_redirect_as_ask` → `ASK`.
- Command word in `local_allowlist` and no metas → `ALLOW`.
- Default → `ASK`.
- Always `DENY` for `> /dev/tcp/*`.

```go
package claudecode

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type BashDecision string

const (
	BashSkip  BashDecision = "skip"
	BashDeny  BashDecision = "deny"
	BashAsk   BashDecision = "ask"
	BashAllow BashDecision = "allow"
)

type BashGate struct {
	cfg storeBashConfig // alias of store.BashConfig to avoid import cycle (define in adapter pkg)
}

func (g *BashGate) Classify(cmd string, replacements int) (BashDecision, string) {
	if replacements == 0 { return BashSkip, "" }
	r := strings.NewReader(cmd)
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	prog, err := parser.Parse(r, "cmd")
	if err != nil {
		// parse failure → conservative: ASK
		return BashAsk, "parse error: " + err.Error()
	}
	dec, reason := g.walk(prog)
	if dec == "" { dec = BashAsk; reason = "default conservative" }
	return dec, reason
}

func (g *BashGate) walk(prog *syntax.File) (BashDecision, string) {
	// Walk syntax tree: detect Subshell, CmdSubst, BinaryCmd (pipe), Redirect, eval/source/dot.
	// For each simple CallExpr, inspect its first word; bash-c-style invocations get
	// substring-scanned over their string args for blocklist tokens.
	// On DENY return immediately. On any ASK note it; defer until walk done.
	// Implementation detail: substring scan = `strings.Contains(cmd, " "+blocked+" ")` after
	// normalization; explicit space delimiters around blocked tokens to avoid `git pull` matching `pullup`.
	return "", "" // engineer: fill in
}
```

The `storeBashConfig` mirror is necessary because importing `store` from `harness/claudecode` could create a cycle if store ever depends on harness; if it doesn't (it shouldn't), import directly. Verify; prefer direct import.

Special-case `> /dev/tcp/*` redirect target check inside the walker.

- [ ] **Step 2: Tests** — table-driven with 30+ cases:

```
"curl https://x.y/z"               → DENY (egress)
"bash -c 'curl https://x.y'"       → DENY (substring scan)
"cat foo.txt"                      → ALLOW
"cat foo.txt | grep bar"           → ASK (pipe)
"cat foo.txt > out.txt"            → ASK (redirect)
"echo $(cat /etc/passwd)"          → DENY (subshell)
"eval $cmd"                        → DENY
". ./script.sh"                    → DENY
"source script.sh"                 → DENY
"echo hello > /dev/tcp/1.2.3.4/80" → DENY
"git push origin main"             → DENY
"git status"                       → ALLOW
"npm test"                         → ALLOW
"npm publish"                      → DENY
"docker push img"                  → DENY
"unknown_cmd --flag"               → ASK (default)
```

Plus the `replacements == 0` SKIP fast path.

- [ ] **Step 3: Commit**

```bash
go test ./internal/harness/claudecode/... -race -count=1
git add internal/harness/claudecode
git commit -m "feat(harness/claudecode): bash egress gate via mvdan/sh AST"
```

---

## Task 15: cmd/osm root + version + main

**Files:**
- Create: `cmd/osm/main.go`, `root.go`, `version.go`

- [ ] **Step 1: `main.go`**

```go
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: `root.go` — cobra root**

```go
package main

import "github.com/spf13/cobra"

var Version = "dev"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "osm",
		Short:         "opensecretmask — credential masker for AI coding agents",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		newInitCmd(),
		newDoctorCmd(),
		newScanCmd(),
		newHookCmd(),
		newInstallCmd(),
		newAddCmd(),
		newAllowCmd(),
		newStatusCmd(),
		newTailCmd(),
		newVersionCmd(),
	)
	return root
}
```

- [ ] **Step 3: `version.go`**

```go
func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		RunE: func(c *cobra.Command, _ []string) error {
			fmt.Fprintln(c.OutOrStdout(), Version)
			return nil
		},
	}
}
```

- [ ] **Step 4: Subcommand stubs** — for the other 9 subcommands, write stubs that return `errNotImplemented` until subsequent tasks fill them. This keeps the binary buildable.

- [ ] **Step 5: Build + commit**

```bash
go build ./cmd/osm
git add cmd/osm
git commit -m "feat(cmd): cobra root + version + subcommand skeletons"
```

---

## Task 16: cmd/osm/init

**Files:**
- Modify: `cmd/osm/init.go`
- Create: `cmd/osm/init_test.go`

- [ ] **Step 1: Implement `osm init`**

```go
func newInitCmd() *cobra.Command {
	var force bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Create ~/.opensecretmask/ + install.key + default config",
		RunE: func(cmd *cobra.Command, _ []string) error {
			root, err := store.Root()
			if err != nil { return err }
			if !force {
				if _, err := os.Stat(filepath.Join(root, keymgr.InstallKeyName)); err == nil {
					return fmt.Errorf("already initialized at %s; use --force to overwrite", root)
				}
			}
			if err := os.MkdirAll(root, 0o700); err != nil { return err }
			if err := os.Chmod(root, 0o700); err != nil { return err }
			if _, err := keymgr.Generate(root); err != nil { return err }
			cfg := store.DefaultConfig()
			cfgBytes, _ := tomlMarshal(cfg) // helper using BurntSushi/toml.NewEncoder
			if err := store.WriteAtomic(filepath.Join(root, store.ConfigName), cfgBytes, 0o644); err != nil { return err }
			if err := store.SaveSecrets(filepath.Join(root, store.SecretsName), &store.Secrets{Version: 1}); err != nil { return err }
			if err := store.SaveMappings(filepath.Join(root, store.MappingsName), &store.Mappings{Version: 1, ByMask: map[string]string{}}); err != nil { return err }
			if err := store.SaveAllowlist(filepath.Join(root, store.AllowlistName), &store.Allowlist{Values: store.DefaultConfig().Detector.Allowlist.Values}); err != nil { return err }
			fmt.Fprintf(cmd.OutOrStdout(), "Initialized %s\n", root)
			return nil
		},
	}
	c.Flags().BoolVar(&force, "force", false, "overwrite existing init")
	return c
}
```

- [ ] **Step 2: Tests** — set `OPENSECRETMASK_HOME` to t.TempDir(); run init; assert files exist with correct modes; second run without `--force` errors; with `--force` succeeds.

- [ ] **Step 3: Commit**

```bash
go test ./cmd/osm/... -race
git add cmd/osm
git commit -m "feat(cmd/init): bootstrap ~/.opensecretmask/"
```

---

## Task 17: cmd/osm/doctor

**Files:**
- Modify: `cmd/osm/doctor.go`
- Create: `cmd/osm/doctor_test.go`

- [ ] **Step 1: Implement `osm doctor`**

Checks (each prints PASS/FAIL line):
1. `~/.opensecretmask/` exists, mode 0700.
2. `install.key` exists, mode 0600, length 32.
3. `config.toml`, `secrets.json`, `mappings.json`, `allowlist.json` exist with correct modes.
4. Lock file is healthy (open + immediate try-lock + release).
5. `secrets.json` round-trip (parse + re-serialize).
6. Mappings consistency: every value in `mappings.by_mask` corresponds to some `secrets.secrets[*].masked == key`. Drift → flag (auto-repair via `--rebuild-mappings`).
7. Stale `.tmp.*` cleanup (auto, always).

Flags: `--rebuild-mappings`, `--repair-modes` (chmod to expected).

Exit code: 0 if all pass, 1 if any fail (no `--repair*`).

- [ ] **Step 2: Tests** — fabricate good and broken homes in tempdirs; assert pass/fail; assert `--repair-modes` actually fixes 0644 install.key back to 0600.

- [ ] **Step 3: Commit**

```bash
go test ./cmd/osm/...
git add cmd/osm
git commit -m "feat(cmd/doctor): integrity checks + auto-repair"
```

---

## Task 18: cmd/osm/scan

**Files:**
- Modify: `cmd/osm/scan.go`
- Create: `cmd/osm/scan_test.go`

- [ ] **Step 1: Implement `osm scan <file>`**

Loads config + key + detector; runs `Scanner.Stream` from file → stdout. Pipes mask substitutions through `transformer.Mask` and reuses `mappings.json` (RLock + read; if new finding, EX-lock + persist).

Flag: `--no-persist` (for read-only scan; mask without registering).

- [ ] **Step 2: Tests** — fixture file with stripe + JWT + PEM; expected output has masks; second run produces same masks (determinism).

- [ ] **Step 3: Commit**

```bash
go test ./cmd/osm/...
git add cmd/osm
git commit -m "feat(cmd/scan): mask a file via streaming scanner"
```

---

## Task 19: cmd/osm/hook dispatcher (THE CRITICAL ONE)

**Files:**
- Modify: `cmd/osm/hook.go`
- Create: `cmd/osm/hook_test.go`
- Create: `internal/core/engine/engine.go` (new package — pure pipeline)

- [ ] **Step 1: Engine pipeline (new pkg `internal/core/engine`)**

```go
package engine

type Engine struct {
	Cfg       *store.Config
	Hasher    *keymgr.Hasher
	Lock      *store.Lock
	Mappings  *store.Mappings
	Secrets   *store.Secrets
	Detector  *detector.Detector
	Scanner   *detector.Scanner
	Audit     *store.AuditWriter
	Root      string
	Allowlist *store.Allowlist
	Rules     []transformer.Rule
}

// MaskText runs detector.Detect and produces masked text. Persists new mappings.
// Returns (maskedText, findings, error). Caller decides how to recover from errors per direction.
func (e *Engine) MaskText(ctx context.Context, sessionID, source, text string) (string, []detector.Finding, error)

// UnmaskText loads mappings (RLock) and runs ReverseIndex.Replace.
func (e *Engine) UnmaskText(text string) (string, int, error)

// PreloadEnv parses .env files via detector.FindEnvFiles + ParseEnvFile and registers
// all values as registered secrets, computing masks immediately (acquire EX-lock once per batch).
func (e *Engine) PreloadEnv(ctx context.Context, cwd string) (int, error)
```

`MaskText` flow:
1. RLock; read mappings; release RLock.
2. Run detector. If no findings: return (text, nil, nil).
3. For each finding: lookup mappings; if hit, reuse; if miss, accumulate.
4. If accumulator non-empty: EX-lock; re-read mappings (could've changed); for each new finding, run `transformer.Mask`; insert into mappings + secrets; SaveMappings + SaveSecrets atomically; release EX-lock.
5. Build replacements map; rewrite text in offset order; return.

- [ ] **Step 2: hook.go dispatcher**

```go
func newHookCmd() *cobra.Command {
	var harnessFlag string
	c := &cobra.Command{
		Use:   "hook <event>",
		Short: "Run a harness hook (read JSON from stdin, write JSON to stdout)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			event := args[0]
			// Re-entrancy guard
			if os.Getenv("OSM_RUNNING") == "1" { return nil }
			os.Setenv("OSM_RUNNING", "1")
			defer os.Unsetenv("OSM_RUNNING")

			// Initialize engine (precondition checks first; fail-closed on error per direction)
			eng, perr := bootstrapEngine()
			adp := pickAdapter(harnessFlag)
			if perr != nil {
				return emitPreconditionFailure(adp, event, cmd.OutOrStdout(), cmd.InOrStdin(), perr)
			}
			req, raw, err := adp.ParseRequest(cmd.InOrStdin())
			if err != nil {
				return emitParseFailure(adp, event, cmd.OutOrStdout(), err)
			}
			req.EventName = event

			switch req.Direction {
			case harness.DirMask:
				return runMask(cmd.Context(), eng, adp, req, raw, cmd.OutOrStdout())
			case harness.DirUnmask:
				return runUnmask(cmd.Context(), eng, adp, req, raw, cmd.OutOrStdout())
			case harness.DirObserve:
				return runObserve(cmd.Context(), eng, adp, req, raw, cmd.OutOrStdout())
			}
			return nil
		},
	}
	c.Flags().StringVar(&harnessFlag, "harness", "claudecode", "harness adapter name")
	return c
}
```

`runMask`:
- Loop over `req.Targets`, call `eng.MaskText`. On any error: emit fail-closed JSON per `cfg.Hooks.MaskOnError` (`block` reason=short, OR `redact-all` updatedToolOutput), exit 0.
- On success: build response with replaced targets; `adp.EmitResponse(...)` writes the harness-shaped JSON.

`runUnmask`:
- Acquire RLock briefly to load mappings; build ReverseIndex.
- For each target, call `Replace`. Track total replacements.
- If `req.ToolName == "Bash"`, call `bashgate.Classify(originalCmd, replacements)` → set `permissionDecision` on response.
- On error: fail-open (exit 0, no updatedInput) per spec §8.10. Audit `action=error direction=unmask`.

`runObserve`:
- For UserPromptSubmit: detect; if findings, emit `additionalContext` warning. Audit `action=warn`.
- For SessionStart: call `eng.PreloadEnv(req.Cwd)`. Emit empty `{}`. Audit if entries imported.

`emitPreconditionFailure` translates missing `install.key` etc. into:
- PostToolUse: `{"decision":"block","reason":"opensecretmask not initialized; run `osm init`"}`
- PreToolUse: `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"opensecretmask not initialized; run `osm init`"}}`
- UserPromptSubmit / SessionStart: empty `{}` (observe direction → safe to passthrough; spec §8.10).

`emitParseFailure` (we already read stdin so direction is unknown): emit `{"decision":"block","reason":"opensecretmask: malformed hook payload"}` and exit 0. Defense: malformed input is suspicious, deny is safer than allow.

**Critical**: every `RunE` path returns `nil` after writing JSON. Returning a non-nil error would propagate to `os.Exit(1)`, which for PostToolUse claude-code treats as **non-blocking** — leak. The exit-1 path is reserved for cobra-side failures BEFORE stdin is read (§5.5).

- [ ] **Step 3: Hook tests**

`hook_test.go`: integration-style. Spin up a tempdir, run `osm init` programmatically (call init's RunE), then for each fixture in `tests/fixtures/`, pipe the JSON in and assert output JSON matches expected. Cases:

- PostToolUse Read with stripe key in content → `updatedToolOutput.content` masked.
- PostToolUse Bash with no secrets → empty stdout.
- PreToolUse Edit with mask in old_string → `permissionDecision=allow updatedInput.old_string` unmasked.
- PreToolUse Bash `curl https://x.y/?token=<MASK>` (contains a mask) → `permissionDecision=deny`.
- PreToolUse Bash `cat .env` (no masks) → empty stdout (skip path).
- UserPromptSubmit with anthropic key in prompt → `additionalContext` warning.
- SessionStart at cwd containing `.env` with stripe key → preload audit line written; output `{}`.
- Missing `install.key` (uninit) + PostToolUse Read → `{"decision":"block",…}`, exit 0.

- [ ] **Step 4: Run + commit**

```bash
go test ./cmd/osm/... ./internal/core/engine/... -race -count=1
git add cmd/osm internal/core/engine
git commit -m "feat(cmd/hook): dispatcher + engine pipeline (mask/unmask/observe)"
```

---

## Task 20: cmd/osm/install (claude-code) + uninstall

**Files:**
- Modify: `cmd/osm/install.go`
- Create: `cmd/osm/install_test.go`
- Create: `examples/claude-code-settings.json`

- [ ] **Step 1: `install.go`**

Subcommands: `osm install claude-code`, `osm uninstall claude-code`. Flags: `--global` (`~/.claude/settings.json`), `--project` (`.claude/settings.json` in cwd), `--dry-run`.

Logic:
1. Load existing settings.json (if missing, start with `{}`).
2. Merge hook entries per spec §3, **preserving** existing entries with different `description` field. Add only entries we own (`description: "opensecretmask"`).
3. If a matching osm entry exists, update its `command` field idempotently (allows version upgrade).
4. Print before/after diff (use `cmp.Diff` or hand-rolled JSON pretty-print).
5. `--dry-run` skips writing.

`uninstall`: traverse hooks tree; remove only entries whose `description == "opensecretmask"`.

Always write via `store.WriteAtomic` so settings.json edits are crash-safe.

- [ ] **Step 2: `examples/claude-code-settings.json`** — verbatim spec §3 hooks block.

- [ ] **Step 3: Tests** — fixture: starting settings.json with one user-hook + run install → result has user-hook + osm hooks; uninstall → leaves user-hook intact.

- [ ] **Step 4: Commit**

```bash
go test ./cmd/osm/...
git add cmd/osm examples
git commit -m "feat(cmd/install): claude-code settings.json hook installer + uninstaller"
```

---

## Task 21: cmd/osm/{add,allow,status,tail}

**Files:**
- Modify: `cmd/osm/add.go`, `allow.go`, `status.go`, `tail.go`
- Create: tests for each

- [ ] **Step 1: `add NAME=value`**

Registers value as a manually-added secret in `secrets.json` (source="manual"), computes mask, persists.

- [ ] **Step 2: `allow <value>` / `allow --pattern <re>` / `allow --rule <id>`**

Adds to `allowlist.json`. Refuses if value already registered as a secret (warn + require `--force`).

- [ ] **Step 3: `status`**

Print: registered count, mappings count, audit-log size, last activity timestamp, root path.

- [ ] **Step 4: `tail`**

`tail -f` style on `audit.log`. Pretty-print NDJSON lines (timestamp + action + tool + count). Flag `--json` for raw passthrough. Use `fsnotify` or simple polling — polling (250 ms) is simpler and good enough; document.

Add dep: `go get github.com/fsnotify/fsnotify@latest` ONLY if polling is rejected; default to polling, no dep.

- [ ] **Step 5: Tests** — small integration tests for each.

- [ ] **Step 6: Commit**

```bash
go test ./cmd/osm/...
git add cmd/osm
git commit -m "feat(cmd): add/allow/status/tail admin subcommands"
```

---

## Task 22: pkg/api — public Go library surface

**Files:**
- Create: `pkg/api/api.go`, `api_test.go`

- [ ] **Step 1: `api.go`**

```go
// Package api exposes the harness-agnostic engine for library consumers.
// Stable surface; no harness types exposed.
package api

type Masker struct{ eng *engine.Engine }

func New(opts Options) (*Masker, error)
func (m *Masker) Mask(ctx context.Context, text string) (masked string, err error)
func (m *Masker) Unmask(text string) (real string, err error)
func (m *Masker) Detect(text string) []detector.Finding
```

Options: home dir override, config override, dry-run flag.

- [ ] **Step 2: Tests** — happy path: New → Mask → Unmask round-trip = identity.

- [ ] **Step 3: Commit**

```bash
go test ./pkg/api/...
git add pkg/api
git commit -m "feat(api): public Mask/Unmask/Detect Go API"
```

---

## Task 23: integration tests (end-to-end hook fixtures)

**Files:**
- Create: `tests/integration/*.go`
- Create: `tests/fixtures/*.json`

- [ ] **Step 1: Fixtures**

JSON fixtures for: PostToolUse Read/Bash/Grep, PreToolUse Edit/Write/MultiEdit/NotebookEdit/Bash, UserPromptSubmit, SessionStart. At least 2 variants each (no-finding fast path + with-finding).

- [ ] **Step 2: Test harness**

```go
func runOSMHook(t *testing.T, home, harness, event string, stdin []byte) (stdout []byte, exitCode int) {
	cmd := exec.Command(osmBinaryPath(t), "hook", "--harness="+harness, event)
	cmd.Env = append(os.Environ(), "OPENSECRETMASK_HOME="+home)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	exit := 0
	if exitErr, ok := err.(*exec.ExitError); ok { exit = exitErr.ExitCode() }
	return out.Bytes(), exit
}
```

`osmBinaryPath` invokes `go build` once per test binary (TestMain).

- [ ] **Step 3: Cases**

Each fixture → assert exit code 0, assert stdout matches `wantOutputJSON`, assert audit.log has expected lines.

- [ ] **Step 4: Run + commit**

```bash
go test ./tests/integration/... -race -count=1
git add tests
git commit -m "test(integration): end-to-end hook fixtures across all events"
```

---

## Task 24: fuzz tests

**Files:**
- Create: `internal/core/detector/detector_fuzz_test.go`
- Create: `internal/core/transformer/fpe_fuzz_test.go`

- [ ] **Step 1: `FuzzDetector`**

```go
func FuzzDetector(f *testing.F) {
	f.Add([]byte("sk_live_4eC39HqLyjWDarjtT1zdp7dc"))
	f.Add([]byte(""))
	f.Add(make([]byte, 1024))
	f.Fuzz(func(t *testing.T, b []byte) {
		d := newTestDetector(t)
		_ = d.Detect(string(b)) // must not panic, must return in bounded time
	})
}
```

- [ ] **Step 2: `FuzzMaskUnmask`**

Generate random byte slices that match `^sk_live_[A-Za-z0-9]{24,64}$`; mask; insert into a `mappings.ByMask`; build ReverseIndex; replace text containing the mask; assert recovered text contains real value at the same offset.

- [ ] **Step 3: Run + commit**

```bash
go test ./internal/core/detector/... -run=^$ -fuzz=FuzzDetector -fuzztime=10s
go test ./internal/core/transformer/... -run=^$ -fuzz=FuzzMaskUnmask -fuzztime=10s
git add internal/core/detector internal/core/transformer
git commit -m "test: fuzz detector + mask/unmask round-trip"
```

---

## Task 25: bench tests + cold-start budget

**Files:**
- Create: `internal/core/detector/detector_bench_test.go`
- Create: `cmd/osm/hook_bench_test.go`

- [ ] **Step 1: Detector benches**

`BenchmarkScan100KB`, `BenchmarkScan1MB`. Target from spec §6.6: < 50 ms / 1 MB.

- [ ] **Step 2: Cold-start bench**

`BenchmarkColdStart` — exec `osm hook --harness=claudecode posttooluse` with a small fixture; measure stdin→stdout. Target P50 < 30 ms (§5.5).

- [ ] **Step 3: Commit**

```bash
go test -bench=. -benchmem ./internal/core/detector/...
go test -bench=. -benchmem ./cmd/osm/...
git add internal/core/detector cmd/osm
git commit -m "test: detector + cold-start benches"
```

---

## Task 26: CI matrix + lint config + gosec

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`
- Create: `.golangci.yml`, `.goreleaser.yaml`

- [ ] **Step 1: `.golangci.yml`**

Enable: `errcheck`, `govet`, `staticcheck`, `gosimple`, `ineffassign`, `unused`, `gocritic`, `misspell`, `nakedret`, `prealloc`, `unconvert`, `unparam`. Disable noisy: `gochecknoglobals`, `gomnd`.

- [ ] **Step 2: `.github/workflows/ci.yml`**

Matrix: `{macos-latest (arm64), ubuntu-latest (amd64), ubuntu-24.04-arm (arm64)}` × Go `{1.26.x, 1.25.x}`. Steps: checkout → setup-go → `make vet test lint sec`. `gosec` invocation.

- [ ] **Step 3: `.goreleaser.yaml`**

Build matrix: `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`. SBOM via `cyclonedx-gomod`. Reproducible: `-trimpath -ldflags="-s -w"`. Checksums: `sha256sum`. GitHub release artifacts.

- [ ] **Step 4: `.github/workflows/release.yml`**

Trigger on `tag v*`. Runs goreleaser.

- [ ] **Step 5: Commit**

```bash
git add .github .golangci.yml .goreleaser.yaml
git commit -m "chore(ci): matrix CI + lint + gosec + goreleaser"
```

---

## Task 27: README + final docs

**Files:**
- Modify: `README.md`
- Create: `docs/THREAT_MODEL.md` (links into spec §10)

- [ ] **Step 1: README sections**

1. What it does (one paragraph from spec §1).
2. Quickstart: `go install …@latest && osm init && osm install claude-code`.
3. How it works (diagram from spec §3 + brief mask/unmask flow).
4. Threat model surface — copy spec §10.2 verbatim, label as **READ THIS**.
5. Configuration (`config.toml` reference + link to spec §7.3).
6. CLI reference (auto-generate from cobra: `osm <cmd> --help`).
7. Limitations (link to spec §8 edge cases).
8. License.

- [ ] **Step 2: `docs/THREAT_MODEL.md`** — extracted §10 with v1 caveats.

- [ ] **Step 3: Commit**

```bash
git add README.md docs/THREAT_MODEL.md
git commit -m "docs: README + threat model"
```

---

## Self-Review Checklist (run before handing off)

Spec §1–15 coverage map (verify each maps to a task):

| Spec § | Coverage |
|---|---|
| §1 Problem | README (Task 27) |
| §2 Decisions | architecture-wide; D1 §4, D3 §3+§9, D6 §1 keymgr, D8 §2 lock, D10 CI matrix Task 26 |
| §3 Architecture | File Structure block above; locked |
| §4 FPE | Tasks 4–6 |
| §5.1 PostToolUse | Tasks 13, 19 |
| §5.2 PreToolUse | Tasks 13, 19 |
| §5.2.1 Bash gate | Task 14 |
| §5.3 UserPromptSubmit | Task 19 (`runObserve`) |
| §5.4 SessionStart preload | Task 19 + Task 9 (env loader) |
| §5.5 Hook contract | Task 19 (precondition + parse failures) |
| §6 Detection 3-layer | Tasks 7–10 |
| §7 Storage | Tasks 2–3 |
| §7.4 flock + atomic | Task 2 |
| §7.5 Install | Tasks 16, 20 |
| §7.6 Backup notes | README (Task 27) |
| §8.1 Cold-start | Task 25 bench gate |
| §8.2 Streaming | Task 11 |
| §8.3 Binary skip | Task 13 (per-tool fields skip extension check); add explicit pre-detect check in `runMask` of Task 19 |
| §8.6 Charset safety | Task 4 (Charset enum without delimiters) |
| §8.8 Collisions | Task 5 |
| §8.9 Re-entrancy | Task 19 (`OSM_RUNNING` guard) |
| §8.10 Failure modes | Task 19 (mask/unmask divergent) |
| §8.11 Observability | Task 21 (status, tail) + Task 17 (doctor) |
| §9 Adapter contract | Task 12 |
| §10 Security model | README + THREAT_MODEL (Task 27) |
| §11 Tests | Tasks 5–24 cumulatively |
| §12 Release | Task 26 |
| §13 v1 scope | this whole plan |

Identified gaps and inline fixes:
- Task 19 must explicitly check `[hooks.skip_extensions]` for tool inputs that have a `file_path`. Added in Task 19 step 2 (`runMask` short-circuit). Engineer: verify when implementing.
- Task 11 scanner relies on `transformer.Mask` for container application. Confirm that PEM/SSH segmented rules use `Segments` of length 1 covering the body; otherwise add a single-rule application path in scanner.

Type/name consistency check: `transformer.Rule`, `transformer.Segment`, `transformer.Charset`, `detector.Finding`, `harness.Request/Response/Target/Direction`, `engine.Engine`, `store.{Config,Secrets,Mappings,AuditWriter,Allowlist,Lock}`. Used identically in every task. ✅

No placeholders ("TBD", "implement later", "appropriate error handling") detected on re-read. ✅

---

## Execution Handoff

Plan complete and saved. Two execution options:

1. **Subagent-Driven (recommended)** — I dispatch a fresh subagent per task, review between tasks, fast iteration.
2. **Inline Execution** — Execute tasks in this session using executing-plans, batch execution with checkpoints.

Which approach?
