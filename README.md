# opensecretmask

`osm` is a Go credential-masking hook binary for AI coding agents. It sits between
your shell tools and the LLM: secrets in tool output are replaced with
format-preserving masks before the model sees them, and the model's own emissions
that contain known masks are reversed before they hit `bash`, `Edit`, or `Write`.
The goal is narrow — keep plaintext credentials out of the conversation
transcript and out of files written by the agent — without touching how you store
secrets at rest. This is a **leak-prevention layer**, not a vault.

> **Read the [Threat Model](docs/THREAT_MODEL.md) before relying on this for
> anything sensitive.** v1 trades at-rest encryption for simplicity.

## Quickstart

Install:

```bash
go install github.com/pratikbin/opensecretmask/cmd/osm@latest
# or build from source:
git clone https://github.com/pratikbin/opensecretmask
cd opensecretmask && make build && ./bin/osm version
```

Initialize the per-user state directory `~/.opensecretmask/` (mode 0700,
generates `install.key`, writes default `config.toml`, creates empty
`secrets.json` / `mappings.json` / `audit.log`):

```bash
osm init
osm doctor          # verify file modes, key presence, config validity
```

Wire the claude-code hooks into `~/.claude/settings.json` (idempotent;
re-runnable; preserves unrelated entries):

```bash
osm install claude-code
osm install claude-code --dry-run    # preview without writing
```

Add a known secret manually (useful when env-file detection misses one):

```bash
osm add MY_TOKEN ghp_realvalueXXXXXXXXXXXXXXXXXXXXXXXX
osm status          # show registered rules + mapping count
osm tail            # follow the audit log
```

Uninstall:

```bash
osm uninstall claude-code   # removes only osm-tagged hook entries
```

## How it works

```
            +-----------------+
  tool ---> |  osm hook       | --(masked output)--> claude-code --> LLM
            |  PostToolUse    |
            +-----------------+

            +-----------------+
   LLM ---> |  osm hook       | --(unmasked input)--> tool
            |  PreToolUse     |
            +-----------------+
```

- **PostToolUse**: stream-scans tool output, runs detectors (env-file rules,
  patterns, optional entropy), HMACs each detected secret with `install.key`,
  derives a format-preserving mask of the same length and charset class, and
  rewrites the output via `updatedToolOutput`.
- **PreToolUse**: parses tool input, looks up known mask strings in
  `mappings.json`, substitutes the real values back, and forwards the
  unmasked input to the tool.
- **Storage**: `~/.opensecretmask/secrets.json` (registered rules),
  `mappings.json` (mask ↔ real lookup, used at unmask time), `config.toml`,
  `install.key` (32 bytes, HMAC key), `audit.log` (NDJSON, never logs real
  values — only truncated mask + rule ID).
- **Concurrency**: `flock` + tmp-file + atomic `rename` for every write.

Architecture detail and the canonical request/response envelope are in
[design spec §3](docs/superpowers/specs/2026-05-02-opensecretmask-design.md#3-architecture-overview).

## Threat model

**READ THIS BEFORE USE.** Full document: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).

What `osm` does defend:

- Secrets in tool output reaching the LLM via PostToolUse rewrite.
- LLM emitting a real secret it never saw — masks are HMAC-derived; without
  `install.key` the LLM cannot derive a real value from a mask alone.
- Concurrent sessions corrupting state (flock + atomic rename).
- Audit log becoming a credential dump (truncated mask + rule ID only).

What `osm` does NOT defend (v1):

- **Plaintext at rest.** `secrets.json` and `mappings.json` store real values
  in plaintext, protected only by mode 0600 + dir 0700. Anyone with read
  access to `~/.opensecretmask/` reads the secrets directly. Use `psst` or
  1Password for true vaulting.
- Secrets already in conversation history before `osm install` ran.
- Encoded secrets (base64, hex, gzip) — v1 is plaintext-only detection.
- Secret split across two tool invocations.
- Local-machine compromise.
- User pasting a raw secret in a prompt (claude-code's `UserPromptSubmit`
  cannot rewrite prompt content; warn-only).

## Configuration

`~/.opensecretmask/config.toml`. Full schema with defaults and field
semantics is in
[design spec §7.3](docs/superpowers/specs/2026-05-02-opensecretmask-design.md#73-configtoml-schema-full).
Highlights:

- `[detector]` — env-file detection, optional entropy, allowlist.
- `[hooks]` — direction-aware failure policy (`mask_on_error = "deny"`,
  `unmask_on_error = "passthrough"`), `lock_timeout_ms`, `max_scan_bytes`.
- `[hooks.skip_extensions]` — skip binary file types entirely.
- `[harness.claudecode]` — matchers, `warn_on_prompt`.
- `[audit]` — `truncate_mask_to`, rotation size.

## CLI

| Command | Description |
|---|---|
| `osm init` | Create `~/.opensecretmask/`, generate `install.key`, write default config. |
| `osm doctor` | Check file modes, key presence, config validity; auto-repair to 600/700. |
| `osm scan [path]` | Scan a path or stdin for secrets without modifying state. |
| `osm hook --harness=<name> <event>` | Internal: invoked by harness hooks (PostToolUse, PreToolUse, UserPromptSubmit, SessionStart). |
| `osm install <harness>` | Install harness hook entries. `--dry-run` previews. |
| `osm uninstall <harness>` | Remove only `osm`-tagged hook entries. |
| `osm add <name> <value>` | Register a known secret manually. |
| `osm allow <value>` | Add a literal value to the detector allowlist. |
| `osm status` | Print registered rules, mapping count, config summary. |
| `osm tail` | Follow `audit.log` (NDJSON). |
| `osm version` | Print build version. |

## Limitations

v1 explicitly excludes container detection beyond a fixed adaptive overlap,
encoded-secret detection (base64/hex/gzip), prompt-content rewriting,
at-rest encryption, and tamper-evident audit chaining. Edge cases and
performance bounds are documented in
[design spec §8](docs/superpowers/specs/2026-05-02-opensecretmask-design.md#8-edge-cases--performance).

## Development

```bash
make build          # ./bin/osm
make test           # go test -race -count=1 ./...
go vet ./...
golangci-lint run   # CI runs this; local optional
```

CI (`.github/workflows/ci.yml`) runs vet, race-tests, build, lint, and
gosec on Linux + macOS across Go 1.25.x and 1.26.x. Releases are cut by
goreleaser on `v*` tags (`.github/workflows/release.yml`,
`.goreleaser.yaml`).

## License

MIT.
