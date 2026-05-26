# opensecretmask — project notes

`osm` is a local CA-MITM proxy that masks secrets in LLM API traffic: secrets
in outbound requests are swapped for format-preserving fakes and restored in
the responses. Real credentials never reach the provider.

## Architecture

| Package | Role |
| --- | --- |
| `cmd/osm` | cobra CLI: `init`, `uninstall`, `proxy`, `run`, `add`, `preload`, `status`, `doctor`, `shell` |
| `internal/crypto` | AES-256-GCM + Argon2id key derivation |
| `internal/store` | encrypted SQLite (`modernc.org/sqlite`, no cgo) |
| `internal/detect` | pluggable `Provider`s (builtin, llm, cloud, chat, git) + Shannon entropy |
| `internal/mask` | format-preserving garble, masker, streaming unmasker |
| `internal/proxy` | `goproxy` CA-MITM, route-by-host, request/response masking |
| `internal/dashboard` | embedded htmx + daisyUI web UI: tabbed overview / requests / secrets, per-request debug view |
| `internal/shell` | embedded posix-shell init script + rc-file installer; modelled on AikidoSec/safe-chain |

## Key design

- Masking is **byte-level** find-and-replace — provider/dialect agnostic.
  Request bodies are masked whole; responses (JSON + SSE) are unmasked.
- A secret maps to a stable mask via the store, not via cryptographic
  inversion; reversal is a lookup.
- SSE unmasking uses tail-hold buffering so a mask split across stream chunks
  is still caught.
- Registered secrets (`osm add` / `preload`) are the guaranteed exact-match
  layer; regex/entropy detection is best-effort.
- The proxy fails closed — an unmaskable request body is blocked, not sent.
- Masking is scoped per provider to request paths (`Provider.Paths`, regexp).
  An empty list or `*` masks every path — the default for every built-in
  provider. An out-of-scope path is logged but forwarded unmasked.
- Secret values are encrypted with a passphrase-derived key; the mask is
  stored in plaintext (it is sent to the LLM by design).
- Headers are never masked — the agent's real `Authorization` / `x-api-key`
  is the upstream credential and must pass through.
- Detection rules live in `internal/detect/rules_<domain>.go` files
  (`rules_builtin.go`, `rules_llm.go`, `rules_cloud.go`, `rules_chat.go`,
  `rules_git.go`, `rules_devtools.go`). Each declares a `Provider` value
  with no init magic and no external config; `DefaultProviders()` in
  `provider.go` composes them. Adding rules from another source = drop one
  `rules_<name>.go` file + append the provider literal. No allowlists, no
  gitleaks-style anchors — prefix-distinctive regexes only, so detection
  stays stateless across JSON bodies, headers, and bare tokens.

## Future TODO

- **Partial-mask leak in response stream.** Unmasker swaps complete mask
  values back to originals byte-for-byte. When the LLM emits only a
  substring of a mask (e.g. references `wi-cx- prefix` instead of the full
  `wi-cx-q46q4711-2n24-93e6-oy66-5jdev08`), no swap fires and the partial
  mask appears in the user's TUI. Harmless for privacy (the upstream still
  saw only the mask), mild UX wart. Fixing robustly requires partial-prefix
  matching with false-positive guards; not worth chasing until a real
  user-facing complaint surfaces.
- **PII detection provider.** SSN sits in `builtinRules`; a dedicated
  `pii` provider (email, phone, credit-card, address) is the natural shape
  but defaults-off because agent prompts legitimately contain user PII —
  masking by default breaks the assistant.

## `osm init` and trust model

`osm init` creates the state dir, encrypted store, and a local CA. It does
**not** modify the system trust store and needs **no administrator access**.

Trust is per-process: `osm run -- <cmd>` exports `HTTPS_PROXY`,
`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and
`CURL_CA_BUNDLE` only for the child command. Nothing outside that one
process trusts the osm CA. This is the only supported path — `osm run -- claude`
is the recommended entry point.

`osm uninstall` is deprecated (nothing to uninstall). To wipe state:
`rm -rf $OPENSECRETMASK_HOME` or `osm uninstall --purge`.

## Shared proxy daemon

The first `osm run` on a machine spawns a background `osm proxy` daemon
(fork-exec, `setsid`, stdio → `$OPENSECRETMASK_HOME/daemon.log`) and records
its PID and bound addresses in `$OPENSECRETMASK_HOME/proxy.pid`. Subsequent
`osm run` invocations read that pidfile, verify the process is alive and the
TCP port is reachable, and reuse the existing daemon — no second proxy is
spawned. If the daemon has died (host reboot, manual kill, crash), the next
`osm run` cleans the stale pidfile and respawns.

The daemon **outlives the child** and is not reaped on parent exit. Stop it
manually with `kill $(jq -r .pid < $OPENSECRETMASK_HOME/proxy.pid)`; a clean
SIGTERM removes the pidfile so the next `osm run` doesn't see it as healthy.

Concurrency-safe: two simultaneous `osm run` invocations serialize on
`flock(proxy.pid.lock)` during the check-and-spawn window so the loser
reuses what the winner started instead of racing a duplicate daemon.

Passphrase flow: the daemon needs `$OSM_KEY` to unlock the store at startup.
When `osm run` is the spawner, it reads `OSM_KEY` (or prompts once) and
passes it via the spawned process's env. On reuse, no prompt — the daemon
already holds the unlocked store. `osm shell` wrappers must therefore have
`OSM_KEY` exported, or the first invocation must run in a TTY.

Flags `--listen`, `--dashboard`, `--provider`, `--detect-entropy`,
`--log-level` on `osm run` apply **only when spawning**; once a daemon is
running, flag changes on subsequent `osm run` calls are ignored. Restart the
daemon to pick them up.

## Shell integration (`osm shell`)

`osm shell install` makes typing bare `claude`, `codex`, or `pi` transparently
run `osm run -- <cmd>`. It writes one source line to `~/.zshrc` and `~/.bashrc`
(whichever exist) pointing at `$OPENSECRETMASK_HOME/scripts/init-posix.sh`
(embedded via `//go:embed`). The script defines shell functions whose names
shadow the PATH lookup; absence of `osm` on PATH falls through to the bare
command with a yellow `Warning:`. Stderr banner suppressible via `OSM_QUIET=1`.

`osm shell uninstall` strips the source line, with the same safety guards used
by safe-chain (line length cap, no embedded newlines). A one-shot pre-osm
backup is written to `<rc>.osm.bak` and never overwritten on subsequent
installs. `osm shell status` reports per-rc-file state.

Note: codex / pi currently bypass the masking proxy (websocket / non-
`HTTPS_PROXY` transport per `osm tool coverage`). The wrapper is in place
ready for when those transports are intercepted.

## Build, test, lint

Makefile targets (preferred):

```sh
make build             # go build -o osm ./cmd/osm
make test              # unit + race
make test-integration  # testcontainers-driven integration suite (Docker req'd)
make test-e2e          # full e2e in container (Docker + ANTHROPIC_AUTH_TOKEN)
make lint              # golangci-lint + gosec + govulncheck
make vuln              # govulncheck only
make fix               # go fix ./... + gofmt -w .
make all               # build + test + lint
```

Or directly:

```sh
go build ./cmd/osm
go test ./...
golangci-lint run ./... && gosec ./... && govulncheck ./...
```

CI pipeline is in `.github/workflows/ci.yml` (build/test/lint/security jobs + weekly scheduled govulncheck).

- Go toolchain is pinned in `.tool-versions` (asdf).
- `.golangci.yml` uses **golangci-lint v2 schema** with the `modernize` linter enabled.
  Requires golangci-lint v2.6.0+: `go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest`.
- The dashboard CSS (`internal/dashboard/assets/dashboard.css`) is a committed,
  embedded artifact built from `styles.css` with Tailwind v4 + daisyUI.
  Regenerate after editing dashboard templates:
  `cd internal/dashboard && bun install && bun run build`.
- `OPENSECRETMASK_HOME` overrides the state directory and `OSM_KEY` supplies
  the passphrase non-interactively — both are used by the tests.
- Tests cover crypto round-trips, detector rules, mask/unmask round-trips,
  the proxy (real CA-MITM round-trip, JSON + split SSE), the dashboard, and
  the CLI.
- Three test layers, distinct shapes:
  | Layer | Where it runs | Docker | LLM creds | Build tag |
  | --- | --- | --- | --- | --- |
  | Unit / CLI | host process | no | no | none |
  | Integration | testcontainers (Linux) | yes | no | `integration` |
  | E2E | testcontainers (Linux) | yes | yes (ANTHROPIC_AUTH_TOKEN) | `e2e` |
- `tests/integration/run_smoke_test.go` exercises `osm run` end-to-end
  (env-var injection + mask round-trip via `osm run -- curl …`) against
  the in-process mock at `tests/internal/mockupstream`. The mock mints
  its TLS leaf from the osm CA, which the proxy auto-trusts upstream —
  see `docs/THREAT_MODEL.md §3.8` for the rationale.
- `tests/e2e/e2e_test.go::TestE2E_Run_MaskRoundTrip` exercises the same
  flow inside the existing claude-code-bearing e2e container.
