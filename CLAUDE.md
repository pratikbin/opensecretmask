# opensecretmask — project notes

`osm` is a local CA-MITM proxy that masks secrets in LLM API traffic: secrets
in outbound requests are swapped for format-preserving fakes and restored in
the responses. Real credentials never reach the provider.

## Architecture

| Package | Role |
| --- | --- |
| `cmd/osm` | cobra CLI: `init`, `proxy`, `run`, `add`, `preload`, `status`, `doctor` |
| `internal/crypto` | AES-256-GCM + Argon2id key derivation |
| `internal/store` | encrypted SQLite (`modernc.org/sqlite`, no cgo) |
| `internal/detect` | 48 vendored credential regexes + Shannon entropy |
| `internal/mask` | format-preserving garble, masker, streaming unmasker |
| `internal/proxy` | `goproxy` CA-MITM, route-by-host, request/response masking |
| `internal/dashboard` | embedded htmx + daisyUI web UI: tabbed overview / requests / secrets, per-request debug view |

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
  An empty list or `*` masks every path; Anthropic/OpenAI default to their
  completion endpoints. An out-of-scope path is logged but forwarded unmasked.
- Secret values are encrypted with a passphrase-derived key; the mask is
  stored in plaintext (it is sent to the LLM by design).
- Headers are never masked — the agent's real `Authorization` / `x-api-key`
  is the upstream credential and must pass through.

## `osm init` and privileges

`osm init` creates the state dir, encrypted store, and a local CA, then
**installs that CA into the system trust store** — the only step needing
administrator access:

- macOS: `sudo security add-trusted-cert -d -k /Library/Keychains/System.keychain ca-cert.pem`
- Linux: cert into `/usr/local/share/ca-certificates/` + `sudo update-ca-certificates`

The install is required so intercepted TLS is trusted. `osm init` prints the
exact action and waits 5 seconds for Ctrl-C before running it. `osm init
--no-trust` skips the install (CA file is still written).

## Build, test, lint

Makefile targets (preferred):

```sh
make build   # go build -o osm ./cmd/osm
make test    # go test -race ./...
make lint    # golangci-lint + gosec + govulncheck
make vuln    # govulncheck only
make fix     # go fix ./... + gofmt -w .
make all     # build + test + lint
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
