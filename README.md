# opensecretmask

`osm` is a local CA-MITM proxy that keeps secrets out of LLM API traffic.
It sits between your AI tools (Claude Code, the OpenAI SDK, …) and the
provider. On the way out it swaps every secret for a **format-preserving
fake**; on the way back it restores the original. The provider only ever
sees the fake — your real keys never leave the machine.

```
  AI tool ──HTTPS──▶  osm proxy  ──HTTPS──▶  api.anthropic.com
                      │ mask request body     (sees only fakes)
                      │ unmask JSON / SSE
  AI tool ◀─HTTPS───  osm proxy  ◀─HTTPS───  api.anthropic.com
```

A secret like `sk-ant-api03-REALKEY…` becomes `sk-ant-api03-9fX2qLm…` — same
prefix, same length, same character classes — so the model treats it exactly
like a real credential. The mapping is kept, encrypted, in a local SQLite
database; restoring the original on the response is a lookup.

## Install

```sh
go install github.com/pratikbin/opensecretmask/cmd/osm@latest
# or from source:
git clone https://github.com/pratikbin/opensecretmask
cd opensecretmask && go build -o osm ./cmd/osm
```

## Quickstart

```sh
osm init                            # state dir, local CA (installed), passphrase
osm add OPENAI_KEY=sk-proj-…         # register a secret to mask
osm preload                         # …or scan .env files in the current directory
osm proxy                           # run the proxy + dashboard
```

Then point your tools at the proxy (`osm init` prints these with real paths):

```sh
export HTTPS_PROXY=http://127.0.0.1:8787
export NODE_EXTRA_CA_CERTS=~/.opensecretmask/ca-cert.pem   # Claude Code / Node tools
export SSL_CERT_FILE=~/.opensecretmask/ca-cert.pem         # some Python / Go tools
```

Or skip both the exports **and** `osm proxy` — `osm run` is self-contained.

Or install shell integration once and just type the bare command:

```sh
osm shell install         # wires ~/.zshrc and ~/.bashrc (write-once .osm.bak backup)
claude                    # auto-runs `osm run -- claude`
```

Wrapped tools: `claude`, `codex`, `pi`. Suppress the per-invocation banner
with `OSM_QUIET=1`. Remove with `osm shell uninstall`.
It reuses a running `osm proxy` if one is up, otherwise starts its own
proxy and dashboard on ephemeral ports for just that command and tears
them down on exit. The per-process env vars make Node, Python, and curl
trust the CA even without the system trust install:

```sh
osm run -- claude          # spawns a proxy, routes claude through it
osm run -- codex
```

## What `osm init` does

`osm init` is one-time setup and needs **no administrator access**:

1. Creates the state directory `~/.opensecretmask/` (mode `0700`).
2. Prompts for a passphrase and creates the encrypted SQLite store. The
   passphrase is never written to disk.
3. Generates a local root CA — `ca-cert.pem` and `ca-key.pem` (mode `0600`).

osm does **not** install the CA into your system trust store. Trust is
per-process: `osm run -- <cmd>` exports `NODE_EXTRA_CA_CERTS`,
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, and
`HTTPS_PROXY` only for the child command, so nothing outside that one
process is affected. This is the recommended way to use osm.

## How it works

- **Interception** — `osm` is an HTTPS proxy with its own local CA.
  `osm run` exports proxy and CA-trust env vars for one child command so
  that command trusts the intercepted TLS; nothing else on the system
  changes. Only configured LLM hosts are intercepted; all other traffic
  is tunnelled untouched.
- **Detection** — request bodies are scanned with 45 vendored credential
  patterns (from [pipelock](https://github.com/luckyPipewrench/pipelock),
  Apache-2.0) plus your registered secrets. An optional Shannon-entropy pass
  (`osm proxy --detect-entropy`) catches unknown high-entropy tokens.
- **Masking** — each secret is replaced by a random, same-shape fake. The
  same secret always maps to the same fake, so the model sees something
  stable and credential-shaped.
- **Unmasking** — JSON responses and SSE token streams are scanned for known
  fakes and reversed. Streaming uses tail-hold buffering, so a fake split
  across two stream chunks is still caught.
- **Storage** — secret values are encrypted with AES-256-GCM; the key is
  derived from your passphrase with Argon2id. The passphrase is never stored.

## Commands

| command | purpose |
| --- | --- |
| `osm init` | create the state directory, CA, and encrypted store |
| `osm uninstall` | _deprecated_ — osm installs nothing system-wide; use `rm -rf ~/.opensecretmask` or `osm uninstall --purge` |
| `osm proxy` | run the masking proxy and dashboard |
| `osm run -- command [args]` | run a command routed through the proxy |
| `osm add NAME=VALUE` | register a secret to mask |
| `osm preload [dir]` | register every value found in `.env` files |
| `osm status` | show stored secrets and proxy activity |
| `osm doctor` | check the installation |
| `osm shell install` | wrap `claude`/`codex`/`pi` so the bare command runs through `osm run` |
| `osm shell uninstall` | remove the source line from `~/.zshrc` / `~/.bashrc` |
| `osm shell status` | report shell integration state per rc file |

`osm proxy` intercepts the major LLM provider API hosts by default —
Anthropic, OpenAI, Google Gemini/Vertex, xAI, Mistral, Cohere, Perplexity,
DeepSeek, Groq, Together, Fireworks, OpenRouter, HuggingFace and more (35
hosts). Add others with `--provider api.example.com=openai` (repeatable).
Cloud platforms with per-resource hostnames (Azure OpenAI, AWS Bedrock,
watsonx, Databricks, OCI) are not matched by default — add them explicitly.

**Path scoping.** Each provider can restrict masking to specific request
paths via `Provider.Paths` (regexp list). An empty list or `"*"` masks every
path — the safe default. Anthropic and OpenAI currently scope to their
completion endpoints (`/v1/messages`, `/v1/chat/completions`, etc.) because
those are the only paths observed to carry secrets; their telemetry/event-log
endpoints are forwarded unmasked. All other hosts mask every path. Out-of-scope
requests are still intercepted and logged (dashboard shows `masked=0`) so you
can spot unexpected secrets and switch a host back to `"*"` if needed.

## Dashboard

`osm proxy` serves a dashboard at `http://127.0.0.1:8788`: live request
history, the secret store, and per-secret reveal-on-click. Secrets are shown
masked — the plaintext is decrypted only when you explicitly reveal it.

## Security model

- **Registered secrets** (`osm add`, `osm preload`) are matched exactly and
  are the **guaranteed** layer — they are always masked.
- **Pattern / entropy detection** is best-effort: it catches common
  credential formats but is not a guarantee. Register anything critical.
- The proxy **fails closed** — if a request body cannot be masked, the
  request is blocked rather than forwarded.
- The local CA private key lives at `~/.opensecretmask/ca-key.pem` (mode
  `0600`). Anything that can read it could intercept your HTTPS traffic;
  treat it like any other private key.
- `osm` binds to loopback only. The dashboard can reveal decrypted secrets —
  keep it loopback-only.

## Limitations

- v1 matches secrets as raw bytes; a secret the client JSON-escapes (quotes,
  backslashes) may be missed. Provider API keys are escape-safe.
- The dashboard has no authentication beyond the loopback bind.

## Development

```sh
make build             # go build -o osm ./cmd/osm
make test              # unit + race
make test-integration  # testcontainers integration suite (Docker required)
make test-e2e          # full e2e (Docker + ANTHROPIC_AUTH_TOKEN required)
make lint              # golangci-lint + gosec + govulncheck
make all               # build + test + lint
```

Test layers:

| Layer | Runs in | Docker | LLM creds |
| --- | --- | --- | --- |
| Unit | host process | no | no |
| Integration | Linux container (built from `tests/integration/Dockerfile`) | yes | no |
| E2E | Linux container with claude-code | yes | yes (`ANTHROPIC_AUTH_TOKEN`) |

The integration suite uses an in-process mock LLM
(`tests/internal/mockupstream`) whose TLS leaf is signed by the osm CA;
the proxy auto-trusts its own CA upstream, so the mock round-trip works
without any extra wiring. See `docs/THREAT_MODEL.md §3.8` for why that
auto-trust is safe.

Or directly:

```sh
go build ./cmd/osm
go test ./...
golangci-lint run ./... && gosec ./... && govulncheck ./...
```
