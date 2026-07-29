# Threat model — opensecretmask

`osm` is a local CA-MITM proxy that replaces matched, mask-eligible secrets in
intercepted LLM API request bodies with format-preserving fakes, and restores
complete known fakes in the responses. It is **not** a vault, not an agent
sandbox, and **not an egress firewall**. This document states the boundary it
defends, what it does not defend, and the facts an operator should verify
before relying on it.

If anything in "What osm does NOT defend" is unacceptable for your workload,
do not route that workload through `osm`.

---

## 1. Trust boundary

One local OS user deliberately routes an HTTP client through `osm`, trusts
the local CA for that one process, and wants payload secrets replaced before
a configured LLM provider receives the request body.

- **Trusted**: the local OS user; the filesystem under
  `$OPENSECRETMASK_HOME` (default `~/.opensecretmask`, mode 0700); the `osm`
  binary; the running daemon process and its unlocked in-memory secret store;
  the local CA (`ca.pem` / `ca-key.pem`).
- **Untrusted**: the LLM provider (receives masked bodies only, for matched
  mask-eligible fields); any process not running as the same OS user; the
  network beyond the proxy.

Trust is per-process: `osm run -- <cmd>` exports `HTTPS_PROXY`,
`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and
`CURL_CA_BUNDLE` for the child only (`cmd/osm/run.go`). The system trust
store is never modified.

`osm` does not protect the local user from themselves. Anyone who can read
your home directory or run code as your OS user already has your secrets.

---

## 2. Protected assets and route

- **Assets**: registered secrets (`osm add`, `osm preload` — the guaranteed
  exact-match layer) and best-effort detected secrets (prefix-distinctive
  regexes + optional entropy; `internal/detect/`).
- **Protected route**: proxied HTTP request bodies for exactly configured
  hosts (`proxy.DefaultProviders` + `--provider`) whose paths fall in the
  provider's masking scope (`Provider.Paths`; empty or `*` = every path).
- Masking is byte-level find-and-replace over decoded JSON string leaves,
  with a raw-byte fallback for non-JSON bodies (`internal/mask/`).
- The proxy **fails closed**: an unreadable or unmaskable request body is
  blocked with 502, never forwarded (`internal/proxy/proxy.go` onRequest).

### Response handling

- Buffered, non-SSE responses that used at least one secret are fully
  reversed (512 MiB cap; over-cap → 502).
- SSE responses are reversed streaming with a bounded tail-hold buffer, so a
  mask split across chunks is still caught (`internal/mask/reader.go`,
  `internal/mask/stream.go`).
- If the model emits only a **substring** of a mask, no replacement fires and
  the partial mask appears in the client. The provider still never saw the
  original — this is a restoration UX limitation, not a disclosure
  (`CLAUDE.md` Future TODO).

---

## 3. What osm does NOT defend

### 3.1 Deliberate coverage exclusions

| Exclusion | Why |
|---|---|
| Authentication headers (`Authorization`, `x-api-key`) | The upstream provider needs the real credential. Headers are never masked. Secrets placed in headers for any other purpose are not protected. |
| Provider-owned opaque fields (Anthropic `thinking.signature`, `redacted_thinking.data`) | Restored byte-for-byte after masking so the provider accepts them (`preserveOpaqueBlocks`). A value matched inside them is forwarded — and can be retained in history — in original form. |
| Tunneled hosts | CONNECT to a non-configured host is piped untouched; osm never sees the plaintext (`tunnelConnect`). |
| Out-of-scope request paths | A path outside a provider's `Paths` allowlist is forwarded unmasked (still logged). |
| Non-proxy transports, WebSocket frames | Codex and Pi currently bypass the proxy (`CLAUDE.md` shell-integration note). |
| Data URLs and base64-like payload strings | Intentionally skipped by the detector. |

### 3.2 At-rest facts

| File | Contents | Protection |
|---|---|---|
| `osm.db` | Secret originals: AES-256-GCM with an Argon2id passphrase-derived key. Masks: plaintext (sent to the LLM by design). Request-history bodies: masked bytes, zstd-compressed over 1 KiB. | Protected by the `$OPENSECRETMASK_HOME` directory (mode 0700) denying traversal to other OS users — the database file itself is created at the SQLite driver's default mode (0644) and is not independently hardened. Passphrase never stored. |
| `ca-key.pem` | Local CA private key. | Mode 0600. Reading it = ability to MITM every `osm run` child, but only on this machine as this user. |
| `proxy.pid` | Daemon PID, bound addresses, spawn config. No secrets. | Mode 0600. |
| `daemon.log` | Proxy/dashboard logs. Request metadata only, no bodies. | Mode 0600. |

The passphrase enters the daemon as `$OSM_KEY` (or a one-time TTY prompt at
spawn) and lives in the daemon's memory for its lifetime. The shared daemon
**outlives the wrapped child** and keeps the store unlocked until it is
stopped (`kill $(jq -r .pid < ~/.opensecretmask/proxy.pid)`).

### 3.3 Local debug surface

The dashboard (`--dashboard`, default `127.0.0.1:8788`) is unauthenticated by
design: the trust boundary is the single-developer machine. Its routes list
masked history and secrets, and `/secrets/{id}/reveal` plus
`/requests/{id}/reveal` **decrypt and render plaintext originals**
(`internal/dashboard/dashboard.go`).

Consequences:

- Any local process that can reach the dashboard port can read revealed
  originals. Loopback binding limits this to local processes.
- A malicious web page can attempt DNS rebinding against the loopback
  dashboard. Same-origin policy blocks reading responses cross-origin;
  rebinding defeats it. This residual risk is **accepted** for the
  single-user boundary; do not browse untrusted sites while treating the
  dashboard as sensitive.

### 3.4 Listener exposure

Both listeners default to loopback and non-loopback binds are **rejected at
startup** (`validateListenAddr`, `cmd/osm/listen.go`; IPv4/IPv6 loopback,
wildcard, and hostname cases covered in `cmd/osm/listen_test.go`).

`--allow-external-bind` overrides the guard as an explicit operator choice.
With it:

- the proxy becomes an **unauthenticated general CONNECT proxy** — anyone who
  can reach it can dial arbitrary hosts through your machine;
- the dashboard's plaintext reveal routes are exposed to the network.

Never use the override on a shared or untrusted network. It is persisted in
the pidfile spawn config so respawns and `osm restart` keep the policy.

### 3.5 Local-machine compromise

If an attacker runs code as your OS user, `osm` provides no defense: they can
kill the daemon and proxy themselves, read `osm.db` and brute-force the
passphrase offline, read the CA key, or replace the `osm` binary. `osm`
defends the **wire to the provider**, not the machine.

### 3.6 Detection is best-effort

Regex/entropy detection catches common credential formats but is not a
guarantee; a missed credential is forwarded and stored in history as-is.
Register anything critical with `osm add`.

### 3.7 Memory hygiene

Secret values live in daemon memory (decrypted cache) and briefly in proxy
buffers. No `mlock`, no zero-on-free. A core dump or swap-out exposes them.

---

## 4. Failure modes

| Mode | Behavior |
|---|---|
| Request body unreadable / mask failure | Request blocked with 502 (fail closed). |
| Request body > 512 MiB | Blocked with 413. |
| Buffered response > 512 MiB (masked exchange) | Client gets 502. |
| Daemon dies mid-session | The `osm run` watchdog respawns it on the same address within ~2 s when `$OSM_KEY` is set; otherwise a warning is printed at startup and a manual restart is required. |
| Store locked (wrong/missing passphrase) | Daemon exits at startup; `osm run` reports readiness timeout and points at `daemon.log`. |
| Non-loopback bind requested | Startup failure naming `--allow-external-bind`. |

---

## 5. Out-of-scope summary

- Egress firewalling, agent sandboxing, tool-output scanning.
- Header masking; opaque provider-field masking.
- WebSocket and non-`HTTPS_PROXY` transports.
- Dashboard authentication and cross-request browser defenses.
- Memory hygiene (`mlock`, zero-on-free).
- Defense against a local attacker as the same OS user.
- Detection of encoded (base64/hex/gzip) secrets.

If your threat model includes any of these, `osm` is not sufficient.

---

## 6. Reporting

Security issues: open a private advisory on the GitHub repository, or email
the maintainer listed in `go.mod`. Do not file public issues for exploitable
findings.
