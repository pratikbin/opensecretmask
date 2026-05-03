# Threat model — opensecretmask v1

`osm` is a **leak-prevention layer** between an AI coding agent's tool
invocations and the LLM transcript. It is not a vault, not a sandbox, and
not a substitute for a credential manager. This document enumerates what
the v1 design does and does not defend against, the trust boundary it
assumes, and the side channels you should be aware of before relying on
it for sensitive work.

If anything in §"What v1 does NOT defend" is unacceptable for your use
case, do not use `osm` for that workload.

---

## 1. Trust boundary

The defended boundary runs between **the AI agent (claude-code + LLM)**
and **the local OS user account that runs the agent**.

- **Trusted**: the local OS user, the filesystem under
  `~/.opensecretmask/` (mode 0700), the `osm` binary, and the harness
  config it installed (`~/.claude/settings.json` entries tagged
  `"description": "opensecretmask"`).
- **Untrusted**: the LLM (may emit any string; will be told the mask),
  tool output (may contain attacker-controlled bytes), the conversation
  transcript (sent over the network to Anthropic), and any process not
  running as the same OS user.

`osm` does not protect the local user from themselves. If you are root,
or if a local attacker has read access to your home directory, the
mappings file is plaintext and they have your secrets.

---

## 2. What v1 DOES defend

| Threat | Defense |
|---|---|
| Secret in tool stdout/stderr reaches the LLM transcript | PostToolUse hook stream-scans output and rewrites via `updatedToolOutput` before the harness emits it to the model. |
| LLM emits a real secret it never saw | Masks are HMAC-SHA256(install.key, value)-derived and format-preserving. Without `install.key` AND a candidate plaintext to verify, an attacker cannot reverse a mask. The LLM has neither. |
| LLM uses a known mask in a tool call | PreToolUse unmasks known mask strings in tool input before the tool executes. |
| Concurrent osm processes corrupt state | All writes go through `flock` + tmp-file + atomic `rename`. |
| Audit log becomes a secondary credential leak | Audit log is NDJSON and stores `{rule_id, mask_truncated_to_12_chars, ts, op}`. Real values never enter the audit log. |
| Hook crash silently passes plaintext through | Mask path is **fail-closed** (`mask_on_error = "deny"` default → harness blocks the turn or `redact-all` zeroes the output). Unmask path is fail-open by design — the tool gets the mask and fails loudly rather than blocking the user. |
| Tool output silently truncated past `max_scan_bytes` | Scanner enforces `on_scan_cap = "truncate"` (default): bytes past the cap are replaced, never silently emitted. |
| Multi-line containers (PEM, SSH key) flushed mid-scan | Container-aware streaming: when an open BEGIN marker is seen without its END, emission is suspended until the close marker arrives or `max_container_bytes` is hit (fail-closed). |

### 2.1 HMAC preimage resistance

Masks are derived as `HKDF-Expand(HMAC-SHA256(install.key, value),
charset_class)`. Given only a mask:

- **Without `install.key`**: reversal requires brute-forcing the keyed
  HMAC, which is computationally infeasible.
- **With `install.key` but no candidate plaintext**: still infeasible —
  HMAC has no inverse; you need a guessing oracle (the candidate set).
- **With `install.key` AND a candidate set** (e.g. you know the secret
  is one of a known list of API tokens): yes, you can verify which one.
  This is intrinsic to deterministic masking and is the cost we pay for
  PreToolUse round-tripping. If you need indistinguishability, do not
  use `osm`.

---

## 3. What v1 does NOT defend

### 3.1 Plaintext at rest

`~/.opensecretmask/secrets.json` (registered rules) and
`~/.opensecretmask/mappings.json` (mask ↔ real lookup) store real values
**in plaintext**. They are protected only by:

- File mode `0600` (owner read/write only).
- Directory mode `0700` (owner enter/list only).
- `osm doctor` refuses to operate if the directory is group- or
  world-readable, and auto-repairs modes on drift.

`install.key` is **not** required to read these files. Anyone who can
`cat ~/.opensecretmask/mappings.json` has every secret you've ever
masked. This is a deliberate v1 simplification — at-rest encryption is
on the v1.1 roadmap (optional keychain-backed vault). For real vaulting
today, use `psst`, `1Password`, or your platform keyring.

**Implication**: `mappings.json` is a forward+reverse map. Possession of
this file is equivalent to possession of all secrets.

### 3.2 Subagent isolation (important)

claude-code subagents share the parent's filesystem. A secret registered
in the parent session is written to `~/.opensecretmask/mappings.json`
**before** any subagent is spawned, and the subagent's hook reads the
same `mappings.json`. Consequences:

- **Masking**: a subagent's tool output is masked using the parent's
  rules — good.
- **Unmasking**: a subagent's tool input has known masks substituted
  back to real values — same as the parent.
- **Persistence beyond the session**: secrets registered in any session
  persist to disk and are visible to every later session of the same OS
  user, including subagents you fire-and-forget. There is no
  per-session or per-subagent scoping in v1.

If a subagent is given a tool that prints `mappings.json` (e.g. `cat`,
`Read`), it will see real values. The PostToolUse hook **does** scan
that output and mask the real values back into masks before the LLM
sees them, but the subagent's local tool received plaintext. Any
network-egressing tool inside a subagent (e.g. `curl` to a third-party
service, an MCP server with outbound access) bypasses the LLM entirely
and can exfiltrate real values directly.

### 3.3 Side channels

| Channel | Risk | Status |
|---|---|---|
| **Mask length / format** | The mask preserves the source secret's length and charset class. An attacker observing the transcript learns "this is a 40-char hex string" — i.e., the secret's shape. | Documented tradeoff. Format preservation is required for PreToolUse round-tripping when the LLM uses the mask in a context that validates length/charset (e.g. a SDK that checks API key shape). |
| **Audit log content** | Truncated to 12 chars of mask + rule ID. With low entropy in a small `mappings.json`, an attacker with the audit log alone can correlate masks across sessions but cannot recover plaintext. With both `mappings.json` and the audit log they have plaintext (but they had it from `mappings.json` anyway). | Acceptable for v1. Tamper-evident chain (`prev_hash`) is a v1.1 design hook, not implemented. |
| **Timing of mask vs. unmask** | An external observer who can measure hook latency might infer whether a given input contained a known mask. This is not a remote attack vector for the LLM (which has no clock) and is bounded by `lock_timeout_ms`. | Out of scope. |
| **Stderr from the hook itself** | Hook never writes real values to stderr. Only `{rule_id, mask_truncated}` plus structural errors. | Verified by tests in `internal/core/store/audit_test.go`. |
| **Process listing / `ps`** | `osm hook` reads input from stdin, never argv. Real values never appear in argv. | By design. |
| **Swap / core dumps** | Real values are held in process memory while masking. v1 does not `mlock` or zero buffers on free. A core dump or swap-out exposes recent values. | Documented tradeoff; v1.1 may add `mlockall` on Linux. |

### 3.4 Encoded and split secrets

- Base64, hex, gzip-encoded, or otherwise transformed secrets are **not
  detected** by v1. The detector is plaintext-only. v1.1 plan: optional
  decode-and-scan pass.
- A secret split across two tool invocations is **not detected**. Each
  invocation is scanned in isolation; there is no cross-invocation
  correlation in v1.

### 3.5 Pre-existing conversation history

`osm install` only affects future tool calls. Any secret that landed in
the transcript before `osm install` ran is already in the conversation
and on Anthropic's servers. `osm` cannot rewrite history.

### 3.6 Prompt content

claude-code's `UserPromptSubmit` hook cannot rewrite prompt content. If
the user pastes a raw secret into a prompt, `osm` can warn (when
`warn_on_prompt = true`) but cannot scrub. The secret will reach the
LLM.

### 3.7 Local-machine compromise

If an attacker has code execution as the same OS user, `osm` provides
no defense. They can:

- Read `mappings.json` and `secrets.json` directly (plaintext).
- Read `install.key` and forge any mask they like.
- Disable hooks by editing `~/.claude/settings.json`.
- Replace the `osm` binary on `$PATH`.

`osm` defends the **transcript**, not the machine. Treat it accordingly.

### 3.8 Rogue tools and MCP servers

Hooks see what reaches the LLM. They do not see what a local tool does
over the network. A malicious or compromised MCP server, CLI, or shell
function can read secrets from environment variables, files, or its own
arguments and POST them to an attacker — `osm` is not in that path. Use
OS-level controls (network egress filters, container isolation,
read-only mounts) for that threat model.

---

## 4. Failure modes

| Mode | Behavior |
|---|---|
| `install.key` missing or unreadable | `osm doctor` fails loudly. Hook fails closed (mask path → deny). |
| `mappings.json` corrupt | `osm doctor` reports; hook fails closed on mask, fail-open on unmask (tool gets the literal mask string and fails on its own). |
| `flock` timeout | After `lock_timeout_ms` the hook returns the configured error policy. Default mask-deny / unmask-passthrough. |
| `max_scan_bytes` exceeded | `on_scan_cap = "truncate"` replaces the tail with a marker; `"deny"` blocks the turn. Never silent passthrough. |
| Open container marker without close before `max_container_bytes` | Fail-closed: container body is not flushed. |
| Hook binary missing on `$PATH` | Harness reports a hook error; turn is blocked or proceeds depending on harness behavior. `osm install` writes absolute paths when `--absolute` is set. |

---

## 5. Out-of-scope summary

For quick reference, the following are explicitly out of scope for v1:

- At-rest encryption of `secrets.json` / `mappings.json`.
- Per-session or per-subagent secret scoping.
- Encoded-secret detection (base64, hex, gzip, …).
- Cross-invocation secret correlation.
- Prompt-content rewriting.
- Tamper-evident audit log chaining.
- Memory hygiene (`mlock`, zero-on-free).
- Network egress control.
- Defense against a local attacker as the same OS user.

If your threat model includes any of these, `osm` is not sufficient.

---

## 6. Reporting

Security issues: open a private advisory on the GitHub repository, or
email the maintainer listed in `go.mod`. Do not file public issues for
exploitable findings.
