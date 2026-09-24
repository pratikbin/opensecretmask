# osm

**Keep your API keys out of the model, without breaking what the model can do.**

A [Claude Code](https://claude.com/claude-code) plugin. It swaps every secret
for a format-preserving fake before Claude reads it, and puts the real value
back on the way into a tool call.

![Installing osm, then watching Claude read a credential file and report a fake](.github/assets/osm-demo.gif)

A real session, not a mock-up: the plugin is installed, a file holding
`sk-ant-api03-Kv8Tz2…` is written and `cat`-ed, and the model answers with a
*different* 74-character key of the same shape. `/osm-secrets` prints the pair.
Recorded by [`scripts/record-demo.sh`](scripts/record-demo.sh).

```mermaid
flowchart LR
    ENV["<b>.env</b> / tool output<br/>sk-ant-api03-Kv8Tz2…"]
    MASK["<b>mask</b>"]
    MODEL["<b>Claude</b><br/>sk-ant-bpc23-VpONd6…"]
    REST["<b>restore</b>"]
    SHELL["<b>your shell</b><br/>sk-ant-api03-Kv8Tz2…"]
    VAULT[("vault<br/>fake ⇄ real")]

    ENV --> MASK --> MODEL --> REST --> SHELL
    MASK -.-> VAULT
    VAULT -.-> REST

    classDef real fill:#1f6f43,stroke:#2ea16a,color:#fff
    classDef fake fill:#7a4b16,stroke:#c98a3a,color:#fff
    class ENV,SHELL real
    class MODEL fake
```

## Why a fake and not `[REDACTED]`

A fake keeps the vendor prefix, the length and the character classes of the
real value: `sk-ant-api03-Xk9…` becomes `sk-ant-nvd59-RAT…`.

`[REDACTED]` tells the model something is *missing* — it stops treating the
value as an Anthropic key and starts treating it as a hole. A same-shaped fake
preserves the plan, so the model writes the command it would have written
anyway. This is the whole point of the project.

## Install

Needs Claude Code **2.1.272+**. Function hooks are early-access, so the flag is
required.

```sh
claude plugin marketplace add pratikbin/opensecretmask
claude plugin install osm@opensecretmask

CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude
```

<details>
<summary>Running from a clone (for working on the plugin itself)</summary>

```sh
git clone https://github.com/pratikbin/opensecretmask ~/.claude/osm
cd ~/your-project
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir ~/.claude/osm
```

`--plugin-dir` takes the directory holding `.claude-plugin/plugin.json`. The
plugin key becomes `osm@inline`, which keeps its own settings and store file.

</details>

## What you see

A masking plugin is otherwise silent, so it reports three things.

**At session start** — what is watched, and what is off:

```
osm: masking (2 secrets from .env, .env.local, 146 rules, entropy on)
```

**Pinned under the prompt** — the round trip actually closing. `masked` counts
values swapped on the way to the model, `restored` counts fakes swapped back on
the way into a tool. Before anything is found it reads `osm: watching`.

```
osm: 3 secrets · 12 masked · 4 restored
```

**`/osm-secrets`** — every secret this session, beside the fake it wears:

```
osm: 3 secrets this session (real → fake)
1. sk-ant-api•••i05rP (53) → sk-ant-loz•••kG8uT (53)  Anthropic API Key · Bash  (3m ago)
2. ghp_1a2B3c•••VwXyZ (40) → ghn_6b0H6u•••NqZeA (40)  GitHub PAT · /repo/.env:GH_TOKEN  (1h ago)
3. -----BEGIN•••Y----- (72) → -----BEGIN•••K----- (72)  Private Key · Read  (2d ago)
```

Each value keeps its ends and states its true length — enough to match a row
against your `.env` without printing the credential. Then the rule, then the
origin: a tool name, or `file:key` for a session-start registration.

> **The model never receives this list** — it goes out through the engine's
> user-only log channel. It *is* on your screen and in the debug log, so treat
> a shared terminal recording accordingly.

## How it works

Claude Code exposes function hooks at each boundary where text moves between
you, the model and the outside world. `osm` sits on ten of them.

```mermaid
flowchart LR
    TOOLS["Read · Bash · Grep<br/>WebFetch · Write · MCP"] -->|tool.call ↑| MODEL
    PROMPT["what you type"] -->|prompt.submit| MODEL
    CTX["CLAUDE.md · memory"] -->|prompt.context<br/>prompt.section| MODEL
    DISK["skill bodies"] -->|skill.prompt| MODEL
    RELAY["relay · peer<br/>Remote Control"] -->|session.receive| MODEL
    PAST["the transcript"] -->|session.compact| MODEL

    MODEL(["Claude<br/><i>sees fakes only</i>"])

    MODEL -->|tool.call ↓<br/><b>restore</b>| OUT["your shell<br/>the real value"]
    MODEL -->|agent.spawn<br/><b>stays fake</b>| SUB(["subagent"])

    ENVF[".env at startup"] -.->|session.start| V[("vault")]

    classDef m fill:#7a4b16,stroke:#c98a3a,color:#fff
    classDef r fill:#1f6f43,stroke:#2ea16a,color:#fff
    class MODEL,SUB m
    class OUT r
```

| Hook | Direction | Action |
| --- | --- | --- |
| `session.start` | — | Registers credentials from the session's `.env` files |
| `tool.call` ↑ | world → model | Masks `result`, `text` and `context` |
| `tool.call` ↓ | model → world | Restores fakes in tool arguments |
| `prompt.submit` | you → model | Masks the prompt you typed |
| `prompt.context` | files → model | Masks `claudeMd`, where instruction files land |
| `prompt.section` | memory → model | Masks `memory` and the other sections |
| `skill.prompt` | disk → model | Masks a skill's expanded prompt |
| `session.receive` | outside → model | Masks a relay, peer or Remote Control delivery |
| `session.compact` | transcript → model | Masks what the summarizer reads at `/compact` |
| `agent.spawn` | model → model | Masks the task text handed to a subagent |

One `tool.call` registration covers Read, Bash, Grep, WebFetch, Write, the
Agent tool and every MCP tool — it matches the event, not a list of tool names.

**A value another model reads is not an external boundary.** Restoring is for a
`Bash` command or a `Write`, never for a subagent's task text. Two layers hold
that line: `agent.spawn` masks every subagent dispatch whatever tool triggered
it, and `policy/model-facing.ts` keeps the real value out of the Agent tool's
recorded arguments on the way there.

## What it detects

Two layers, different on purpose.

**Registered secrets — exact match.** At `session.start` the plugin reads the
session's `.env` files. A value qualifies on its *name* (`*_KEY`, `*_TOKEN`,
`*_PASSWORD`, …) or on its shape. So a credential with a dull name is caught,
`PORT=3000` stays readable, and shapeless values like
`DB_PASSWORD=zezyhd4-esvgwsw-islmz` are covered.

**Detection rules — best effort.** 146 patterns in six groups under
`hooks/detect/rules/`, covering about 96 vendors. No allowlists, no anchors, so
a rule behaves the same in a JSON body, in file contents and in a bare token.

Most rules are gated on a literal vendor prefix (`sk-ant-`, `ghp_`). Thirteen
are shape or context rules, and those cover far more ground than a vendor count
suggests:

| Shape | Example |
| --- | --- |
| Credential in a URL | `postgres://user:PASS@host` |
| Auth header | `Authorization: Bearer …` |
| Assignment | `DD_API_KEY=…`, `aws_secret_access_key = "…"` |
| Private key block | PEM or PGP, the whole block |
| JWT | a signed `eyJ…` token |

A context rule masks only its capture group, and that group is checked before
it is trusted — quotes and commas trimmed, and anything that merely *names* a
credential dropped: `${DB_PASSWORD}`, `$ANTHROPIC_API_KEY`, `<your-key-here>`,
`[MASKED-0001]`, `changeme`, a bare UUID, a regex source. Plain hex and digit
runs are deliberately **not** dropped — under an explicit credential name they
are usually the real key.

A value caught once is remembered, so a secret first matched by a context rule
is masked later when it appears on its own.

Adding a rule is one line in one file — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Configuration

`/config` inside Claude Code, or `settings.json` under `pluginConfigs`. The
plugin key is `osm`, or `osm@inline` under `--plugin-dir`.

| Option | Default | What it does |
| --- | --- | --- |
| `entropy` | `false` | Shannon-entropy layer for tokens no pattern matches |
| `entropyThreshold` | `4` | Bits per character above which a string counts as random |
| `entropyMinLen` | `24` | Shortest string the entropy layer considers |
| `envFiles` | `.env`, `.env.local` | Files the exact-match layer reads at session start |
| `persist` | `true` | Carries the map across a resume, a fork or `/reload-plugins` |
| `retentionDays` | `120` | How long a stored **literal** secret survives |

<details>
<summary>The same thing as JSON</summary>

```json
{
  "pluginConfigs": {
    "osm": {
      "options": {
        "entropy": false,
        "entropyThreshold": 4.0,
        "entropyMinLen": 24,
        "envFiles": [".env", ".env.local"],
        "persist": true,
        "retentionDays": 120
      }
    }
  }
}
```

Defaults are declared in `.claude-plugin/plugin.json` and mirrored in
`hooks/options.ts`; a check asserts the two agree, because for a while they did
not and `persist` behaved one way in development and another once installed.

</details>

**On `entropy`:** it catches vendors with no rule — an Atlassian token, an
Azure storage key — and costs precision, since it will mask a long
random-looking path inside an ordinary URL. It runs behind
`hooks/detect/suppress.ts`, which keeps git SHAs, UUIDs, digit runs and public
object ids (Stripe `pk_`, YouTube channel ids) out of the results unless a
credential name sits immediately to their left. Turn it on when you would
rather over-mask than miss something.

## Where your secrets live

**By default, `osm` stores nothing.** The map is a `Map` in memory, for one load
of the plugin. Your real secrets stay where they already were.

```mermaid
stateDiagram-v2
    [*] --> Live: session starts
    Live: vault in memory<br/>fake ⇄ real
    Live --> Live: /clear · /compact (kept)
    Live --> Dead: reload · fork · --resume
    Dead: new empty vault<br/>old fakes no longer restore
    Dead --> Live: persist true → restores from $.store
    Dead --> [*]: persist false
```

"Old fakes no longer restore" means the model writes a stale fake into a tool
call, the hook does not recognise it, and the tool receives the fake. The
command fails against an invalid credential — safe for privacy, wrong for
usability. That is what `persist` fixes.

Three places hold a real credential. Only the first two are the plugin's.

**1. The vault, in memory.** `hooks/vault/index.ts`. Two maps. No file, no
keychain, no network, no encryption — nothing at rest to encrypt.

**2. The store, only when `persist` is on.** Plain JSON at
`~/.claude/plugins/store/osm_<key>-<hash>.json`, mode `644` in a `755`
directory; 497 bytes for two entries.

| Kind | Stored | Expires |
| --- | --- | --- |
| `env` | the fake plus a pointer to `{file, key}` | never — the source is re-read |
| `literal` | the fake **and the secret** | after `retentionDays` |

A `.env` secret is already on disk, so a pointer puts nothing new at rest. A
secret first seen in tool output exists nowhere else — restoring it later means
storing the value. That is the only kind that creates new exposure, and the
only kind `retentionDays` applies to.

> **The file is world-readable and the plugin cannot change that.** `$.fs` has
> no chmod and the engine writes mode `644`. Tighten the directories instead.

**3. The session transcript, which the engine owns.**
`~/.claude/projects/<slug>/<session-id>.jsonl`, mode `600`. Mostly fakes, since
that is what the model saw. Two record types still carry the real value, both
confirmed by grepping this project's own test transcripts:

- `attachment` / `hook_success` — a classic hook's stdout, verbatim. A
  `PreToolUse` hook that echoes what it rewrote lands the credential here.
- `queue-operation` / `enqueue` — your prompt as typed, written *before*
  `prompt.submit` runs. The model gets the fake; the disk keeps what you typed.

## Hardening on a Mac

In order of how much they buy you.

```sh
# 1. Tighten the directories — durable; the engine resets file modes, not these
chmod 700 ~/.claude ~/.claude/projects ~/.claude/plugins/store

# 2. Keep transcripts out of backups you do not control
tmutil addexclusion ~/.claude/projects

# 3. Deleting the store is safe at any time — .env entries rebuild, the rest re-mint
rm -f ~/.claude/plugins/store/osm_*.json
```

**Turn `persist` off** if you want nothing of the plugin's own on disk. It ships
on because a map that dies with the plugin load breaks `--resume`, a fork and
`/reload-plugins`, and the usual entry is env-backed and stores no secret.

**Turn on FileVault** — it protects `~/.claude` when the Mac is off or stolen,
and does nothing while you are logged in, which is what the directory modes
above are for.

**Rotate what has already been in a transcript.** No file mode retroactively
protects a credential that sat in a `.jsonl` on a shared or backed-up disk.

## Limits and non-goals

The threat model is a careless leak, not an attacker with code execution on
your machine.

**Does not protect against**

- **A tool run with the real credential.** Restoring is the feature. If Claude
  writes a command that ships the value to a third party, it ships the real one.
- **A secret no layer recognizes.** Not in `.env`, matches no rule, entropy
  off — the model reads it.
- **Prompt injection.** `osm` masks credentials; it is not an injection defense.
- **Anything outside Claude Code.** A hook-boundary plugin, not a network proxy.

**Known limits**

- **The fake stays on screen.** A hook can append below an answer but not
  rewrite it, so "your key is `sk-ant-…`" shows the fake. Cosmetic — the model
  never held the real one.
- **A partial fake does not restore.** Restoration swaps a whole fake byte for
  byte; an echoed prefix stays.
- **Secret-shaped JSON property *names* are not masked.** Values only.
- **Masking cost grows with the number of known secrets** — every string is
  tested against every secret the vault holds. Fine at the usual scale; worth
  watching with `persist` on and a long retention window.
- **A classic hook downstream sees the real value**, and its stdout is written
  verbatim into the transcript.
- **A secret you type is masked for the model and still recorded** by the
  engine, before the masking hook runs.

## Failure behavior

**Every hook fails closed.** The engine *skips* a hook that throws or overruns
its budget and runs core in its place — for a masking hook that is worse than
not being installed, since the unmasked content goes straight through. So each
hook answers for itself. The guard covers this plugin's own work and never a
`next()` call, because charging the hooks beneath us to our budget would drop
your prompt whenever another plugin is slow. A visible refusal beats an
invisible leak.

## Tests

No Claude Code install needed:

```sh
bun run scripts/unit-check.ts    # 158 checks on the pure logic
bun run scripts/hook-check.ts    # 41 checks on the hooks, through a fake engine
bun run scripts/corpus-check.ts  # our rules vs gitleaks, Nosey Parker, secretlint fixtures
npx --yes --package typescript@7 tsc -p tsconfig.json
claude plugin validate .claude-plugin/plugin.json
```

These cost real model calls:

```sh
bash scripts/local-e2e.sh        # 3 passes, 8 checks
bash scripts/scenario-e2e.sh     # 11 scenarios in parallel tmux windows, 25 checks
bash scripts/wire-e2e.sh         # what actually left the machine
bash scripts/send-e2e.sh         # what a SendMessage recipient read
```

<details>
<summary>Why <code>wire-e2e.sh</code> is the only one that proves anything</summary>

Every unit and hook check asserts that our hook *returned* a fake. None can
show the engine *sent* one — a skipped hook fails open, and a returned `ref`
makes core serve the messages it already built. Both look fine from inside.

`wire-e2e.sh` puts a recording proxy in `ANTHROPIC_BASE_URL`, plants a canary
credential, and reads the request bodies Claude Code actually sent. It asserts
three things, and the third is what makes the other two mean anything: the
canary appears in no request body, a same-shaped fake appears in one, and a
control run *without* the plugin **does** leak the canary. Without the control,
a model that never read the file scores identically to a model that read a fake.

Request bodies are recorded; headers never are, because they carry the caller's
own token.

`scenario-e2e.sh` also runs the fail cases, because a masker that breaks must
break closed: an unknown fake must not be restored, and a sabotaged `mask()`
must refuse rather than let the engine serve the real result.
`sandbox-e2e.sh` and `sandbox-scenarios.sh` run the same matrix in a disposable
Linux box against OpenRouter — 25 of 25 on both `anthropic/claude-sonnet-4.5`
and `anthropic/claude-haiku-4.5`.

</details>

## Project layout

One file per job: `hooks/events/` has one module per engine event, `vault/`
holds the two-way map and the format-preserving `garble`, `detect/` the scanner
and the six rule groups, `policy/` the boundary and the failure fallbacks.
[CLAUDE.md](CLAUDE.md) has the full module map and the engine facts behind each
design decision.

`types/claude-code.d.ts` is the engine's own declaration file, vendored so CI
can typecheck without a Claude Code install. Not our code.

## Contributing

New rules are the most useful contribution, and the bar is one rule, one line,
one test. [CONTRIBUTING.md](CONTRIBUTING.md) has the anatomy of a rule, the
prefix requirement, and the checklist.

**Found a way to make the plugin leak a credential?** Report it privately
through [Security Advisories](https://github.com/pratikbin/opensecretmask/security/advisories/new),
not a public issue — [SECURITY.md](SECURITY.md) says what counts. A missing
rule for a vendor is a normal issue.

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to every space this project
uses.

## License

MIT. See [LICENSE](LICENSE).

False-positive suppression shapes and the binary-payload skip list are adapted
from [awesome-claude-code-function-hooks](https://github.com/ray-amjad/awesome-claude-code-function-hooks)
(MIT, Copyright © 2026 Ray Amjad).
