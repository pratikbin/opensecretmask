# osm

Keep your API keys out of the model, without breaking what the model can do.

`osm` is a plugin for [Claude Code](https://claude.com/claude-code). It replaces
each secret with a fake before Claude reads it, then puts the real secret back
on the way into a tool call. Claude works with the fake. Your terminal works
with the real value.

```
you       cat .env
                                 ANTHROPIC_API_KEY=sk-ant-api03-Xk9Qw2…
osm                              masks it
Claude reads                     ANTHROPIC_API_KEY=sk-ant-nvd59-RATmp7…
Claude writes                    curl -H "x-api-key: sk-ant-nvd59-RATmp7…"
osm                              restores it
your shell runs                  curl -H "x-api-key: sk-ant-api03-Xk9Qw2…"
```

A fake is **format-preserving**. It keeps the vendor prefix, the length and the
character classes of the real value, so `sk-ant-api03-Xk9…` becomes
`sk-ant-nvd59-RAT…`. This is the whole point of the project. An opaque
`[REDACTED]` tag tells the model that something is missing and changes how it
reasons. A same-shaped fake tells it "this is an Anthropic key", so it writes
the same command it would have written anyway.

Nothing of the plugin's own is written to disk by default. The map of fake to
real value lives in memory and dies with the session. For the full account of
what is stored where, read [Where your secrets live](#where-your-secrets-live).

## Who this is for

- You paste credentials into a terminal where Claude Code is running.
- Your `.env` file is one `cat` away from the conversation transcript.
- You run agents that read logs, config files or HTTP responses that carry
  tokens.

If you never let a model see a credential in the first place, you do not need
this.

## Install

You need Claude Code 2.1.272 or newer. Function hooks are an early-access
feature, so you must set `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`.

```sh
claude plugin marketplace add pratikbin/opensecretmask
claude plugin install osm@opensecretmask
```

Then start Claude Code with the feature flag on:

```sh
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude
```

To run from a clone instead, which is what you want while you work on the
plugin itself:

```sh
git clone https://github.com/pratikbin/opensecretmask ~/.claude/osm
cd ~/your-project
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir ~/.claude/osm
```

`--plugin-dir` takes the directory that holds `.claude-plugin/plugin.json`.

## What you see

One line when the session starts, naming what is watched and what is off:

```
osm: masking (2 secrets from .env, .env.local, 146 rules, entropy on)
osm: masking on, nothing registered (146 rules)
```

Then a line pinned under the prompt, which is how you know it is working while
you work. A masking plugin is otherwise silent by design:

```
osm: 3 secrets · 12 masked · 4 restored
```

`masked` counts values swapped on the way to the model and `restored` counts
fakes swapped back on the way into a tool, so the second number is the round
trip actually closing. Before anything is found the line reads `osm: watching`.

And `/osm-secrets`, which prints the pairs: every secret the session has
masked, beside the fake it wears.

```
osm: 3 secrets this session (real → fake)
1. sk-ant-api•••i05rP (53) → sk-ant-loz•••kG8uT (53)
2. ghp_1a2B3c•••VwXyZ (40) → ghn_6b0H6u•••NqZeA (40)
3. -----BEGIN•••Y----- (72) → -----BEGIN•••K----- (72)
```

One bounded line per secret, not a column table: a PEM key carries newlines and
a JWT runs to 300 characters, so aligned columns come apart the moment a real
session has thirty secrets in it. Both values keep their ends, lose the middle
and state their true length, which is enough to match a row against your `.env`
without printing the credential whole. The list goes out through the engine's
user-only log channel, so **the model never receives it** — printing it as the command's own output would hand the model
every fake beside its original, which is the leak the plugin exists to prevent.
It is still on your screen and in the debug log, so treat a shared terminal
recording accordingly.

## How it works

Claude Code exposes function hooks at each boundary where text moves between
you, the model and the outside world. `osm` sits on seven of them.

| Hook | Direction | Action |
| --- | --- | --- |
| `session.start` | none | Registers credentials from the session's `.env` files |
| `tool.call` down | model to world | Restores fakes in tool arguments |
| `tool.call` up | world to model | Masks secrets in `result`, `text` and `context` |
| `prompt.submit` | you to model | Masks the prompt you typed and its context blocks |
| `prompt.context` | files to model | Masks `claudeMd`, where instruction files land |
| `prompt.section` | memory to model | Masks `memory` and the other prompt sections |
| `agent.spawn` | model to model | Masks the task text handed to a subagent |
| `skill.prompt` | disk to model | Masks a skill's expanded prompt |
| `session.receive` | outside to model | Masks a relay, peer or Remote Control delivery |
| `session.compact` | transcript to model | Masks what the summarizer reads at `/compact` |

One `tool.call` registration covers Read, Bash, Grep, WebFetch, Write, the
Agent tool and every MCP tool, because it matches the event and not a list of
tool names.

A value another model reads is not an external boundary. Restoring a fake is
for a `Bash` command or a `Write`, never for a subagent's task text. Two layers
hold that line: `agent.spawn` masks the task of every subagent dispatch
whatever tool triggered it, and `policy/model-facing.ts` stops the real value
appearing in the Agent tool's recorded arguments on the way there.

### Diagrams

Each PNG links to an interactive, self-contained HTML version — open it in a
browser, no server needed.

[![Module architecture](docs/diagrams/architecture.png)](docs/diagrams/architecture.html)

`register.ts`'s wiring fan-out, the mask/restore core, and the vault's
persistence path.

[![Tool-call round trip](docs/diagrams/tool-call-sequence.png)](docs/diagrams/tool-call-sequence.html)

`inbound()` restoring a fake before the real tool runs, `outbound()` masking
the result after, both fail-closed.

[![Vault lifetime](docs/diagrams/vault-lifecycle.png)](docs/diagrams/vault-lifecycle.html)

What survives `/clear`, what a reload kills, and the `persist: true` recovery
path.

## What it detects

Two layers, and they work differently on purpose.

**Registered secrets** are the exact-match layer. At `session.start` the plugin
reads the session's `.env` files. A value qualifies on its name (`*_KEY`,
`*_TOKEN`, `*_PASSWORD`, and so on) or on its shape. So a credential with a
dull name is still caught, and `PORT=3000` stays readable. This layer does not
care what the secret looks like, which is why it catches
`DB_PASSWORD=hunter2-correct-horse-battery-staple`.

**Detection rules** are the best-effort layer: 146 patterns in six groups under
`hooks/detect/rules/`, covering about 96 vendors. There are no allowlists and
no anchors, so a rule behaves the same in a JSON body, in file contents and in
a bare token.

Most rules are gated on a literal vendor prefix, such as `sk-ant-` or `ghp_`.
Thirteen are shape or context rules, and those cover far more ground than a
vendor count suggests:

- a credential in a URL or a connection string, such as `postgres://user:PASS@host`
- an `Authorization: Bearer` header
- an assignment such as `DD_API_KEY=…` or `aws_secret_access_key = "…"`
- a PEM or PGP private key block, the whole block and not the header
- a JSON Web Token (a signed `eyJ…` token)

A context rule masks only its capture group, and that group is checked before
it is trusted: surrounding quotes and commas are trimmed off, and a value that
merely names a credential is dropped. `${DB_PASSWORD}`, `$ANTHROPIC_API_KEY`,
`<your-key-here>`, `[MASKED-0001]`, `changeme`, a bare UUID and a regex source
all stay readable. Plain hex and digits are not dropped: under an explicit
credential name they are usually the real key.

So a vendor with no rule of its own is often still caught. A secret with no
recognizable shape at all is the `.env` layer's job.

A value caught once is remembered. A secret first matched by a context rule is
masked later when it appears on its own.

Adding a rule is one line in one file. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Configuration

Set an option with `/config` inside Claude Code, or write it into
`settings.json` under `pluginConfigs`:

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

The values above are the defaults. The plugin key is `osm`, or `osm@inline`
when you load it with `--plugin-dir`.

| Option | What it does |
| --- | --- |
| `entropy` | Adds a Shannon-entropy layer for tokens that no pattern matches |
| `entropyThreshold` | Bits per character above which a string counts as random |
| `entropyMinLen` | Shortest string the entropy layer will consider |
| `envFiles` | Which files the exact-match layer reads at session start |
| `persist` | Carries the map across a resume, a fork or `/reload-plugins` |
| `retentionDays` | How long a stored literal secret survives |

`entropy` catches vendors that have no rule, such as an Atlassian token or an
Azure storage key. It costs precision: it will mask a long random-looking path
inside an ordinary URL. It runs behind the suppression set in
`hooks/detect/suppress.ts`, which keeps git SHAs, UUIDs, digit runs and public
object ids (Stripe `pk_` and `price_`, YouTube channel ids) out of the results
unless a credential name sits immediately to their left. Turn it on when you
would rather over-mask than miss something.

## Where your secrets live

By default `osm` stores nothing. The map of fake to real value is a `Map` in
the plugin's memory, for one load of the plugin. It is never written anywhere,
and it dies with the session. Your real secrets stay where they already were:
in `.env`, in the output of a tool, in your shell.

Three places hold a real credential while you use the plugin. Only the first is
the plugin's own.

### 1. The vault, in memory

`hooks/vault/index.ts`. Two maps, secret to fake and fake back to secret. No
file, no keychain, no network, no encryption, because there is nothing at rest
to encrypt. A `/clear` or a `/compact` keeps it. A reload, a fork or a
`--resume` starts an empty one, which is why an old fake no longer restores.

### 2. The store, only when `persist` is on

`persist: true` writes the map through `$.store`, which is a plain JSON file:

```
~/.claude/plugins/store/osm_inline-<hash>.json      mode 644
~/.claude/plugins/store/                            mode 755
```

The file name carries the plugin key, so an installed `osm` and a
`--plugin-dir` `osm@inline` keep separate files. Measured on a fresh box: 497
bytes for two entries.

Entries come in two kinds, and the split is the point:

| Kind | Stored | Expires |
| --- | --- | --- |
| `env` | the fake plus a pointer to `{file, key}` | never, because the source is re-read |
| `literal` | the fake **and the secret** | after `retentionDays` |

A `.env` secret is already on your disk, so storing a pointer to it puts
nothing new at rest. A secret first seen in tool output exists nowhere else, so
restoring it later means storing the value itself. That is the only kind that
creates new exposure, and the only kind the retention window applies to. A run
that registered one of each confirmed it: the `.env` password does not appear
in the file, the literal one does.

**The file is world-readable and the plugin cannot change that.** `$.fs` has no
chmod, and the engine writes the file with mode 644. Anyone with an account on
the machine can read it.

### 3. The session transcript, which the engine owns

```
~/.claude/projects/<slugged-cwd>/<session-id>.jsonl   mode 600
~/.claude/projects/                                   mode 755
```

Masked values are what the model saw, so the transcript is mostly fakes. Two
records can still carry the real value, and both were confirmed by grepping
real transcripts from this project's own test runs:

- `type: "attachment"` with `attachment.type: "hook_success"`. A classic hook's
  stdout, recorded verbatim. If you run a `PreToolUse` hook that echoes the
  command it rewrote, the restored credential lands here.
- `type: "queue-operation"` with `operation: "enqueue"`. The prompt exactly as
  you typed it, written before `prompt.submit` masking runs. The model receives
  the fake. The disk keeps what you typed.

So a secret you paste into a prompt is masked for the model and still written
to the transcript. That is the engine's record of your input, not something a
hook can rewrite.

## Hardening this on a Mac

In order of how much they buy you.

**Turn `persist` off.** It ships on, because a map that dies with the plugin
load breaks `--resume`, a fork and `/reload-plugins`, and the usual entry is
env-backed and stores no secret. Off, nothing of the plugin's own reaches the
disk and the only remaining exposure is the transcript, which you have with or
without this plugin. On, a `literal` entry — a secret first seen in tool output
— is written in plaintext for `retentionDays`.

**Tighten the directories, which is durable.** The engine rewrites the store
file and resets its mode, but it does not touch the mode of the directories
above it:

```sh
chmod 700 ~/.claude ~/.claude/projects ~/.claude/plugins/store
```

A `700` directory stops another account on the Mac from reaching the files
inside it, whatever mode the files carry.

**Turn on FileVault.** System Settings, Privacy and Security, FileVault. It
protects `~/.claude` when the Mac is off or stolen. It does nothing while you
are logged in, which is the point of the directory modes above.

**Keep the transcripts out of backups you do not control.**

```sh
tmutil addexclusion ~/.claude/projects
```

Do the same for any cloud-sync folder. A transcript copied into a synced
directory is a credential copied into someone else's storage.

**Shorten the window and clean up.** `retentionDays` bounds how long a literal
secret survives. Deleting the store file is safe at any time: the plugin
rebuilds what it can from `.env` and simply mints new fakes for the rest.

```sh
rm -f ~/.claude/plugins/store/osm_*.json
```

**Rotate what has already been in a transcript.** No file mode retroactively
protects a credential that sat in a `.jsonl` on a shared or backed-up disk.

## What this does not protect against

Read this part before you rely on the plugin.

- **A tool you run with the real credential.** Restoring is the feature. If
  Claude writes a command that ships the value to a third party, it ships the
  real one.
- **A secret that no layer recognizes.** If it is not in `.env`, matches no
  rule, and entropy is off, the model reads it.
- **A malicious prompt in a file the model reads.** `osm` masks credentials. It
  is not a prompt-injection defense.
- **Anything outside Claude Code.** This is a plugin at the hook boundary, not
  a network proxy.

The threat model is a careless leak, not an attacker with code execution on
your machine.

## Known limits

- **The fake stays on screen.** A hook can append below an answer but cannot
  rewrite it, so when Claude says "your key is `sk-ant-…`" you read the fake.
  The model never held the real one, so this is cosmetic.
- **A partial fake does not restore.** Restoration swaps a whole fake byte for
  byte. If the model echoes only the first characters, those stay.
- **Secret-shaped JSON property names are not masked.** Values only. Rewriting
  keys needs collision handling in both directions and risks corrupting real
  structures, for a case that barely occurs.
- **Masking cost grows with the number of known secrets.** Each string is
  tested against every secret the vault holds. This is fine at the usual scale.
  With `persist` on and a long retention window it is worth watching.
- **A classic hook downstream of this one sees the real value.** Its stdout is
  written verbatim into the session transcript, so a `PreToolUse` hook that
  echoes its rewritten input puts the restored credential on disk. See
  [Where your secrets live](#where-your-secrets-live).
- **A secret you type is masked for the model and still recorded.** The engine
  writes the prompt as you typed it into the transcript before the masking hook
  runs.

## Failure behavior

Every hook fails closed. The engine *skips* a hook that throws or overruns its
time budget and runs its own code in that hook's place. For a masking hook that
outcome is worse than not being installed, because the unmasked content goes
straight through.

Each hook therefore answers for itself instead of letting the engine answer. A
guard covers this plugin's own work and never a `next()` call, because charging
the hooks beneath us to our budget would drop your prompt whenever some other
plugin is slow. A visible refusal beats an invisible leak.

Every masking call is synchronous, so a guard is a plain try/catch rather than
a timer: synchronous work cannot overrun a deadline it blocks.

## Tests

```sh
bun run scripts/unit-check.ts   # 117 checks on the pure logic
bun run scripts/hook-check.ts   # 35 checks on the hooks, through a fake engine
bun run scripts/corpus-check.ts # our rules against gitleaks, Nosey Parker and secretlint fixtures
npx --yes --package typescript@5 tsc -p tsconfig.json
claude plugin validate .claude-plugin/plugin.json   # the engine must accept the hooks
```

Neither check script needs Claude Code installed. The two runs below do, and
they cost real model calls:

```sh
bash scripts/local-e2e.sh       # 3 passes, 8 checks
bash scripts/scenario-e2e.sh    # 11 scenarios in parallel tmux windows, 25 checks
```

`scripts/scenario-e2e.sh` covers every masking channel and the fail cases: an
unknown fake must not be restored, a sabotaged `mask()` must refuse rather than
let the engine serve the real result, and the hooks module must still validate.
It prints tokens, cost and subagent counts per scenario.
`scripts/sandbox-e2e.sh` runs one round trip in a disposable Linux box against
OpenRouter, and `scripts/sandbox-scenarios.sh` runs the whole matrix there. The
box-side wrapper installs tmux and jq, upgrades Claude Code to a version that
has function hooks, and repoints the model at OpenRouter:

```sh
export OPENROUTER_API_KEY=…            # in your own shell, never in a prompt
cos offload -s s-2vcpu-4gb -v OPENROUTER_API_KEY -o matrix.log . \
    'bash /work/scripts/sandbox-scenarios.sh'
```

The matrix passed 25 of 25 there on `anthropic/claude-sonnet-4.5` and again on
`anthropic/claude-haiku-4.5`.

## Project layout

```
hooks/
  register.ts          wiring only
  options.ts           plugin settings
  env.ts               .env parsing, comment-aware
  events/              one file per engine event
    session-start.ts  tool-call.ts  prompt.ts  agent-spawn.ts  command.ts
    compact.ts
  vault/
    index.ts           the two-way map
    garble.ts          the format-preserving fake
    walk.ts            bounded traversal, opaque-payload aware
    persist.ts         $.store backing, opt-in
  detect/
    index.ts           the scanner
    prefix.ts          literal-prefix extraction
    entropy.ts         the Shannon layer
    suppress.ts        false-positive suppression
    rules/             builtin llm cloud chat git devtools
  policy/
    boundary.ts        outbound and inbound, the one place `ref` is stripped
    model-facing.ts    arguments that keep their fakes
    budget.ts          failure fallbacks
```

`types/claude-code.d.ts` is the engine's own declaration file, written by
`/plugin-types` and vendored so that CI can typecheck without a Claude Code
install. It is not our code, and `.gitattributes` marks it generated.

## Contributing

New rules are the most useful contribution, and the bar is one rule, one line,
one test. [CONTRIBUTING.md](CONTRIBUTING.md) has the anatomy of a rule, the
prefix requirement, how to avoid false positives, and the checklist.

If you find a way to make the plugin leak a credential, please open a GitHub
issue with the shape of the input and not the real value.

## License

MIT. See [LICENSE](LICENSE).

False-positive suppression shapes and the binary-payload skip list are adapted
from [awesome-claude-code-function-hooks](https://github.com/ray-amjad/awesome-claude-code-function-hooks)
(MIT, Copyright © 2026 Ray Amjad).
