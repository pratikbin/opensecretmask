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

Nothing is written to disk by default. The map of fake to real value lives in
memory and dies with the session.

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

To check that it loaded, look for the `osm:` line at the start of the session.
It reports how many secrets it registered.

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

One `tool.call` registration covers Read, Bash, Grep, WebFetch, Write, the
Agent tool and every MCP tool, because it matches the event and not a list of
tool names.

A value another model reads is not an external boundary. Restoring a fake is
for a `Bash` command or a `Write`, never for a subagent's task text. Two layers
hold that line: `agent.spawn` masks the task of every subagent dispatch
whatever tool triggered it, and `policy/model-facing.ts` stops the real value
appearing in the Agent tool's recorded arguments on the way there.

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

So a vendor with no rule of its own is often still caught. A secret with no
recognizable shape at all is the `.env` layer's job.

A value caught once is remembered. A secret first matched by a context rule is
masked later when it appears on its own.

Adding a rule is one line in one file. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Configuration

Plugin options, with their defaults:

```json
{
  "entropy": false,
  "entropyThreshold": 4.0,
  "entropyMinLen": 24,
  "envFiles": [".env", ".env.local"],
  "persist": false,
  "retentionDays": 120
}
```

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

## Persistence

The map lives in memory and dies with one load of the plugin. That is safe, but
it breaks `--resume`. The replayed transcript is full of fakes that the new map
has never seen, so a tool call built around one runs against an invalid
credential. Nothing leaks. The command just fails.

With `persist: true` the map is written to `$.store`, which is the plugin's own
JSON file under the Claude Code configuration directory. Entries come in two
kinds, and the split is the point:

| Kind | Stored | Expires |
| --- | --- | --- |
| `env` | the fake plus a pointer to `{file, key}` | never, because the source is re-read |
| `literal` | the fake **and the secret** | after `retentionDays` |

A `.env` secret is already on disk, so storing a pointer to it puts nothing new
at rest and needs no expiry. A secret first seen in tool output exists nowhere
else, so restoring it later means storing the value itself. That is the only
kind that creates new exposure, and the only kind the retention window applies
to.

The store is plaintext and the plugin cannot set its file mode. Leave `persist`
off if that matters more to you than resuming a session.

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
  echoes its rewritten input puts the restored credential on disk.

## Failure behavior

Every hook fails closed. The engine *skips* a hook that throws or overruns its
time budget and runs its own code in that hook's place. For a masking hook that
outcome is worse than not being installed, because the unmasked content goes
straight through.

Each hook therefore answers for itself instead of letting the engine answer.
The deadline covers this plugin's own work and never a `next()` call, because
charging the hooks beneath us to our budget would drop your prompt whenever
some other plugin is slow. A visible refusal beats an invisible leak.

## Tests

```sh
bun run scripts/unit-check.ts   # 52 checks on the pure logic
bun run scripts/hook-check.ts   # 12 checks on the hooks, through a fake engine
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
`scripts/sandbox-e2e.sh` runs the same round trip in a disposable Linux box
against OpenRouter.

## Project layout

```
hooks/
  register.ts          wiring only
  options.ts           plugin settings
  env.ts               .env parsing, comment-aware
  events/              one file per engine event
    session-start.ts  tool-call.ts  prompt.ts  agent-spawn.ts
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
