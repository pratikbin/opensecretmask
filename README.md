# osm

`osm` keeps your secrets out of the model. It is a Claude Code plugin. It
replaces a secret with a fake before the model reads it, and puts the real
secret back on the way into a tool call.

A fake is **format-preserving**: it keeps the vendor prefix, the length, and
the character classes of the real value. `sk-ant-api03-Xk9…` becomes
`sk-ant-nvd59-RAT…`. That is the whole point. An opaque `[REDACTED]` tag tells
the model "something was here" and derails its reasoning; a same-shaped fake
tells it "this is an Anthropic key", so it plans exactly as it would have.

## Install

Needs Claude Code 2.1.272 or newer. Function hooks are early access.

```sh
git clone https://github.com/pratikbin/opensecretmask ~/.claude/osm

cd ~/your-project
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir ~/.claude/osm
```

`--plugin-dir` takes the directory holding `.claude-plugin/plugin.json`. From
inside the clone itself, that is `--plugin-dir .`.

## What it hooks

| Hook | Direction | Action |
| --- | --- | --- |
| `session.start` | — | Registers credentials from the session's `.env` files |
| `tool.call` ↓ | model → world | Restores fakes in tool arguments |
| `tool.call` ↑ | world → model | Masks secrets in `result`, `text` and `context` |
| `prompt.submit` | user → model | Masks the typed prompt and its context blocks |
| `prompt.context` | files → model | Masks `claudeMd`, where instruction files land |
| `prompt.section` | memory → model | Masks `memory` and the other prompt sections |
| `agent.spawn` | model → model | Masks the task text handed to a subagent |

One `tool.call` registration covers Read, Bash, Grep, WebFetch, Write, the
Agent tool and every MCP tool, because it matches the event rather than a list
of tool names.

**Model-facing arguments keep their fakes.** Restoring a fake is for external
boundaries — a `Bash` curl, a `Write` — never for a value another model reads.
Two layers enforce that: `agent.spawn` masks the task text of every subagent
dispatch whatever tool triggered it, and `policy/model-facing.ts` stops the
real value materialising in the Agent tool's recorded arguments on the way
there.

## Detection

Two layers.

**Registered secrets** are the exact-match layer, read from `.env` at
`session.start`. A value qualifies on its name (`*_KEY`, `*_TOKEN`, …) or on
its shape, so a credential with a dull name is still caught and `PORT=3000`
stays readable.

**Detection rules** are best-effort: 140 prefix-distinctive patterns in six
groups under `hooks/detect/rules/`. No allowlists, no anchors, so they behave
the same in JSON, in file contents and in bare tokens.

A value caught once is remembered, so a secret first matched by a
context-bearing rule (`aws_secret_access_key = "…"`) is still masked when it
reappears on its own.

## Options

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

`entropy` adds a Shannon-entropy layer for tokens no pattern matches. Off by
default. It runs behind the suppression set in `hooks/detect/suppress.ts`,
which keeps git SHAs, UUIDs, digit runs and public object ids (Stripe `pk_`,
`price_`, YouTube channel ids) out of the results unless a credential name sits
immediately to their left.

`persist` carries the map across a resume, a fork or `/reload-plugins`. See
below.

## Persistence

The map lives in memory and dies with one load of the plugin. That is safe, but
it breaks `--resume`: the replayed transcript is full of fakes the new map has
never seen, so a tool call built around one runs against an invalid credential.

With `persist: true` the map is written to `$.store`, the plugin's own JSON
file under the Claude Code configuration directory. Entries come in two kinds,
and the split is the point:

| Kind | Stored | Expires |
| --- | --- | --- |
| `env` | the fake plus a pointer to `{file, key}` | never — the source is re-read |
| `literal` | the fake **and the secret** | after `retentionDays` |

A `.env` secret is already on disk, so storing a pointer to it puts nothing new
at rest and needs no expiry. A secret first seen in tool output exists nowhere
else, so restoring it later means storing the value — that is the only kind
that creates new exposure, and the only kind the window applies to.

The store is plaintext and the plugin cannot set its file mode. Leave `persist`
off if that matters more to you than resuming a session.

## Layout

```
hooks/
  register.ts          wiring only
  options.ts           plugin settings
  env.ts               .env parsing (comment-aware)
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
    entropy.ts         Shannon layer
    suppress.ts        false-positive suppression
    rules/             builtin llm cloud chat git devtools
  policy/
    boundary.ts        outbound/inbound, the one place `ref` is stripped
    model-facing.ts    arguments that keep their fakes
    budget.ts          failure fallbacks
```

`types/claude-code.d.ts` is the engine's own declaration file, written by
`/plugin-types` and vendored so CI can typecheck without a Claude Code install.
It is not our code, and `.gitattributes` marks it generated.

## Failure behaviour

Every hook fails closed. The engine *skips* a hook that throws or overruns its
time budget and runs core in its place, which for a masking hook is worse than
not being installed at all — the unmasked content goes straight through.

Each hook therefore answers for itself rather than letting the engine answer.
The deadline covers *our* work only and never a `next()` call — charging the
hooks beneath us to our budget would drop the user's prompt whenever some other
plugin is slow. A visible refusal beats an invisible leak.

A rewritten tool result also drops `ref`, which names the messages core already
built from the unmasked content.

## Tests

```sh
bun run scripts/unit-check.ts   # 40 checks, no Claude Code needed
bun run scripts/hook-check.ts   # 12 hook-level checks
npx --yes --package typescript@5 tsc -p tsconfig.json
bash scripts/local-e2e.sh       # real end-to-end run on your own account
bash scripts/scenario-e2e.sh    # every channel, in parallel tmux windows, with metrics
```

`scripts/local-e2e.sh` runs three headless passes against a real model and
prints a verdict per check. Run it under `tmux`; each pass takes about a
minute. `scripts/sandbox-e2e.sh` does the same in a disposable Linux box
against OpenRouter.

## Known limits

- **The fake stays on screen.** `turn.complete` can append below an answer but
  cannot rewrite it, so when Claude says "your key is `sk-ant-…`" you read the
  fake. The model never held the real one, so this is cosmetic.
- **A partial fake does not restore.** Restoration swaps a whole fake byte for
  byte. If the model echoes only the first characters, those stay.
- **Restoring into `Bash` is real, by design.** If a command ships that value
  to a third party, it ships the real one.
- **Secret-shaped JSON property names are not masked.** Values only. Rewriting
  keys needs collision handling in both directions and risks corrupting real
  structures, for a case that barely occurs.
- **Masking cost grows with the number of known secrets.** Each string is
  tested against every secret the vault holds. Fine at the usual scale; with
  `persist` on and a long retention it is worth watching.
- **A classic hook downstream of us sees the real value.** Its stdout is
  written verbatim into the session transcript, so a `PreToolUse` hook that
  echoes its rewritten input puts the restored credential on disk.

## License

MIT. See [LICENSE](LICENSE).

False-positive suppression shapes and the binary-payload skip list are adapted
from [awesome-claude-code-function-hooks](https://github.com/ray-amjad/awesome-claude-code-function-hooks)
(MIT, Copyright © 2026 Ray Amjad).
