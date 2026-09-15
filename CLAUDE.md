# osm — project notes

A Claude Code plugin that swaps secrets for format-preserving fakes before the
model reads them, and restores the real value on the way into a tool call.

This repo held a Go CA-MITM proxy before commit `e2c2b38`. That code is gone;
`git log` has it.

## The one invariant

**A fake looks exactly like the real thing.** Same vendor prefix, same length,
same character classes. Never `[REDACTED]`, never a hash tag, never a
placeholder. An opaque token changes how the model reasons — it stops treating
the value as an Anthropic key and starts treating it as a hole. A same-shaped
fake preserves the plan.

Everything else in this codebase is negotiable. That is not.

## Module map

| Path | Owns |
| --- | --- |
| `hooks/register.ts` | Wiring. One `Vault`, four `register*` calls. No logic. |
| `hooks/options.ts` | `PluginOptions` → typed `Options` |
| `hooks/env.ts` | `.env` parsing, comment- and quote-aware |
| `hooks/events/session-start.ts` | `.env` registration + persistence restore |
| `hooks/events/tool-call.ts` | The round trip, both directions |
| `hooks/events/prompt.ts` | `prompt.submit` / `.context` / `.section` |
| `hooks/events/agent-spawn.ts` | `agent.spawn`, the subagent boundary |
| `hooks/vault/index.ts` | The two-way map |
| `hooks/vault/garble.ts` | The format-preserving fake |
| `hooks/vault/walk.ts` | Bounded deep traversal, binary-safe |
| `hooks/vault/persist.ts` | `$.store` backing, opt-in |
| `hooks/detect/index.ts` | The scanner |
| `hooks/detect/prefix.ts` | Literal-prefix extraction |
| `hooks/detect/entropy.ts` | Shannon layer |
| `hooks/detect/suppress.ts` | False-positive suppression |
| `hooks/detect/rules/*.ts` | 140 patterns in six groups |
| `hooks/policy/boundary.ts` | `outbound`/`inbound`, where `ref` is stripped |
| `hooks/policy/model-facing.ts` | Arguments that must keep their fakes |
| `hooks/policy/budget.ts` | Failure fallbacks |

Adding a rule source is one file in `rules/` plus one line in `rules/index.ts`.
No registry, no init-time side effects.

`types/claude-code.d.ts` (10.7k lines) is the engine's own declaration file
from `/plugin-types`, vendored so CI typechecks without a Claude Code install.
Not our code. `.gitattributes` marks it `linguist-generated`. Refresh it when
the engine API moves.

## Engine facts that shape the code

These are not style choices. Each one caused a bug.

**A skipped hook fails OPEN.** The engine skips a hook that throws *or
overruns its budget* and runs core in its place. For a masker that is worse
than being absent, so every hook answers for itself via `policy/budget.ts`.

The deadline must cover our own work and never a `next()` call. An earlier
version wrapped `next()`, which charged every hook beneath us to our budget —
a slow unrelated plugin made osm drop the user's prompt and blame itself.

**`ref` pins the unmasked messages.** `next(e)` returns a `ref` naming the
messages core already built. Return it and core uses those verbatim — the
unmasked ones. Any rewritten result must answer without `ref`.

**`claudeMd` rides in `prompt.context`, not `prompt.section`.** Instruction
files land in `prompt.context.blocks` under the name `claudeMd`.
`prompt.section` carries `memory` and friends. Both are needed; hooking only
one leaves a live channel.

**Three model-facing fields on a tool result, not two.** `result`, `text`, and
`context` — the last carries a PostToolUse hook's additional text straight to
the model where the user never sees it.

**`agentId` is camelCase.** The classic-hook spelling `agent_id` reads
`undefined`.

**Restoring is for external boundaries only.** A value another model reads is
not one. `agent.spawn` is the general guarantee — every subagent dispatch goes
through it whatever tool triggered it, so a tool-name list can never be the
only answer. `model-facing.ts` additionally keeps the real value out of the
Agent tool's recorded arguments.

**"Opaque payload" is a property of the string, not of its key.** `walk.ts`
once skipped subtrees by key name (`data`, `base64`, …) to avoid garbling
images. That made `{ data: { apiKey: "sk-ant-…" } }` reach the model
unmasked — a fix for one problem became a leak. Test the leaf: long,
whitespace-free, base64 alphabet.

## Vault lifetime

Module memory, one load of the plugin.

| Action | Vault | Result |
| --- | --- | --- |
| `/clear`, `/compact` | kept | Safe |
| `/reload-plugins`, hook edit | new | Old fakes dead |
| `--resume`, `--continue`, fork | new | Old fakes dead |

"Dead" means the model writes an old fake into a tool call, the hook does not
recognise it, and the tool gets the fake. The command fails against an invalid
credential. No secret leaks — safe for privacy, wrong for usability.

`persist: true` fixes it via `$.store`, with a deliberate split: an `env` entry
stores only `{fake, file, key}` and never expires, because the secret is
already in `.env` and gets re-read. A `literal` entry stores the value itself
and expires after `retentionDays` (default 120). Only `literal` puts a
previously-transient secret at rest, which is why only it has a window.

The store is plaintext and the plugin cannot chmod it — `$.fs` has no chmod.

## Build and test

```sh
bun run scripts/unit-check.ts                          # 40 pure-logic checks
bun run scripts/hook-check.ts                          # 12 hook-level checks
npx --yes --package typescript@5 tsc -p tsconfig.json  # NB: --package, see below
bash scripts/local-e2e.sh                              # real model, your account
bash scripts/sandbox-e2e.sh                            # real model, throwaway box
```

`npx typescript@5 tsc` fails with "could not determine executable to run" — the
package's bin is `tsc`, not `typescript`. `--package` is required.

### e2e traps

Four things make a runner look broken when it is not.

- `--allowedTools` is variadic, so a prompt after it parses as a tool name.
  Pass the prompt on stdin.
- A prompt asking the model to write a credential to a file is refused as an
  exfiltration pattern. Observe the restore direction with `grep -c` instead.
- The `Read` tool needs explicit approval for a `.env` file. Put the same value
  in a normal file for the model to read.
- `--plugin-dir` takes the directory holding `.claude-plugin`. From inside the
  clone that is `.`.

## Open items

- Secret-shaped JSON property *names* are not masked. Values only. Rewriting
  keys needs two-way collision handling for a case that barely occurs.
- A partial fake does not restore; prefix matching needs false-positive guards.
- No PII group. SSN sits in `builtin`. Email/phone/card would have to default
  off, since agent prompts carry user data on purpose.
- A classic hook downstream of us receives the restored value, and the engine
  writes its stdout verbatim into the transcript JSONL. Observed with a
  `PreToolUse` rewriter. Nothing the plugin can do from inside.

## Attribution

Suppression shapes and the binary skip list adapted from
`ray-amjad/awesome-claude-code-function-hooks` (MIT).
