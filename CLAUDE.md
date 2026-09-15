# osm, project notes

`osm` is a Claude Code plugin that masks secrets. A secret becomes a
format-preserving fake before the model reads it. The real secret returns on
the way into a tool call. The plugin holds its state in memory and writes
nothing to disk.

This repository held a local proxy before. That Go code is deleted. If you
need that code, read the git history.

## Layout

| Path | Role |
| --- | --- |
| `.claude-plugin/plugin.json` | The plugin manifest |
| `hooks/hooks.json` | Names the hooks module |
| `hooks/register.ts` | The five hooks and the `.env` reader |
| `hooks/rules.ts` | The 138 detection patterns, in six groups |
| `hooks/detect.ts` | The scanner, the prefix walker, the entropy test |
| `hooks/vault.ts` | The fake generator and the two-way map |
| `hooks/index.ts` | Re-exports for callers |
| `tests/` | Hook tests for `claude plugin test` |
| `scripts/sandbox-e2e.sh` | The end-to-end runner for a disposable box |
| `types/claude-code.d.ts` | The vendored engine declarations |

## Hooks

| Hook | Direction | Action |
| --- | --- | --- |
| `session.start` | none | Registers the credentials in the `.env` files |
| `tool.call` down | model to world | Restores every fake in the tool arguments |
| `tool.call` up | world to model | Masks every secret in the tool result |
| `prompt.submit` | user to model | Masks the prompt and its context blocks |
| `prompt.section` | memory to model | Masks `CLAUDE.md` and the memory files |

One `tool.call` hook covers Read, Bash, Grep, WebFetch, Write, the Agent
tool, and every MCP tool. It sits at the tool boundary, so it is not a list
of tool names.

## Key design

- Masking is a plain text replacement. It reads no provider format.
- A secret maps to a fake through the vault map and not through reversible
  math. Restoring a secret is a lookup.
- Registered secrets are the exact-match layer. Detection rules are the
  best-effort layer.
- The vault dies with the session, so there is nothing at rest to encrypt and
  no passphrase to enter.
- Every pattern in `hooks/rules.ts` starts with a distinctive prefix. There
  are no allowlists and no anchors, so detection works the same way in JSON
  bodies, in file contents, and in bare tokens.
- `literalPrefix()` in `hooks/detect.ts` walks a pattern source and returns
  the fixed text that the pattern must begin with. That prefix gates the scan,
  and `garble()` keeps it verbatim. For the Anthropic rule it returns 7, so
  `sk-ant-` survives and `api03` becomes something else.
- A fake is public by design, because the model reads it. So `garble()` uses
  `Math.random` and not a cryptographic generator.
- A fake matches the detection patterns by design. So `mask()` skips any value
  that the vault already knows as a fake.

## Engine invariants

Two rules come from the engine and shape the hook code.

- The engine skips a hook that throws an error and runs its own code instead.
  For a masking hook that outcome is worse than not being installed. So every
  hook catches its own errors, and it denies or drops.
- `next(e)` returns a `ref` that names the messages the engine already built
  for the call. If a hook returns that `ref`, the engine uses those messages
  unmasked. A rewritten result must answer without `ref`.

## Build and test

```sh
npx tsc -p tsconfig.json     # type-check the hooks and the tests
claude plugin test .         # run the hook tests
```

`types/claude-code.d.ts` is the vendored declaration file that
`/plugin-types` writes. When the engine API moves, refresh it.

### End-to-end runs

Two runners drive a real model through the whole round trip.

`scripts/local-e2e.sh` runs on this machine and this account. It needs Claude
Code 2.1.272 or newer. Run it inside `tmux`, because each pass takes a minute.

`scripts/sandbox-e2e.sh` runs in a disposable Linux box against OpenRouter.
Export `OPENROUTER_API_KEY` before you run it. The `devbox:1` image ships
Claude Code 2.1.260, which is too old for function hooks, so the script
upgrades Claude Code first.

Both runners passed every check. The local run used Claude Code 2.1.272. The
sandbox run used the same version with `anthropic/claude-sonnet-4.5`.

| Test | Observed |
| --- | --- |
| Control, no plugin | The model echoed the real key, so the test is meaningful |
| Result masked | The model echoed `sk-ant-rqm01-XGEEYNMQ…` and not the real key |
| Format kept | The `sk-ant-` prefix stayed, and the length matched |
| Args unmasked | `grep` found the real key, so the tool received it |
| `.env` layer | `ACME_DB_PASSWORD` was masked, `PORT` and `NODE_ENV` were not |

Row two and row four together are the round trip. The model composed a
command around the fake it read. The command ran against the real credential.

Three traps make these runners look broken when they are not.

- `--allowedTools` is variadic, so a prompt placed after it is read as another
  tool name. `scripts/local-e2e.sh` passes the prompt on stdin.
- A prompt that asks the model to write a credential into a file reads as an
  exfiltration pattern, and the model refuses. The restore direction is
  observed with `grep -c` instead.
- The `Read` tool needs explicit approval for a `.env` file. The local runner
  puts the same value in `app-config.txt` and reads that.

## Open items

- `prompt.context` blocks are not masked. When a secret turns up in a context
  block, add the hook.
- A partial fake does not restore. Restoration swaps a whole fake, byte for
  byte. If the model repeats only the first characters of a fake, those
  characters stay on screen. A complete fix needs prefix matching with guards
  against false positives.
- There is no PII group. A social security number pattern sits in the builtin
  group. A separate group for email, phone, and card numbers is the natural
  shape. That group must default to off, because agent prompts carry user
  data on purpose.
