# osm, project notes

`osm` is a Claude Code plugin that keeps secrets away from the model. It
replaces a secret with a format-preserving fake before the model reads it, and
it puts the real secret back on the way into a tool call. The plugin holds its
state in memory and writes nothing to disk.

The repository root is the plugin. Point Claude Code at it with
`--plugin-dir`, and set `CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1`, because function
hooks are early access. You need Claude Code 2.1.272 or newer.

This repository held a local proxy before commit `e2c2b38`. That Go code is
deleted. If you need it, read the git history.

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
| `tests/register.test.ts` | Hook tests for `claude plugin test` |
| `scripts/local-e2e.sh` | End-to-end runner for this machine |
| `scripts/sandbox-e2e.sh` | End-to-end runner for a disposable box |
| `types/claude-code.d.ts` | The vendored engine declarations |

## The round trip

A secret makes one trip out and one trip back.

1. A tool result carries a secret. The `tool.call` hook scans the result,
   mints a fake for each secret it finds, and hands the fake to the model.
2. The model reasons about the fake and writes it into the next tool call.
3. The same `tool.call` hook reads the arguments on the way down, finds the
   fake, and puts the real secret in its place. The tool runs on the real one.

The model never reads the real value. The tool never receives the fake.

## Hooks

| Hook | Direction | Action |
| --- | --- | --- |
| `session.start` | none | Registers the credentials in the `.env` files |
| `tool.call` down | model to world | Restores every fake in the tool arguments |
| `tool.call` up | world to model | Masks every secret in the tool result |
| `prompt.submit` | user to model | Masks the prompt and its context blocks |
| `prompt.section` | memory to model | Masks `CLAUDE.md` and the memory files |

One `tool.call` hook covers Read, Bash, Grep, WebFetch, Write, the Agent tool,
and every MCP tool. It sits at the tool boundary, so it is not a list of tool
names.

## The vault and how long it lives

The vault is a plain map in module memory. `register()` builds one, so a vault
lives exactly as long as one load of the plugin. Nothing reaches disk, so
there is no store to unlock and no passphrase to enter.

That lifetime has a cost. A fake restores only while the vault that minted it
is alive.

| Action | Process | Plugin | Vault | Result |
| --- | --- | --- | --- | --- |
| `/clear` | lives | stays loaded | kept | Safe. The transcript is empty, so nothing refers to a fake. |
| `/compact` | lives | stays loaded | kept | Safe. A fake inside the summary still restores. |
| `/reload-plugins` or a hook edit | lives | reloads | new and empty | Broken. A fake from an earlier turn no longer restores. |
| `claude --resume`, `--continue`, a fork | new | loads | new and empty | Broken. Every fake in the replayed transcript is dead. |
| A brand new session | new | loads | new and empty | Safe. Nothing refers to an old fake. |

"Broken" means one thing. The model writes an old fake into a tool call, the
hook does not recognize it, and the tool receives the fake instead of the real
credential. The command then runs against an invalid credential and fails.

The real secret never leaks in this state. The failure is safe for privacy and
wrong for usability. `session.start` does re-read the `.env` files on the new
load, but `garble()` draws at random, so the value it mints the second time
differs from the one already sitting in the transcript.

This reading comes from the code and from the engine declarations. No test
covers it yet.

Two paths lead out, and nobody has taken either.

- Make the fake a function of the secret instead of a random draw. Derive it
  from a keyed hash, with the key a random salt in `$.store`. A salt is not a
  secret, so it can live on disk. A reload then re-registers the same `.env`
  value, mints the same fake, and old fakes in the transcript restore again.
  This repairs registered secrets only.
- Detect the case and say so. `classic.SessionStart` carries
  `source: 'startup' | 'resume' | 'clear' | 'compact' | 'fork'`. On `resume`
  or `fork`, one `$.ui.log` line turns a silent wrong state into a visible one.

A secret first seen in a tool result of the earlier session comes back under
neither path. Recovering it needs the secret on disk, which is the thing this
design removes.

## Key design

- Masking is a plain text replacement. It reads no provider format.
- A secret maps to a fake through the vault map and not through reversible
  math. Restoring a secret is a lookup.
- Registered secrets are the exact-match layer. `session.start` reads them
  from the `.env` files. A value qualifies when its name reads like a
  credential name, and also when a pattern matches its shape, so `PORT=3000`
  stays readable to the model.
- Detection rules are the best-effort layer. They run on every tool result and
  on every prompt.
- Every pattern in `hooks/rules.ts` starts with a distinctive prefix. There are
  no allowlists and no anchors, so detection works the same way in JSON bodies,
  in file contents, and in bare tokens.
- `literalPrefix()` in `hooks/detect.ts` walks a pattern source and returns the
  fixed text the pattern must begin with. That prefix gates the scan, and
  `garble()` keeps it verbatim. The Anthropic rule returns 7, so `sk-ant-`
  survives and `api03` becomes something else.
- A fake is public by design, because the model reads it. So `garble()` uses
  `Math.random` and not a cryptographic generator.
- A fake matches the detection patterns by design. So `mask()` skips any value
  that the vault already knows as a fake.
- The entropy test is off by default. On ordinary prompt text it reports
  hashes, base64 blocks, and git commit ids as secrets.

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

Two runners drive a real model through the whole round trip. Each one opens
with a control pass that loads no plugin, so a passing run proves the fixture
is readable rather than proving nothing.

`scripts/local-e2e.sh` runs on this machine and this account. Run it inside
`tmux`, because each pass takes about a minute.

`scripts/sandbox-e2e.sh` runs in a disposable Linux box against OpenRouter.
Export `OPENROUTER_API_KEY` before you run it. The `devbox:1` image ships
Claude Code 2.1.260, which is too old for function hooks, so the script
upgrades Claude Code first.

Both runners passed every check on Claude Code 2.1.272. The sandbox run used
`anthropic/claude-sonnet-4.5` through OpenRouter.

| Test | Observed |
| --- | --- |
| Control, no plugin | The model echoed the real key, so the test is meaningful |
| Result masked | The model echoed `sk-ant-rqm01-XGEEYNMQ…` and not the real key |
| Format kept | The `sk-ant-` prefix stayed, and the length matched |
| Args unmasked | `grep` found the real key, so the tool received it |
| `.env` layer | `ACME_DB_PASSWORD` was masked, `PORT` and `NODE_ENV` were not |

Row two and row four together are the round trip.

### Traps

Four traps make a runner look broken when it is not.

- `--allowedTools` is variadic, so a prompt placed after it is read as another
  tool name. `scripts/local-e2e.sh` passes the prompt on stdin.
- A prompt that asks the model to write a credential into a file reads as an
  exfiltration pattern, and the model refuses. The restore direction is
  observed with `grep -c` instead.
- The `Read` tool needs explicit approval for a `.env` file. The local runner
  puts the same value in `app-config.txt` and reads that.
- `--plugin-dir` takes the directory that holds `.claude-plugin`. From inside
  the clone, that is a plain dot.

## Open items

- A reload or a resume drops the vault. Read the lifetime section above.
- `prompt.context` blocks are not masked. When a secret turns up in a context
  block, add the hook.
- A partial fake does not restore. Restoration swaps a whole fake, byte for
  byte. If the model repeats only the first characters of a fake, those
  characters stay on screen. A complete fix needs prefix matching with guards
  against false positives.
- There is no PII group. A social security number pattern sits in the builtin
  group. A separate group for email, phone, and card numbers is the natural
  shape. That group must default to off, because agent prompts carry user data
  on purpose.
