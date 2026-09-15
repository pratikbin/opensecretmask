# osm

`osm` keeps your secrets out of the model. It is a Claude Code plugin. It
replaces a secret with a fake before the model reads it. It puts the real
secret back on the way into a tool call. Everything stays in memory, and
nothing is written to disk.

A fake is format-preserving. It keeps the vendor prefix, the length, and the
character classes of the real secret. The real key `sk-ant-api03-Xk9…` becomes
`sk-ant-nvd59-RAT…`. The model treats the fake the way it treats a real key.
When the model writes that fake into a tool call, `osm` swaps the fake back
for the real key.

## Install

You need Claude Code 2.1.272 or newer. Function hooks are early access. A
function hook is a TypeScript function that wraps one engine event.

Clone the plugin once, then point Claude Code at that directory from inside
your own project. `--plugin-dir` takes the directory that holds
`.claude-plugin/plugin.json`, so pass the clone and not a path under it.

```sh
git clone https://github.com/pratikbin/opensecretmask ~/.claude/osm

cd ~/your-project
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir ~/.claude/osm
```

If you run Claude Code from the clone itself, pass `--plugin-dir .` instead.

## Test results

The plugin ran end to end twice. One run used a local machine with Claude
Code 2.1.272 on a normal account. The other used a disposable Linux box with
`anthropic/claude-sonnet-4.5` through OpenRouter. Both runs passed every
check.

| Test | Result |
| --- | --- |
| Control run without the plugin | The model read the real key, so the test is meaningful |
| Tool result masked | The model read `sk-ant-rqm01-XGEEYNMQ…` and not the real key |
| Format kept | The fake kept the `sk-ant-` prefix and the same length |
| Tool argument restored | `grep` found the real key, so the tool received it |
| `.env` layer | `ACME_DB_PASSWORD` was masked, `PORT` and `NODE_ENV` were not |

Row two and row four are the round trip. The model built a command around the
fake it read. The command ran against the real key.

## What it hooks

| Hook | Direction | Action |
| --- | --- | --- |
| `session.start` | none | Registers the credentials in the `.env` files of the session |
| `tool.call` down | model to world | Restores every fake in the arguments of the tool |
| `tool.call` up | world to model | Replaces every secret in the result of the tool |
| `prompt.submit` | user to model | Replaces every secret in the prompt and its context blocks |
| `prompt.section` | memory to model | Replaces every secret in `CLAUDE.md` and the other memory files |

One `tool.call` hook covers `Read`, `Bash`, `Grep`, `WebFetch`, `Write`, the
Agent tool, and every MCP tool. The hook sits at the tool boundary. It is not
a list of tool names.

## Detection

`hooks/rules.ts` holds 138 patterns across six groups: builtin, llm, cloud,
chat, git, and devtools. Every pattern starts with a distinctive prefix. There
are no allowlists and no anchors, so detection works the same way in JSON
bodies, in file contents, and in bare tokens.

`osm` uses two layers.

- Registered secrets are the exact-match layer. `osm` reads them from the
  `.env` files of the session at `session.start`. A value qualifies on two
  grounds. If its name reads like a credential name, for example `*_KEY` or
  `*_TOKEN`, `osm` registers it. If a pattern matches its shape, `osm`
  registers it. `PORT=3000` stays readable to the model.
- Detection rules are the best-effort layer. `osm` applies them to every tool
  result and to every prompt.

## Options

These are the plugin options and their default values.

```json
{ "entropy": false, "entropyThreshold": 4.0, "entropyMinLen": 24,
  "envFiles": [".env", ".env.local"] }
```

`entropy` turns on a Shannon entropy test for tokens that no pattern matches.
It is off by default. On ordinary prompt text that test reports hashes, base64
blocks, and git commit ids as secrets.

## Layout

| Path | Holds |
| --- | --- |
| `.claude-plugin/plugin.json` | The plugin manifest |
| `hooks/hooks.json` | Names the hooks module |
| `hooks/register.ts` | The five hooks |
| `hooks/rules.ts` | The 138 detection patterns |
| `hooks/detect.ts` | The scanner and the entropy test |
| `hooks/vault.ts` | The fake generator and the two-way map |
| `tests/` | Hook tests for `claude plugin test` |
| `scripts/local-e2e.sh` | The end-to-end runner for your own machine |
| `scripts/sandbox-e2e.sh` | The end-to-end runner for a disposable box |
| `types/claude-code.d.ts` | The vendored engine declarations |

## Design

The vault is the session. A vault is an in-memory map from a secret to its
fake. A secret maps to a fake through this map and not through reversible
math. Restoring a secret is a lookup. The map dies with the process, so there
is nothing to encrypt and no passphrase to enter.

The hooks fail closed. The engine skips a hook that throws an error and runs
its own code instead. For a masking hook that behavior is worse than no hook
at all. So each hook catches its own errors. An unmaskable result is denied.
An unmaskable prompt is dropped.

A rewrite drops `ref`. `next(e)` returns a `ref` value that names the messages
the engine already built for the call. If a hook returns that `ref`, the
engine uses those messages as they are, without the masking. A rewritten
result answers without `ref`.

A fake is never masked twice. A fake matches the detection patterns by design,
because it keeps the format of the real secret. So `mask()` skips any value
that the vault already knows as a fake.

## Tests

```sh
claude plugin test .          # the hook tests
npx tsc -p tsconfig.json      # type-check the hooks and the tests
bash scripts/local-e2e.sh     # a real end-to-end run on your own account
```

`scripts/local-e2e.sh` writes a fixture to a temporary directory, runs three
headless passes, and prints a verdict for each check. Run it inside `tmux`,
because each pass takes a minute.

```sh
tmux new-session -d -s osmtest 'bash scripts/local-e2e.sh 2>&1 | tee /tmp/osm.log'
tmux capture-pane -p -t osmtest
```

`scripts/sandbox-e2e.sh` runs the same round trip in a disposable Linux box
against OpenRouter. Its header holds the command.

## Known limits

- The fake stays on screen. `turn.complete` can add text under an answer, but
  it cannot rewrite the answer. When Claude writes "your key is `sk-ant-…`",
  you read the fake. The model never held the real key, so this is a display
  problem only.
- A partial fake does not restore. Restoration swaps a whole fake, byte for
  byte. If the model repeats only the first characters of a fake, those
  characters stay.
- Unmasking into `Bash` is real, by design. The fake becomes the real
  credential on its way into the tool. If a command sends that value to a
  third party, it sends the real one.

## License

MIT. See [LICENSE](LICENSE).
