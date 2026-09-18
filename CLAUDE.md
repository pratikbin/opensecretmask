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
| `hooks/register.ts` | Wiring. One `Vault`, six `register*` calls. No logic. |
| `hooks/options.ts` | `PluginOptions` → typed `Options` |
| `hooks/env.ts` | `.env` parsing, comment- and quote-aware |
| `hooks/events/session-start.ts` | `.env` registration + persistence restore |
| `hooks/events/tool-call.ts` | The round trip, both directions |
| `hooks/events/prompt.ts` | The five channels that carry a prompt to the model |
| `hooks/events/compact.ts` | `session.compact`, what the summarizer reads |
| `hooks/events/agent-spawn.ts` | `agent.spawn`, the subagent boundary |
| `hooks/events/command.ts` | `/osm-secrets`: one bounded `real → fake` line per secret |
| `hooks/vault/index.ts` | The two-way map, and the ledger behind `/osm-secrets` |
| `hooks/vault/garble.ts` | The format-preserving fake |
| `hooks/vault/walk.ts` | Bounded deep traversal, binary-safe |
| `hooks/vault/persist.ts` | `$.store` backing, on by default via the manifest |
| `hooks/detect/index.ts` | The scanner |
| `hooks/detect/prefix.ts` | Literal-prefix extraction |
| `hooks/detect/entropy.ts` | Shannon layer |
| `hooks/detect/suppress.ts` | Entropy scoring; capture-group shapes live in `rules/deny.ts` |
| `hooks/detect/rules/*.ts` | 146 patterns in six groups |
| `hooks/policy/boundary.ts` | `outbound`/`inbound`, where `ref` is stripped |
| `hooks/policy/model-facing.ts` | Arguments that must keep their fakes |
| `hooks/policy/budget.ts` | Failure fallbacks |
| `hooks/status.ts` | The start line and the pinned line, both pure |
| `.claude-plugin/marketplace.json` | The install source for `claude plugin install osm@opensecretmask` |
| `hooks/detect/rules/deny.ts` | What a capture-group rule must refuse |
| `corpus/corpus.json` | Upstream fixtures. Generated; see `THIRD-PARTY.md` |
| `corpus/baseline.json` | What we catch and where we knowingly differ |
| `CONTRIBUTING.md` | How to add a rule. Update its counts when `RULES` grows |

Adding a rule source is one file in `rules/` plus one line in `rules/index.ts`.
No registry, no init-time side effects. Excluding a shape is one line in
`rules/deny.ts`, which is the same directory on purpose: 138 rules match a
whole value and need no exclusions, but eight match a context and take
whatever follows, and what that wildcard must refuse is a property of the
rules, not a heuristic hidden elsewhere.

`types/claude-code.d.ts` (14.6k lines) is the engine's own declaration file
from `/plugin-types`, vendored so CI typechecks without a Claude Code install.
Not our code. `.gitattributes` marks it `linguist-generated`. Refresh it when
the engine API moves: run `/plugin-types` and copy `.claude/types/claude-code.d.ts`
over it. Earlier engine versions also wrote `.keys` and `.names` sidecars beside
it; 2026-09-18's does not, so they are gone rather than left to rot.

## Engine facts that shape the code

These are not style choices. Each one caused a bug.

**A skipped hook fails OPEN.** The engine skips a hook that throws *or
overruns its budget* and runs core in its place. For a masker that is worse
than being absent, so every hook answers for itself via `policy/budget.ts`.

A guard must cover our own work and never a `next()` call. An earlier version
wrapped `next()`, which charged every hook beneath us to our budget — a slow
unrelated plugin made osm drop the user's prompt and blame itself.

Every masking call is synchronous, so `guard` is a try/catch and not a timer.
A `guardAsync` with a real deadline existed for two months and never had a
caller; add one back only when an async hook actually needs it.

**`ref` pins the unmasked messages.** `next(e)` returns a `ref` naming the
messages core already built. Return it and core uses those verbatim — the
unmasked ones. Any rewritten result must answer without `ref`.

**A prompt has five doors, not three.** Beyond the three below, `skill.prompt`
carries a skill's expanded text — skill bodies are files on disk and reach the
model without passing `prompt.context` — and `session.receive` carries a
delivery before it is queued: a relay event, a peer's message, a Remote
Control prompt. That last one is a whole inbound path `prompt.submit` never
sees. Neither answers with a drop: `skill.prompt` owes the engine a prompt, so
it hands back an empty one, and `session.receive` answers `{ consumed }`,
which drops the delivery without queueing it.

**A compaction hands the transcript to a model.** `session.compact` is the one
place where everything the session ever held is read at once and turned into a
summary that survives every later turn. On a healthy session it changes
nothing, because the model only ever saw fakes; it exists so that a secret
arriving through a channel we do not hook cannot be laundered into something
durable. Rewriting a message means surrendering its `handle` — the engine
stands its own copy whole for a message that keeps one — so only the messages
that actually change give it up.

**`claudeMd` rides in `prompt.context`, not `prompt.section`.** Instruction
files land in `prompt.context.blocks` under the name `claudeMd`.
`prompt.section` carries `memory` and friends. Both are needed; hooking only
one leaves a live channel.

**Three model-facing fields on a tool result, not two.** `result`, `text`, and
`context` — the last carries a PostToolUse hook's additional text straight to
the model where the user never sees it.

**An option reaches the plugin only if the manifest declares it.**
`register(on, options)` receives the fields of `.claude-plugin/plugin.json`'s
`userConfig`, and nothing else. Without that block the engine passes `{}`, a
user's `pluginConfigs.osm.options` is ignored, and every option silently uses
its default. Every option here was dead until 2026-09-16 for exactly that
reason. Adding an option means adding it in two places: `hooks/options.ts` and
`userConfig`.

**A `userConfig` default beats the module's own fallback.** The engine fills a
declared option from the manifest before `register()` sees it, so the `??` in
`options.ts` only ever fires for an option the manifest does not declare. The
two disagree today: `persist` reads `false` in `options.ts` and `true` in the
manifest, and the manifest wins — a machine with no `pluginConfigs.osm` entry
still has a populated store. Change a default in one place and the code lies
about itself.

**A capture group is not evidence; a prefix is.** `sk-ant-…` is a key by
construction, but a context-bearing rule takes whatever sits right of
`PASSWORD=`, and the session store showed what that collects: `${DB_PASSWORD}`,
`[MASKED-0001]`, the literal word PASSWORD out of a documented DSN, a UUID, and
this repository's own rule source read back as a value. Only `group > 0`
matches run through `trimCapture` and `isPlaceholder`, and both the raw and the
trimmed form are tested, because trimming removes the very brackets that make a
reference recognisable. Plain hex and digit runs are deliberately NOT
suppressed there: under an explicit credential name they are usually real.

**A restored entry must carry its provenance or every row reads alike.**
`adopt()` once stamped each restored pair `literal / store / now`, so after a
`/reload-plugins` all thirty-four rows of `/osm-secrets` said the same thing at
the same second. `Entry` now carries `rule`, `where` and `firstAt`, and a row
whose store predates them says "earlier session" rather than inventing one.

**The log channel wraps, so a column table is not a table.** `$.ui.log` draws
one line that the terminal folds at its own width, and a ledger row holds a PEM
key with newlines in it. `/osm-secrets` bounds every field and prints one line
per secret instead; an aligned table survived the tests and fell apart on a
real session's 34 entries.

**A command's `{ text }` is model-facing.** `command.run` output lands in the
transcript the model reads, so `/osm-secrets` answers `{}` and draws its rows
with `$.ui.log`, which the engine shows dim and never sends to the model. The
command is declared from `session-start.ts` rather than its own hook, because
`$.command.register` must be called in the file that declares the hook.

**An empty secret is not useless, it is catastrophic.** `mask()` substitutes
with `split`/`join`, and every string contains `""`, so one empty entry cuts
between every character and rejoins them around the fake. A prompt becomes a
wall of one token repeated per character, the engine skips `prompt.context`
and `prompt.section` for size, and the session is unusable until the store is
cleaned — a reload alone does not help, because the entry is re-adopted.

The one that shipped came from the store: `load()` dropped an `env` entry only
when its key read `undefined`, and a key emptied to `KEY=` reads `""`, which is
not `undefined`. `adopt()` took it unguarded.

Three doors lead into the map — `register()`, `maskOf()` and `adopt()` — and
all three now check `MIN_SECRET_LEN`, as does `load()` before it resolves
anything. `register()` always did. `maskOf()` is public and mints on the spot,
so it stayed open until the tests went looking for it.

**The harness must run the shipped configuration.** `hook-check.ts` passed
`{}` to `register()`, so every hook test ran with `options.ts`'s fallback
`persist: false` while the manifest ships `true`. The restore path therefore
never executed under test, and the empty-secret bug — which arrives only
through `load()` — could not be caught at the hook layer however many checks
were added. `seat()` now defaults to the manifest's values. When a default
moves in `plugin.json`, move it there too.

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

**The plugin masks its own development, and a model cannot tell.** osm is
installed on this machine, so a session editing this repo reads every tool
result through osm's own `outbound`. A value registered once — from a fixture
`.env`, from a scenario run, from anything — is replaced in *all* later tool
output, including the source of the plugin itself. A model that reads a
masked file believes the fake is the text, and writes the fake into new code.

That already happened. The word `PASSWORD` was registered as a literal secret,
persisted, and thereafter every occurrence came back as an eight-letter garble
of the same shape. Some session copied it into `env.ts`'s `SECRETISH` and into
`builtin.ts`'s `Environment Variable Secret` rule, then into README and into
every e2e fixture's variable name — self-consistently, which is why no test
caught it. Both regexes still carry it. See Open items.

Two consequences when working here:

- A literal you cannot explain is suspect. Check it against `/osm-secrets` or
  the store before treating it as intentional.
- You cannot type the fake back. An Edit argument goes through `inbound`, which
  restores a fake to its secret, so the file receives the real word and the
  sentence you meant to write changes under you. Name the file and line
  instead of quoting the garble.

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
stores only `{fake, file, key}` plus how it was first found, and never expires, because the secret is
already in `.env` and gets re-read. A `literal` entry stores the value itself
and expires after `retentionDays` (default 120). Only `literal` puts a
previously-transient secret at rest, which is why only it has a window.

The store is `~/.claude/plugins/store/osm_<key>-<hash>.json`, written with mode
644 in a 755 directory. The plugin cannot change either: `$.fs` has no chmod.
README's "Hardening this on a Mac" tells the user to tighten the directories
instead, because the engine rewrites the file.

## Build and test

```sh
bun run scripts/unit-check.ts                          # 117 pure-logic checks
bun run scripts/hook-check.ts                          # 35 hook-level checks
bun run scripts/corpus-check.ts                        # our rules vs upstream fixtures
bun run scripts/fetch-corpus.ts                        # refresh corpus/, needs network
npx --yes --package typescript@5 tsc -p tsconfig.json  # NB: --package, see below
bash scripts/local-e2e.sh                              # real model, 3 passes
bash scripts/scenario-e2e.sh                           # 11 scenarios in tmux, 25 checks
bash scripts/sandbox-e2e.sh                            # real model, throwaway box
```

`npx typescript@5 tsc` fails with "could not determine executable to run" — the
package's bin is `tsc`, not `typescript`. `--package` is required.

`scripts/scenario-e2e.sh` also runs the fail cases, because a masker that
breaks must break closed. `stale` gives the model a fake no vault has minted,
the shape a transcript carries after a resume, and the tool must receive that
dead fake rather than a guess. `broken` runs a sabotaged copy whose `mask()`
throws, and the refusal must come from the plugin: a silent pass means the
engine skipped the hook and served the real result. `validate` and `noload`
need no model and catch the failure with no symptom, where the module is
rejected, no hook loads, and every other scenario quietly reports the
control's answer.

### e2e traps

Five things make a runner look broken when it is not.

- `--allowedTools` is variadic, so a prompt after it parses as a tool name.
  Pass the prompt on stdin.
- A prompt asking the model to write a credential to a file is refused as an
  exfiltration pattern. Observe the restore direction with `grep -c` instead.
- The `Read` tool needs explicit approval for a `.env` file. Put the same value
  in a normal file for the model to read.
- `--plugin-dir` takes the directory holding `.claude-plugin`. From inside the
  clone that is `.`.
- A run writes its fixture credentials into the real host store, because
  `persist` is on by default and `$.store` is per-plugin, not per-fixture. The
  store on a machine that has run the matrix is mostly dead scenario keys, and
  anything registered there keeps being masked in later sessions.

## Open items

- Secret-shaped JSON property *names* are not masked. Values only. Rewriting
  keys needs two-way collision handling for a case that barely occurs.
- A partial fake does not restore; prefix matching needs false-positive guards.
- No PII group. SSN sits in `builtin`. Email/phone/card would have to default
  off, since agent prompts carry user data on purpose.
- A classic hook downstream of us receives the restored value, and the engine
  writes its stdout verbatim into the transcript JSONL. Observed with a
  `PreToolUse` rewriter. Nothing the plugin can do from inside.
- `env.ts:46` and `builtin.ts:102` carry a garble where `PASSWORD` belongs, so
  neither the name test nor the `Environment Variable Secret` rule fires on
  `DB_PASSWORD=` and its siblings. A value with no vendor shape behind such a
  name is not masked at all. The same garble is in README and in every e2e
  fixture's variable name, which is why the suite is green. Fixing it means
  editing the two regexes, the docs, and the fixtures together, and dropping
  the stale entry from the store first — otherwise the word is masked again on
  the way in and the edit does not say what it reads.

## Attribution

Suppression shapes and the binary skip list adapted from
`ray-amjad/awesome-claude-code-function-hooks` (MIT).
