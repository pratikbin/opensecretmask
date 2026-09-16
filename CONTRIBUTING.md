# Contributing to osm

The most useful contribution is a new detection rule. The bar is one rule, one
line, one test. This guide covers that first, then the rest of the project.

## Setup

You need [bun](https://bun.sh) to run the checks, and Claude Code 2.1.272 or
newer to run the plugin.

```sh
git clone https://github.com/pratikbin/opensecretmask
cd opensecretmask
bun run scripts/unit-check.ts
bun run scripts/hook-check.ts
npx --yes --package typescript@5 tsc -p tsconfig.json
```

There is no build step and no dependency to install. The hooks are TypeScript
that the engine loads directly.

To try your change against a real session:

```sh
cd ~/some-project
CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1 claude --plugin-dir /path/to/opensecretmask
```

## The one invariant

**A fake looks exactly like the real thing.** Same vendor prefix, same length,
same character classes. Never `[REDACTED]`, never a hash, never a placeholder.

An opaque token changes how the model reasons about the value. A same-shaped
fake preserves the plan the model would have made. A change that breaks this is
not a trade-off to discuss. It is the reason the project exists.

## Adding a detection rule

### 1. Pick the file

| File | Holds |
| --- | --- |
| `hooks/detect/rules/builtin.ts` | The common vendors and every shape or context rule |
| `hooks/detect/rules/llm.ts` | Model providers |
| `hooks/detect/rules/cloud.ts` | Cloud, hosting and observability |
| `hooks/detect/rules/chat.ts` | Chat platforms and webhook URLs |
| `hooks/detect/rules/git.ts` | Git platforms |
| `hooks/detect/rules/devtools.ts` | Everything else a developer signs into |

Pick by where a reader would look for it. Nothing else depends on the choice.
Adding a whole new group is one file plus one line in `rules/index.ts`.

### 2. Write the rule

```ts
rule('Vendor Token', 'critical', /vnd_[A-Za-z0-9]{32}/g)
```

The arguments are the display name, the severity, the pattern, and an optional
capture-group index.

**The pattern must carry the `g` flag.** The scanner uses `matchAll`.

**Do not anchor the pattern.** No `^`, no `$`, no `\b` at the start. A rule has
to match inside a JSON body, inside file contents and in a bare token. Anchors
break at least one of those.

**Start with a literal prefix when the vendor has one.** `literalPrefix()` in
`hooks/detect/prefix.ts` reads the fixed text a pattern must begin with, and
that prefix does two jobs. It gates the scan, so 146 rules cost one regex match
instead of 146. And `garble()` keeps it verbatim, so the fake stays
recognizable as that vendor's key. For the Anthropic rule the prefix is
`sk-ant-`, which is why `sk-ant-` survives and `api03` becomes something else.

A rule with no literal prefix runs against every string. That is acceptable for
a shape rule such as a JWT, and wasteful for a vendor that has a prefix you did
not write into the pattern.

**Use a capture group when the match carries context.** The fourth argument is
the group index that holds the credential itself, and only that group is
masked.

```ts
// Only the password is masked, so the DSN stays a valid DSN.
rule('Connection String Password', 'critical',
  /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/@:]{1,80}:([^\s/@]{3,200})@/gi, 1)
```

**Severity** is `low`, `medium`, `high` or `critical`. Nothing filters on it
today. It documents what the value unlocks: `critical` for a credential that
acts on an account, lower for an identifier.

**Order matters.** When two rules claim the same value, the first one in
`RULES` wins, so a specific vendor rule must come before a generic shape.

### 3. Avoid the false positive

Before you send the rule, ask what else has that shape. A 32-character hex
string is also a git object id. A `pk_` prefix is a Stripe *publishable* key,
which is public by design and must stay readable.

`hooks/detect/suppress.ts` holds the shapes that must survive: git SHAs, UUIDs,
digit runs, and public object ids. A value in that set is masked only when a
credential name sits immediately to its left. If your rule needs the same
treatment, add the shape there rather than making the pattern more clever.

### 4. Test it

Add both directions to `scripts/unit-check.ts`: one string that must be masked,
and one look-alike that must not be.

```ts
hit('Vendor token', 'vnd_' + 'a'.repeat(32))
keep('a vendor docs URL', 'https://vendor.example/docs/vnd_format')
```

Then run the checks:

```sh
bun run scripts/unit-check.ts
npx --yes --package typescript@5 tsc -p tsconfig.json
```

Use a fabricated value. Never put a real credential in a test, a commit or an
issue, even a revoked one.

### 5. Update the counts

The rule total appears in `README.md` and in `CLAUDE.md`. Both say 146 today.

## Working on the hooks

Two engine behaviors shape every hook in this repository. Neither is a style
choice. Each one caused a bug.

**A skipped hook fails open.** The engine skips a hook that throws *or*
overruns its budget and runs its own code in that place, which sends the
unmasked content to the model. So every hook catches its own errors and denies
or drops. Use `guard()` from `hooks/policy/budget.ts`, and never wrap a
`next()` call in it: that charges every hook beneath us to our budget, and a
slow unrelated plugin then makes `osm` drop your prompt.

**`ref` pins the unmasked messages.** `next(e)` returns a `ref` that names the
messages the engine already built. Return that `ref` and the engine uses those
messages, which are the unmasked ones. A rewritten result must answer without
it. `hooks/policy/boundary.ts` is the one place that strips it.

**`$` never crosses an import boundary.** The engine's validator follows `$`
only inside the file that declares the function. Passing `$` to a function from
another module makes `claude plugin validate` reject the whole module, and then
no hook loads at all and the plugin silently does nothing. Build the adapter in
the file that uses it.

Run `claude plugin validate .claude-plugin/plugin.json` before you send a hook
change. Pass the manifest and not the directory. This repository also holds
`.claude-plugin/marketplace.json`, and a directory that has one validates the
marketplace alone and never reads the hooks, so `validate .` would pass while
the module is broken. The `noload` scenario in `scripts/scenario-e2e.sh`
guards this.

## Tests

| Command | Covers | Needs |
| --- | --- | --- |
| `bun run scripts/unit-check.ts` | Detection, vault, `.env`, persistence, budget | bun |
| `bun run scripts/hook-check.ts` | The six hooks, through a fake engine | bun |
| `npx --yes --package typescript@5 tsc -p tsconfig.json` | Types | npx |
| `claude plugin validate .claude-plugin/plugin.json` | The engine accepts the module | Claude Code |
| `bash scripts/local-e2e.sh` | One round trip against a real model | Claude Code, money |
| `bash scripts/scenario-e2e.sh` | Every channel and the fail cases | Claude Code, tmux, jq, money |
| `cos offload … 'bash /work/scripts/sandbox-scenarios.sh'` | The same matrix in a disposable box | CreateOS, OpenRouter |

The first four are the ones a pull request must pass. The last two cost real
model calls, so run them when you change a hook rather than a rule.

`npx typescript@5 tsc` fails with "could not determine executable to run". The
package's bin is named `tsc`, so `--package` is required.

## Pull requests

- One logical change per pull request.
- Conventional commit subjects: `feat(detect): add Vendor token rule`.
- Say what you ran. "52 unit checks pass" is enough for a rule.
- No real credentials anywhere, including in the commit message.

## Reporting a leak

If you find input that makes the plugin hand a real credential to the model,
open a GitHub issue that describes the *shape* of the input. Do not include the
real value. A fabricated value with the same format is what the fix needs.
