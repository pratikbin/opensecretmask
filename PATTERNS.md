# Secret patterns: sources and verification

Research date: 2026-10-16. Searches used `cfsearch`; source reads used direct
HTTP. No Firecrawl execution or scanner dependency is part of this change.

## Scope and compatibility

26 additions take osm from 149 to **175 rules in six groups**. Three existing
patterns also change: OpenAI service keys accept underscores, and GitLab PATs
and runner credentials include routable suffixes instead of masking their heads.

The existing generic rules, capture exclusions, entropy defaults, hooks and
persistence behavior remain unchanged. Broad new JSON/YAML/TOML credential-field,
header, registry, CLI-password and signed-URL rules were evaluated but deferred.
They added matches to upstream negatives and could mask ordinary configuration
or source code. An unprefixed Entra client-secret heuristic was deferred too.
There are **no new false-positive baseline exceptions**.

All new literal-prefix rules require a leading word boundary. `literalPrefix()`
now skips that zero-width assertion, so the scanner still gates on the vendor
prefix and the fake keeps it. A suffix boundary prevents partial matches of
longer token-like values. Tests also cover sentence-ending periods: a dot must
not hide a valid GitLab key or become part of a Buildkite credential.

## Research references

| Reference | What was compared |
| --- | --- |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Offline vendor regexes, context, entropy and negative fixtures |
| [TruffleHog](https://github.com/trufflesecurity/trufflehog) | Detector coverage and detection versus network verification; no detector code copied |
| [GitGuardian catalog](https://docs.gitguardian.com/secrets-detection/secrets-detection-engine/detectors/supported_credentials) | AI, infrastructure and generic credential families |
| [GitHub supported patterns](https://docs.github.com/en/code-security/reference/secret-security/supported-secret-scanning-patterns) | Provider formats, generic patterns and paired credentials |
| [detect-secrets](https://github.com/Yelp/detect-secrets) | Keyword/entropy approaches and baselines |
| [Secretlint](https://github.com/secretlint/secretlint) | Formats and boundary tests, including Tailscale negatives |
| [Trivy](https://aquasecurity.github.io/trivy/latest/docs/scanner/secret/) | Infrastructure/configuration scanning and custom rules |
| [Nosey Parker](https://github.com/praetorian-inc/noseyparker) / [Titus](https://github.com/praetorian-inc/titus) | Pattern/fixture comparison; Nosey Parker directs users to Titus |
| [OpenRouter secret formats](https://openrouter.ai/docs/guides/features/guardrails/secret-formats) | AI-provider format cross-check |

Repository scanners can inspect filenames, files and history. Osm scans strings
at the model boundary, including strings outside Git. A filename allowlist could
hide a credential a model is about to read. Network verification would add hook
latency and send a credential to another endpoint. Osm keeps detection offline
and synchronous.

## Added formats and evidence

| Group | Additions | Sources |
| --- | --- | --- |
| AI/agents, 6 | OpenRouter `sk-or-v1-`, OpenAI `sk-admin-`, Langfuse `sk-lf-`, Tavily `tvly-`, Firecrawl `fc-`, E2B `e2b_` | [OpenRouter catalog](https://openrouter.ai/docs/guides/features/guardrails/secret-formats), [Langfuse generator](https://github.com/langfuse/langfuse/blob/main/packages/shared/src/server/auth/apiKeys.ts), [Tavily docs](https://docs.tavily.com/documentation/api-reference/introduction), [Tavily reference pattern](https://github.com/praetorian-inc/noseyparker/blob/main/crates/noseyparker/data/default/builtin/rules/tavily.yml), [client prefix handling](https://github.com/hekmon/tavily/blob/main/client.go), [Firecrawl reference pattern](https://github.com/praetorian-inc/noseyparker/blob/main/crates/noseyparker/data/default/builtin/rules/firecrawl.yml), [E2B generator](https://github.com/e2b-dev/infra/blob/main/packages/shared/pkg/keys/key.go) and [prefix](https://github.com/e2b-dev/infra/blob/main/packages/shared/pkg/keys/constants.go) |
| Cloud/network, 10 | Five Tailscale key types; Fly.io `fo1_`, `fm1a_`, `fm1r_`, `fm2_`; modern Azure DevOps PAT | [Tailscale prefixes](https://tailscale.com/docs/reference/key-prefixes), [Azure DevOps PATs](https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/use-personal-access-tokens-to-authenticate), [Gitleaks at the audited revision](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml) |
| Developer/CI, 10 | SonarQube `squ_`, `sqp_`, `sqa_`; Harness `pat.`, `sat.`; Buildkite `bkct_`, `bkar_`, `bkaa_`, `bkaj_`, `bkjat_` | [Gitleaks rules](https://github.com/gitleaks/gitleaks/blob/b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b/config/gitleaks.toml), [Buildkite token types](https://buildkite.com/docs/platform/security/tokens) |

Tavily uses a 32-alphanumeric body, matching the reference scanner's shape;
optional `dev-` and `prod-` prefixes come from provider/client documentation.
The provider does not promise that width for every future key. Tailscale and
Buildkite use bounded body lengths because provider docs establish prefixes but
do not promise a single width for all key types. These rules are conservative
masking heuristics, not live-provider validity checks.

## Deliberate limits

- A bare unprefixed UUID, hash or arbitrary password does not establish a
  vendor. Existing registration/context mechanisms remain available. This
  change does not claim standalone coverage for Cohere, Mistral, DeepSeek,
  Exa, Browserbase, Brave, Jina, Daytona or other ambiguous formats.
- Public keys and publishable IDs must remain readable. Capture exclusions
  apply to heuristic captures; explicit `.env` registration is a separate
  source of truth.
- The scanner sees string leaves, not their enclosing object keys.
  Secret-shaped JSON property names remain outside scope.
- Arbitrary base64 is not evidence of a credential. This change does not
  decode Kubernetes `Secret.data`, Docker `auth`, archives or binary payloads.
- MCP has no universal secret prefix. OAuth/provider credentials use the
  existing token/context rules or exact registration.
- No PII expansion, network credential validation or file/history crawler
  was added.

## Regression gates

```sh
bun run scripts/unit-check.ts
bun run scripts/corpus-check.ts
bunx --yes --package typescript@7 tsc -p tsconfig.json
claude plugin validate .claude-plugin/plugin.json
claude plugin test .
```

`pattern-fixtures.ts` generates **31 positive cases and 47 decoy lines** without
storing complete keys in source. `pattern-check.ts`, called by `unit-check.ts`,
adds **372 checks** for extraction, gates, JSON, shape/length, remembered bare
values, restoration, prefix preservation, malformed values and punctuation.
Together with the original 193 checks, that is **565 unit checks**.

A per-fixture comparison with the pre-change scanner found no lost previously
detected positive and no newly matched negative. The corpus baseline rises
from 237 to 240 of 579 positives and from 39 to 44 of 56 positive documents.
The negative gate passes 1,863 cases plus 35 clean documents. The old GitLab
runner difference `75e5aa4bfa08` no longer matches; removing it reduces known
differences from 117 to 116. No exceptions were added.

## Haiku 5.5 in local tmux

This costs model calls. Use an authenticated Claude CLI and a fresh temporary
folder, with persistence off. Run the negative file first so previous vault
registrations cannot alter it. The control intentionally sends only fabricated
credentials without masking. Do not use real credentials as fixtures.

Use model ID [`claude-haiku-5-5`](https://platform.claude.com/docs/en/models/haiku-5-5/overview).
The terminal matters: `/osm-secrets` writes UI logs, not model-facing output.
The helper is plain Bun-compatible JavaScript so it needs no Node type package;
plugin implementation and offline fixtures remain TypeScript.

From the repository root:

```sh
P="$PWD"
D=$(mktemp -d /tmp/osm-patterns.XXXXXX)
S="osm-patterns-$$"
bun run scripts/pattern-live.mjs prepare "$D"
tmux new-session -d -s "$S" -x 240 -y 100 -c "$D"
tmux new-window -t "$S" -n control-wire -c "$P" \
  "WIRE_PORT=18188 WIRE_OUT='$D/control-wire' bun run scripts/wire-recorder.ts"
tmux new-window -t "$S" -n plugin-wire -c "$P" \
  "WIRE_PORT=18189 WIRE_OUT='$D/plugin-wire' bun run scripts/wire-recorder.ts"
```

Wait until the recorders announce their ports. Run the control in the temporary
directory (through a tmux window if desired):

```sh
cd "$D"
printf '%s\n' 'Read positive.txt completely with Read. Do not quote values. Reply CONTROL_DONE.' |
  ANTHROPIC_BASE_URL=http://127.0.0.1:18188 claude -p \
    --model claude-haiku-5-5 --safe-mode --strict-mcp-config \
    --tools Read --allowedTools Read --output-format json --max-budget-usd 2 \
    > control.json
```

Launch an interactive plugin session in the same temporary directory. The
shipped configuration has persistence off, and this folder contains no `.env`:

```sh
tmux new-window -t "$S" -n plugin -c "$D" \
  "ANTHROPIC_BASE_URL=http://127.0.0.1:18189 claude --model claude-haiku-5-5 \
   --plugin-dir '$P' --setting-sources '' --strict-mcp-config --tools Read,Bash \
   --allowedTools Read 'Bash(grep *)' --permission-mode dontAsk"
tmux attach -t "$S:plugin"
```

Approve trust for this temporary folder only. Confirm the start line says 182
rules. Submit these steps individually, waiting for each turn to finish:

1. Ask Claude to read `negative.txt` completely, inspect no other files and reply
   `NEGATIVE_DONE` without quoting values. Enter `/osm-secrets`. It must say
   `no secrets masked yet this session`. Detach and capture:
   `tmux capture-pane -p -t "$S:plugin" > "$D/negative-pane.txt"`.
2. Ask Claude to read `positive.txt` completely, take the value on `CASE_1`, and
   run `grep -F -c -- "<observed value>" positive.txt`. Ask it to reply
   `RESTORE_COUNT=<count>` and `POSITIVE_DONE`, without quoting credentials.
   Capture the completed turn as `positive-turn.txt` using the same command.
3. Enter `/osm-secrets` again. It must report 31 secrets. If necessary, resize
   the window with `tmux resize-window -t "$S:plugin" -y 400` to keep the
   ledger header visible. Capture it as `positive-pane.txt`.

Finally:

```sh
bun run "$P/scripts/pattern-live.mjs" verify "$D" > "$D/verdict.jsonl"
tmux kill-session -t "$S"
```

The verifier checks the originals in the control, Haiku 5.5 on each plugin
request, absence of originals from plugin requests, same-shaped replacement
lines, unchanged decoys, an empty then 31-entry ledger, and restoration. It
checks the actual grep tool call used the observed fake and its tool result
was one match, in addition to the model's report. Missing artifacts and failed
assertions exit nonzero. Output contains counts/verdicts, not credentials;
request recordings omit authentication headers.
