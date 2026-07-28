# Architecture review evidence

## Snapshot and worktree

- Reviewed commit: `240a2148a7eb8c0ee488a35951fa4c07e115ebd4`.
- Branch at review time: `recovered-may23`, ahead of its upstream.
- The worktree was already dirty. Pre-existing changes included
  `.tool-versions`, `CLAUDE.md`, `go.mod`, `go.sum`, four detection rule files,
  and `internal/detect/detect_test.go`.
- New review artifacts are additive. The accompanying `.gitignore` and
  `README.md` edits publish and link them; no pre-existing dirty source change
  was modified.

Because the current detection expansion was uncommitted, this review examined
both `HEAD` and the working tree. Source line references point to the working
tree as reviewed on 2026-07-28.

## Method

1. Read `CLAUDE.md` as the current architecture and domain map.
2. Confirmed that `CONTEXT.md` and `docs/adr/` are absent.
3. Read the threat model, original design documents, modular detection plan,
   test-coverage plan, and test audit.
4. Walked 80 commits to identify repeated-change areas.
5. Inspected current source and tests around detection, daemon lifecycle, proxy,
   mask, store, and dashboard.
6. Applied the deletion test to each candidate.
7. Rejected splits that would add hypothetical seams with only one adapter.
8. Delegated an independent read-only exploration and reconciled its ranking
   with the primary inspection.

## Recent-change evidence

Across the most recent 80 commits, frequently changed current files included:

| File | Changes |
| --- | ---: |
| `internal/detect/detect_test.go` | 8 |
| `internal/store/store.go` | 6 |
| `internal/proxy/proxy.go` | 6 |
| `internal/mask/masker_test.go` | 6 |
| `internal/detect/provider.go` | 6 |
| `cmd/osm/root.go` | 6 |
| `internal/store/store_test.go` | 5 |
| `internal/store/secrets.go` | 5 |
| `internal/proxy/proxy_test.go` | 5 |
| `internal/mask/masker.go` | 5 |
| `cmd/osm/status.go` | 5 |
| `cmd/osm/run.go` | 5 |

Relevant history:

- Detection: `35d0f76`, `2922d58`, `e418b3e`, `3456f11`, `9111071`,
  `dbfddd5`, `6265e47`.
- Daemon lifecycle: `4d043ce`, `5b3e5fa`, `7d17bff`.
- Proxy: `4d043ce`, `5b3e5fa`, `6265e47`, `df6f761`.
- Request history: `5b3e5fa`, `6265e47`, `df6f761`, `69fc302`,
  `38c988c`, `240a214`.

Commit frequency is a scope signal, not proof of bad architecture. Candidates
were kept only when current source and tests also showed low locality or a
shallow interface.

## Evidence matrix

| Candidate | Current friction | Deletion-test result | Test-surface evidence |
| --- | --- | --- | --- |
| Daemon lifecycle | State protocol crosses `daemon.go`, `run.go`, `restart.go`, `dashboard.go`, and `proxy.go`. | Process, pidfile, flock, health, poll, and restart logic spread across four callers. | `cmd/osm/run_test.go:75-137` uses real fork-exec, sleeps, and a 15-second deadline. |
| Proxy-process runtime | Cobra closure owns construction, two listeners, pidfile, serving, and shutdown. | A genuinely deep runtime deletion spreads resource ownership back into Cobra. | Proxy and dashboard are tested separately; combined lifecycle is integration-only. |
| Request history | Capture, queue, transaction, codec, retention, and presentation policy cross three packages. | Individual helper deletion moves policy to adjacent callers; no single deep module exists. | Tests are separated by proxy/store/dashboard and do not exercise admission-to-retention as one interface. |

## Accepted constraints

The review does not reopen these documented choices:

- byte-level, provider-dialect-agnostic masking;
- stable format-shaped masks backed by store lookup;
- registered secrets as the exact-match layer within mask-eligible fields;
- fail-closed request masking;
- authentication headers are intentionally outside body masking;
- exact-host proxy interception;
- loopback listener defaults, with non-loopback listener binding treated as an
  unresolved security prerequisite rather than an enforced invariant;
- per-process CA trust rather than system trust;
- SQLite with encrypted originals;
- prefix-distinctive, stateless detection rules;
- the `detect.Provider` composition seam.

## Rejected candidates

### Split `Store` into repository adapters

Rejected. The current store module hides substantial SQLite, encryption, cache,
transaction, and codec implementation. There is one SQLite adapter. Additional
repository interfaces would be hypothetical seams and reduce depth.

### Split dashboard handlers into many modules

Rejected. `dashboard.Server` already has a small interface and a substantial
implementation. Handler extraction would mostly move code without increasing
leverage.

### General provider-dialect request parsing

Rejected. Current masking intentionally operates on decoded string leaves
rather than maintaining full schemas for every upstream provider. One focused
proxy helper protects the demonstrated byte-fragile exception.

### Create a proxy request-transformation module

Rejected after a stricter deletion test. There is one production caller,
`internal/proxy.Server.onRequest`, composing one `MaskBody` call, one
conditional, and one call to the existing deep `preserveOpaqueBlocks` helper.
Deleting a wrapper would not spread complexity across callers. Keep the helper
and add a full proxy round-trip test for opaque-field preservation and history
capture. Reconsider only when a second caller or different provider-specific
orchestration appears.

### External rule configuration or allowlists

Rejected. The accepted modular detection plan explicitly excludes them, and
live-traffic masking has a different false-positive budget from repository
scanners.

### Deepen detection providers with adjacent tests and provenance

Rejected as an architecture candidate. Current provider adapters are shallow,
and the dirty worktree shows poor test locality, but moving cases into
per-domain `_test.go` files does not add leverage through the `Provider`
interface. Treat that as a focused test-organization improvement. Revisit
depth only when provider construction has demonstrated behaviour to hide, such
as invariants required by more than one real adapter.

### Create an unmask substitution-plan module

Rejected as an architecture candidate. Batch and streaming implementations
duplicate a small amount of ordering and replacement logic, but they do not
satisfy one interface at a shared seam. Prefer a shared internal helper plus a
batch-versus-stream parity test. Introduce a module only if another response
path proves broader leverage.

### Add a provider-dialect callback now

Deferred. Anthropic opaque-field preservation is the only demonstrated
provider-specific post-mask behaviour. The existing proxy helper keeps that
exception local without adding a callback seam. A callback or adapter becomes
justified only after a second provider demonstrates different behaviour.

### Unify `proxy.Provider` and `detect.Provider` as one policy

Rejected. The proxy type selects interception hosts and paths; the detect type
supplies secret-classification rules. Combining independent transport and
detection axes would reduce cohesion. Candidate 2 may centralize their
construction without inventing one shared domain object.

## External review verification

The supplied external review was checked claim by claim. Full decisions are in
[External review assessment](EXTERNAL-REVIEW-ASSESSMENT.md); security findings
are in [Security and product prerequisites](SECURITY-PREREQUISITES.md).

Material corrections:

- stable masks are store-backed, but response reversal is not O(1);
  `UnmaskBody` scans the response for each secret used by the exchange;
- dashboard history stores capped masked bodies, but unauthenticated reveal
  routes can return plaintext originals;
- the 512 MiB response cap applies only to buffered non-SSE responses when
  masking used a secret;
- partial-mask streaming is a restoration UX limitation, not disclosure of the
  original;
- opaque Anthropic fields are restored before forwarding and history capture,
  so matched bytes inside them can remain original;
- `proxy.Provider` and `detect.Provider` name distinct concepts, but a combined
  policy object would couple independent axes.

## Verification record

The architecture documents themselves are verified by:

- Markdown link checks;
- Mermaid fence pairing checks;
- required-section checks for every candidate;
- `git diff --check` for tracked changes;
- `git diff --no-index --check /dev/null <file>` for every new Markdown file;
- an adversarial review of the documentation change set.

The source baseline test suite passed in an ephemeral CreateOS sandbox:

```sh
cos offload -E . \
  'test -e /dev/fd || ln -s /proc/self/fd /dev/fd; asdf install golang 1.26.5 && go test ./...'
```

Result: exit code `0`. All packages under `cmd/osm`, `internal/*`, and
`tests/internal/mockupstream*` built; every package containing tests passed.
The box was destroyed automatically.

Two earlier provisioning attempts did not reach project tests: the first image
lacked the pinned Go version, and the second exposed the image's missing
`/dev/fd` link during asdf checksum verification. The final command above fixed
only that disposable-image compatibility issue and then ran the unmodified
worktree.
