# External review assessment

This file records how the supplied external review was incorporated. Feedback
was not accepted by consensus; each claim was checked against the current
working tree.

## Incorporated

| External point | Decision | Where incorporated |
| --- | --- | --- |
| The MITM proxy fits a local, proxy-routed, single-user trust boundary | Accept, with explicit limits | [Security and product prerequisites](SECURITY-PREREQUISITES.md) |
| `THREAT_MODEL.md` describes the old hook/HMAC/plaintext-file design | Accept; P0 documentation defect | [Security and product prerequisites](SECURITY-PREREQUISITES.md) |
| Coverage excludes bypassed transports and non-configured hosts | Accept | [Security and product prerequisites](SECURITY-PREREQUISITES.md) |
| Headers are not masked | Accept as deliberate constraint, not forwarding bug | [Security and product prerequisites](SECURITY-PREREQUISITES.md) |
| Explicitly out-of-scope paths are forwarded unmasked | Accept | [Security and product prerequisites](SECURITY-PREREQUISITES.md) |
| Shared daemon retains an unlocked store after a wrapped child exits | Accept within same-user local model | Candidate 1 and security prerequisites |
| Listener exposure needs a stronger security decision | Accept and strengthen: the proxy can become a general CONNECT proxy, and dashboard reveal routes can return originals | [Security and product prerequisites](SECURITY-PREREQUISITES.md) |
| `proxy.Provider` and `detect.Provider` name different concepts | Accept as contributor friction; low-priority rename | This assessment |
| `cmd/osm` owns too much runtime and lifecycle wiring | Already covered | Candidates 1 and 2 |
| Stored request bodies remain sensitive | Accept | Candidate 3 and security prerequisites |

## Incorporated into existing candidates

### Proxy request transformation

The external review correctly located Anthropic-specific opaque-field
preservation in the generic proxy package. It did not identify a second
provider-specific transformation, so it does not yet justify a dialect adapter
or callback interface.

The earlier request-transformation candidate was removed after a stricter
deletion test. Deleting the proposed module would move one `MaskBody` call, one
conditional, and one call to the existing deep helper back into the sole
production caller. Keep the helper; add a full proxy round-trip test that proves
opaque preservation and history-capture policy. Revisit module depth only when
a second caller or a second provider-specific orchestration appears.

### Request history

Candidate 3 now treats body-capture level as policy, not an incidental storage
detail. Mask-eligible matches are replaced, but detection can miss credentials
and restored opaque fields can retain original matched bytes. Prompts and PII
also remain.

### Daemon lifecycle and runtime

The external `cmd/osm` observation is not a fourth candidate. Candidate 1 owns
daemon state and readiness; Candidate 2 owns process resource construction and
shutdown. An additional `internal/app` package would overlap both unless
grilling finds a distinct invariant.

## Deferred or rejected

### Add `mask.PostProcess` or a dialect adapter now

**Deferred.** The location problem is real; the proposed interface is
premature. `internal/mask` is intentionally provider-dialect-agnostic, and only
one concrete provider repair exists. Moving Anthropic knowledge into a generic
mask callback would weaken that module's contract.

Trigger for reconsideration: a second provider requires a different,
demonstrated post-mask invariant.

### Add structured provider schemas alongside byte fallback

**Rejected for current scope.** `MaskBody` already walks JSON string leaves and
falls back to byte masking for non-JSON bodies. One demonstrated opaque-field
exception already has a focused helper. Provider-schema adapters would create an
N-provider maintenance surface without evidence that the current approach
breaks additional provider payloads.

Trigger for reconsideration: captured provider-valid payloads show at least two
distinct structural invariants that byte/JSON-leaf masking cannot preserve.

### Unify interception and detection in one `Policy` object

**Rejected as proposed.** The same type name hides different axes:

- `proxy.Provider` selects exact upstream hosts, labels a dialect, and may scope
  request paths (`internal/proxy/proxy.go:23-33`);
- `detect.Provider` supplies named secret-detection rules
  (`internal/detect/provider.go:3-23`).

Combining them would couple transport routing to secret classification. Entropy
is also detector behaviour, while fail-closed handling is transport safety
policy. Candidate 2 may centralize runtime construction without pretending
these independent policies are one domain object.

A surgical future rename such as `proxy.InterceptRule` could reduce grep and
onboarding ambiguity. It is not a deepening candidate by itself.

### Add hooks, WebSocket interception, or SDK middleware

**Deferred to product scope.** These are valid alternative coverage planes, not
automatic extensions of the proxy module. Each sees different data and has
different bypass and lifecycle risks. First decide whether `osm` promises
proxy-only protection or multi-plane protection.

### Create another response/unmask module

**Rejected.** Existing streaming reversal already owns split-chunk buffering
behind a small interface. The partial-mask item is a documented UX limitation:
the model may echo a mask prefix that cannot be mapped back, but it still never
saw the original. No cross-caller architectural friction was demonstrated.

## Corrections to the supplied review

### Unmask is not O(1)

Stable mask creation and original recovery use store-backed records, but
response reversal does not perform one O(1) lookup. `UnmaskBody` sorts the
secrets used by the exchange, then performs `bytes.Contains` and potentially
`bytes.ReplaceAll` for each one (`internal/mask/masker.go:257-277`). Roughly,
the work is `O(S log S + S*B)` for `S` used secrets and body size `B`.

### Listener and dashboard risk was understated

Persisted bodies are capped, but only mask-eligible content is guaranteed to be
transformed; restored opaque fields can remain original. Unauthenticated reveal
routes can also decrypt and render mapped originals. The dangerous combination
is not merely “masked prompts on a debug port”: arbitrary dashboard binding
exposes both views, while arbitrary proxy binding creates an unauthenticated
general CONNECT proxy.

### Response cap needs qualification

The 512 MiB cap is not applied to every response. It is applied to buffered,
non-SSE responses only when the corresponding request used secrets. SSE uses a
streaming reader and does not accumulate the whole response.

### Header claim is a coverage constraint

The proxy body transformer leaves headers alone. That is necessary for the
provider's real authentication credential and is not evidence of broken header
forwarding. The security contract must avoid the broader claim that every
credential is removed from all wire data.

## Positive findings retained

The source supports the external review's positive observations:

- fail-closed request masking;
- JSON string-leaf masking with raw-byte fallback;
- pure detection-provider values;
- exact-host CA-MITM with untouched tunnelling elsewhere;
- shared daemon serialization through a lock and pidfile;
- per-process CA trust;
- encrypted originals with stable format-shaped masks;
- unit, integration, and CA-MITM round-trip test layers.

These remain constraints, not reasons to freeze the architecture.
