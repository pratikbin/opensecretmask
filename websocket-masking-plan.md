# osm WebSocket secret-masking — implementation plan

## Goal

osm masks outbound secrets and restores them inbound for **WebSocket** traffic,
the same guarantee it gives HTTP today. After this, codex/pi WebSocket transport
is covered instead of silently leaking, and osm's fail-closed promise holds for
WS as well as HTTP.

## Background

- osm today is a goproxy CA-MITM that masks **HTTP request/response bodies** in
  `internal/proxy/proxy.go` (`onRequest` / `onResponse`).
- WebSocket transport bypasses masking completely. pi's
  `packages/ai/src/providers/openai-codex-responses.ts` supports
  `transport: "sse" | "websocket" | "auto"` and connects to
  `wss://chatgpt.com/backend-api/codex/responses`. codex 0.132.0 has a gated
  `responses_websockets` WS transport (path `/responses_websocket`, off by
  default).
- The `response.create` JSON request — which carries the registered secrets —
  travels as WebSocket **frame payload**. osm's body pipeline never sees it.
- Three failure layers today: (1) `chatgpt.com` not in `DefaultProviders` → its
  CONNECT is raw-tunnelled; (2) goproxy raw-copies WS frames after the 101;
  (3) pi's WS client ignores `HTTPS_PROXY`.
- "websocket+cached" is not a separate mode — caching is two body fields
  (`prompt_cache_key`, `prompt_cache_retention`); osm's stable masks keep
  prompt-cache hits intact. No special handling needed.

## Approach — Option C: wrap the WS connection, no goproxy fork

goproxy v1.8.3 MITM mode **already** handles WebSocket upgrades
(`https.go:360-382`):

```go
resp = proxy.filterResponse(resp, ctx)        // <- osm's onResponse runs HERE
...
if isWebSocketHandshake(resp.Header) {
    wsConn, ok := resp.Body.(io.ReadWriter)   // <- picks up whatever Body is
    resp.Body = nil
    resp.Write(client)                        // writes 101 headers only
    proxy.proxyWebsocket(ctx, wsConn, client) // raw io.Copy both directions
}
```

`filterResponse` (osm's `onResponse`) runs **before** the WS check. So osm can
replace `resp.Body` with a frame-masking `io.ReadWriteCloser`; goproxy then
copies through it. `proxyWebsocket` runs two `io.Copy`s — client→server lands on
`wsConn.Write`, server→client on `wsConn.Read` — exactly the two hooks osm
needs. This is the same seam osm already uses to wrap SSE responses with
`mask.NewUnmaskReader`.

**Rejected:** forking goproxy to patch `proxyWebsocket`. Unnecessary — the
body-wrap seam works — and it adds permanent maintenance. Keep as the fallback
only if Phase 0 spikes find a blocker.

## Architecture

- **Providers.** Add `chatgpt.com` to `DefaultProviders` (path scope
  `^/backend-api/codex`). Extend `api.openai.com` paths with
  `^/v1/responses_websocket` for codex API-key WS.
- **Frame codec** — new file `internal/mask/wsframe.go` (or `internal/wsmask/`):
  RFC 6455 frame parse + build. Pure, table-tested.
- **Masking conn** — new `wsMaskConn` implementing `io.ReadWriteCloser`,
  wrapping the upstream WS `io.ReadWriteCloser`:
  - `Write(p)` — client→server. Buffer `p`, parse frames, unmask payload
    (client frames are XOR-masked, RFC 6455 §5.3), defragment to a whole
    message, run `Masker.MaskBody`, re-frame with a fresh masking key, write to
    upstream. Returns `len(p), nil`.
  - `Read(p)` — server→client. Read upstream, parse frames (server frames are
    unmasked), defragment, run `Masker.UnmaskBody`, re-frame, return.
  - Control frames (ping/pong/close, opcodes 0x8–0xA) pass through untouched.
- **Shared secret set.** For HTTP, `onRequest` records `ex.used` and
  `onResponse` consumes it. For WS the request is masked inside `wsMaskConn.Write`
  — *after* `onResponse` already returned — so `Read` (unmask) and `Write` (mask)
  share one mutex-guarded `used` set that grows as client frames are masked.
- **Install point.** `onResponse` detects `isWebSocketHandshake(resp.Header)` +
  status 101 and swaps `resp.Body` for a `wsMaskConn`.
- **permessage-deflate.** `onRequest` strips `Sec-WebSocket-Extensions:
  permessage-deflate` from the handshake so the server returns uncompressed
  frames the codec can read. Avoids shipping a DEFLATE sliding-window codec.

## Phases

### Phase 0 — Spikes (de-risk before building)
- **S1** — Confirm goproxy MITM forwards the WS handshake upstream intact
  (`Upgrade` / `Connection` / `Sec-WebSocket-*` survive `RemoveProxyHeaders`)
  and returns a 101 whose `Body` is an `io.ReadWriteCloser`.
  *Verify:* throwaway test MITM'ing a known `wss://` echo server.
- **S2** — Confirm swapping `resp.Body` for a 101 doesn't corrupt the
  handshake. goproxy forces `Transfer-Encoding: chunked` at `https.go:341` when
  the body changed; `resp.Write` must suppress it for a 1xx status.
  *Verify:* assert the bytes goproxy writes to the client are a clean
  `101 Switching Protocols` with no `Transfer-Encoding` header.
- **S3** — Confirm pi and codex still work with `permessage-deflate` stripped.
  *Verify:* manual run of each with the extension removed.
- *Exit:* all three green → Option C confirmed. Any red → reassess (fork).

### Phase 1 — RFC 6455 frame codec
Parse: FIN, opcode, MASK, payload length (7 / 7+16 / 7+64), masking key, payload.
Build: frame from opcode + payload + (optional) mask key.
*Verify:* table tests — masked/unmasked, all three length forms, control frames,
round-trip parse→build→parse.

### Phase 2 — `wsMaskConn` masking wrapper
Stateful buffering across arbitrary chunk boundaries (TCP reads ≠ frame
boundaries). Message defragmentation across continuation frames (opcode 0x0) —
same tail-hold idea as the SSE unmasker. Mask-key rewrite on the client→server
direction.
*Verify:* unit tests with frames split mid-header and mid-payload; fragmented
message; interleaved control frame.

### Phase 3 — Wire into the proxy
Add the providers; strip `permessage-deflate` in `onRequest`; install
`wsMaskConn` in `onResponse`; thread `Masker` + shared `used` set through.
*Verify:* existing HTTP/SSE tests still green; `go build` + `go test -race`.

### Phase 4 — Fail-closed
On a frame parse error or a `MaskBody` failure, close the WS connection rather
than forward raw bytes. Mirror osm's HTTP fail-closed behaviour.
*Verify:* test feeding a deliberately unmaskable message → connection closes,
nothing leaks.

### Phase 5 — Dashboard / request log
`logExchange` runs once at the 101 today (status 101, 0 masked). Rework WS
logging to record per-message or a summary on connection close, so the
dashboard's request view reflects WS traffic.
*Verify:* dashboard shows a WS exchange with masked-secret count.

### Phase 6 — pi-mono patch (separate repo / PR)
pi's WS uses the native `WebSocket` constructor with no dispatcher, so it
ignores `HTTPS_PROXY` and never reaches osm. Patch `connectWebSocket()` in
`openai-codex-responses.ts` to pass a proxy-aware dispatcher (undici
`EnvHttpProxyAgent`), mirroring how the Bedrock provider already uses
`proxy-agent`. codex needs no change — its reqwest client already honours
`HTTPS_PROXY`.
*Verify:* `pi` with `transport: "websocket"` routed through `osm run` shows
masked traffic in the dashboard.

### Phase 7 — Integration tests + docs
Real WS CA-MITM round-trip test (peer to the existing SSE test); fragmented
message; fail-closed. Update `CLAUDE.md` + `README.md`.

## Risks

- **R1 — goproxy chunked-TE forcing on 101** (`https.go:341`). Phase 0/S2. If
  `resp.Write` emits `Transfer-Encoding` into the 101, the handshake breaks →
  fall back to forking goproxy. goproxy ships a passing `TestWebSocketMitm`, so
  this is likely already safe, but must be proven.
- **R2 — `RemoveProxyHeaders` stripping `Connection`/`Upgrade`** upstream
  (`https.go:328`). Phase 0/S1.
- **R3 — defragmentation correctness.** A secret split across two WS frames
  must still be caught — the tail-hold pattern. Highest-bug-risk code; heavy
  unit tests in Phase 2.
- **R4 — performance.** Per-frame parse + per-message mask on a hot
  interactive path. Keep allocations low; benchmark.
- **R5 — pi-mono is a separate codebase.** Phase 6 is a cross-repo PR with its
  own review/merge cycle; osm Phases 1–5 land independently and cover codex WS
  regardless.
- **R6 — codex WS is off by default.** Phases 1–5 are forward-looking for
  codex; the immediate beneficiary is pi `transport: websocket`/`auto`.

## Out of scope / open questions

- Q1 — Should osm **block** WS upgrades on a provider host until masking ships
  (interim fail-closed), or wait and land masking directly? This plan assumes
  land masking directly.
- Q2 — `internal/mask/wsframe.go` vs a new `internal/wsmask/` package — naming
  / placement preference?
- Q3 — Non-codex WebSocket APIs (e.g. OpenAI Realtime `/v1/realtime` voice) are
  out of scope; this plan targets the Responses-over-WS shape only.
- Q4 — codex's `responses_websockets` is gated; do we add
  `^/v1/responses_websocket` to the openai paths now, or defer until codex
  ships it on by default?
