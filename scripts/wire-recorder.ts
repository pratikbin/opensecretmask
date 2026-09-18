// A recording reverse proxy, so an e2e run can assert on what actually left
// the machine:
//
//   WIRE_UPSTREAM=https://openrouter.ai/api WIRE_OUT=/tmp/wire \
//     bun run scripts/wire-recorder.ts &
//
// Point Claude Code at it with ANTHROPIC_BASE_URL. Every other check in this
// repository is in-process: they assert that our hook RETURNED a fake. None of
// them can show that the engine SENT one. A hook that is skipped fails open,
// and a `ref` returned by mistake makes core serve the messages it already
// built, so the only ground truth for "the model never saw it" is the request
// body.
//
// Request bodies are written verbatim. Headers are NOT: they carry the API key
// or OAuth token of whoever runs this, and a credential that reaches a file or
// a tool result is a credential the local osm install registers and masks
// forever after. They are forwarded and forgotten.

import { appendFileSync, mkdirSync } from 'node:fs'

const PORT = Number(process.env.WIRE_PORT ?? 8788)
const UPSTREAM = (process.env.WIRE_UPSTREAM ?? 'https://api.anthropic.com').replace(/\/$/, '')
const OUT = process.env.WIRE_OUT ?? '/tmp/wire'

mkdirSync(OUT, { recursive: true })
const FILE = `${OUT}/bodies.txt`
appendFileSync(FILE, '')

let n = 0

Bun.serve({
  port: PORT,
  // A streamed completion holds the connection open well past a default.
  idleTimeout: 255,
  async fetch(req) {
    const url = new URL(req.url)
    const body = req.method === 'GET' || req.method === 'HEAD' ? undefined : await req.text()
    if (body !== undefined) {
      appendFileSync(FILE, `\n===== request ${++n} ${req.method} ${url.pathname} =====\n${body}\n`)
    }

    const headers = new Headers(req.headers)
    // `host` names us, not upstream. The other two are recomputed by fetch, and
    // asking for an identity encoding keeps the response readable if a caller
    // ever wants to record it too.
    headers.delete('host')
    headers.delete('content-length')
    headers.set('accept-encoding', 'identity')

    try {
      return await fetch(`${UPSTREAM}${url.pathname}${url.search}`, {
        method: req.method,
        headers,
        body,
      })
    } catch (e) {
      // Fail loudly rather than looking like an upstream refusal.
      return new Response(`wire-recorder: ${e}`, { status: 502 })
    }
  },
})

console.log(`wire-recorder: :${PORT} -> ${UPSTREAM}, bodies in ${FILE}`)
