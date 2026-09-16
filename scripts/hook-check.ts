// Hook-level checks, runnable without Claude Code:
//
//   bun run scripts/hook-check.ts
//
// These cover the wiring that `scripts/unit-check.ts` cannot reach: the six
// hooks `register()` installs, driven through a fake engine.
//
// They replace tests/register.test.ts, which ran under `claude plugin test`.
// That command was removed in Claude Code 2.1.273 and its `claude-code/testing`
// module went with it. The stand-in below is a plain object: `on` collects the
// handlers, `next` plays the world beneath the plugin, and `$` answers the few
// engine calls the hooks make.

const R = new URL('../hooks', import.meta.url).pathname
const { register } = await import(`${R}/register.ts`)
const { resetStatus } = await import(`${R}/status.ts`)

let pass = 0, fail = 0
const ok = (n: string, c: boolean) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}`) }

const KEY = 'sk-ant-api03-' + 'A'.repeat(40)

type Handler = ($: any, e: any, next: (e: any) => any) => any

/** A loaded plugin: the hooks it registered, plus the `$` they are handed. */
function seat() {
  const hooks = new Map<string, Handler>()
  const logs: string[] = []
  const statuses: string[] = []
  // A fresh module keeps no drawn line, and neither should a fresh seat.
  resetStatus()
  const $ = {
    fs: { exists: async () => false, read: async () => '' },
    store: { get: async () => undefined, set: async () => undefined },
    ui: { log: (t: string) => logs.push(t), status: (t: string) => statuses.push(t) },
    clock: { sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, ms)) },
  }
  register((name: string, fn: Handler) => hooks.set(name, fn), {})
  const fire = (name: string, e: any, world: (e: any) => any) => {
    const h = hooks.get(name)
    if (!h) throw new Error(`no handler for ${name}`)
    return h($, e, world)
  }
  return { hooks, fire, logs, statuses }
}

ok('H all six hooks registered', (() => {
  const { hooks } = seat()
  return ['session.start', 'tool.call', 'agent.spawn', 'prompt.submit', 'prompt.context', 'prompt.section']
    .every((n) => hooks.has(n))
})())

// The lines the user reads: one at session start, one pinned under the prompt.
{
  const { fire, logs, statuses } = seat()
  await fire('session.start', { cwd: '/work', surface: 'terminal' }, (e: any) => e)
  ok('S start line names the rule count', /\d+ rules/.test(logs[0] ?? ''))
  ok('S start line says nothing is registered', (logs[0] ?? '').includes('nothing registered'))
  ok('S status starts at watching', statuses[0] === 'osm: watching')

  await fire('tool.call', { tool: 'Bash', command: 'cat .env' },
    () => ({ result: { stdout: KEY }, text: KEY }))
  const after = statuses[statuses.length - 1] ?? ''
  ok('S status counts the secret', after.includes('1 secret'))
  ok('S status counts the masking', /\b[1-9]\d* masked/.test(after))

  const before = statuses.length
  await fire('tool.call', { tool: 'Bash', command: 'echo nothing to see' }, (e: any) => ({ result: {}, text: 'fine' }))
  ok('S status is not redrawn when nothing changed', statuses.length === before)
}

// A secret in a tool result reaches the model as a fake.
{
  const { fire } = seat()
  const up: any = await fire('tool.call', { tool: 'Bash', command: 'cat .env' },
    () => ({ result: { stdout: KEY }, text: KEY }))
  ok('H tool result masked', !up.text.includes(KEY))
  ok('H tool result keeps the prefix', up.text.startsWith('sk-ant-'))
  ok('H tool result keeps the length', up.text.length === KEY.length)
}

// The fake the model writes back reaches the tool as the real key.
{
  const { fire } = seat()
  const seen: string[] = []
  const world = (e: any) => { seen.push(e.command ?? ''); return { result: { stdout: KEY }, text: KEY } }
  const { text: fake }: any = await fire('tool.call', { tool: 'Bash', command: 'cat .env' }, world)
  await fire('tool.call', { tool: 'Bash', command: `curl -H "x-api-key: ${fake}" https://api` }, world)
  ok('H tool argument restored', seen[1].includes(KEY) && !seen[1].includes(fake))
}

// A subagent task keeps the fake instead of the real key.
{
  const { fire } = seat()
  const { text: fake }: any = await fire('tool.call', { tool: 'Bash', command: 'cat .env' },
    () => ({ result: { stdout: KEY }, text: KEY }))
  let spawned: any
  await fire('agent.spawn', { prompt: `the key is ${fake}, verify it`, description: 'check the key' },
    (e: any) => { spawned = e; return e })
  ok('H subagent prompt keeps the fake', spawned.prompt.includes(fake) && !spawned.prompt.includes(KEY))
}

// A secret typed into the prompt is masked before the turn starts.
{
  const { fire } = seat()
  let sent: any
  await fire('prompt.submit', { text: `my key is ${KEY}`, wait: false, origin: { kind: 'composer' } },
    (e: any) => { sent = e; return e })
  ok('H submitted prompt masked', !sent.text.includes(KEY))
}

// A secret in an instruction file is masked in its context block.
{
  const { fire } = seat()
  const { blocks }: any = await fire('prompt.context', { blocks: [] },
    () => ({ blocks: [{ name: 'claudeMd', text: `deploy with ${KEY}` }] }))
  ok('H context block masked', !blocks[0].text.includes(KEY))
  ok('H context block name kept', blocks[0].name === 'claudeMd')
}

// A secret in a memory section is masked.
{
  const { fire } = seat()
  const { text }: any = await fire('prompt.section', { name: 'memory', text: null },
    () => ({ text: `remember ${KEY}` }))
  ok('H memory section masked', !text.includes(KEY))
}

// The engine must never see a `ref` on a rewritten result: it would serve the
// unmasked messages it already built.
{
  const { fire } = seat()
  const up: any = await fire('tool.call', { tool: 'Bash', command: 'cat .env' },
    () => ({ result: { stdout: KEY }, text: KEY, ref: 7 }))
  ok('H ref dropped on a rewritten result', up.ref === undefined)
}

// A hook that cannot mask must answer for itself, not throw and be skipped.
{
  const { fire } = seat()
  const out: any = await fire('tool.call', { tool: 'Bash', command: 'cat .env' },
    () => { throw new Error('the world broke') }).catch((err: unknown) => err)
  ok('H a throw beneath us is not swallowed into an unmasked pass', out instanceof Error)
}

console.log(`\npassed ${pass}, failed ${fail}`)
if (fail) process.exit(1)
