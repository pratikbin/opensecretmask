// Hook-level checks, runnable without Claude Code:
//
//   bun run scripts/hook-check.ts
//
// These cover the wiring that `scripts/unit-check.ts` cannot reach: the nine
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
const { resetKnownStore } = await import(`${R}/vault/persist.ts`)

let pass = 0, fail = 0
const ok = (n: string, c: boolean) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}`) }

const KEY = 'sk-ant-api03-' + 'A'.repeat(40)

type Handler = ($: any, e: any, next: (e: any) => any) => any

/** A loaded plugin: the hooks it registered, plus the `$` they are handed. */
// `{}` is the shipped configuration: options.ts now falls back to exactly what
// the manifest declares, and scripts/unit-check.ts asserts the two agree. It
// did not always. While they disagreed a harness passing `{}` ran with
// `persist: false`, the restore path never executed, and a store that poisoned
// every session at run time looked perfectly healthy here.
function seat(stored?: unknown, envFiles: Record<string, string> = {}, options: any = {}) {
  const hooks = new Map<string, Handler>()
  const logs: string[] = []
  const statuses: string[] = []
  // A fresh module keeps no drawn line, and neither should a fresh seat.
  resetStatus()
  resetKnownStore()
  const $ = {
    fs: {
      exists: async (p: string) => p in envFiles,
      read: async (p: string) => envFiles[p] ?? '',
    },
    store: { get: async () => stored, set: async () => undefined },
    ui: { log: (t: string) => logs.push(t), status: (t: string) => statuses.push(t) },
    clock: { sleep: (ms: number) => new Promise<void>((r) => setTimeout(r, ms)) },
    command: { register: async () => ({ command: 'osm-secrets' }) },
  }
  // `on` takes an optional matcher between the name and the handler.
  register((name: string, a: any, b?: Handler) => hooks.set(name, b ?? a), options)
  const fire = (name: string, e: any, world: (e: any) => any) => {
    const h = hooks.get(name)
    if (!h) throw new Error(`no handler for ${name}`)
    return h($, e, world)
  }
  return { hooks, fire, logs, statuses }
}

ok('H all nine hooks registered', (() => {
  const { hooks } = seat()
  return ['session.start', 'tool.call', 'agent.spawn', 'prompt.submit', 'prompt.context',
    'prompt.section', 'skill.prompt', 'session.receive', 'session.compact']
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

// /osm-secrets draws its table on the user-only channel and tells the model
// nothing: a `{ text }` answer would put every pair into the transcript.
{
  const { fire, logs } = seat()
  await fire('tool.call', { tool: 'Bash', command: 'cat .env' },
    () => ({ result: { stdout: KEY }, text: KEY }))
  const before = logs.length
  const out: any = await fire('command.run',
    { command: 'osm-secrets', args: '', origin: { kind: 'composer' } }, (e: any) => e)
  const drawn = logs.slice(before).join('\n')
  ok('C command answers with no model-facing text', out.text === undefined)
  ok('C command logs the pairs', drawn.includes('real → fake') && drawn.includes('→'))
  ok('C command never logs the whole secret', !drawn.includes(KEY))
}

// A store carrying an entry that resolves to nothing must not reach the vault.
// This is the shape that shipped: `.env` still had the key, the key had been
// emptied, and every later mask() cut between every character of every string.
{
  const poisoned = {
    version: 1,
    entries: [
      { kind: 'env', fake: 'sk-ant-api03-dead', file: '/work/.env', key: 'TOKEN', at: Date.now() },
      { kind: 'literal', fake: 'sk-ant-api03-void', secret: '', at: Date.now() },
    ],
  }
  const { fire, logs } = seat(poisoned, { '/work/.env': 'TOKEN=\nPORT=3000\n' })
  await fire('session.start', { cwd: '/work', surface: 'terminal' }, (e: any) => e)
  ok('E start line restores nothing from a poisoned store', !(logs[0] ?? '').includes('restored'))

  const text = 'deploy the service and read the log'
  const out: any = await fire('prompt.submit', { text, context: [] }, (e: any) => e)
  ok('E a poisoned store leaves the prompt alone', out.text === text)

  const up: any = await fire('tool.call', { tool: 'Bash', command: 'echo hi' },
    () => ({ result: { stdout: 'hello world' }, text: 'hello world' }))
  ok('E a poisoned store leaves a tool result alone', up.text === 'hello world')
}

// The channels that reach the model without passing `prompt.submit`.
// Each one registers the secret through a tool result first, the way a real
// session would, then checks that this channel no longer carries it.
{
  const { fire } = seat()
  await fire('tool.call', { tool: 'Bash', command: 'cat .env' },
    () => ({ result: { stdout: KEY }, text: KEY }))

  const skill: any = await fire('skill.prompt', { skill: 'commit', text: `use ${KEY} to push` }, (e: any) => e)
  ok('C skill prompt masked', !skill.text.includes(KEY))
  ok('C skill prompt keeps its shape', skill.text.startsWith('use sk-ant-') && skill.text.endsWith(' to push'))

  const got: any = await fire('session.receive', { origin: 'peer', text: `the key is ${KEY}` }, (e: any) => e)
  ok('C delivery masked', !got.text.includes(KEY) && got.consumed === undefined)

  const messages = [
    { role: 'user', text: 'what is in the env file', toolUses: [], handle: 'h1' },
    { role: 'assistant', text: `it holds ${KEY}`, toolUses: [], handle: 'h2' },
  ]
  const done: any = await fire('session.compact', { trigger: 'manual', messages }, (e: any) => e)
  ok('C compaction masks the transcript', !JSON.stringify(done.messages).includes(KEY))
  ok('C compaction keeps the handle of an untouched message', done.messages[0].handle === 'h1')
  // A rewritten message must give its handle up, or the engine stands its own
  // copy — the unmasked one — in place of ours.
  ok('C compaction drops the handle of a masked message', done.messages[1].handle === undefined)
  ok('C compaction keeps the role of a masked message', done.messages[1].role === 'assistant')
  // The message is masked whole rather than field by field, so a content field
  // the engine adds later is covered without anyone updating a list.
  ok('C compaction masks a field no list names', await (async () => {
    const odd = [{ role: 'user', text: '', toolUses: [], future: `see ${KEY}`, handle: 'h4' }]
    const out: any = await fire('session.compact', { trigger: 'manual', messages: odd }, (e: any) => e)
    return !JSON.stringify(out.messages).includes(KEY)
  })())
  ok('C compaction masks a tool result inside a message', await (async () => {
    const deep = [{ role: 'assistant', text: '', toolUses: [{ name: 'Bash', result: { stdout: KEY } }], handle: 'h3' }]
    const out: any = await fire('session.compact', { trigger: 'auto', messages: deep }, (e: any) => e)
    return !JSON.stringify(out.messages).includes(KEY)
  })())
}

// A channel that cannot be masked must not pass the value on regardless.
{
  const { fire } = seat()
  await fire('tool.call', { tool: 'Bash', command: 'cat .env' },
    () => ({ result: { stdout: KEY }, text: KEY }))
  const boom = () => { throw new Error('masking failed') }

  const got: any = await fire('session.receive', { origin: 'relay', get text() { return boom() } }, (e: any) => e)
  ok('C a delivery that cannot be masked is consumed', typeof got.consumed === 'string' && got.text === undefined)

  const done: any = await fire('session.compact',
    { trigger: 'manual', messages: [{ role: 'user', get text() { return boom() }, toolUses: [] }] },
    (e: any) => e)
  ok('C a compaction that cannot be masked is skipped', typeof done.skip === 'string' && done.messages === undefined)
}

console.log(`\npassed ${pass}, failed ${fail}`)
if (fail) process.exit(1)
