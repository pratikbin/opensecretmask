// Unit checks for the pure logic, runnable without Claude Code:
//
//   bun run scripts/unit-check.ts
//
// The hook-level checks live in scripts/hook-check.ts. This file covers the
// detector, the vault, the .env parser, the persistence split and the budget.

const R = new URL('../hooks', import.meta.url).pathname
const { Vault } = await import(`${R}/vault/index.ts`)
const { scan, RULES } = await import(`${R}/detect/index.ts`)
const { parseEnv, parseValue } = await import(`${R}/env.ts`)
const { isModelFacing, RESERVED } = await import(`${R}/policy/model-facing.ts`)
const { inbound, outbound } = await import(`${R}/policy/boundary.ts`)
const { isOpaque } = await import(`${R}/vault/walk.ts`)
const { load, save, prune } = await import(`${R}/vault/persist.ts`)
const { guard, guardAsync } = await import(`${R}/policy/budget.ts`)

let pass = 0, fail = 0
const ok = (n: string, c: boolean) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}`) }

const KEY = 'sk-ant-api03-' + 'A'.repeat(40)
console.log(`rules: ${RULES.length}\n`)

// F1 Agent.prompt keeps its fake
{
  const v = new Vault(); const fake = v.maskOf(KEY)
  const agent: any = inbound(v, { tool: 'Agent', prompt: `use ${fake}`, description: fake } as any)
  ok('F1 Agent.prompt keeps the fake', !agent.prompt.includes(KEY) && agent.prompt.includes(fake))
  const ask: any = inbound(v, { tool: 'AskUserQuestion', questions: [{ q: fake }] } as any)
  ok('F1 AskUserQuestion keeps the fake', ask.questions[0].q === fake)
  const bash: any = inbound(v, { tool: 'Bash', command: `curl -H "k: ${fake}"` } as any)
  ok('F1 Bash.command still restored', bash.command.includes(KEY))
  ok('F1 agentId is reserved', RESERVED.has('agentId'))
  ok('F1 keep-fakes table', isModelFacing('Agent', 'prompt') && isModelFacing('AskUserQuestion', 'questions') && !isModelFacing('Bash', 'command'))
}

// F3 tool-result context masked
{
  const v = new Vault()
  const up: any = outbound(v, { result: {}, text: '', context: [`leaked ${KEY}`], ref: 7 } as any)
  ok('F3 result.context masked', !up.context[0].includes(KEY))
  ok('F3 ref dropped on rewrite', up.ref === undefined)
}

// F6 remember-once
{
  const v = new Vault()
  const secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
  v.mask(`aws_secret_access_key = "${secret}"`)
  ok('F6 bare value masked later', !v.mask(`value is ${secret}`).includes(secret))
}

// F7 whole PEM block
{
  const pem = `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAx7Vv9mQKcE2pL0bTn5sYhQwR3kZdFgH8jN1cPqSvUwXyZaBc\n-----END RSA PRIVATE KEY-----`
  ok('F7 PEM body masked', !new Vault().mask(pem).includes('MIIEowIBAAKCAQEAx7Vv9mQKcE2pL0bTn5sYhQwR3kZdFgH8'))
}

// F8 .env comments
{
  ok('F8 unquoted comment stripped', parseValue('hunter2-correct-horse # prod') === 'hunter2-correct-horse')
  ok('F8 quoted + comment', parseValue('"abc123def456" # staging') === 'abc123def456')
  ok('F8 plain value intact', parseValue('justthevalue') === 'justthevalue')
  const m = parseEnv('A=1 # x\n# comment\nB="two" # y\n')
  ok('F8 parseEnv', m.get('A') === '1' && m.get('B') === 'two')
}

// F9 binary payloads skipped
{
  const png = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQ=='
  const v = new Vault({ entropy: true, entropyThreshold: 4.0, entropyMinLen: 24 })
  const big = png.replace(/=+$/, '').repeat(60) + '=='   // >4KiB, padding only at the end
  const out: any = v.maskDeep({ type: 'image', source: { data: big } })
  ok('F9 large base64 payload preserved', out.source.data === big)
  ok('F9 isOpaque(short base64) is false', !isOpaque(png))
  // The regression: skipping by key name skipped the whole subtree.
  const nested: any = v.maskDeep({ data: { apiKey: KEY }, payload: { token: KEY } })
  ok('F9 secret under `data` IS masked', nested.data.apiKey !== KEY)
  ok('F9 secret under `payload` IS masked', nested.payload.token !== KEY)
  const back: any = v.unmaskDeep({ data: { cmd: v.maskOf(KEY) } })
  ok('F9 fake under `data` restores', back.data.cmd === KEY)
}

// suppression: no FP on git SHA / UUID / Stripe public id
{
  const cfg = { entropy: true, entropyThreshold: 3.5, entropyMinLen: 24 }
  const sha = 'a'.repeat(4) + '9f2c1e7b3d5a8c04e6f1b2d39c7e5a10'
  const txt = `commit ${sha} price_1MqLyJ2eZvKYlo2C price_abc uuid 550e8400-e29b-41d4-a716-446655440000`
  const v = new Vault(cfg)
  ok('SUP git SHA not masked', v.mask(txt).includes(sha))
  ok('SUP stripe public id kept', v.mask(txt).includes('price_1MqLyJ2eZvKYlo2C'))
  ok('SUP uuid kept', v.mask(txt).includes('550e8400-e29b-41d4-a716-446655440000'))
  // but a named key still wins
  const v2 = new Vault(cfg)
  const named = `api_key = ${sha}`
  ok('SUP named key still masked', !v2.mask(named).includes(sha))
  // The general "a credential name sits to the left" rule outranks the list.
  const v3 = new Vault(cfg)
  const prefixed = 'pi_9fX2qLmZ4vT7bN1cQ8wE3rY6uI0oP5aS'
  ok('SUP bare public prefix kept', v3.mask(`id ${prefixed}`).includes(prefixed))
  ok('SUP named public prefix masked', !new Vault(cfg).mask(`secret_key = ${prefixed}`).includes(prefixed))
  ok('SUP pk_ stays public even when named', new Vault(cfg).mask('secret_key = pk_live_9fX2qLmZ4vT7bN1cQ8wE3rY6').includes('pk_live_9fX2qLmZ4vT7bN1cQ8wE3rY6'))
}

// walk depth bound
{
  let deep: any = KEY
  for (let i = 0; i < 40; i++) deep = { n: deep }
  const v = new Vault()
  ok('WALK deep object does not blow the stack', typeof v.maskDeep(deep) === 'object')
}

// persistence round trip: env ref carries no secret
{
  const v = new Vault()
  v.register('hunter2-correct-horse-staple', { kind: 'env', file: '/p/.env', key: 'DB_PASSWORD' })
  const entries = v.entries()
  const json = JSON.stringify(entries)
  ok('P env entry stores no secret', !json.includes('hunter2-correct-horse-staple'))
  ok('P env entry is a pointer', entries[0].kind === 'env' && entries[0].key === 'DB_PASSWORD')

  let stored: any
  const port = {
    get: async () => stored,
    set: async (_k: string, v: unknown) => { stored = v },
    readFile: async (p: string) => p === '/p/.env' ? 'DB_PASSWORD=hunter2-correct-horse-staple\n' : '',
  }
  await save(port, entries)
  const resolved = await load(port, 120)
  ok('P env entry rebinds from .env', resolved.length === 1 && resolved[0].secret === 'hunter2-correct-horse-staple')

  // literal entry does store the value, and expires
  const v2 = new Vault(); v2.register(KEY)
  const lit = v2.entries(Date.now() - 200 * 86400000)
  ok('P literal entry stores value', JSON.stringify(lit).includes(KEY))
  ok('P literal expires past window', prune(lit, 120, Date.now()).length === 0)
  ok('P env never expires', prune(entries.map(e => ({...e, at: 0})), 120, Date.now()).length === 1)
}

// budget: a hung hook denies instead of being skipped
{
  const sleep = (ms: number) => new Promise<void>(r => setTimeout(r, ms))
  ok('B sync throw falls back', guard(() => { throw new Error('x') }, () => 'DENIED') === 'DENIED')
  ok('B sync ok wins', guard(() => 'OK', () => 'DENIED') === 'OK')
  ok('B async hung falls back', (await guardAsync(() => new Promise(() => {}), () => 'DENIED', sleep, 50)) === 'DENIED')
  ok('B async fast wins', (await guardAsync(async () => 'OK', () => 'DENIED', sleep, 500)) === 'OK')
}

// rules recovered from the Go proxy's detector, plus the PGP header it caught
// and the plugin did not
{
  const hit = (label: string, text: string) =>
    ok(`PX ${label}`, new Vault().mask(text) !== text)
  hit('PGP block', '-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGXyz1kBCADP3n2VqK8\n-----END PGP PRIVATE KEY BLOCK-----')
  hit('Terraform Cloud', 'AbCdEf12345678.atlasv1.' + 'z'.repeat(70))
  hit('Sentry DSN', 'https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o12345.ingest.sentry.io/678901')
  hit('Atlassian token', 'ATATT3xFfGF0' + 'a'.repeat(185))
  hit('Notion legacy secret', 'secret_' + 'a'.repeat(43))
  hit('Bearer header', 'Authorization: Bearer abcdef1234567890ABCDEFghijkl')
  hit('access_token in URL', 'https://api.example.com/v1/x?access_token=abcdef1234567890ABCDEF')
  hit('Twilio account SID', 'ACa1b2c3d4e5f60718293a4b5c6d7e8f90')
  // The DSN keeps its shape: only the key half is masked.
  const dsn = new Vault().mask('https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o12345.ingest.sentry.io/678901')
  ok('PX Sentry DSN keeps the host', dsn.includes('@o12345.ingest.sentry.io/678901'))
  // And the new rules do not fire on ordinary text.
  const keep = (label: string, text: string) =>
    ok(`PX keeps ${label}`, new Vault().mask(text) === text)
  keep('a bare Authorization line', 'Authorization: Bearer')
  keep('a sentry issue URL', 'https://sentry.io/organizations/acme/issues/12345')
  keep('an ordinary query string', 'https://example.com/docs?page=2&sort=name')
}

// round trip still works
{
  const v = new Vault()
  const body = `export ANTHROPIC_API_KEY=${KEY}\ncurl -H "x-api-key: ${KEY}"`
  const m = v.mask(body)
  ok('RT secret gone', !m.includes(KEY))
  ok('RT prefix kept', m.includes('sk-ant-'))
  ok('RT round trip', v.unmask(m) === body)
  ok('RT idempotent', v.mask(m) === m)
}

console.log(`\npassed ${pass}, failed ${fail}`)
if (fail) process.exit(1)
