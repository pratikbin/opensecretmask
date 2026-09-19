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
const { denyRules } = await import(`${R}/detect/rules/deny.ts`)
const { isPlaceholder, denialOf } = await import(`${R}/detect/suppress.ts`)
const { inbound, outbound } = await import(`${R}/policy/boundary.ts`)
const { isOpaque } = await import(`${R}/vault/walk.ts`)
const { load, save, prune, identityKey, resetKnownStore } = await import(`${R}/vault/persist.ts`)
const { readOptions } = await import(`${R}/options.ts`)
const { guard } = await import(`${R}/policy/budget.ts`)
const { elide, secretsTable, provenance, age } = await import(`${R}/events/command.ts`)

let pass = 0, fail = 0
const ok = (n: string, c: boolean) => { c ? pass++ : fail++; console.log(`${c ? 'PASS' : 'FAIL'}  ${n}`) }

/** A string the rules must mask, and a look-alike they must leave alone. */
const hit = (label: string, text: string) => ok(label, new Vault().mask(text) !== text)
const keep = (label: string, text: string) => ok(`keeps ${label}`, new Vault().mask(text) === text)

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

// OPT the module's fallbacks must be the manifest's declared defaults. The
// engine fills a declared option before register() sees it, so these only fire
// where the manifest does not reach — a --plugin-dir run, this harness. When
// the two disagreed, every hook test ran a configuration nobody ships.
{
  const manifest = await Bun.file(
    new URL('../.claude-plugin/plugin.json', import.meta.url).pathname,
  ).json()
  const declared: Record<string, any> = {}
  for (const [name, spec] of Object.entries<any>(manifest.userConfig ?? {})) declared[name] = spec.default
  const fallback: any = readOptions({} as any)
  ok('OPT persist is on without a manifest', fallback.persist === true)
  ok('OPT persist matches what the manifest declares', declared.persist === fallback.persist)
  ok('OPT retentionDays matches the manifest', declared.retentionDays === fallback.retentionDays)
  ok('OPT entropy matches the manifest', declared.entropy === fallback.detect.entropy)
  ok('OPT entropyThreshold matches the manifest', declared.entropyThreshold === fallback.detect.entropyThreshold)
  ok('OPT entropyMinLen matches the manifest', declared.entropyMinLen === fallback.detect.entropyMinLen)
  ok('OPT envFiles matches the manifest',
    JSON.stringify(declared.envFiles) === JSON.stringify(fallback.envFiles))
  // An explicit false must still turn it off, in either spelling.
  ok('OPT persist false is honoured', readOptions({ persist: false } as any).persist === false)
  ok('OPT persist "false" is honoured', readOptions({ persist: 'false' } as any).persist === false)
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

// RC reconciling a save against the store, not overwriting it. Two sessions
// share one store file, and a session's own snapshot only grows — so a save
// that just writes "everything I hold" resurrects anything a concurrent
// session purged since this one loaded. That happened twice in one day.
{
  const literal = (secret: string, fake: string) =>
    ({ kind: 'literal' as const, fake, secret, at: Date.now() })
  const snap = (entries: unknown[]) => ({ version: 1, entries })
  const portOver = (initial: unknown) => {
    let stored = initial
    return {
      get: async () => stored,
      set: async (_k: string, v: unknown) => { stored = v },
      readFile: async () => '',
      peek: () => stored as { entries: any[] } | undefined,
    }
  }

  ok('RC identityKey ignores the fake', (() => {
    const a = literal('hunter2-correct-horse-one', 'sk-ant-api03-aaaa')
    const b = { ...a, fake: 'sk-ant-api03-bbbb' }
    return identityKey(a) === identityKey(b)
  })())
  ok('RC identityKey separates env by file and key, not by value', (() => {
    const a = { kind: 'env' as const, fake: 'x', file: '/p/.env', key: 'A', at: 0 }
    const b = { ...a, key: 'B' }
    return identityKey(a) !== identityKey(b)
  })())

  {
    // A purge on disk must survive this session's next save, even though this
    // session's own vault never learned the entry was gone.
    const gone = literal('hunter2-correct-horse-gone', 'sk-ant-api03-gggg')
    const port = portOver(snap([gone]))
    resetKnownStore()
    await load(port, 120) // seeds `known` with `gone`'s identity
    port.set('', snap([])) // another session purges it, out from under this one
    await save(port, [gone]) // this session still holds it; save() must not restore it
    ok('RC a purge is not resurrected by a stale save', port.peek()!.entries.length === 0)
  }

  {
    // A genuinely new entry, never seen on disk or by this session before,
    // must still be added — reconciling is not a synonym for "never write".
    const known = literal('hunter2-correct-horse-known', 'sk-ant-api03-kkkk')
    const fresh = literal('hunter2-correct-horse-fresh', 'sk-ant-api03-ffff')
    const port = portOver(snap([known]))
    resetKnownStore()
    await load(port, 120)
    await save(port, [known, fresh])
    const secrets = port.peek()!.entries.map((e: any) => e.secret)
    ok('RC a genuinely new entry is added', secrets.includes('hunter2-correct-horse-fresh'))
  }

  {
    // A concurrent session's own new entry, which this session never adopted,
    // must not be dropped just because this session's own snapshot omits it.
    const mine = literal('hunter2-correct-horse-mine', 'sk-ant-api03-mmmm')
    const theirs = literal('hunter2-correct-horse-theirs', 'sk-ant-api03-tttt')
    const port = portOver(snap([mine]))
    resetKnownStore()
    await load(port, 120)
    port.set('', snap([mine, theirs])) // the other session adds its own entry
    await save(port, [mine]) // this session never saw `theirs`
    const secrets = port.peek()!.entries.map((e: any) => e.secret)
    ok('RC a concurrent addition is not clobbered', secrets.includes('hunter2-correct-horse-theirs'))
  }

  {
    // A read failure must skip the save outright, not read as "disk was
    // empty" — that would silently erase every entry a concurrent session
    // has written.
    const theirs = literal('hunter2-correct-horse-guard', 'sk-ant-api03-uuuu')
    let stored = snap([theirs])
    const port = {
      get: async () => { throw new Error('store unreadable') },
      set: async (_k: string, v: unknown) => { stored = v },
      readFile: async () => '',
    }
    resetKnownStore()
    await save(port, [])
    ok('RC a read failure skips the save rather than erasing the store',
      (stored as any).entries.length === 1)
  }

  resetKnownStore()
}

// DS a degraded store. Everything below reached the vault through `load()`
// once, and the empty case made every later mask() cut between every
// character of every string. The happy-path round trip above cannot see any
// of it, which is why the bug shipped with 85 checks green.
{
  const snap = (entries: unknown[]) => ({ version: 1, entries })
  const portFor = (stored: unknown, files: Record<string, string> = {}) => ({
    get: async () => stored,
    set: async () => undefined,
    readFile: async (p: string) => {
      const text = files[p]
      if (text === undefined) throw new Error('ENOENT')
      return text
    },
  })
  const envEntry = { kind: 'env', fake: 'sk-ant-api03-ffff', file: '/p/.env', key: 'TOKEN', at: Date.now() }

  const drops = async (label: string, env: string | undefined) => {
    const files = env === undefined ? {} : { '/p/.env': env }
    const got = await load(portFor(snap([envEntry]), files), 120)
    ok(`DS drops ${label}`, got.length === 0)
  }
  await drops('an emptied key', 'TOKEN=')
  await drops('a key emptied with quotes', 'TOKEN=""')
  await drops('a value under the minimum', 'TOKEN=abc')
  await drops('a key that is gone', 'OTHER=hunter2-correct-horse')
  await drops('a file that no longer reads', undefined)

  const kept = await load(portFor(snap([envEntry]), { '/p/.env': 'TOKEN=hunter2-correct-horse' }), 120)
  ok('DS keeps a key that still resolves', kept.length === 1)

  // A store written by an older or broken writer, straight from JSON.
  const literal = { kind: 'literal', fake: 'sk-ant-api03-gggg', secret: '', at: Date.now() }
  const badLiteral = await load(portFor(snap([literal])), 120)
  ok('DS an empty literal does not resolve', badLiteral.length === 0)
  ok('DS an empty literal never survives adoption', (() => {
    const v = new Vault()
    for (const r of badLiteral) v.adopt(r.entry.fake, r.secret)
    return v.size === 0 && v.mask('hello world') === 'hello world'
  })())

  for (const [label, raw] of [
    ['a missing store', undefined],
    ['a store of the wrong version', { version: 99, entries: [] }],
    ['a store whose entries are not an array', { version: 1, entries: 'nope' }],
    ['a store entry of the wrong shape', snap([{ kind: 'env', fake: 1 }])],
    ['a store that throws on read', 'THROW'],
  ] as [string, unknown][]) {
    const port = raw === 'THROW'
      ? { ...portFor(undefined), get: async () => { throw new Error('store gone') } }
      : portFor(raw)
    ok(`DS survives ${label}`, (await load(port, 120)).length === 0)
  }

  // The invariant the whole file exists to protect: whatever the store says,
  // a vault built from it leaves ordinary text alone.
  const v = new Vault()
  for (const bad of ['', ' ', '\n', 'a', 'short']) v.adopt(`sk-ant-api03-${bad || 'x'}zz`, bad)
  ok('DS no short or blank secret enters the map', v.size === 0)
  ok('DS ordinary text is untouched by a poisoned store', v.mask('the quick brown fox') === 'the quick brown fox')
}

// budget: a hook that cannot mask denies instead of being skipped
{
  ok('B sync throw falls back', guard(() => { throw new Error('x') }, () => 'DENIED') === 'DENIED')
  ok('B sync ok wins', guard(() => 'OK', () => 'DENIED') === 'OK')
}

// rules recovered from the Go proxy's detector, plus the PGP header it caught
// and the plugin did not
{
  hit('PX PGP block', '-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBGXyz1kBCADP3n2VqK8\n-----END PGP PRIVATE KEY BLOCK-----')
  hit('PX Terraform Cloud', 'AbCdEf12345678.atlasv1.' + 'z'.repeat(70))
  hit('PX Sentry DSN', 'https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o12345.ingest.sentry.io/678901')
  hit('PX Atlassian token', 'ATATT3xFfGF0' + 'a'.repeat(185))
  hit('PX Notion legacy secret', 'secret_' + 'a'.repeat(43))
  hit('PX Bearer header', 'Authorization: Bearer abcdef1234567890ABCDEFghijkl')
  // The scan gate is case-sensitive, so a case-insensitive rule must not be
  // gated on its prefix. A lowercase header once went through unmasked.
  hit('PX Bearer header, lowercase', 'authorization: bearer abcdef1234567890ABCDEFghijkl')
  hit('PX Bearer header, mixed case', 'AUTHORIZATION: BEARER abcdef1234567890ABCDEFghijkl')
  hit('PX connection string, uppercase scheme', 'POSTGRES://admin:hunter2horsebattery@db:5432/app')
  hit('PX access_token in URL', 'https://api.example.com/v1/x?access_token=abcdef1234567890ABCDEF')
  hit('PX Twilio account SID', 'ACa1b2c3d4e5f60718293a4b5c6d7e8f90')
  // The DSN keeps its shape: only the key half is masked.
  const dsn = new Vault().mask('https://a1b2c3d4e5f60718293a4b5c6d7e8f90@o12345.ingest.sentry.io/678901')
  ok('PX Sentry DSN keeps the host', dsn.includes('@o12345.ingest.sentry.io/678901'))
  // And the new rules do not fire on ordinary text.
  keep('a bare Authorization line', 'Authorization: Bearer')
  keep('a sentry issue URL', 'https://sentry.io/organizations/acme/issues/12345')
  keep('an ordinary query string', 'https://example.com/docs?page=2&sort=name')
}

// FP the classes the session store showed masked and should not have been
{
  const PW = String.fromCharCode(80, 65, 83, 83, 87, 79, 82, 68)
  keep('a connection-string placeholder', `postgres://user:${PW}@db:5432/app`)
  keep('an env var reference', 'DATABASE_PASSWORD=${DB_PASSWORD}')
  keep('a shell var reference', 'API_KEY="$ANTHROPIC_API_KEY"')
  keep('a windows var reference', 'API_TOKEN=%API_TOKEN%')
  keep('an angle-bracket placeholder', 'API_KEY=<your-api-key-here>')
  keep('a bracketed placeholder', 'API_TOKEN=[MASKED-0001]')
  keep('a documentation word', 'SECRET_KEY=changeme')
  keep('a uuid under a credential name', 'SESSION_TOKEN=550e8400-e29b-41d4-a716-446655440000')
  keep('a rule regex read out of this repo', String.raw`/\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/@:]{1,80}:([^\s/@]{3,200})@/gi`)
  keep('a truncated key from documentation', 'sk-ant-api03-Zx8Q2mLp')
  keep('a truncated openai key', 'sk-proj-Zx8Q2mLp')
  keep('an ssn inside a longer run', 'build 1234-56-78901')
  // `\S{8,}` does not stop at whitespace that is not there: a second
  // NAME=value glued straight onto the first reads as one token, and the
  // session store held exactly this — a captured value that was itself
  // `ARTIFACT_TOKEN=oss://bucket/path`, which `Secret reference` alone cannot
  // deny because that rule requires the whole value to be a bare locator.
  keep('a second assignment glued to the first', 'CONFIG_API_KEY=ARTIFACT_TOKEN=oss://my-bucket/path/to/object')

  // And the real things the same rules exist for still go.
  hit('FP a full anthropic key', KEY)
  hit('FP a hex value under a credential name', `SERVICE_API_KEY=${'a1b2c3d4'.repeat(4)}`)
  hit('FP a password in a connection string', 'postgres://user:hunter2horsebattery@db:5432/app')
  hit('FP a bare ssn', 'ssn 123-45-6789')

  // The capture must stop at the value, not run into the quote that follows.
  const v = new Vault()
  const masked = v.mask(`SERVICE_API_KEY="${'a1b2c3d4'.repeat(4)}",`)
  ok('FP capture keeps the surrounding syntax', masked.endsWith('",') && !masked.includes('a1b2c3d4'))
}

// EM an empty secret must never enter the map: mask() splits on it, so one
// such entry rebuilds every string around the fake, character by character.
{
  const v = new Vault()
  v.adopt('sk-ant-api03-zzzz', '')
  ok('EM empty secret is refused', v.size === 0)
  ok('EM text survives an attempted empty adopt', v.mask('hello world') === 'hello world')
  v.adopt('', KEY)
  ok('EM empty fake is refused', v.size === 0)

  // maskOf is public and mints on the spot, so it is a door of its own.
  const m = new Vault()
  ok('EM maskOf returns an empty secret unchanged', m.maskOf('') === '')
  ok('EM maskOf refuses a secret under the minimum', m.maskOf('short') === 'short')
  ok('EM neither entered the map', m.size === 0)
  ok('EM text survives an attempted empty maskOf', m.mask('abc') === 'abc')

  // The trivial cases, so nobody has to re-derive that they are safe.
  const t = new Vault()
  t.register('')
  ok('EM register refuses an empty secret', t.size === 0)
  ok('EM masking an empty string is an empty string', t.mask('') === '')
  ok('EM unmasking an empty string is an empty string', t.unmask('') === '')
  ok('EM an empty string inside a tree is untouched', JSON.stringify(t.maskDeep({ a: '', b: [''] })) === '{"a":"","b":[""]}')
}

// DY the deny rules: declared beside the rules they answer, same as a rule.
{
  ok('DY every deny rule carries a reason', denyRules.every((d: any) => d.why.length > 0))
  // `test()` on a global regex carries lastIndex between calls and starts
  // skipping matches, which would let a placeholder through every other time.
  ok('DY no deny rule is global', denyRules.every((d: any) => !d.re.flags.includes('g')))
  ok('DY a deny rule names itself', denialOf('${DB_PASSWORD}')?.name === 'Variable reference')
  ok('DY a uuid is denied as an identifier', denialOf('550e8400-e29b-41d4-a716-446655440000')?.name === 'UUID')
  ok('DY a secret reference is denied as a locator',
    denialOf('op://my-vault/db/password')?.name === 'Secret reference')
  ok('DY a plain url under a credential name is denied',
    denialOf('https://example.com/a/b')?.name === 'Secret reference')
  // A DSN carrying its password inline is NOT a locator. `Connection String
  // Password` masks that group by itself, and denying the whole value here
  // would put the password back in the clear.
  ok('DY a dsn with inline credentials is not denied',
    denialOf('postgres://user:Xk29fmQpLz@host/db') === undefined)
  ok('DY a real value is denied by nothing', denialOf('hunter2-correct-horse') === undefined)
  ok('DY hex under a name is still a candidate', !isPlaceholder('a1b2c3d4'.repeat(4)))
  ok('DY a glued second assignment is denied as chained',
    denialOf('ARTIFACT_TOKEN=oss://my-bucket/path')?.name === 'Chained assignment')
  // The value must actually be credential-named, or a base64 secret that
  // happens to contain '_' or '-' before its own '=' padding would be denied.
  ok('DY a value merely containing "=" is not denied as chained',
    denialOf('QWxhZGRpbi1vcGVuX3Nlc2FtZQ==') === undefined)
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

// LG the ledger behind /osm-secrets
{
  ok('LG elide hides the middle only', elide('0123456789') === '0123•••789')
  ok('LG elide leaves both ends', elide(KEY).startsWith('sk-ant-') && elide(KEY).endsWith('AAA'))
  ok('LG elide keeps the length', elide(KEY).length === KEY.length)

  const v = new Vault()
  v.register(KEY, { file: '/work/.env', key: 'ANTHROPIC_API_KEY' })
  const fake = v.maskOf(KEY)
  v.mask(`use ${KEY} twice: ${KEY}`, 'Bash')
  v.unmask(`curl ${fake}`)

  const [entry] = v.ledger()
  ok('LG ledger records the env source', entry.file === '/work/.env' && entry.key === 'ANTHROPIC_API_KEY')
  ok('LG ledger counts substitutions', entry.masked === 2 && entry.restored === 1)
  ok('LG ledger pairs the fake with the secret', entry.fake === fake && entry.secret === KEY)

  const found = new Vault().mask(`token ${KEY}`, 'Read')
  const noted = new Vault()
  noted.mask(`token ${KEY}`, 'Read')
  const [seen] = noted.ledger()
  ok('LG ledger names the rule that fired', seen.rule !== 'detected' && seen.rule.length > 0)
  ok('LG ledger names the channel', seen.where === 'Read' && found !== '')

  // What the store carries back: the row must still name the rule, the
  // channel and the first sighting, not the moment of the reload.
  const next = new Vault()
  for (const e of v.entries()) next.adopt(e.fake, e.kind === 'env' ? KEY : e.secret,
    e.kind === 'env' ? { file: e.file, key: e.key } : undefined, e)
  const carried = next.ledger()[0]
  ok('LG provenance survives the store', carried.rule === entry.rule && carried.where === entry.where)
  ok('LG first sighting survives the store', carried.at === entry.at)
  ok('LG table row has exactly one pair', secretsTable(v.ledger())[1]!.split('→').length === 2)
  ok('LG table row names the rule and the channel',
    secretsTable(v.ledger())[1]!.includes(entry.rule) && secretsTable(v.ledger())[1]!.includes(entry.where))

  const table = secretsTable(v.ledger())
  ok('LG table never prints the whole secret', !table.join('\n').includes(KEY))
  ok('LG table pairs each secret with its fake', table.join('\n').includes(fake.slice(0, 10)))
  ok('LG table keeps every row on one line', table.every((l: string) => !l.includes('\n') && l.length < 140))
  ok('LG table says so when empty', secretsTable([])[0].includes('no secrets'))

  ok('LG provenance names the env file', provenance({ ...entry }).includes('/work/.env'))
  ok('LG provenance does not repeat where it already equals file',
    // register() always sets where to the file itself for an env secret, so
    // showing both would spend half the budget saying the same path twice.
    (provenance({ ...entry }).match(/\/work\/\.env/g) ?? []).length === 1)
  ok('LG provenance falls back to where when there is no file', provenance(seen).includes(seen.where))
  ok('LG provenance is bounded even for a long rule name',
    provenance({ ...entry, rule: 'X'.repeat(80), file: undefined, key: undefined }).length <= 29)

  const now = Date.now()
  ok('LG age counts seconds', age(now - 5_000, now) === '5s')
  ok('LG age counts minutes', age(now - 5 * 60_000, now) === '5m')
  ok('LG age counts hours', age(now - 5 * 3_600_000, now) === '5h')
  ok('LG age counts days', age(now - 5 * 86_400_000, now) === '5d')
  ok('LG age never goes negative', age(now + 10_000, now) === '0s')

  ok('LG table row shows the age', secretsTable(v.ledger(), Date.now())[1]!.includes('ago)'))
}

console.log(`\npassed ${pass}, failed ${fail}`)
if (fail) process.exit(1)
