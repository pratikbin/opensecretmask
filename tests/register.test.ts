// Hook-level checks, run by `claude plugin test .`
//
// The plugin under test is the real one, loaded the way the engine loads it,
// with the manifest's `userConfig` defaults: the shipped configuration. The
// test's own hooks sit BENEATH it and play the world: what a tool answers,
// what the store holds, what `.env` contains. A hook beneath sees the event
// AFTER osm rewrote it, which is how "what the tool received" is observed.
//
// These replace scripts/hook-check.ts, whose fake engine could not prove the
// two things only the real one decides: that a hook which throws reaches its
// `.catch`, and that the engine accepts what the hook returns.
//
// Three engine facts shape the file:
//   - An event is plain data. A getter that throws is refused at the boundary,
//     so "cannot be masked" is reached with a malformed value (`text: 5`)
//     that really does throw inside `vault.mask`, not with a booby-trapped one.
//   - `$.session.compact()` takes `instructions` only and raises the event
//     without `trigger` or `messages`; both are handed in with a cast.
//   - A hook that throws, or whose `next()` throws, reaches its `.catch`. That is
//     the only way to run a `.catch` here, and it is the real one.

import type { On } from 'claude-code'
import { describe, expect, mock, test } from 'claude-code/testing'
import { STORE_KEY } from '../hooks/vault/persist'

const KEY = 'sk-ant-api03-' + 'A'.repeat(40)

type World = {
  logs: string[]
  statuses: (string | undefined)[]
}

/**
 * The world beneath the plugin: `.env` files, a store, a clock-free UI.
 *
 * `$.ui.log` and `$.ui.status` are ops, so a hook beneath records what the
 * plugin drew. `fs.read` answers an unlisted path with `''`, the same answer
 * a missing `.env` gives the plugin through its own `.catch`.
 */
function seatWorld(
  on: On,
  {
    store = {},
    files = {},
  }: { store?: Record<string, unknown>; files?: Record<string, string> } = {},
): World {
  const world: World = { logs: [], statuses: [] }
  mock.store(on, store)
  on('ui.log', ($, e) => {
    world.logs.push(e.text)
    return { value: undefined }
  })
  on('ui.status', ($, e) => {
    world.statuses.push(e.text)
    return { value: undefined }
  })
  on('fs.read', ($, e) => ({ value: files[e.path] ?? '' }))
  on('command.register', () => ({ value: { command: 'osm-secrets' } }))
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  return world
}

/** A subagent dispatch as the engine raises it, whatever tool triggered it. */
const spawnOf = (prompt: string) =>
  ({
    tool_use_id: 'toolu_1',
    prompt,
    description: 'check the key',
    subagentType: 'general-purpose',
    provider: { plugin: 'engine', tier: 'core' },
    parentModel: 'test-model',
    background: false,
    fork: false,
  }) as const

const START = { cwd: '/work', surface: 'terminal', isInteractive: true } as const

/** The world beneath the plugin throws. */
const broke = (): never => {
  throw new Error('the world broke')
}

/** What a tool says when it prints the key: the result and the text the model reads. */
const printsKey = () => ({ result: { stdout: KEY }, text: KEY })

describe('register', () => {
  // The lines the user reads: one at session start, one pinned under the prompt.
  test('session start draws one line, the pinned status counts and is not redrawn', async ($, on) => {
    const { logs, statuses } = seatWorld(on)
    on('tool.call', ($, e) =>
      e.tool === 'Bash' && e.command.includes('nothing')
        ? { result: {}, text: 'fine' }
        : printsKey(),
    )

    await $.session.start(START)
    expect(logs[0] ?? '', 'S start line names the rule count').toMatch(/\d+ rules/)
    expect(logs[0] ?? '', 'S start line says nothing is registered').toContain('nothing registered')
    expect(statuses[0], 'S status starts at watching').toBe('osm: watching')

    await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    const after = statuses[statuses.length - 1] ?? ''
    expect(after, 'S status counts the secret').toContain('1 secret')
    expect(after, 'S status counts the masking').toMatch(/\b[1-9]\d* masked/)

    const before = statuses.length
    await $.tool.call({ tool: 'Bash', command: 'echo nothing to see' })
    expect(statuses.length, 'S status is not redrawn when nothing changed').toBe(before)
  })

  test('a secret in a tool result reaches the model as a fake', async ($, on) => {
    seatWorld(on)
    on('tool.call', printsKey)

    const up = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(up.text, 'H tool result masked').not.toContain(KEY)
    expect(up.text, 'H tool result keeps the prefix').toMatch(/^sk-ant-/)
    expect(up.text, 'H tool result keeps the length').toHaveLength(KEY.length)
  })

  test('the fake the model writes back reaches the tool as the real key', async ($, on) => {
    seatWorld(on)
    const seen: string[] = []
    on('tool.call', ($, e) => {
      if (e.tool === 'Bash') seen.push(e.command)
      return printsKey()
    })

    const { text: fake } = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    await $.tool.call({ tool: 'Bash', command: `curl -H "x-api-key: ${fake}" https://api` })
    expect(seen[1], 'H tool argument restored').toContain(KEY)
    expect(seen[1], 'H tool argument restored').not.toContain(fake)
  })

  test('a subagent prompt keeps the fake instead of the real key', async ($, on) => {
    seatWorld(on)
    on('tool.call', printsKey)
    let spawned = ''
    on('agent.spawn', ($, e) => {
      spawned = e.prompt
      return { model: 'test-model' }
    })

    const { text: fake } = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    await $.agent.spawn(spawnOf(`the key is ${fake}, verify it`))
    expect(spawned, 'H subagent prompt keeps the fake').toContain(String(fake))
    expect(spawned, 'H subagent prompt keeps the fake').not.toContain(KEY)

    // Belt and braces: a real key that reaches the dispatch by another route
    // is masked here, the one place every subagent passes through.
    await $.agent.spawn(spawnOf(`the key is ${KEY}`))
    expect(spawned, 'H a real key in a subagent prompt is masked').not.toContain(KEY)
  })

  test('a secret typed into the prompt is masked before the turn starts', async ($, on) => {
    seatWorld(on)
    let sent = ''
    on('prompt.submit', ($, e) => {
      sent = e.text
      return { text: e.text }
    })

    await $.prompt.submit({ text: `my key is ${KEY}`, wait: false, origin: { kind: 'composer' } })
    expect(sent, 'H submitted prompt masked').not.toContain(KEY)
  })

  test('a secret in an instruction file is masked in its context block', async ($, on) => {
    seatWorld(on)
    on('prompt.context', () => ({ blocks: [{ name: 'claudeMd', text: `deploy with ${KEY}` }] }))

    const { blocks } = await $.prompt.context({ blocks: [] })
    expect(blocks[0]?.text, 'H context block masked').not.toContain(KEY)
    expect(blocks[0]?.name, 'H context block name kept').toBe('claudeMd')
  })

  test('a secret in a memory section is masked', async ($, on) => {
    seatWorld(on)
    on('prompt.section', () => ({ text: `remember ${KEY}` }))

    const { text } = await $.prompt.section({ name: 'memory', text: null })
    expect(text, 'H memory section masked').not.toContain(KEY)
  })

  // The engine must never see a `ref` on a rewritten result: it would serve the
  // unmasked messages it already built.
  test('the ref is dropped on a rewritten result', async ($, on) => {
    seatWorld(on)
    on('tool.call', () => ({ ...printsKey(), ref: 7 }))

    const up = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(up.ref, 'H ref dropped on a rewritten result').toBeUndefined()
  })

  // /osm-secrets draws its table on the user-only channel and tells the model
  // nothing: a `{ text }` answer would put every pair into the transcript.
  test('/osm-secrets logs the pairs and answers the model nothing', async ($, on) => {
    const { logs } = seatWorld(on)
    on('tool.call', printsKey)

    await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    const before = logs.length
    const out = await $.command.run({
      command: 'osm-secrets',
      args: '',
      origin: { kind: 'composer' },
    } as never)
    const drawn = logs.slice(before).join('\n')
    expect(
      (out as { text?: string }).text,
      'C command answers with no model-facing text',
    ).toBeUndefined()
    expect(drawn, 'C command logs the pairs').toContain('real → fake')
    expect(drawn, 'C command never logs the whole secret').not.toContain(KEY)
  })

  // A store carrying an entry that resolves to nothing must not reach the vault.
  // This is the shape that shipped: `.env` still had the key, the key had been
  // emptied, and every later mask() cut between every character of every string.
  test('a poisoned store restores nothing and leaves every channel alone', async ($, on) => {
    const poisoned = {
      version: 1,
      entries: [
        {
          kind: 'env',
          fake: 'sk-ant-api03-dead',
          file: '/work/.env',
          key: 'TOKEN',
          at: Date.now(),
        },
        { kind: 'literal', fake: 'sk-ant-api03-void', secret: '', at: Date.now() },
      ],
    }
    const { logs } = seatWorld(on, {
      store: { [STORE_KEY]: poisoned },
      files: { '/work/.env': 'TOKEN=\nPORT=3000\n' },
    })
    on('prompt.submit', ($, e) => ({ text: e.text }))
    on('tool.call', () => ({ result: { stdout: 'hello world' }, text: 'hello world' }))

    await $.session.start(START)
    expect(logs[0] ?? '', 'E start line restores nothing from a poisoned store').not.toContain(
      'restored',
    )

    const text = 'deploy the service and read the log'
    const out = await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
    expect(out.text, 'E a poisoned store leaves the prompt alone').toBe(text)

    const up = await $.tool.call({ tool: 'Bash', command: 'echo hi' })
    expect(up.text, 'E a poisoned store leaves a tool result alone').toBe('hello world')
  })

  // The channels that reach the model without passing `prompt.submit`.
  // Each one registers the secret through a tool result first, the way a real
  // session would, then checks that this channel no longer carries it.
  test('the channels that skip prompt.submit are masked', async ($, on) => {
    seatWorld(on)
    on('tool.call', printsKey)
    on('skill.prompt', ($, e) => ({ text: e.text }))
    on('session.receive', ($, e) => ({ text: e.text }))
    let sent = ''
    on('session.send', ($, e) => {
      sent = e.text
      return { isDelivered: true }
    })
    let compacted: readonly { handle?: string; role: string }[] = []
    on('session.compact', ($, e) => {
      compacted = e.messages
      return { messages: e.messages }
    })

    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const skill = await $.skill.prompt({ skill: 'commit', text: `use ${KEY} to push` })
    expect(skill.text, 'C skill prompt masked').not.toContain(KEY)
    expect(skill.text, 'C skill prompt keeps its shape').toMatch(/^use sk-ant-.* to push$/)

    const got = await $.session.receive({
      origin: { kind: 'peer', teammate: 'a', isVerified: true },
      text: `the key is ${KEY}`,
    })
    expect(got.text, 'C delivery masked').not.toContain(KEY)
    expect(got.consumed, 'C delivery masked').toBeUndefined()

    // Another model reads it, and its vault has never seen this secret.
    await $.session.send({ to: 'peer', text: `use ${KEY}`, origin: { kind: 'model' } })
    expect(sent, 'C outgoing message masked').not.toContain(KEY)
    expect(sent, 'C outgoing message masked').toMatch(/^use sk-ant-/)

    // A skipped compaction has no `messages`, and `JSON.stringify(undefined)`
    // contains no key: without this check a refusal would pass every assertion.
    const compact = async (messages: unknown[], trigger = 'manual') => {
      const out = (await $.session.compact({ trigger, messages } as never)) as unknown as {
        messages?: { role: string; handle?: string }[]
        skip?: string
      }
      expect(out.skip, 'the compaction was not refused').toBeUndefined()
      return out as { messages: { role: string; handle?: string }[] }
    }

    const done = await compact([
      { role: 'user', text: 'what is in the env file', toolUses: [], handle: 'h1' },
      { role: 'assistant', text: `it holds ${KEY}`, toolUses: [], handle: 'h2' },
    ])
    expect(JSON.stringify(done.messages), 'C compaction masks the transcript').not.toContain(KEY)
    expect(done.messages[0]?.handle, 'C compaction keeps the handle of an untouched message').toBe(
      'h1',
    )
    // A rewritten message must give its handle up, or the engine stands its own
    // copy — the unmasked one — in place of ours.
    expect(
      done.messages[1]?.handle,
      'C compaction drops the handle of a masked message',
    ).toBeUndefined()
    expect(done.messages[1]?.role, 'C compaction keeps the role of a masked message').toBe(
      'assistant',
    )

    // The message is masked whole rather than field by field, so a content field
    // the engine adds later is covered without anyone updating a list.
    const odd = await compact([
      { role: 'user', text: '', toolUses: [], future: `see ${KEY}`, handle: 'h4' },
    ])
    expect(JSON.stringify(odd.messages), 'C compaction masks a field no list names').not.toContain(
      KEY,
    )

    const deep = await compact(
      [
        {
          role: 'assistant',
          text: '',
          toolUses: [{ tool_use_id: 'toolu_1', tool: 'Bash', input: {}, result: { stdout: KEY } }],
          handle: 'h3',
        },
      ],
      'auto',
    )
    expect(
      JSON.stringify(deep.messages),
      'C compaction masks a tool result inside a message',
    ).not.toContain(KEY)
    expect(compacted.length, 'the compaction reached the bottom').toBe(1)
  })

  // A channel that cannot be masked must not pass the value on regardless.
  // Plain data cannot carry a throwing getter, so each message is malformed
  // instead: `mask()` throws on a non-string, and each hook's guard answers.
  test('a channel that cannot be masked does not pass the value on', async ($, on) => {
    seatWorld(on)
    on('tool.call', printsKey)
    const reached: string[] = []
    on('session.receive', ($, e) => {
      reached.push('receive')
      return { text: e.text }
    })
    const skillSeen: string[] = []
    on('skill.prompt', ($, e) => {
      skillSeen.push(e.text)
      return { text: e.text }
    })
    on('session.send', () => {
      reached.push('send')
      return { isDelivered: true }
    })
    on('session.compact', ($, e) => {
      reached.push('compact')
      return { messages: e.messages }
    })

    await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    const got = await $.session.receive({ origin: { kind: 'relay' }, text: 5 } as never)
    expect(typeof got.consumed, 'C a delivery that cannot be masked is consumed').toBe('string')
    expect(got.text, 'C a delivery that cannot be masked is consumed').toBeUndefined()

    const unsent = await $.session.send({ to: 'peer', text: 5 } as never)
    expect(unsent.isDelivered, 'C a message that cannot be masked is not sent').toBe(false)
    expect(
      (unsent as { text?: string }).text,
      'C a message that cannot be masked is not sent',
    ).toBeUndefined()

    const done = await $.session.compact({ trigger: 'manual', messages: 'not a list' } as never)
    expect(typeof done.skip, 'C a compaction that cannot be masked is skipped').toBe('string')
    expect(done.messages, 'C a compaction that cannot be masked is skipped').toBeUndefined()

    // No drop on this channel: the engine's answer is a prompt, so the guard
    // hands down the empty one rather than the unmasked one.
    await $.skill.prompt({ skill: 'commit', text: 5 } as never)
    expect(skillSeen, 'C a skill prompt that cannot be masked is emptied').toEqual([''])

    expect(reached, 'nothing was passed down').toEqual([])
  })

  // A throw beneath the plugin must not turn into an unmasked pass. The engine
  // skips a hook that throws and runs core in its place, so a masking hook
  // carries a `.catch` that answers for it. In this runtime a hook whose
  // `next()` throws reaches that `.catch`, which is how it is exercised here.
  test('a throw beneath the plugin is not swallowed into an unmasked pass', async ($, on) => {
    seatWorld(on)
    on('tool.call', broke)

    const up = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    expect(typeof up.deny, 'H a throw beneath us is not swallowed into an unmasked pass').toBe(
      'string',
    )
    expect(up.text, 'H a throw beneath us is not swallowed into an unmasked pass').toBeUndefined()
  })

  // Every hook answers for itself, or the engine treats it as absent and serves
  // core's unmasked result. A hook with no `.catch`, or one not registered at
  // all, surfaces here as the bare error instead of the plugin's own answer.
  // `session.start` has no `.catch`: its failures are survivable, and the start
  // line in the first test shows it is registered.
  test('every masking hook answers for itself when one beneath it throws', async ($, on) => {
    const { logs } = seatWorld(on)
    const hooks = [
      'tool.call',
      'agent.spawn',
      'prompt.submit',
      'prompt.context',
      'prompt.section',
      'skill.prompt',
      'session.receive',
      'session.compact',
      'session.send',
    ] as const
    for (const name of hooks) {
      on(name, broke)
    }

    const denied = await $.tool.call({ tool: 'Bash', command: 'x' })
    expect(typeof denied.deny, 'X a failed tool.call denies rather than serving the result').toBe(
      'string',
    )

    const dropped = await $.prompt.submit({ text: KEY, wait: false, origin: { kind: 'composer' } })
    expect(typeof dropped.drop, 'X a failed prompt.submit drops the prompt').toBe('string')

    const blocked = await $.agent.spawn(spawnOf(KEY))
    expect(typeof blocked.deny, 'X a failed agent.spawn denies the subagent').toBe('string')

    const empty = await $.prompt.context({ blocks: [{ name: 'claudeMd', text: KEY }] })
    expect(empty.blocks, 'X a failed prompt.context yields no blocks').toEqual([])

    const skipped = await $.session.compact({
      trigger: 'auto',
      messages: [{ role: 'user', text: KEY, toolUses: [] }],
    })
    expect(typeof skipped.skip, 'X a failed session.compact skips').toBe('string')

    // The four the original checks named only as a set: each must answer as well.
    const section = await $.prompt.section({ name: 'memory', text: KEY })
    expect(
      section.text,
      'X every masking hook installs a catch handler (prompt.section)',
    ).toBeNull()

    // The one hook whose `.catch` answers through `next` (the engine's own answer
    // here is a prompt, so refusing means handing back the empty one). With the
    // world beneath it broken that `next` has nothing to call, so the call
    // rejects: it must not resolve with the unmasked text.
    await expect(
      $.skill.prompt({ skill: 'commit', text: KEY }),
      'X every masking hook installs a catch handler (skill.prompt)',
    ).rejects.toThrow()

    const got = await $.session.receive({ origin: { kind: 'relay' }, text: KEY } as never)
    expect(
      typeof got.consumed,
      'X every masking hook installs a catch handler (session.receive)',
    ).toBe('string')

    const sent = await $.session.send({ to: 'peer', text: KEY, origin: { kind: 'model' } })
    expect(sent.isDelivered, 'X every masking hook installs a catch handler (session.send)').toBe(
      false,
    )

    // Ten hooks in all: the nine above each answered, and this is the tenth.
    await $.session.start(START)
    expect(logs.length, 'H all ten hooks registered').toBe(1)
  })
})
