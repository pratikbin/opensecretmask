import { describe, expect, mock, test, tier } from 'claude-code/testing'

tier('user')

const KEY = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

/** The world beneath the plugin: no .env, no store, a clock the test drives. */
function seatWorld(on: Parameters<typeof mock.clock>[0]) {
  mock.clock(on)
  on('session.start', ($, e) => ({ cwd: e.cwd }))
  on('fs.exists', () => ({ value: false }))
  on('store.get', () => ({ value: undefined }))
  on('store.set', () => ({ value: undefined }))
}

describe('register', () => {
  test('a secret in a tool result reaches the model as a fake', async ($, on) => {
    seatWorld(on)
    on('tool.call', () => ({ result: { stdout: KEY }, text: KEY }))

    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
    const up = await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    expect(up.text).not.toContain(KEY)
    expect(up.text).toMatch(/^sk-ant-/)
    expect(up.text).toHaveLength(KEY.length)
  })

  test('the fake the model writes back reaches the tool as the real key', async ($, on) => {
    const seen: string[] = []
    seatWorld(on)
    on('tool.call', ($, e) => {
      if (e.tool === 'Bash') seen.push(e.command)
      return { result: { stdout: KEY }, text: KEY }
    })

    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
    const { text: fake } = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    await $.tool.call({ tool: 'Bash', command: `curl -H "x-api-key: ${fake}" https://api` })

    expect(seen[1]).toContain(KEY)
    expect(seen[1]).not.toContain(fake)
  })

  test('a subagent prompt keeps the fake instead of the real key', async ($, on) => {
    const prompts: string[] = []
    seatWorld(on)
    on('tool.call', ($, e) => {
      if (e.tool === 'Agent') prompts.push(String((e as { prompt?: unknown }).prompt ?? ''))
      return { result: { stdout: KEY }, text: KEY }
    })

    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
    const { text: fake } = await $.tool.call({ tool: 'Bash', command: 'cat .env' })
    await $.tool.call({
      tool: 'Agent',
      description: 'check the key',
      prompt: `the key is ${fake}, verify it`,
    })

    expect(prompts[0]).toContain(fake)
    expect(prompts[0]).not.toContain(KEY)
  })

  test('a secret typed into the prompt is masked before the turn starts', async ($, on) => {
    seatWorld(on)
    on('prompt.submit', ($, e) => ({ text: e.text, origin: e.origin }))

    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
    const { text } = await $.prompt.submit({
      text: `my key is ${KEY}`,
      wait: false,
      origin: { kind: 'composer' },
    })

    expect(text).not.toContain(KEY)
  })

  test('a secret in an instruction file is masked in its context block', async ($, on) => {
    seatWorld(on)
    on('prompt.context', () => ({
      blocks: [{ name: 'claudeMd', text: `deploy with ${KEY}` }],
    }))

    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
    const { blocks } = await $.prompt.context({ blocks: [] })

    expect(blocks[0]?.text).not.toContain(KEY)
    expect(blocks[0]?.name).toBe('claudeMd')
  })

  test('a secret in a memory section is masked', async ($, on) => {
    seatWorld(on)
    on('prompt.section', () => ({ text: `remember ${KEY}` }))

    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
    const { text } = await $.prompt.section({ name: 'memory', text: null })

    expect(text).not.toContain(KEY)
  })
})
