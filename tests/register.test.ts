import { describe, expect, mock, test, tier } from 'claude-code/testing'

tier('user')

const KEY = 'sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

describe('register', () => {
  test('a secret in a tool result reaches the model as a fake', async ($, on) => {
    mock.clock(on)
    on('session.start', ($, e) => ({ cwd: e.cwd }))
    on('fs.exists', () => ({ value: false }))
    on('tool.call', () => ({ result: { stdout: `ANTHROPIC_API_KEY=${KEY}` }, text: KEY }))

    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
    const up = await $.tool.call({ tool: 'Bash', command: 'cat .env' })

    expect(up.text).not.toContain(KEY)
    expect(up.text).toMatch(/^sk-ant-/) // the shape survived
  })

  test('the fake the model writes back reaches the tool as the real key', async ($, on) => {
    const seen: string[] = []
    mock.clock(on)
    on('session.start', ($, e) => ({ cwd: e.cwd }))
    on('fs.exists', () => ({ value: false }))
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

  test('a secret typed into the prompt is masked before the turn starts', async ($, on) => {
    mock.clock(on)
    on('session.start', ($, e) => ({ cwd: e.cwd }))
    on('fs.exists', () => ({ value: false }))
    on('prompt.submit', ($, e) => ({ text: e.text, origin: e.origin }))

    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/work' })
    const { text } = await $.prompt.submit({
      text: `my key is ${KEY}`,
      wait: false,
      origin: { kind: 'composer' },
    })

    expect(text).not.toContain(KEY)
  })
})
