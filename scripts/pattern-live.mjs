// Prepare fabricated files and verify artifacts from a Claude/tmux run.
// See PATTERNS.md for the commands. No credentials are printed.
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { argv, exit } from 'node:process'
import { patternFixtures, patternDecoys } from './pattern-fixtures.ts'

const [action, dir] = argv.slice(2)
if (!dir || !['prepare', 'verify'].includes(action ?? '')) throw new Error('usage: pattern-live.mjs prepare|verify DIRECTORY')

try {
  if (action === 'prepare') {
    await mkdir(dir, { recursive: true })
    const cases = patternFixtures(Date.now() >>> 0)
    await writeFile(`${dir}/positive.txt`, cases.map((c, i) => `CASE_${i + 1}: ${c.text}`).join('\n') + '\n')
    await writeFile(`${dir}/negative.txt`, patternDecoys.join('\n') + '\n')
    await writeFile(`${dir}/manifest.json`, JSON.stringify(cases))
    console.log(JSON.stringify({ prepared: cases.length, decoys: patternDecoys.length, dir }))
  } else {
    const cases = JSON.parse(await readFile(`${dir}/manifest.json`, 'utf8'))
    const bodies = async (name) => {
      const raw = await readFile(`${dir}/${name}/bodies.txt`, 'utf8')
      const requests = raw.split(/\n===== request \d+ [^\n]+ =====\n/).filter(s => s.trim()).map(s => JSON.parse(s))
      const strings = []
      const walk = (v) => {
        if (typeof v === 'string') strings.push(v)
        else if (Array.isArray(v)) v.forEach(walk)
        else if (v && typeof v === 'object') Object.values(v).forEach(walk)
      }
      for (const req of requests) walk(req.messages)
      return { text: strings.join('\n'), requests, raw }
    }
    const control = await bodies('control-wire')
    const plugin = await bodies('plugin-wire')
    let failed = 0, passed = 0
    const ok = (name, condition) => {
      if (condition) passed++
      else failed++
      console.log(JSON.stringify({ check: name, pass: condition }))
    }
    ok('control actually read every positive', cases.every(c => control.text.includes(c.value)))
    ok('plugin used Haiku 5.5 throughout', plugin.requests.length > 0 && plugin.requests.every(r => r.model === 'claude-haiku-5-5'))
    ok('every original credential absent from full plugin request bodies', cases.every(c => !plugin.raw.includes(c.value)))
    // Each line reached the model, and only its credential characters changed.
    const shape = (s) => s.replace(/[a-z]/g, 'a').replace(/[A-Z]/g, 'A').replace(/[0-9]/g, '9')
    for (const [i, c] of cases.entries()) {
      // Read adds line numbers before the file text; they are not fixture bytes.
      const label = `CASE_${i + 1}: `
      const numbered = plugin.text.split('\n').find(s => s.includes(label))
      const line = numbered?.slice(numbered.indexOf(label))
      ok(`case ${i + 1} reached the model with length/classes intact`, !!line && shape(line) === shape(`CASE_${i + 1}: ${c.text}`))
    }
    ok('all negative lines reached the model unchanged', patternDecoys.every(s => plugin.text.includes(s)))
    const negative = await readFile(`${dir}/negative-pane.txt`, 'utf8')
    const positive = await readFile(`${dir}/positive-pane.txt`, 'utf8')
    const expected = new Set(cases.map(c => c.value)).size
    ok('negative file leaves the ledger empty', /osm: no secrets masked yet this session\./.test(negative))
    ok('positive file populates the ledger', positive.includes(`osm: ${expected} secrets this session`))
    const blocks = plugin.requests.flatMap(r => r.messages.flatMap(m => Array.isArray(m.content) ? m.content : []))
    const grep = blocks.filter(b => b.type === 'tool_use' && b.name === 'Bash' && b.input?.command?.includes('grep') && b.input.command.includes('positive.txt'))
    const fake = plugin.text.split('\n').find(s => s.includes('CASE_1: '))?.split('CASE_1: ')[1]
    ok('grep used the fake observed in Read', !!fake && grep.some(b => b.input.command.includes(fake)))
    const ids = new Set(grep.map(b => b.id))
    ok('actual grep tool result was one match', blocks.some(b => b.type === 'tool_result' && ids.has(b.tool_use_id) && !b.is_error && b.content === '1'))
    const turn = await readFile(`${dir}/positive-turn.txt`, 'utf8')
    ok('tool restored the value for local grep', /RESTORE_COUNT=1/.test(turn))
    console.log(JSON.stringify({ passed, failed, expectedSecrets: expected, model: [...new Set(plugin.requests.map(r => r.model))] }))
    if (failed) exit(1)
  }
} catch {
  console.error(JSON.stringify({ error: 'pattern-live: missing or invalid run artifacts', action, dir }))
  exit(1)
}
