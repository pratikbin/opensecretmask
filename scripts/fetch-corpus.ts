// Builds `corpus/corpus.json` from upstream projects that test their own rules.
//
//   bun run scripts/fetch-corpus.ts
//
// Run by hand when a pin below moves, not on every build: it needs the network
// and it rewrites a vendored file. `scripts/corpus-check.ts` is what runs in
// CI, against the committed result.
//
// Why fixtures we did not write: ours were invented alongside the rules they
// test, by the same author, in the same sitting, and they agreed with each
// other while the rules were wrong. These come from projects that have been
// wrong in public and written a case down each time. The negative fixtures are
// the point — the strings that look like credentials and are not.
//
// The pins are exact commits. An upstream that reorganises its files should
// break this script loudly rather than silently collect nothing.

const PINS = {
  gitleaks: {
    repo: 'gitleaks/gitleaks',
    sha: 'b58d3f102cf3a2c84cb7f923d05c25c9b1aed84b',
    license: 'MIT',
    holder: 'Copyright (c) 2019 Zachary Rice',
  },
  noseyparker: {
    repo: 'praetorian-inc/noseyparker',
    sha: '2e6e7f36ce36619852532bbe698d8cb7a26d2da7',
    license: 'Apache-2.0',
    holder: 'Copyright Praetorian Security, Inc.',
  },
  secretlint: {
    repo: 'secretlint/secretlint',
    sha: 'c0b8bc16dd8da80b0add80b1ddbf863e2987fce2',
    license: 'MIT',
    holder: 'Copyright (c) 2020 azu',
  },
} as const

type Case = { value: string; from: string }
type Doc = { text: string; from: string; expect: 'hit' | 'clean' }

const positives: Case[] = []
const negatives: Case[] = []
const documents: Doc[] = []

const raw = (repo: string, sha: string, path: string) =>
  `https://raw.githubusercontent.com/${repo}/${sha}/${path}`

async function get(url: string): Promise<string> {
  const r = await fetch(url)
  if (!r.ok) throw new Error(`${r.status} ${url}`)
  return r.text()
}

/** Paths under `dir`, one level, via the git tree API. */
async function list(repo: string, sha: string, dir: string, suffix: string): Promise<string[]> {
  const r = await fetch(`https://api.github.com/repos/${repo}/git/trees/${sha}?recursive=1`, {
    headers: process.env.GITHUB_TOKEN
      ? { authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
      : {},
  })
  if (!r.ok) throw new Error(`${r.status} tree ${repo}`)
  const tree = (await r.json()) as { tree: { path: string; type: string }[] }
  return tree.tree
    .filter((n) => n.type === 'blob' && n.path.startsWith(dir) && n.path.endsWith(suffix))
    .map((n) => n.path)
}

/** Run `work` over `items`, `limit` at a time. Upstream is a public host. */
async function pool<T>(items: T[], limit: number, work: (item: T) => Promise<void>) {
  let next = 0
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length) await work(items[next++]!)
    }),
  )
}

/** Go string literals inside one `name := []string{ … }` slice. */
function goSlice(src: string, name: string): string[] {
  const out: string[] = []
  const re = new RegExp(`${name}\\s*:?=\\s*\\[\\]string\\{`, 'g')
  for (const m of src.matchAll(re)) {
    let i = m.index! + m[0].length
    let depth = 1
    const start = i
    for (; i < src.length && depth > 0; i++) {
      if (src[i] === '{') depth++
      else if (src[i] === '}') depth--
    }
    const body = src.slice(start, i - 1)
    // Both quoting forms; Go's raw strings carry PEM blocks and backslashes.
    for (const lit of body.matchAll(/`([^`]*)`|"((?:[^"\\]|\\.)*)"/g)) {
      const value = lit[1] ?? JSON.parse(`"${lit[2]}"`)
      if (typeof value === 'string' && value.length > 0) out.push(value)
    }
  }
  return out
}

/**
 * The `examples:` / `negative_examples:` lists of a noseyparker rule.
 *
 * A hand parser rather than a YAML dependency: the files are generated and
 * uniform, and the only shapes that appear are a quoted scalar and a `|`
 * block. A parser that meets anything else says so.
 */
function yamlExamples(src: string, key: string): string[] {
  const out: string[] = []
  const lines = src.split('\n')
  for (let i = 0; i < lines.length; i++) {
    const head = lines[i]!.match(new RegExp(`^(\\s*)${key}:\\s*$`))
    if (!head) continue
    // The list sits at the key's own indentation, because each rule is itself
    // a list item. Comparing `at <= indent` ended the list on its first entry
    // and collected 3 of the 99 upstream negatives.
    const indent = head[1]!.length
    for (i++; i < lines.length; i++) {
      const line = lines[i]!
      if (line.trim() === '') continue
      const at = line.search(/\S/)
      const item = line.trim()
      if (at < indent || !item.startsWith('- ')) { i--; break }
      const body = item.slice(2).trim()
      if (body === '|' || body === '|-' || body === '>') {
        const block: string[] = []
        const blockIndent = at + 2
        for (i++; i < lines.length; i++) {
          const b = lines[i]!
          if (b.trim() !== '' && b.search(/\S/) < blockIndent) { i--; break }
          block.push(b.slice(blockIndent))
        }
        out.push(block.join('\n').replace(/\n+$/, ''))
      } else if (/^'.*'$/s.test(body)) out.push(body.slice(1, -1).replace(/''/g, "'"))
      else if (/^".*"$/s.test(body)) {
        try { out.push(JSON.parse(body)) } catch { out.push(body.slice(1, -1)) }
      } else out.push(body)
    }
  }
  return out.filter((s) => s.length > 0)
}

// ── gitleaks: the tp/fp strings each rule is validated against ──────────────
{
  const { repo, sha } = PINS.gitleaks
  const files = await list(repo, sha, 'cmd/generate/config/rules/', '.go')
  if (files.length === 0) throw new Error('gitleaks: no rule files; the layout moved')
  await pool(files, 8, async (path) => {
    const src = await get(raw(repo, sha, path))
    const name = path.split('/').pop()!
    if (name === 'stopwords.go') {
      // Words the generic rule refuses. Nothing here is a credential.
      for (const w of goSlice(src, 'DefaultStopWords')) negatives.push({ value: w, from: 'gitleaks:stopwords' })
      return
    }
    for (const v of goSlice(src, 'tps')) positives.push({ value: v, from: `gitleaks:${name}` })
    for (const v of goSlice(src, 'fps')) negatives.push({ value: v, from: `gitleaks:${name}` })
  })
}

// ── noseyparker: examples and negative_examples, inline in each rule ────────
{
  const { repo, sha } = PINS.noseyparker
  const dir = 'crates/noseyparker/data/default/builtin/rules/'
  const files = await list(repo, sha, dir, '.yml')
  if (files.length === 0) throw new Error('noseyparker: no rule files; the layout moved')
  await pool(files, 8, async (path) => {
    const src = await get(raw(repo, sha, path))
    const name = path.split('/').pop()!
    for (const v of yamlExamples(src, 'examples')) positives.push({ value: v, from: `noseyparker:${name}` })
    for (const v of yamlExamples(src, 'negative_examples')) negatives.push({ value: v, from: `noseyparker:${name}` })
  })
}

// ── secretlint: whole-file snapshots, which test a document not a string ────
{
  const { repo, sha } = PINS.secretlint
  // `ok.allows`, `ok.filePathGlobs-no-match`, `ok.pattern-allows` and friends
  // are suppressed by secretlint's own configuration, not by its detection:
  // the file does hold a credential and the rule was told to ignore it. Only
  // the snapshots that assert "this is not a credential" belong in a gate.
  const CONFIGURED = /allows|filePathGlobs|patterns?-|disable/
  const files = (await list(repo, sha, 'packages/@secretlint/secretlint-rule-', 'input.txt'))
    .filter((p) => /\/snapshots\/(ng|ok)[^/]*\//.test(p))
    .filter((p) => {
      const snap = p.match(/\/snapshots\/([^/]+)\//)?.[1] ?? ''
      return !(snap.startsWith('ok') && CONFIGURED.test(snap))
    })
  if (files.length === 0) throw new Error('secretlint: no snapshots; the layout moved')
  await pool(files, 8, async (path) => {
    const text = await get(raw(repo, sha, path))
    const rule = path.match(/secretlint-rule-([^/]+)/)?.[1] ?? '?'
    const snap = path.match(/\/snapshots\/([^/]+)\//)?.[1] ?? '?'
    documents.push({
      text,
      from: `secretlint:${rule}/${snap}`,
      expect: snap.startsWith('ng') ? 'hit' : 'clean',
    })
  })
}

const corpus = {
  note: 'Generated by scripts/fetch-corpus.ts. Upstream fixtures, not ours. See THIRD-PARTY.md.',
  sources: PINS,
  positives,
  negatives,
  documents,
}

await Bun.write('corpus/corpus.json', JSON.stringify(corpus, null, 1))
console.log(
  `positives ${positives.length}, negatives ${negatives.length}, documents ${documents.length}` +
    ` (${documents.filter((d) => d.expect === 'clean').length} must stay clean)`,
)
