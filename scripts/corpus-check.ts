// Our rules against fixtures written by projects that are not us:
//
//   bun run scripts/corpus-check.ts
//
// Two gates, deliberately different.
//
// A NEGATIVE is a hard failure. Every string here is one an upstream project
// wrote down as "looks like a credential, is not" — a `${VAR}` reference, a
// too-short key, a publishable Stripe id, a stopword. If we match it, we mask
// something the user needed to read, which is the failure that started this.
//
// A POSITIVE is a ratchet, not a gate. Upstream covers vendors we do not, so
// demanding every positive match would fail on day one for honest reasons.
// The baseline records what we catch today; a commit may raise it and may not
// lower it. Raising it is how a new rule earns its place.
//
// Nothing here prints a fixture value. The plugin is installed on the machine
// that runs this, `persist` is on, and a value that reaches a tool result gets
// registered and written to the store — after which every later session masks
// it in any file. Failures are named by their source and their shape.

import { createHash } from 'node:crypto'

import { scan } from '../hooks/detect'

type Case = { value: string; from: string }
type Doc = { text: string; from: string; expect: 'hit' | 'clean' }

const corpus = (await Bun.file('corpus/corpus.json').json()) as {
  positives: Case[]
  negatives: Case[]
  documents: Doc[]
}
const baseline = (await Bun.file('corpus/baseline.json').json()) as {
  positives: number
  documents: number
  /**
   * Fixtures we match today and upstream says we should not, each pinned by a
   * hash of its source and value.
   *
   * Ids rather than source names: one source covers dozens of strings, so
   * allowing it by name would hide the next one to go wrong. An id that is not
   * here fails the run; an id here that stops matching is reported as
   * removable. The list is meant to shrink.
   */
  knownFalsePositives: string[]
}

/** Identifies a fixture without printing it. */
const idOf = (from: string, value: string) =>
  createHash('sha1').update(from + ' :: ' + value).digest('hex').slice(0, 12)

/** A value's shape, so a failure can be identified without printing it. */
const shape = (s: string) =>
  s
    .replace(/[A-Z]/g, 'A')
    .replace(/[a-z]/g, 'a')
    .replace(/[0-9]/g, '9')
    .replace(/\s/g, '_')
    .replace(/(.)\1{2,}/g, (m, c) => `${c}x${m.length}`)
    .slice(0, 40)

const allowed = new Set(baseline.knownFalsePositives)
const seen = new Set<string>()
let failed = 0

// ── negatives: a hard gate ──────────────────────────────────────────────────
const falsePositives: { from: string; rule: string; shape: string }[] = []
for (const c of corpus.negatives) {
  const hits = scan(c.value)
  if (hits.length === 0) continue
  const id = idOf(c.from, c.value)
  seen.add(id)
  if (allowed.has(id)) continue
  falsePositives.push({ from: `${c.from} ${id}`, rule: hits[0]!.rule, shape: shape(c.value) })
}

// ── documents: a snapshot upstream says reports nothing ─────────────────────
for (const d of corpus.documents.filter((x) => x.expect === 'clean')) {
  const hits = scan(d.text)
  if (hits.length === 0) continue
  const id = idOf(d.from, d.text)
  seen.add(id)
  if (allowed.has(id)) continue
  falsePositives.push({ from: `${d.from} ${id}`, rule: hits[0]!.rule, shape: `<document, ${hits.length} hits>` })
}

if (falsePositives.length > 0) {
  failed = 1
  console.log(`FAIL  ${falsePositives.length} upstream negatives matched:\n`)
  for (const f of falsePositives.slice(0, 40)) {
    console.log(`  ${f.from.padEnd(34)} ${f.rule.padEnd(28)} ${f.shape}`)
  }
  if (falsePositives.length > 40) console.log(`  … ${falsePositives.length - 40} more`)
  console.log(
    '\n  Either the rule is too loose, or the fixture is a credential we do want' +
      '\n  and upstream does not. For the second case add the id to' +
      '\n  knownFalsePositives in corpus/baseline.json, with the reason in the' +
      '\n  commit message.',
  )
} else {
  const clean = corpus.documents.filter((d) => d.expect === 'clean').length
  console.log(
    `PASS  ${corpus.negatives.length - allowed.size} negatives and ${clean} clean documents` +
      ` behaved, ${allowed.size} known divergences`,
  )
}

// A known divergence that stopped matching is a rule that got tighter. Say so:
// the list is only useful while it is exactly the outstanding work.
const stale = [...allowed].filter((id) => !seen.has(id))
if (stale.length > 0) {
  console.log(`\n      ${stale.length} known divergences no longer match; remove them from the baseline`)
}

// ── positives: a ratchet ────────────────────────────────────────────────────
const caught = corpus.positives.filter((c) => scan(c.value).length > 0).length
const docsCaught = corpus.documents.filter((d) => d.expect === 'hit' && scan(d.text).length > 0).length
const pct = (n: number, of: number) => `${n}/${of} (${Math.round((n / of) * 100)}%)`

console.log(`      positives ${pct(caught, corpus.positives.length)}, baseline ${baseline.positives}`)
console.log(`      documents ${pct(docsCaught, corpus.documents.filter((d) => d.expect === 'hit').length)}, baseline ${baseline.documents}`)

if (caught < baseline.positives || docsCaught < baseline.documents) {
  failed = 1
  console.log('\nFAIL  coverage fell below the baseline. A commit may raise it, never lower it.')
} else if (caught > baseline.positives || docsCaught > baseline.documents) {
  console.log(`\n      coverage rose. Update corpus/baseline.json to ${caught} and ${docsCaught}.`)
}

process.exit(failed)
