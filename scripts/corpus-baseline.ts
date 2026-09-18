// Rewrites `corpus/baseline.json` from what the rules do right now:
//
//   bun run scripts/corpus-baseline.ts
//
// Run it when a rule change moves the numbers, and read the diff before
// committing. It is the only way the baseline may go down — a divergence that
// disappears should disappear because a rule got tighter, and the diff is
// where that claim is visible.

import { createHash } from 'node:crypto'

import { scan } from '../hooks/detect'

const corpus = (await Bun.file('corpus/corpus.json').json()) as {
  positives: { value: string; from: string }[]
  negatives: { value: string; from: string }[]
  documents: { text: string; from: string; expect: 'hit' | 'clean' }[]
}

const idOf = (from: string, value: string) =>
  createHash('sha1').update(from + ' :: ' + value).digest('hex').slice(0, 12)

const known: string[] = []
for (const n of corpus.negatives) if (scan(n.value).length > 0) known.push(idOf(n.from, n.value))
for (const d of corpus.documents) {
  if (d.expect === 'clean' && scan(d.text).length > 0) known.push(idOf(d.from, d.text))
}

const positives = corpus.positives.filter((p) => scan(p.value).length > 0).length
const documents = corpus.documents.filter((d) => d.expect === 'hit' && scan(d.text).length > 0).length

await Bun.write(
  'corpus/baseline.json',
  JSON.stringify({ positives, documents, knownFalsePositives: known.sort() }, null, 1),
)
console.log(`positives ${positives}, documents ${documents}, known divergences ${known.length}`)
