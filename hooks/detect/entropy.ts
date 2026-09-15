import { isSuppressed } from './suppress'

/** Shannon entropy of `s`, in bits per character. */
export function shannon(s: string): number {
  if (s.length === 0) return 0
  const freq = new Map<string, number>()
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1)
  let h = 0
  for (const count of freq.values()) {
    const p = count / s.length
    h -= p * Math.log2(p)
  }
  return h
}

const TOKEN = /[0-9a-zA-Z\-_.+/=]+/g

/**
 * High-entropy runs that survive suppression.
 *
 * This layer is off unless `entropy` is set, because even with suppression it
 * is a heuristic over free text and a wrong hit garbles something the model
 * needed to read.
 */
export function entropyTokens(text: string, threshold: number, minLen: number): string[] {
  const out: string[] = []
  TOKEN.lastIndex = 0
  for (const m of text.matchAll(TOKEN)) {
    const token = m[0]
    if (token.length < minLen) continue
    if (shannon(token) < threshold) continue
    if (isSuppressed(token, text.slice(0, m.index))) continue
    out.push(token)
  }
  return out
}
