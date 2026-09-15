// Detection: the regex rules always run. The Shannon-entropy heuristic runs
// only when the `entropy` plugin option turns it on, because on ordinary
// prompt text it reports hashes, base64 blocks and git SHAs as secrets.

import { RULES } from './rules'

export type DetectConfig = {
  entropy: boolean
  entropyThreshold: number // bits per character
  entropyMinLen: number
}

export const DEFAULT_DETECT: DetectConfig = {
  entropy: false,
  entropyThreshold: 4.0,
  entropyMinLen: 24,
}

const QUANTIFIER = new Set(['?', '*', '+', '{'])
const META = new Set(['[', '(', ')', '{', '}', '?', '*', '+', '|', '^', '$', '.'])

/**
 * The fixed text a pattern must begin with, the JS answer to Go's
 * `Regexp.LiteralPrefix`. Used for two things: a cheap `includes` gate before
 * running a rule, and the number of leading bytes a garble keeps verbatim so a
 * fake still reads as that vendor's credential.
 */
export function literalPrefix(source: string): string {
  let out = ''
  for (let i = 0; i < source.length; i++) {
    const c = source[i]!
    if (c === '\\') {
      const escaped = source[i + 1]
      // \d \w \s \b … are classes, not literals.
      if (escaped === undefined || /[a-zA-Z0-9]/.test(escaped)) break
      if (QUANTIFIER.has(source[i + 2] ?? '')) break
      out += escaped
      i++
      continue
    }
    if (META.has(c)) break
    // A quantifier makes the character it follows optional or repeated, so it
    // is not part of a fixed prefix.
    if (QUANTIFIER.has(source[i + 1] ?? '')) break
    out += c
  }
  return out
}

const PREFIXES: readonly string[] = RULES.map((r) => literalPrefix(r.re.source))

export type Finding = {
  value: string
  rule: string
  severity: string
}

/**
 * Every distinct secret in `text`. First rule to claim a value wins, matching
 * first-rule-wins dedup.
 */
export function scan(text: string, cfg: DetectConfig = DEFAULT_DETECT): Finding[] {
  const seen = new Map<string, Finding>()

  RULES.forEach((r, i) => {
    const prefix = PREFIXES[i]!
    if (prefix.length > 0 && !text.includes(prefix)) return
    r.re.lastIndex = 0
    for (const m of text.matchAll(r.re)) {
      const value = m[r.group]
      if (!value) continue
      if (!seen.has(value)) {
        seen.set(value, { value, rule: r.name, severity: r.severity })
      }
    }
  })

  if (cfg.entropy) {
    for (const token of entropyTokens(text, cfg.entropyThreshold, cfg.entropyMinLen)) {
      if (!seen.has(token)) {
        seen.set(token, { value: token, rule: 'entropy', severity: 'medium' })
      }
    }
  }

  return [...seen.values()].sort((a, b) => (a.value < b.value ? -1 : a.value > b.value ? 1 : 0))
}

/**
 * The length of the longest rule prefix `value` begins with; 0 when none
 * matches.
 */
export function literalPrefixLen(value: string): number {
  let best = 0
  for (const p of PREFIXES) {
    if (p.length > best && value.startsWith(p)) best = p.length
  }
  return best
}

// ------------------------------------------------------------------ entropy

function shannon(s: string): number {
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

const TOKEN = /[0-9a-zA-Z\-_.+/=]{1,}/g

function entropyTokens(text: string, threshold: number, minLen: number): string[] {
  const out: string[] = []
  TOKEN.lastIndex = 0
  for (const m of text.matchAll(TOKEN)) {
    const token = m[0]
    if (token.length >= minLen && shannon(token) >= threshold) out.push(token)
  }
  return out
}
