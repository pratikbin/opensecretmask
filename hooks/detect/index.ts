import { entropyTokens } from './entropy'
import { literalPrefix } from './prefix'
import { RULES } from './rules'

export { literalPrefix } from './prefix'
export { shannon } from './entropy'
export { isSuppressed } from './suppress'
export { RULES } from './rules'
export type { Rule } from './rule'

export type DetectConfig = {
  entropy: boolean
  entropyThreshold: number
  entropyMinLen: number
}

export const DEFAULT_DETECT: DetectConfig = {
  entropy: false,
  entropyThreshold: 4.0,
  entropyMinLen: 24,
}

export type Finding = {
  value: string
  rule: string
  severity: string
}

/** Each rule's literal prefix, computed once, used as the scan gate. */
const PREFIXES: readonly string[] = RULES.map((r) => literalPrefix(r.re.source))

/** The length of the longest rule prefix `value` begins with; 0 when none matches. */
export function literalPrefixLen(value: string): number {
  let best = 0
  for (const p of PREFIXES) {
    if (p.length > best && value.startsWith(p)) best = p.length
  }
  return best
}

/**
 * Every distinct secret in `text`, sorted by value.
 *
 * The regex rules always run. The entropy layer runs only when the config
 * turns it on. First rule to claim a value wins.
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

  return [...seen.values()].sort((a, b) =>
    a.value < b.value ? -1 : a.value > b.value ? 1 : 0,
  )
}
