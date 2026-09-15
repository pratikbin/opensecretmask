import { entropyTokens } from './entropy'
import { literalPrefix } from './prefix'
import type { Rule } from './rule'
import { RULES } from './rules'

export { literalPrefix } from './prefix'
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

/**
 * Each rule paired with the fixed text it must begin with.
 *
 * Carried together rather than in a parallel array indexed by position: a
 * filter or reorder of `RULES` would silently desync two arrays, and this
 * cannot.
 */
const GATED: ReadonlyArray<{ rule: Rule; prefix: string }> = RULES.map((rule) => ({
  rule,
  prefix: literalPrefix(rule.re.source),
}))

/**
 * One alternation over every rule prefix, so a string is scanned once to learn
 * which rules can possibly match instead of once per rule.
 *
 * `mask()` runs per string in a result tree, so a 1000-string tool result was
 * paying 127 full `String.includes` passes per string before a single regex
 * ran. This turns that into one pass.
 */
const PREFIX_GATE = new RegExp(
  [...new Set(GATED.map((g) => g.prefix).filter(Boolean))]
    .map((p) => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('|'),
  'g',
)

/** The length of the longest rule prefix `value` begins with; 0 when none matches. */
export function literalPrefixLen(value: string): number {
  let best = 0
  for (const { prefix } of GATED) {
    if (prefix.length > best && value.startsWith(prefix)) best = prefix.length
  }
  return best
}

/**
 * Every distinct secret in `text`, first rule to claim a value winning.
 *
 * `into` receives each value with the rule that found it. Callers that only
 * need the values pass a `Set`, and nothing is allocated per match beyond the
 * value itself; `scan` passes a `Map` when it wants the attribution too.
 */
function run(text: string, cfg: DetectConfig, into: (value: string, rule?: Rule) => void): void {
  PREFIX_GATE.lastIndex = 0
  const present = new Set(text.match(PREFIX_GATE) ?? [])

  for (const { rule, prefix } of GATED) {
    if (prefix !== '' && !present.has(prefix)) continue
    rule.re.lastIndex = 0
    for (const m of text.matchAll(rule.re)) {
      const value = m[rule.group]
      if (value) into(value, rule)
    }
  }

  if (cfg.entropy) {
    for (const token of entropyTokens(text, cfg.entropyThreshold, cfg.entropyMinLen)) {
      into(token)
    }
  }
}

/**
 * The values alone, which is all the masking path needs.
 *
 * Unordered: the caller puts them straight into a set. Sorting them, as an
 * earlier version did, ordered an array nobody read on every string in every
 * tool result.
 */
export function scanValues(text: string, cfg: DetectConfig = DEFAULT_DETECT): Set<string> {
  const found = new Set<string>()
  run(text, cfg, (value) => found.add(value))
  return found
}

/** The values with the rule that claimed each one, for reporting paths. */
export function scan(text: string, cfg: DetectConfig = DEFAULT_DETECT): Finding[] {
  const seen = new Map<string, Finding>()
  run(text, cfg, (value, rule) => {
    if (seen.has(value)) return
    seen.set(value, {
      value,
      rule: rule?.name ?? 'entropy',
      severity: rule?.severity ?? 'medium',
    })
  })
  return [...seen.values()]
}
