import { entropyTokens } from './entropy'
import { isPlaceholder, trimCapture } from './suppress'
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
 *
 * `prefix` is what a fake copies verbatim. `gate` is what the scan tests, and
 * it is empty for a case-insensitive rule: `authorization:` and
 * `Authorization:` are the same rule but not the same string, so gating one on
 * the other drops the match and the credential reaches the model. Such a rule
 * runs on every string, which is correct and costs one regex.
 */
const GATED: ReadonlyArray<{ rule: Rule; prefix: string; gate: string }> = RULES.map((rule) => {
  const prefix = literalPrefix(rule.re.source)
  return { rule, prefix, gate: rule.re.flags.includes('i') ? '' : prefix }
})

/**
 * One alternation over every rule prefix, so a string is scanned once to learn
 * which rules can possibly match instead of once per rule.
 *
 * `mask()` runs per string in a result tree, so a 1000-string tool result was
 * paying 127 full `String.includes` passes per string before a single regex
 * ran. This turns that into one pass.
 */
const PREFIX_GATE = new RegExp(
  [...new Set(GATED.map((g) => g.gate).filter(Boolean))]
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

  for (const { rule, gate } of GATED) {
    if (gate !== '' && !present.has(gate)) continue
    rule.re.lastIndex = 0
    for (const m of text.matchAll(rule.re)) {
      const raw = m[rule.group]
      if (!raw) continue
      // A whole-match rule is its own evidence. A capture group holds whatever
      // followed `PASSWORD=`, so it is trimmed of the syntax it ran into and
      // dropped when it names a secret instead of being one.
      if (rule.group === 0) {
        into(raw, rule)
        continue
      }
      // Both forms are tested: trimming strips the very brackets that make
      // `${DB_PASSWORD}` and `[MASKED-0001]` recognisable as placeholders.
      const value = trimCapture(raw)
      if (value.length < 3 || isPlaceholder(raw) || isPlaceholder(value)) continue
      into(value, rule)
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
