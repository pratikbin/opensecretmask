const QUANTIFIER = new Set(['?', '*', '+', '{'])
const META = new Set(['[', '(', ')', '{', '}', '?', '*', '+', '|', '^', '$', '.'])

/**
 * The fixed text a pattern must begin with.
 *
 * Two jobs: a cheap `includes` gate before running a rule, and the number of
 * leading characters a garble copies verbatim so a fake still reads as that
 * vendor's credential. `sk-ant-[a-zA-Z0-9\-_]{10,}` yields `sk-ant-`, so the
 * fake keeps the prefix and only `api03…` changes.
 */
export function literalPrefix(source: string): string {
  let out = ''
  for (let i = 0; i < source.length; i++) {
    const c = source[i]!
    if (c === '\\') {
      const escaped = source[i + 1]
      // \d \w \s \b are classes, not literals.
      if (escaped === undefined || /[a-zA-Z0-9]/.test(escaped)) break
      if (QUANTIFIER.has(source[i + 2] ?? '')) break
      out += escaped
      i++
      continue
    }
    if (META.has(c)) break
    // A quantifier makes the character it follows optional or repeated, so
    // that character is not part of a fixed prefix.
    if (QUANTIFIER.has(source[i + 1] ?? '')) break
    out += c
  }
  return out
}
