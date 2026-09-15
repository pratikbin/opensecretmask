/**
 * One detection pattern.
 *
 * `group` is the submatch index holding the credential itself (0 = the whole
 * match), so a context-bearing rule masks the secret and not the text around
 * it. Every pattern carries the `g` flag; `scan` relies on `matchAll`.
 */
export type Rule = {
  name: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  re: RegExp
  group: number
}

export const rule = (
  name: string,
  severity: Rule['severity'],
  re: RegExp,
  group = 0,
): Rule => ({ name, severity, re, group })
