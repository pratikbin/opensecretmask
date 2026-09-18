// What a captured value must NOT be, declared the way a rule is declared.
//
// 138 of the rules match a whole value: `sk-ant-…` is a credential by
// construction and needs no second opinion. Eight match a CONTEXT and take
// whatever follows — `SERVICE_TOKEN=(\S{8,})` cannot know what sits to its
// right. That wildcard is the price of catching a credential with no vendor
// shape, such as a Postgres password, and it is where every false positive
// came from: `${DB_PASSWORD}`, `[MASKED-0001]`, a bare UUID, a printf format
// string, and this repository's own regex source read back out of a file.
//
// These lived as private constants in `suppress.ts`, which made the codebase
// asymmetric: what counts as a credential was declared in `rules/`, what
// obviously is not was buried a directory away. Both halves are here now.
// Excluding a class costs one line, the same as including one.
//
// Order does not matter: the first match wins and they all mean "not a
// credential". Never give one the `g` flag — `test()` on a global regex
// carries `lastIndex` between calls and starts skipping matches.

/** One shape a capture-group rule must refuse. */
export type Deny = {
  name: string
  re: RegExp
  why: string
}

export const deny = (name: string, re: RegExp, why: string): Deny => ({ name, re, why })

export const denyRules: readonly Deny[] = [
  deny(
    'Variable reference',
    /^(?:\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*|%[A-Za-z_][A-Za-z0-9_]*%)$/,
    'names the secret rather than being it: $KEY, ${KEY}, %KEY%',
  ),
  deny(
    'Bracketed placeholder',
    /^(?:<[^>]*>|\{\{[^}]*\}\}|\[[^\]]*\])$/,
    'a slot in documentation or a template: <your-key>, {{KEY}}, [MASKED-0001]',
  ),
  // Two patterns rather than one with `i`: a case-insensitive `[A-Z]` class
  // matches any letter, which suppressed every lowercase bearer token.
  deny(
    'Shouted placeholder',
    /^(?:[A-Z][A-Z_-]{2,}|x{3,}|\*{3,}|\.{3,})$/,
    'the word standing in for the value in a documented example',
  ),
  deny(
    'Documentation word',
    /^(?:changeme|your[_-]?\w*|example\w*|redacted|dummy|placeholder|sample)$/i,
    'says outright that it is not a real credential',
  ),
  deny(
    'Regex syntax',
    /\\[bdswBDSW]|\[\^|\(\?:|\{\d+,\d*\}|\\\//,
    'a pattern, which arrives whenever a rule file is read aloud',
  ),
  // `op://vault/item/field`, `vault://…`, `https://…`: a locator for the
  // credential, not the credential. A DSN that carries one inline has an `@`
  // before the host, and `Connection String Password` masks that group on its
  // own, so requiring no `@` anywhere keeps the two apart.
  deny(
    'Secret reference',
    /^[a-z][a-z0-9+.-]{1,20}:\/\/[^\s@]*$/i,
    'points at where the secret lives: op://vault/item/field',
  ),
  deny(
    'UUID',
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
    'an identifier, and a session id under a credential name is still an id',
  ),
]

/**
 * Deliberately absent: plain hex and digit runs.
 *
 * Under an explicit `API_KEY=` the name is the evidence, and a 32-hex value
 * there is usually the real thing. The entropy layer suppresses them, because
 * a bare 40-hex run in prose is a git SHA — but that is a different question,
 * asked of a different candidate, and it lives in `suppress.ts`.
 */
export const DENY_NOTE = 'hex and digit runs are judged by the entropy layer, not here'
