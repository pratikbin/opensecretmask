// .env parsing, shared by the session.start hook and the persistence layer.

const LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/

/**
 * The value from the right-hand side of a `.env` line.
 *
 * A quoted value ends at its closing quote, so a trailing comment after it is
 * dropped. An unquoted value ends at an unescaped ` #`. Getting this wrong is
 * not cosmetic: registering `hunter2 # prod` means the real password
 * `hunter2` is never registered at all, and the exact-match layer silently
 * does nothing for that line.
 */
export function parseValue(raw: string): string {
  const s = raw.trim()
  const quote = s[0]
  if (quote === '"' || quote === "'") {
    const end = s.indexOf(quote, 1)
    if (end > 0) return s.slice(1, end)
    return s.slice(1)
  }
  const comment = s.search(/\s#/)
  return (comment === -1 ? s : s.slice(0, comment)).trim()
}

/** Every `KEY=value` pair in `text`, comments and blank lines skipped. */
export function parseEnv(text: string): Map<string, string> {
  const out = new Map<string, string>()
  for (const line of text.split('\n')) {
    if (line.trimStart().startsWith('#')) continue
    const m = LINE.exec(line)
    if (!m) continue
    out.set(m[1]!, parseValue(m[2]!))
  }
  return out
}

/**
 * Whether a `.env` entry looks like a credential worth registering.
 *
 * `looksLikeSecret` is the name test. The caller adds a shape test, so a value
 * a detection rule recognises is registered whatever its name. `PORT=3000` and
 * `NODE_ENV=development` pass neither and stay readable to the model.
 */
const SECRETISH =
  /KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|PRIVATE|AUTH|DSN|SALT|SIGNATURE|CERT/i

export const MIN_SECRET_LEN = 8

export function looksLikeSecret(name: string): boolean {
  return SECRETISH.test(name)
}
