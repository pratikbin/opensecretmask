// `/osm-secrets`: what has been masked, and where it came from.
//
// The table goes out through `$.ui.log`, which draws a dim transcript line the
// model never receives. Returning it as the command's `{ text }` would put
// every fake beside its real secret straight into the model's context, which
// is the leak this plugin exists to prevent. So the command shows nothing as
// text and answers `{}`.
//
// Even on a user-only channel a real secret is not printed whole: `elide`
// hides the middle, keeping enough of both ends to recognise the value.
//
// One line per secret, not a column table. A table needs every cell on one
// terminal row, and these cells cannot be: a PEM key carries newlines, a JWT
// runs to 300 characters, and the log channel wraps. The aligned table came
// apart into a wall of fragments the moment a real session had 34 secrets in
// it. So each field is bounded first, then the row is short enough to survive
// a wrap intact.

import type { On } from 'claude-code'

import type { LedgerEntry } from '../vault'
import type { Vault } from '../vault'

export const COMMAND = 'osm-secrets'

/**
 * `value` with its middle 30% hidden: characters 5 to 7 of a ten-character
 * string, scaled for anything longer.
 *
 * The ends stay because they are what a user matches against their `.env`; a
 * prefix alone does not tell two keys from the same vendor apart.
 */
export function elide(value: string): string {
  const start = Math.floor(value.length * 0.4)
  const end = Math.ceil(value.length * 0.7)
  if (end <= start) return '•'.repeat(value.length)
  return `${value.slice(0, start)}${'•'.repeat(end - start)}${value.slice(end)}`
}

/** The widest a secret or a fake is drawn. Bounded so a row cannot wrap. */
const CELL = 22

/**
 * `value` as one short, single-line, middle-hidden fragment.
 *
 * Whitespace goes first, because a PEM key's newlines would otherwise break
 * the row into pieces. Anything past `CELL` keeps both ends and states its
 * real length, which is what tells two keys of the same vendor apart.
 */
export function preview(value: string): string {
  const flat = value.replace(/\s+/g, ' ').trim()
  if (flat.length <= CELL) return elide(flat)
  return `${flat.slice(0, 10)}•••${flat.slice(-6)} (${value.length})`
}

/** The report as lines, one secret per line. Pure, so the unit checks can read it. */
export function secretsTable(entries: readonly LedgerEntry[]): string[] {
  if (entries.length === 0) {
    return ['osm: no secrets masked yet this session.']
  }

  const width = String(entries.length).length
  return [
    `osm: ${entries.length} secret${entries.length === 1 ? '' : 's'} this session (real → fake)`,
    ...entries.map(
      (e, i) => `${String(i + 1).padStart(width)}. ${preview(e.secret)} → ${preview(e.fake)}`,
    ),
  ]
}

export const SPEC = {
  name: COMMAND,
  description: 'Show the secrets osm has masked this session, and where they came from.',
}

/**
 * Serves the command. `session.start` declares it, because that hook is
 * already there and the engine's validator follows `$` only within a file.
 */
export function registerCommand(on: On, vault: Vault) {
  on('command.run', { command: COMMAND }, ($) => {
    for (const row of secretsTable(vault.ledger())) $.ui.log(row)
    return {}
  })
}
