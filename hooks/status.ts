// The line under the prompt, and the line at session start.
//
// Two different jobs. The start line is read once and answers "is this on, and
// what did it find". The status line stays on screen and answers "is it doing
// anything", which is the question a masking plugin is otherwise silent about:
// when it works, the user sees nothing at all.

import type { Options } from './options'
import type { Stats } from './vault'

/** Counts that have already been drawn, so an unchanged line is not redrawn. */
let lastDrawn = ''

function plural(n: number, one: string): string {
  return `${n} ${one}${n === 1 ? '' : 's'}`
}

/**
 * The start line: what is watched, and what is off.
 *
 * `registered` is what the `.env` files gave us, `restored` what a previous
 * session left in the store. The trailing notes name the layers that are NOT
 * running, because a user who expected entropy masking and did not get it has
 * no other way to find out.
 */
export function startLine(
  registered: number,
  restored: number,
  rules: number,
  options: Options,
): string {
  const parts: string[] = []
  if (registered > 0) parts.push(`${plural(registered, 'secret')} from ${options.envFiles.join(', ')}`)
  if (restored > 0) parts.push(`${restored} restored`)
  parts.push(`${rules} rules`)
  if (options.detect.entropy) parts.push('entropy on')
  if (options.persist) parts.push(`persist on, ${options.retentionDays}d`)

  const head = registered === 0 && restored === 0 ? 'masking on, nothing registered' : 'masking'
  return `osm: ${head} (${parts.join(', ')})`
}

/**
 * The pinned line, or `undefined` when it would say what it already says.
 *
 * The caller passes it to `$.ui.status`, because the hook validator follows `$`
 * only inside the file that declares the function. Returning `undefined` for an
 * unchanged line matters: the masking hooks run on every tool result, and
 * `$.ui.status` is an engine round trip.
 */
export function statusLine(stats: Stats): string | undefined {
  const line =
    stats.secrets === 0
      ? 'osm: watching'
      : `osm: ${plural(stats.secrets, 'secret')} · ${stats.masked} masked · ${stats.restored} restored`
  if (line === lastDrawn) return undefined
  lastDrawn = line
  return line
}

/** For the tests, which load the module once and run several sessions through it. */
export function resetStatus(): void {
  lastDrawn = ''
}
