import type { On, ToolCallInput, ToolCallResult } from 'claude-code'

import { inbound, outbound } from '../policy/boundary'
import { guard } from '../policy/budget'
import type { Options } from '../options'
import { portOf, save } from '../vault/persist'
import type { Vault } from '../vault'

export const DENY_MASK =
  'osm: blocked. The result could not be masked, so it was not shown to the model.'
export const DENY_UNMASK =
  'osm: blocked. The arguments could not be restored, so the tool was not run.'

/**
 * The round trip, both directions in one hook.
 *
 * One registration covers Read, Bash, Grep, WebFetch, Write, the Agent tool
 * and every MCP tool, because it matches the event and not a list of names.
 * The direction policy lives in `policy/boundary.ts`, so this file is the
 * sequence and nothing more.
 */
export function registerToolCall(on: On, vault: Vault, options: Options) {
  // The vault only grows, so a size change is an exact "something new to
  // save". Without this the plugin wrote the entire snapshot to the host
  // store on every single tool call, re-serialising data that had not moved.
  let savedSize = -1

  on('tool.call', async ($, e, next) => {
    let down: ToolCallInput
    try {
      down = inbound(vault, e)
    } catch {
      return { deny: DENY_UNMASK }
    }

    const up = await next(down)

    const masked = guard(
      () => outbound(vault, up),
      () => ({ deny: DENY_MASK }) as ToolCallResult,
    )

    if (options.persist && vault.size !== savedSize) {
      savedSize = vault.size
      void save(portOf($), vault.entries()).catch(() => undefined)
    }
    return masked
  })
}
