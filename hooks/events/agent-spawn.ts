import type { On } from 'claude-code'

import { guard } from '../policy/budget'
import type { Vault } from '../vault'

/**
 * The subagent boundary.
 *
 * `agent.spawn` fires when the engine is about to start a subagent, whatever
 * tool triggered it, with the task text rewritable. That makes it the one
 * place the "never hand a real credential to another model" rule can be stated
 * once and hold for dispatch paths that do not exist yet.
 *
 * `tool.call` cannot do this job. It would need a table of tool names, and the
 * table is always one entry behind: a message-passing tool, an MCP server
 * taking a `prompt`, a plugin's own agent tool. Each omission is a silent leak
 * that surfaces only when somebody notices.
 *
 * Masking here is belt and braces. `policy/boundary.ts` already declines to
 * restore a fake it does not recognise, so the usual case is that the prompt
 * still carries fakes by the time it arrives. This catches the other routes.
 */
export function registerAgentSpawn(on: On, vault: Vault) {
  on('agent.spawn', ($, e, next) => {
    const masked = guard(
      () => ({ prompt: vault.mask(e.prompt), description: vault.mask(e.description) }),
      () => undefined,
    )
    return masked === undefined
      ? { deny: 'osm: blocked. The subagent task could not be masked.' }
      : next({ ...e, ...masked })
  })
}
