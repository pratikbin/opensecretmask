import type { On, PluginOptions } from 'claude-code'

import { registerAgentSpawn } from './events/agent-spawn'
import { registerCommand } from './events/command'
import { registerPrompt } from './events/prompt'
import { registerSessionStart } from './events/session-start'
import { registerToolCall } from './events/tool-call'
import { readOptions } from './options'
import { Vault } from './vault'

/**
 * Wiring, and nothing else.
 *
 * One vault per load of the plugin, shared by every hook. Each event module
 * owns its own behaviour and its own failure mode, so this file stays a map of
 * what is hooked rather than a place where logic accumulates.
 *
 * @param on the engine's registrar
 * @param options the plugin's settings
 */
export function register(on: On, options: PluginOptions) {
  const opts = readOptions(options)
  const vault = new Vault(opts.detect)

  registerSessionStart(on, vault, opts)
  registerToolCall(on, vault, opts)
  registerAgentSpawn(on, vault)
  registerPrompt(on, vault)
  registerCommand(on, vault)
}
