// The two directions, stated once.
//
// Every event module routes through these rather than re-deriving which
// fields are model-facing and remembering to strip `ref`. That was a per-site
// review question before, and it failed silently when missed: the engine just
// used its own unmasked messages. Now it is a property of the boundary.

import type { ToolCallInput, ToolCallResult } from 'claude-code'

import type { Vault } from '../vault'

import { isModelFacing, RESERVED } from './model-facing'

/**
 * A result on its way to the model, with every secret in it replaced.
 *
 * Three model-facing fields, not two: `result`, `text`, and `context`, which
 * carries a PostToolUse hook's additional text straight to the model where the
 * user never sees it.
 *
 * `ref` names the messages core already built. Returning it makes core use
 * those verbatim, which are the unmasked ones, so any rewrite must answer
 * without it. Stripping it here is the whole reason this function exists.
 */
export function outbound(vault: Vault, up: ToolCallResult, where = 'tool'): ToolCallResult {
  if (up.deny !== undefined) {
    const deny = vault.mask(up.deny, where)
    return deny === up.deny ? up : { deny }
  }

  const result = vault.maskDeep(up.result, where)
  const text = up.text === undefined ? undefined : vault.mask(up.text, where)
  const context = vault.maskDeep(up.context, where)

  if (result === up.result && text === up.text && context === up.context) return up

  const { ref: _ref, ...rest } = up as ToolCallResult & { ref?: number }
  return { ...rest, result, text, context } as ToolCallResult
}

/**
 * Tool arguments on their way out of the process, with every fake restored.
 *
 * A reserved key is passed through because the engine refuses a rewrite of it.
 * A model-facing argument is passed through because its consumer is another
 * model, and handing that model the real credential is the leak this plugin
 * exists to prevent.
 */
export function inbound(vault: Vault, e: ToolCallInput): ToolCallInput {
  let changed = false
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(e)) {
    if (RESERVED.has(key) || isModelFacing(e.tool, key)) {
      out[key] = value
      continue
    }
    const next = vault.unmaskDeep(value)
    if (next !== value) changed = true
    out[key] = next
  }
  return changed ? (out as ToolCallInput) : e
}
