import type { EngineInterface, On, ToolCallInput, ToolCallResult } from 'claude-code'

import { guard } from '../policy/budget'
import { isModelFacing, RESERVED } from '../policy/model-facing'
import type { Options } from '../options'
import { save, type PersistPort } from '../vault/persist'
import type { Vault } from '../vault'

export const DENY_MASK =
  'osm: blocked. The result could not be masked, so it was not shown to the model.'
export const DENY_UNMASK =
  'osm: blocked. The arguments could not be restored, so the tool was not run.'

/**
 * The round trip, both directions in one hook.
 *
 * Down: a fake in the tool's arguments becomes the real secret, except where
 * the argument is read by a model rather than by an external operation.
 * Up: a secret in the tool's answer becomes a fake.
 *
 * One registration covers Read, Bash, Grep, WebFetch, Write, the Agent tool
 * and every MCP tool, because it matches the event and not a list of names.
 */
export function registerToolCall(on: On, vault: Vault, options: Options) {
  on('tool.call', async ($, e, next) => {
    let down: ToolCallInput
    try {
      down = restoreArgs(vault, e)
    } catch {
      return { deny: DENY_UNMASK }
    }

    const up = await next(down)

    const masked = await guard(
      async () => maskResult(vault, up),
      () => ({ deny: DENY_MASK }) as ToolCallResult,
      $.clock.sleep,
    )

    if (options.persist) void persist($, vault)
    return masked
  })
}

function persist($: EngineInterface, vault: Vault): Promise<void> {
  const port: PersistPort = {
    get: (key) => $.store.get(key),
    set: (key, value) => $.store.set(key, value),
    readFile: (path) => $.fs.read(path),
  }
  return save(port, vault.entries()).catch(() => undefined)
}

/**
 * `e` with every fake in its arguments restored.
 *
 * A reserved key is passed through untouched because the engine refuses a
 * rewrite of it. A model-facing argument is passed through because restoring
 * it would hand the real credential to another model.
 */
export function restoreArgs(vault: Vault, e: ToolCallInput): ToolCallInput {
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

/**
 * The tool's answer with every secret in it replaced by its fake.
 *
 * Three model-facing fields, not two: `result`, `text`, and `context`, which
 * carries a PostToolUse hook's additional text straight to the model where the
 * user never sees it.
 */
export function maskResult(vault: Vault, up: ToolCallResult): ToolCallResult {
  if (up.deny !== undefined) {
    const deny = vault.mask(up.deny)
    return deny === up.deny ? up : { deny }
  }

  const result = vault.maskDeep(up.result)
  const text = up.text === undefined ? undefined : vault.mask(up.text)
  const context =
    up.context === undefined ? undefined : up.context.map((block) => vault.mask(block))

  const contextChanged =
    up.context !== undefined && context!.some((block, i) => block !== up.context![i])
  if (result === up.result && text === up.text && !contextChanged) return up

  // `ref` names the messages core already built for this call. Returning it
  // makes core use those verbatim, which are the unmasked ones. Drop it so
  // core rebuilds from what this hook answers.
  const { ref: _ref, ...rest } = up as ToolCallResult & { ref?: number }
  return { ...rest, result, text, context } as ToolCallResult
}
