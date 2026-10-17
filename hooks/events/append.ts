import type { ApiContentBlock, On } from 'claude-code'

import { guard } from '../policy/budget'
import type { Vault } from '../vault'

export const WITHHELD =
  'osm: withheld. This content could not be masked, so it was not stored or sent to the model.'

/**
 * Masks every row a conversation keeps, before it is stored and sent.
 *
 * The other hooks guard named channels. This one guards the place they all
 * end up: a prompt, a tool result, the model's own blocks, an attachment such
 * as a nested CLAUDE.md read mid-session, a classic hook's additional context
 * (door `hook-context`), another plugin's note, a compaction summary. A door
 * we never enumerated still passes here.
 *
 * On a healthy session most rows already carry fakes and nothing changes,
 * because `mask` never re-mints a fake. Media blocks, tool_use, thinking and
 * every pinned field are left as they arrived; the engine refuses or reverts a
 * change to them.
 *
 * Adopted from karanb192/claude-code-redact, which hooks this event alone. osm
 * keeps its prompt hooks too: CLAUDE.md, memory and skill bodies reach the
 * model as prompt sections and context, not as rows.
 */
export function registerAppend(on: On, vault: Vault) {
  on('session.append', ($, e, next) => {
    const content = guard(
      () => maskBlocks(e.message.content, vault, `append:${e.door}`),
      () => withhold(e.message.content),
    )
    if (content === e.message.content) return next(e)
    return next({ ...e, message: { ...e.message, content } })
    // A row cannot be refused, only rewritten, so failing closed means storing
    // the notice in place of the text. When `next` was already called, the
    // engine replays what it settled to and ignores the argument.
  }).catch(($, e, next) => next({ ...e, message: { ...e.message, content: withhold(e.message.content) } }))
}

/** `blocks` with every secret in their text replaced; the same array when none was found. */
export function maskBlocks(blocks: readonly ApiContentBlock[], vault: Vault, where: string): ApiContentBlock[] {
  let out: ApiContentBlock[] | undefined
  blocks.forEach((block, i) => {
    const next = maskBlock(block, vault, where)
    if (next !== block) out ??= blocks.slice(0, i)
    out?.push(next)
  })
  return out ?? (blocks as ApiContentBlock[])
}

function maskBlock(block: ApiContentBlock, vault: Vault, where: string): ApiContentBlock {
  if (block.type === 'text') {
    const text = vault.maskDeep(block.text, where)
    return text === block.text ? block : { ...block, text }
  }
  if (block.type === 'tool_result') {
    const content =
      typeof block.content === 'string'
        ? vault.maskDeep(block.content, where)
        : Array.isArray(block.content)
          ? maskBlocks(block.content as ApiContentBlock[], vault, where)
          : block.content
    return content === block.content ? block : ({ ...block, content } as ApiContentBlock)
  }
  return block
}

/** Every text replaced by the notice. Total by construction: it is the fallback's fallback. */
export function withhold(blocks: unknown): ApiContentBlock[] {
  if (!Array.isArray(blocks)) return []
  return blocks.map((block) => {
    if (block?.type === 'text') return { ...block, text: WITHHELD }
    if (block?.type === 'tool_result') return { ...block, content: WITHHELD }
    return block
  })
}
