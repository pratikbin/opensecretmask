import type { On } from 'claude-code'

import { guard } from '../policy/budget'
import { statusLine } from '../status'
import type { Vault } from '../vault'

const DROP =
  'osm: dropped. The prompt could not be masked, so it was not sent to the model.'

const CONSUMED =
  'osm: consumed. The delivery could not be masked, so it was not queued.'

/**
 * The three prompt-side channels, all outbound.
 *
 * `prompt.submit`   what the person typed, plus any context blocks attached.
 * `prompt.context`  the blocks on the first user message. `claudeMd` lives
 *                   here, which is where the instruction files reach the
 *                   model. Without this hook CLAUDE.md goes through unmasked.
 * `prompt.section`  the named sections of the system prompt, `memory` among
 *                   them.
 * `skill.prompt`    a skill's expanded prompt. Skill bodies are files on
 *                   disk, and one of them reaching the model goes through
 *                   here rather than through `prompt.context`.
 * `session.receive` a delivery before it is queued: a relay event, a peer's
 *                   message, a Remote Control prompt. An inbound prompt path
 *                   that never passes `prompt.submit`.
 *
 * Each guards only its own masking. Wrapping the `next()` call instead would
 * charge every hook beneath us to our budget and drop the user's prompt when
 * some other plugin is slow.
 */
export function registerPrompt(on: On, vault: Vault) {
  on('prompt.submit', ($, e, next) => {
    const masked = guard(
      () => ({
        text: vault.mask(e.text, 'prompt'),
        context: e.context?.map((block) => vault.mask(block, 'prompt')),
      }),
      () => undefined,
    )
    if (masked === undefined) return { drop: DROP }
    const line = statusLine(vault.stats)
    if (line) $.ui.status(line)
    return next({ ...e, ...masked })
  })

  // A skill's own text, which `prompt.context` never sees.
  on('skill.prompt', ($, e, next) => {
    const text = guard(
      () => vault.mask(e.text, `skill:${e.skill}`),
      () => undefined,
    )
    // No drop on this channel: the engine's answer is a prompt, so refusing
    // means handing back the empty one rather than the unmasked one.
    return next({ ...e, text: text ?? '' })
  })

  // Queued, transcribed and read by the model, all without `prompt.submit`.
  on('session.receive', ($, e, next) => {
    const text = guard(
      () => vault.mask(e.text, `receive:${e.origin}`),
      () => undefined,
    )
    if (text === undefined) return { consumed: CONSUMED }
    return next({ ...e, text })
  })

  on('prompt.context', async ($, e, next) => {
    const { blocks } = await next(e)
    return guard(
      () => ({ blocks: blocks.map((b) => ({ ...b, text: vault.mask(b.text, 'prompt.context') })) }),
      () => ({ blocks: [] }),
    )
  })

  on('prompt.section', async ($, e, next) => {
    const { text } = await next(e)
    return guard(
      () => ({ text: typeof text === 'string' ? vault.mask(text, 'prompt.section') : text }),
      () => ({ text: null }),
    )
  })
}
