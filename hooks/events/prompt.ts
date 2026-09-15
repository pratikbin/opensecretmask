import type { On } from 'claude-code'

import { guard } from '../policy/budget'
import type { Vault } from '../vault'

const DROP =
  'osm: dropped. The prompt could not be masked, so it was not sent to the model.'

/**
 * The three prompt-side channels, all outbound.
 *
 * `prompt.submit`   what the person typed, plus any context blocks attached.
 * `prompt.context`  the blocks on the first user message. `claudeMd` lives
 *                   here, which is where the instruction files reach the
 *                   model. Without this hook CLAUDE.md goes through unmasked.
 * `prompt.section`  the named sections of the system prompt, `memory` among
 *                   them.
 *
 * Each falls closed on its own: a prompt that cannot be masked is dropped, and
 * a section that cannot be masked is emptied rather than sent through.
 */
export function registerPrompt(on: On, vault: Vault) {
  on('prompt.submit', async ($, e, next) =>
    guard(
      () =>
        next({
          ...e,
          text: vault.mask(e.text),
          context: e.context?.map((block) => vault.mask(block)),
        }),
      () => ({ drop: DROP }),
      $.clock.sleep,
    ),
  )

  on('prompt.context', async ($, e, next) =>
    guard(
      async () => {
        const { blocks } = await next(e)
        return { blocks: blocks.map((b) => ({ ...b, text: vault.mask(b.text) })) }
      },
      () => ({ blocks: [] }),
      $.clock.sleep,
    ),
  )

  on('prompt.section', async ($, e, next) =>
    guard(
      async () => {
        const { text } = await next(e)
        return { text: typeof text === 'string' ? vault.mask(text) : text }
      },
      () => ({ text: null }),
      $.clock.sleep,
    ),
  )
}
