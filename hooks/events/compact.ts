import type { On, SessionMessage } from 'claude-code'

import { guard } from '../policy/budget'
import type { Vault } from '../vault'

const SKIP =
  'osm: not compacted. The transcript could not be masked, so it was not summarized.'

/**
 * Masks what the summarizer reads.
 *
 * A compaction hands the transcript to a model and keeps what that model
 * writes, so a secret that reached the transcript through a channel we do not
 * hook would be read here and then laundered into a summary that survives
 * every later turn. Everything the model has already seen is masked, which is
 * exactly why this hook is cheap: on a healthy session it changes nothing.
 *
 * Only the messages that actually change are rewritten. The engine's `handle`
 * marks a message as its own and makes it stand whole; a message handed back
 * without one is rebuilt from its fields, losing whatever the summary shape
 * does not carry. So an untouched message keeps its handle, and one we had to
 * mask gives it up — a fidelity cost paid only where a real secret was found.
 */
export function registerCompact(on: On, vault: Vault) {
  on('session.compact', ($, e, next) => {
    const masked = guard(
      () => e.messages.map((m) => scrub(m, vault)),
      () => undefined,
    )
    if (masked === undefined) return { skip: SKIP }
    return next({ ...e, messages: masked })
  })
}

function scrub(message: SessionMessage, vault: Vault): SessionMessage {
  const where = 'compact'
  const next: SessionMessage = {
    ...message,
    text: vault.mask(message.text, where),
    toolUses: vault.maskDeep(message.toolUses, where),
    ...(message.toolResults ? { toolResults: vault.maskDeep(message.toolResults, where) } : {}),
  }
  // `handle` is an opaque engine token. It is never masked, and it is only
  // surrendered when something under it moved.
  if (JSON.stringify(next) === JSON.stringify(message)) return message
  return { ...next, handle: undefined }
}
