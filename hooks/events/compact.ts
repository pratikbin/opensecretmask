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

/**
 * Masks everything in a message except the two fields the engine reads as
 * structure.
 *
 * Masking what is left rather than naming the content fields: `walk` never
 * skips by key, and CLAUDE.md records what deciding by key name cost last
 * time. A content field added upstream is covered here by default instead of
 * reaching the summarizer because nobody updated a list.
 *
 * `walk` returns the original identity when no leaf moved, which is the same
 * signal `boundary.ts` uses to tell a rewrite from a pass-through.
 */
function scrub(message: SessionMessage, vault: Vault): SessionMessage {
  const { handle, role, ...rest } = message
  const masked = vault.maskDeep(rest, 'compact')
  if (masked === rest) return message
  return { role, ...masked, handle: undefined }
}
