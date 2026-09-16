// Failing closed without blaming the wrong party.
//
// The engine skips a hook that throws OR overruns its budget and runs core in
// its place. For a masking hook that is the worst outcome: being skipped means
// the unmasked content goes straight to the model. So a hook must answer for
// itself rather than let the engine answer for it.
//
// The subtlety that cost us once: the deadline must cover OUR work only, never
// a `next()` call. Wrapping `next()` charges every hook beneath us and the
// engine's own work to our budget, so a slow unrelated plugin makes osm drop
// the user's prompt with a message blaming osm. Masking is string replacement
// measured in microseconds; if it ever takes seconds, that is our bug.
//
// Synchronous work cannot overrun a timer it blocks, so `guard` is a plain
// try/catch. `guardAsync` adds a real deadline for the rare async case, and
// takes an AbortSignal so the host-side timer ends with the dispatch instead
// of parking for the full window.

/** Our deadline, comfortably inside the engine's own. */
export const BUDGET_MS = 8_000

/** A cancellable wait. In a hook that is `$.clock.sleep`. */
export type Sleep = (ms: number, options?: { signal?: AbortSignal }) => Promise<void>

const EXPIRED = Symbol('osm.expired')

/**
 * Runs `work` and falls back to `onFailure()` if it throws.
 *
 * For the synchronous masking calls, which is all of them today. `work` must
 * not call `next()`.
 */
export function guard<T>(work: () => T, onFailure: () => T): T {
  try {
    return work()
  } catch {
    return onFailure()
  }
}

/**
 * Runs `work` and falls back to `onFailure()` on a throw or an overrun.
 *
 * `work` must not call `next()`; see the note at the top of this file. The
 * losing wait is aborted, so no host-side timer outlives the dispatch.
 */
export async function guardAsync<T>(
  work: () => Promise<T>,
  onFailure: () => T,
  sleep: Sleep,
  ms: number = BUDGET_MS,
): Promise<T> {
  const abort = new AbortController()
  try {
    const expired = sleep(ms, { signal: abort.signal }).then(() => EXPIRED)
    const winner = await Promise.race([work(), expired])
    return winner === EXPIRED ? onFailure() : (winner as T)
  } catch {
    return onFailure()
  } finally {
    abort.abort()
  }
}
