// Failing closed without blaming the wrong party.
//
// The engine skips a hook that throws OR overruns its budget and runs core in
// its place. For a masking hook that is the worst outcome: being skipped means
// the unmasked content goes straight to the model. So a hook must answer for
// itself rather than let the engine answer for it.
//
// The subtlety that cost us once: a guard must cover OUR work only, never a
// `next()` call. Wrapping `next()` charges every hook beneath us and the
// engine's own work to our budget, so a slow unrelated plugin makes osm drop
// the user's prompt with a message blaming osm. Masking is string replacement
// measured in microseconds; if it ever takes seconds, that is our bug.
//
// Every masking call is synchronous, and synchronous work cannot overrun a
// timer it blocks, so this is a plain try/catch and not a deadline. An earlier
// `guardAsync` carried an AbortSignal and a real timer for an async caller
// that never arrived.

/**
 * Runs `work` and falls back to `onFailure()` if it throws.
 *
 * `work` must not call `next()`; see the note at the top of this file.
 */
export function guard<T>(work: () => T, onFailure: () => T): T {
  try {
    return work()
  } catch {
    return onFailure()
  }
}
