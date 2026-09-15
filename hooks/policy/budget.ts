// Failing closed on a slow hook.
//
// The engine skips a hook that throws OR overruns its time budget, and runs
// core in its place. For most plugins that is a sensible default. For a
// masking hook it is the worst possible outcome: being skipped means the
// unmasked content goes straight to the model, so a slow hook is strictly
// worse than no hook at all.
//
// A local try/catch cannot help, because a timeout is not an exception this
// code ever sees. So the hook polices itself: it races its own work against a
// shorter deadline and RETURNS a deny before the engine's skip can fire. A
// deny is a visible, safe failure. Being skipped is an invisible, unsafe one.

/** Our deadline, comfortably inside the engine's own. */
export const BUDGET_MS = 8_000

/** A wait, supplied by the caller. In a hook that is `$.clock.sleep`. */
export type Sleep = (ms: number) => Promise<void>

const EXPIRED = Symbol('osm.expired')

/**
 * Runs `work`, and if it has not settled within `ms`, resolves `onTimeout()`.
 *
 * The losing promise is left to settle on its own. It cannot be cancelled and
 * its result is discarded.
 */
export async function withBudget<T>(
  work: Promise<T>,
  onTimeout: () => T,
  sleep: Sleep,
  ms: number = BUDGET_MS,
): Promise<T> {
  const expired = sleep(ms).then(() => EXPIRED)
  const winner = await Promise.race([work, expired])
  return winner === EXPIRED ? onTimeout() : (winner as T)
}

/**
 * Runs `work` and falls back to `onFailure()` on a throw or an overrun.
 *
 * With no `sleep` it degrades to a plain try/catch, which still covers the
 * throwing case. Every hook passes `$.clock.sleep` so the overrun case is
 * covered too.
 */
export async function guard<T>(
  work: () => Promise<T>,
  onFailure: () => T,
  sleep?: Sleep,
  ms: number = BUDGET_MS,
): Promise<T> {
  try {
    const running = work()
    if (!sleep) return await running
    return await withBudget(running, onFailure, sleep, ms)
  } catch {
    return onFailure()
  }
}
