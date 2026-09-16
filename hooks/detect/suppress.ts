// False-positive suppression for the entropy layer.
//
// The regex rules are prefix-distinctive and need none of this. The entropy
// heuristic does: on ordinary prompt text a bare high-entropy run is far more
// often a git SHA, a UUID, a content hash or an identifier than a credential.
//
// Shapes and prefixes adapted from ray-amjad/awesome-claude-code-function-hooks
// (MIT, Copyright (c) 2026 Ray Amjad).

/**
 * Prefixes that name a PUBLIC object id, not a key.
 *
 * Stripe hands these out in dashboards, invoices and source code, and `pk_`
 * is its publishable key. Masking them makes a session useless and protects
 * nothing.
 */
const PUBLIC_PREFIX =
  /^(?:price|prod|cus|sub|sched|in|ch|pi|cs|py|re|txn|il|si|seti|evt|acct|promo|coupon|plan|card|ba|src|dp|du|iv|ii|rcpt|file|link|pm|tok|test|toolu|msg|req|run|wf)_/i

/** Stripe's publishable key: public by design, printed in client-side source. */
const PUBLISHABLE = /^pk_(?:live|test)_/i

/** Public ids identified by shape rather than prefix: YouTube channel and playlist. */
const PUBLIC_SHAPE = /^(?:UC[A-Za-z0-9_-]{22}|PL[A-Za-z0-9_-]{16,32})$/

const HEX_ONLY = /^[0-9a-f]+$/i
const DIGITS_ONLY = /^[0-9]+$/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** A name to the left of a candidate that says the candidate is a credential. */
const NAMED =
  /(?:key|token|secret|password|passwd|pwd|credential|auth|bearer|private|signature|session|cookie|dsn|salt|nonce|otp)["'\]\s]{0,4}[:=]{1,2}\s*["'`]?\s*$/i

/** How far left of the candidate to look for that name. */
const LOOKBEHIND = 64

/** An identifier written in code: `archivedModulesMarker`, `handle-checkout-session`. */
function isCodeName(token: string): boolean {
  const words = token.split(/[-_]|(?<=[a-z])(?=[A-Z])/).filter(Boolean)
  if (words.length < 3) return false
  return words.every((w) => /^[A-Za-z]+$/.test(w) && w.length <= 14)
}

/** How many distinct characters the token draws on. A key spans a wide alphabet. */
function alphabetWidth(token: string): number {
  return new Set(token).size
}

/**
 * Whether an entropy candidate should be left alone.
 *
 * `before` is the text immediately to the left of the candidate; a credential
 * name there overrides most suppression, because `api_key = <40 hex>` is a key
 * even though a bare 40-hex run is usually a commit id.
 */
export function isSuppressed(token: string, before: string): boolean {
  // Stripe's publishable key is public by definition, so it stays suppressed
  // even under a credential name. It is the one documented exception.
  if (PUBLISHABLE.test(token)) return true

  // The general rule outranks the enumerated one. Put the prefix list first
  // and every addition to it permanently subtracts from the signal that
  // actually generalises, which is how such a list grows without end.
  if (NAMED.test(before.slice(-LOOKBEHIND))) return false

  if (PUBLIC_PREFIX.test(token) || PUBLIC_SHAPE.test(token)) return true

  if (DIGITS_ONLY.test(token)) return true
  if (UUID.test(token)) return true
  // A 40-char hex run is a git SHA far more often than a key.
  if (HEX_ONLY.test(token)) return true
  if (isCodeName(token)) return true
  // A real key mixes cases and digits; 16 distinct characters is a low bar
  // that still excludes repetitive filler and base64-encoded prose.
  if (alphabetWidth(token) < 16) return true

  return false
}
