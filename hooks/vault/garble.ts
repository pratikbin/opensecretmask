const DIGITS = '0123456789'
const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

// A fake is sent to the model by design, so it is public and predicting one
// buys nothing. Math.random is the right tool; a CSPRNG here would be theatre.
const pick = (set: string) => set[Math.floor(Math.random() * set.length)]!

/**
 * A format-preserving fake of `value`.
 *
 * The first `keepPrefix` characters are copied verbatim, each digit becomes a
 * digit, each letter a letter of the same case, and structure (`-`, `_`, `.`)
 * stays where it was. Length and shape survive, so the model reasons about the
 * fake exactly as it would the real credential.
 *
 * This is the whole reason the plugin exists. An opaque `[REDACTED]` tag tells
 * the model "something was here"; a same-shaped fake tells it "this is an
 * Anthropic key", which is what keeps its reasoning intact.
 */
export function garble(value: string, keepPrefix: number): string {
  const keep = Math.min(Math.max(keepPrefix, 0), value.length)
  let out = value.slice(0, keep)
  for (let i = keep; i < value.length; i++) {
    const c = value[i]!
    if (c >= '0' && c <= '9') out += pick(DIGITS)
    else if (c >= 'a' && c <= 'z') out += pick(LOWER)
    else if (c >= 'A' && c <= 'Z') out += pick(UPPER)
    else out += c
  }
  return out
}
