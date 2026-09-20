// Deep traversal of a tool result or argument tree.
//
// The hard-won rule here: "this is an opaque payload" is a property of the
// STRING, not of the key its parent filed it under. An earlier version gated
// on a list of key names (`data`, `base64`, …) and skipped the whole subtree,
// which meant `{ data: { apiKey: "sk-ant-…" } }` — the commonest JSON envelope
// shape there is — reached the model completely unmasked, and a fake the model
// placed anywhere under `data` never restored. A fix for garbled images became
// a leak. Test it at the leaf instead: nothing is ever skipped structurally.

/** Past this depth a result is pathological, not data. */
export const MAX_DEPTH = 12

/** Past this length a string is a payload, not prose. */
export const MAX_STRING = 8_000_000

/** Long enough that a substitution is not worth the risk of corrupting a blob. */
const OPAQUE_MIN = 4096

/** Base64 and base64url, the encodings a binary payload actually arrives in. */
const BASE64_ONLY = /^[A-Za-z0-9+/_-]+={0,2}$/

/** A data: URI carries its own payload after the comma. */
const DATA_URI = /^data:[\w.+-]+\/[\w.+-]+;base64,/

/**
 * Whether `s` is an encoded payload rather than text worth scanning.
 *
 * A credential is short. A PNG, a PDF or an audio buffer is long, unbroken and
 * drawn from the base64 alphabet. Requiring all three keeps `apiKey` values in
 * play at any nesting depth while leaving real blobs untouched.
 */
export function isOpaque(s: string): boolean {
  if (s.length < OPAQUE_MIN) return false
  if (DATA_URI.test(s)) return true
  // Whitespace means prose, a log, or a file listing: still worth scanning.
  if (/\s/.test(s)) return false
  return BASE64_ONLY.test(s)
}

/**
 * `value` with `fn` applied to every string in it, at any depth.
 *
 * Returns the original identity when nothing changed, so a caller can tell a
 * rewrite from a pass-through. The replacement node is allocated lazily, on
 * the first child that actually changes.
 *
 * Property NAMES are left alone. Rewriting keys would need collision handling
 * in both directions and risks corrupting a real structure, for a case that
 * barely occurs: a credential used as a JSON key.
 */
export function walk<T>(value: T, fn: (s: string) => string, depth = 0): T {
  if (typeof value === 'string') {
    // `isOpaque` no longer gates this. Skipping a payload skipped BOTH of
    // mask()'s passes, and only the scan pass has false positives to protect
    // a blob from; the exact-match pass cannot fire on a string that does not
    // already contain a registered secret. A 6KB whitespace-free log line
    // carrying a known credential reached the model verbatim. mask() now
    // decides for itself whether to scan; see Vault.mask.
    if (value.length > MAX_STRING) return value
    return fn(value) as T
  }
  if (depth >= MAX_DEPTH) return value

  if (Array.isArray(value)) {
    let out: unknown[] | undefined
    for (let i = 0; i < value.length; i++) {
      const next = walk(value[i], fn, depth + 1)
      if (next === value[i]) {
        out?.push(next)
        continue
      }
      out ??= value.slice(0, i)
      out.push(next)
    }
    return (out ?? value) as T
  }

  if (value !== null && typeof value === 'object') {
    let out: Record<string, unknown> | undefined
    for (const [key, item] of Object.entries(value)) {
      const next = walk(item, fn, depth + 1)
      if (next !== item) out ??= { ...(value as Record<string, unknown>) }
      if (out) out[key] = next
    }
    return (out ?? value) as T
  }

  return value
}
