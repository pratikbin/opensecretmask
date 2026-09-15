/**
 * Property names whose value is an opaque blob, never text to scan.
 *
 * An MCP image result carries base64 under one of these. Running a
 * substitution over it corrupts the payload while protecting nothing, because
 * a PNG is not a credential. Adapted from
 * ray-amjad/awesome-claude-code-function-hooks (MIT).
 */
export const SKIP_KEYS = new Set([
  'data',
  'base64',
  'b64_json',
  'imageData',
  'thumbnail',
  'bytes',
  'blob',
  'buffer',
])

/** Past this depth a result is pathological, not data. */
export const MAX_DEPTH = 12

/** Past this length a string is a payload, not prose. */
export const MAX_STRING = 8_000_000

/**
 * `value` with `fn` applied to every string in it, at any depth.
 *
 * Returns the original object identity when nothing changed, so a caller can
 * tell a rewrite from a pass-through and avoid a pointless copy.
 *
 * Property NAMES are left alone. Rewriting keys would need collision handling
 * in both directions and risks corrupting a real structure, for a case that
 * barely occurs: a credential used as a JSON key.
 */
export function walk<T>(value: T, fn: (s: string) => string, depth = 0): T {
  if (typeof value === 'string') {
    return (value.length > MAX_STRING ? value : fn(value)) as T
  }
  if (depth >= MAX_DEPTH) return value

  if (Array.isArray(value)) {
    let changed = false
    const out = value.map((item) => {
      const next = walk(item, fn, depth + 1)
      if (next !== item) changed = true
      return next
    })
    return (changed ? out : value) as T
  }

  if (value !== null && typeof value === 'object') {
    let changed = false
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value)) {
      if (SKIP_KEYS.has(key)) {
        out[key] = item
        continue
      }
      const next = walk(item, fn, depth + 1)
      if (next !== item) changed = true
      out[key] = next
    }
    return (changed ? out : value) as T
  }

  return value
}
