// The vault: a secret's stable fake, and the reverse lookup that restores it.
//
// A secret maps to a fake through this map, not through any cryptographic
// inversion; reversal is a lookup. The map lives in this module, in memory,
// for the session, and nothing is written to disk — so there is no store to
// unlock and no passphrase to prompt for.

import { DEFAULT_DETECT, literalPrefixLen, scan, type DetectConfig } from './detect'

const DIGITS = '0123456789'
const LOWER = 'abcdefghijklmnopqrstuvwxyz'
const UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'

// ponytail: Math.random, not a CSPRNG. A mask is sent to the model by design,
// so it is public; unpredictability buys nothing. Swap for crypto.getRandomValues
// if a mask ever has to double as a nonce.
const pick = (set: string) => set[Math.floor(Math.random() * set.length)]!

/**
 * A format-preserving fake of `value`: the first `keepPrefix` characters are
 * copied verbatim, each digit becomes a digit, each letter a letter of the
 * same case, and structure (`-`, `_`, `.`) stays where it was. Length and
 * shape survive, so the model treats the fake exactly as it would the real
 * credential.
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

/** Values shorter than this are never masked: too short to be a credential. */
const MIN_SECRET_LEN = 8
const GARBLE_TRIES = 8

export class Vault {
  readonly #bySecret = new Map<string, string>()
  readonly #byMask = new Map<string, string>()
  readonly #registered = new Set<string>()
  #masks = 0

  constructor(private readonly cfg: DetectConfig = DEFAULT_DETECT) {}

  get size(): number {
    return this.#bySecret.size
  }

  /** How many substitutions this session has made. */
  get substitutions(): number {
    return this.#masks
  }

  /**
   * The guaranteed exact-match layer: a value read out of a `.env` file or
   * named by the plugin's options is masked wherever it appears, whether or
   * not a regex rule recognises its shape.
   */
  register(secret: string): void {
    if (secret.length < MIN_SECRET_LEN || this.#byMask.has(secret)) return
    this.#registered.add(secret)
    this.maskOf(secret)
  }

  /** `secret`'s fake, minted on first sight and stable for the session. */
  maskOf(secret: string): string {
    const known = this.#bySecret.get(secret)
    if (known) return known

    const keep = literalPrefixLen(secret)
    let mask = ''
    for (let i = 0; i < GARBLE_TRIES; i++) {
      const candidate = garble(secret, keep)
      if (candidate !== secret && !this.#byMask.has(candidate) && !this.#bySecret.has(candidate)) {
        mask = candidate
        break
      }
    }
    // Every garble collided (a value with no variable characters left, such as
    // a bare `-----BEGIN ... KEY-----` header). Give up on the shape rather
    // than on the masking.
    if (mask === '') mask = `[MASKED-${(this.#bySecret.size + 1).toString(16).padStart(4, '0')}]`

    this.#bySecret.set(secret, mask)
    this.#byMask.set(mask, secret)
    return mask
  }

  /** `text` with every secret in it replaced by its fake. */
  mask(text: string): string {
    if (text === '') return text

    const candidates = new Set<string>()
    for (const finding of scan(text, this.cfg)) {
      if (finding.value.length >= MIN_SECRET_LEN) candidates.add(finding.value)
    }
    for (const secret of this.#registered) {
      if (text.includes(secret)) candidates.add(secret)
    }

    let out = text
    // Longest first, so a secret that contains another is substituted whole.
    for (const secret of [...candidates].sort((a, b) => b.length - a.length)) {
      // A fake already in flight must not be masked a second time.
      if (this.#byMask.has(secret)) continue
      const mask = this.maskOf(secret)
      if (!out.includes(secret)) continue
      out = out.split(secret).join(mask)
      this.#masks++
    }
    return out
  }

  /** `text` with every fake in it restored to the secret it stands for. */
  unmask(text: string): string {
    if (text === '' || this.#byMask.size === 0) return text
    let out = text
    for (const mask of [...this.#byMask.keys()].sort((a, b) => b.length - a.length)) {
      if (!out.includes(mask)) continue
      out = out.split(mask).join(this.#byMask.get(mask)!)
    }
    return out
  }

  maskDeep<T>(value: T): T {
    return walk(value, (s) => this.mask(s))
  }

  unmaskDeep<T>(value: T): T {
    return walk(value, (s) => this.unmask(s))
  }
}

/**
 * `value` with `fn` applied to every string in it, at any depth. Returns the
 * original object identity when nothing changed, so a caller can tell a
 * rewrite from a pass-through.
 */
export function walk<T>(value: T, fn: (s: string) => string): T {
  if (typeof value === 'string') return fn(value) as T
  if (Array.isArray(value)) {
    let changed = false
    const out = value.map((item) => {
      const next = walk(item, fn)
      if (next !== item) changed = true
      return next
    })
    return (changed ? out : value) as T
  }
  if (value !== null && typeof value === 'object') {
    let changed = false
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value)) {
      const next = walk(item, fn)
      if (next !== item) changed = true
      out[key] = next
    }
    return (changed ? out : value) as T
  }
  return value
}
