import { literalPrefixLen, scanValues, DEFAULT_DETECT, type DetectConfig } from '../detect'
import { MIN_SECRET_LEN } from '../env'

import { garble } from './garble'
import type { Entry } from './persist'
import { walk } from './walk'

export { garble } from './garble'
export { walk, isOpaque, MAX_DEPTH, MAX_STRING } from './walk'
export * from './persist'

const GARBLE_TRIES = 8

/** Where a secret came from. Absent means it exists nowhere but this process. */
export type EnvSource = { file: string; key: string }

/**
 * The two-way map between a secret and its fake.
 *
 * A secret maps to a fake through this map, not through reversible maths, so
 * restoring one is a lookup and nothing else. The map lives in module memory
 * for one load of the plugin; `persist.ts` optionally carries it across.
 */
export class Vault {
  readonly #bySecret = new Map<string, string>()
  readonly #byMask = new Map<string, string>()
  readonly #envSource = new Map<string, EnvSource>()

  // Both directions scan longest-first so a value containing another is
  // substituted whole. Sorting per call meant sorting the whole key set once
  // per string in every tool result; the maps only ever grow, so caching and
  // clearing on insert gives the same order for the cost of one sort per new
  // secret.
  #secretsByLength: string[] | undefined
  #masksByLength: string[] | undefined

  constructor(private readonly cfg: DetectConfig = DEFAULT_DETECT) {}

  get size(): number {
    return this.#bySecret.size
  }

  #remember(secret: string, fake: string): void {
    this.#bySecret.set(secret, fake)
    this.#byMask.set(fake, secret)
    this.#secretsByLength = undefined
    this.#masksByLength = undefined
  }

  /**
   * Adopts a fake-to-secret pair from a previous session.
   *
   * Used only by the persistence layer on load. A pair whose fake already
   * resolves is ignored, so a live mapping always beats a stored one.
   */
  adopt(fake: string, secret: string, source?: EnvSource): void {
    if (this.#byMask.has(fake) || this.#bySecret.has(secret)) return
    this.#remember(secret, fake)
    if (source) this.#envSource.set(secret, source)
  }

  /**
   * Registers a secret read from a known source.
   *
   * This is the exact-match layer: a registered value is masked wherever it
   * appears, whether or not a rule recognises its shape.
   */
  register(secret: string, source?: EnvSource): void {
    if (secret.length < MIN_SECRET_LEN || this.#byMask.has(secret)) return
    if (source) this.#envSource.set(secret, source)
    this.maskOf(secret)
  }

  /** `secret`'s fake, minted on first sight and stable for as long as the map lives. */
  maskOf(secret: string): string {
    const known = this.#bySecret.get(secret)
    if (known) return known

    const keep = literalPrefixLen(secret)
    let fake = ''
    for (let i = 0; i < GARBLE_TRIES; i++) {
      const candidate = garble(secret, keep)
      if (
        candidate !== secret &&
        !this.#byMask.has(candidate) &&
        !this.#bySecret.has(candidate)
      ) {
        fake = candidate
        break
      }
    }
    // Every garble collided, which means the value has no variable characters
    // left to vary. Give up on the shape rather than on the masking.
    if (fake === '') {
      fake = `[MASKED-${(this.#bySecret.size + 1).toString(16).padStart(4, '0')}]`
    }

    this.#remember(secret, fake)
    return fake
  }

  /** `text` with every secret in it replaced by its fake. */
  mask(text: string): string {
    if (text === '') return text

    const candidates = new Set<string>()
    for (const value of scanValues(text, this.cfg)) {
      if (value.length >= MIN_SECRET_LEN) candidates.add(value)
    }
    // Every secret the vault has ever seen stays a candidate, not just the
    // ones registered from a file. A value first caught by a context-bearing
    // rule (`aws_secret_access_key = "…"`) must still be masked when it turns
    // up later on its own, where no rule would fire.
    this.#secretsByLength ??= [...this.#bySecret.keys()].sort((a, b) => b.length - a.length)
    for (const secret of this.#secretsByLength) {
      if (text.includes(secret)) candidates.add(secret)
    }

    let out = text
    for (const secret of [...candidates].sort((a, b) => b.length - a.length)) {
      // A fake already in flight must never be masked a second time.
      if (this.#byMask.has(secret)) continue
      const fake = this.maskOf(secret)
      if (!out.includes(secret)) continue
      out = out.split(secret).join(fake)
    }
    return out
  }

  /** `text` with every fake in it restored to the secret it stands for. */
  unmask(text: string): string {
    if (text === '' || this.#byMask.size === 0) return text
    this.#masksByLength ??= [...this.#byMask.keys()].sort((a, b) => b.length - a.length)
    let out = text
    for (const fake of this.#masksByLength) {
      if (!out.includes(fake)) continue
      out = out.split(fake).join(this.#byMask.get(fake)!)
    }
    return out
  }

  maskDeep<T>(value: T): T {
    return walk(value, (s) => this.mask(s))
  }

  unmaskDeep<T>(value: T): T {
    return walk(value, (s) => this.unmask(s))
  }

  /** The map as persistable entries. Called only when `persist` is on. */
  entries(now: number = Date.now()): Entry[] {
    const out: Entry[] = []
    for (const [secret, fake] of this.#bySecret) {
      const source = this.#envSource.get(secret)
      out.push(
        source
          ? { kind: 'env', fake, file: source.file, key: source.key, at: now }
          : { kind: 'literal', fake, secret, at: now },
      )
    }
    return out
  }
}
