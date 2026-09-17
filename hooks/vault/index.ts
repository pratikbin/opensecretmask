import { literalPrefixLen, scan, scanValues, DEFAULT_DETECT, type DetectConfig } from '../detect'
import { MIN_SECRET_LEN } from '../env'

import { garble } from './garble'
import type { Entry, Provenance } from './persist'
import { walk } from './walk'

export { garble } from './garble'
export { walk, isOpaque, MAX_DEPTH, MAX_STRING } from './walk'
export * from './persist'

const GARBLE_TRIES = 8

/** Where a secret came from. Absent means it exists nowhere but this process. */
export type EnvSource = { file: string; key: string }

/**
 * One secret's paper trail, for `/osm-secrets`.
 *
 * Written once when the fake is minted, then only counted up. `rule` says what
 * recognised the value, `where` the channel it first came through, and `at` is
 * the first sighting.
 */
export type LedgerEntry = {
  secret: string
  fake: string
  rule: string
  where: string
  file?: string
  key?: string
  at: number
  masked: number
  restored: number
}

/** What minted a fake, as far as the caller knows. */
type Origin = { rule: string; where: string; source?: EnvSource }

/**
 * What the session has done so far, for the status line.
 *
 * `masked` and `restored` count substitutions and not distinct secrets: one
 * key read twice is two. That is the number that tells a user the plugin is
 * doing work, which is what the line is for.
 */
export type Stats = {
  secrets: number
  masked: number
  restored: number
}

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
  readonly #ledger = new Map<string, LedgerEntry>()

  // `unmask` substitutes straight down this list, so it must be longest-first:
  // a fake containing another has to be replaced whole. Sorting per call meant
  // sorting the whole key set once per string in every tool result; the map
  // only ever grows, so caching and clearing on insert costs one sort per new
  // secret. `mask` needs no such list — its candidates land in a set that it
  // sorts once, just before substituting.
  #masksByLength: string[] | undefined

  #masked = 0
  #restored = 0

  constructor(private readonly cfg: DetectConfig = DEFAULT_DETECT) {}

  get size(): number {
    return this.#bySecret.size
  }

  get stats(): Stats {
    return {
      secrets: this.#bySecret.size,
      masked: this.#masked,
      restored: this.#restored,
    }
  }

  #remember(secret: string, fake: string): void {
    this.#bySecret.set(secret, fake)
    this.#byMask.set(fake, secret)
    this.#masksByLength = undefined
  }

  /**
   * Adopts a fake-to-secret pair from a previous session.
   *
   * Used only by the persistence layer on load. A pair whose fake already
   * resolves is ignored, so a live mapping always beats a stored one.
   */
  adopt(fake: string, secret: string, source?: EnvSource, was?: Provenance): void {
    if (this.#byMask.has(fake) || this.#bySecret.has(secret)) return
    this.#remember(secret, fake)
    if (source) this.#envSource.set(secret, source)
    this.#note(
      secret,
      fake,
      { rule: was?.rule ?? (source ? 'env' : 'literal'), where: was?.where ?? 'store', source },
      was?.firstAt,
    )
  }

  /** Every secret the session knows, oldest first. */
  ledger(): LedgerEntry[] {
    return [...this.#ledger.values()]
  }

  #note(secret: string, fake: string, origin: Origin, firstAt?: number): void {
    if (this.#ledger.has(secret)) return
    const now = firstAt ?? Date.now()
    this.#ledger.set(secret, {
      secret,
      fake,
      rule: origin.rule,
      where: origin.where,
      file: origin.source?.file,
      key: origin.source?.key,
      at: now,
      masked: 0,
      restored: 0,
    })
  }

  #count(secret: string, field: 'masked' | 'restored', n: number): void {
    const entry = this.#ledger.get(secret)
    if (!entry) return
    entry[field] += n
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
    this.maskOf(secret, { rule: source ? 'env' : 'registered', where: source?.file ?? 'options', source })
  }

  /** `secret`'s fake, minted on first sight and stable for as long as the map lives. */
  maskOf(secret: string, origin?: Origin): string {
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
    this.#note(secret, fake, origin ?? { rule: 'unknown', where: 'unknown' })
    return fake
  }

  /** `text` with every secret in it replaced by its fake. */
  mask(text: string, where = 'unknown'): string {
    if (text === '') return text

    const candidates = new Set<string>()
    for (const value of scanValues(text, this.cfg)) {
      if (value.length >= MIN_SECRET_LEN) candidates.add(value)
    }
    // Every secret the vault has ever seen stays a candidate, not just the
    // ones registered from a file. A value first caught by a context-bearing
    // rule (`aws_secret_access_key = "…"`) must still be masked when it turns
    // up later on its own, where no rule would fire.
    for (const secret of this.#bySecret.keys()) {
      if (text.includes(secret)) candidates.add(secret)
    }

    let out = text
    for (const secret of [...candidates].sort((a, b) => b.length - a.length)) {
      // A fake already in flight must never be masked a second time.
      if (this.#byMask.has(secret)) continue
      // The rule name costs one scan of the value itself, once per secret per
      // session, and never on the hot path: a known secret is already noted.
      const origin = this.#bySecret.has(secret)
        ? undefined
        : { rule: scan(secret, this.cfg)[0]?.rule ?? 'detected', where }
      const fake = this.maskOf(secret, origin)
      const parts = out.split(secret)
      if (parts.length === 1) continue
      this.#masked += parts.length - 1
      this.#count(secret, 'masked', parts.length - 1)
      out = parts.join(fake)
    }
    return out
  }

  /** `text` with every fake in it restored to the secret it stands for. */
  unmask(text: string): string {
    if (text === '' || this.#byMask.size === 0) return text
    this.#masksByLength ??= [...this.#byMask.keys()].sort((a, b) => b.length - a.length)
    let out = text
    for (const fake of this.#masksByLength) {
      const parts = out.split(fake)
      if (parts.length === 1) continue
      const secret = this.#byMask.get(fake)!
      this.#restored += parts.length - 1
      this.#count(secret, 'restored', parts.length - 1)
      out = parts.join(secret)
    }
    return out
  }

  maskDeep<T>(value: T, where = 'unknown'): T {
    return walk(value, (s) => this.mask(s, where))
  }

  unmaskDeep<T>(value: T): T {
    return walk(value, (s) => this.unmask(s))
  }

  /** The map as persistable entries. Called only when `persist` is on. */
  entries(now: number = Date.now()): Entry[] {
    const out: Entry[] = []
    for (const [secret, fake] of this.#bySecret) {
      const source = this.#envSource.get(secret)
      const seen = this.#ledger.get(secret)
      const was = { rule: seen?.rule, where: seen?.where, firstAt: seen?.at }
      out.push(
        source
          ? { kind: 'env', fake, file: source.file, key: source.key, at: now, ...was }
          : { kind: 'literal', fake, secret, at: now, ...was },
      )
    }
    return out
  }
}
