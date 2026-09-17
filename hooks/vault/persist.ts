// Optional persistence, so a fake still restores after a resume or a reload.
//
// The in-memory map dies with one load of the plugin. That is safe but it
// breaks `--resume`, `--continue`, a fork and `/reload-plugins`: the replayed
// transcript is full of fakes the new map has never seen, so a tool call built
// around one runs against an invalid credential.
//
// Two kinds of entry, and the split is the whole point:
//
//   env     the secret lives in a .env file already. Store only the fake and a
//           pointer to {file, key}. Nothing secret reaches this store, and the
//           entry never expires because the source is still there to re-read.
//
//   literal the secret was first seen in tool output and exists nowhere on
//           disk. Restoring it later means storing the value itself, so this
//           is the only kind that puts a new secret at rest, and the only kind
//           the retention window applies to.
//
// Off unless `persist` is set. When it is off nothing is written at all.

import { parseEnv } from '../env'

/**
 * How a secret was first found, carried across sessions.
 *
 * Without it every restored entry looked alike: `/osm-secrets` showed thirty
 * rows all reading "literal via store" at the moment of the reload, which is
 * true of the restore and says nothing about the secret.
 */
export type Provenance = {
  rule?: string
  where?: string
  firstAt?: number
}

export type EnvEntry = Provenance & {
  kind: 'env'
  fake: string
  file: string
  key: string
  at: number
}

export type LiteralEntry = Provenance & {
  kind: 'literal'
  fake: string
  secret: string
  at: number
}

export type Entry = EnvEntry | LiteralEntry

/** An entry paired with the secret it resolved to. */
export type Resolved = { entry: Entry; secret: string }

export type Snapshot = {
  version: 1
  entries: Entry[]
}

/**
 * The slice of the engine this module needs, named so tests can supply it.
 *
 * Each caller builds it from its own `$`. The engine's hook validator follows
 * `$` only inside one file, so an adapter living here would fail validation.
 */
export type PersistPort = {
  get: (key: string) => Promise<unknown>
  set: (key: string, value: unknown) => Promise<void>
  readFile: (path: string) => Promise<string>
}

export const STORE_KEY = 'osm.vault.v1'

const DAY_MS = 86_400_000

function isEntry(v: unknown): v is Entry {
  if (typeof v !== 'object' || v === null) return false
  const e = v as Record<string, unknown>
  if (typeof e.fake !== 'string' || typeof e.at !== 'number') return false
  if (e.kind === 'env') return typeof e.file === 'string' && typeof e.key === 'string'
  if (e.kind === 'literal') return typeof e.secret === 'string'
  return false
}

/** Entries still inside the window. An env entry never expires: it holds no secret. */
export function prune(entries: readonly Entry[], retentionDays: number, now: number): Entry[] {
  const cutoff = now - retentionDays * DAY_MS
  return entries.filter((e) => e.kind === 'env' || e.at >= cutoff)
}

/**
 * Reads the store and resolves every entry to the secret it stands for.
 *
 * An env entry whose file or key is gone is dropped rather than guessed at.
 * Never throws: persistence is a convenience, and a broken store must not stop
 * the session.
 */
export async function load(
  port: PersistPort,
  retentionDays: number,
  now: number = Date.now(),
): Promise<Resolved[]> {
  let raw: unknown
  try {
    raw = await port.get(STORE_KEY)
  } catch {
    return []
  }

  const snap = raw as Partial<Snapshot> | undefined
  if (snap?.version !== 1 || !Array.isArray(snap.entries)) return []

  const entries = prune(snap.entries.filter(isEntry), retentionDays, now)
  const resolved: Resolved[] = []
  const files = new Map<string, Map<string, string>>()

  for (const entry of entries) {
    if (entry.kind === 'literal') {
      resolved.push({ entry, secret: entry.secret })
      continue
    }
    let parsed = files.get(entry.file)
    if (!parsed) {
      try {
        parsed = parseEnv(await port.readFile(entry.file))
      } catch {
        parsed = new Map()
      }
      files.set(entry.file, parsed)
    }
    const secret = parsed.get(entry.key)
    // The source moved on. Drop the entry instead of carrying a dead fake.
    if (secret === undefined) continue
    resolved.push({ entry, secret })
  }

  return resolved
}

/** Writes the snapshot. A failure is swallowed: persistence never breaks a turn. */
export async function save(port: PersistPort, entries: readonly Entry[]): Promise<void> {
  try {
    await port.set(STORE_KEY, { version: 1, entries: [...entries] } satisfies Snapshot)
  } catch {
    // Store full, disk read-only, engine refused. The session continues.
  }
}
