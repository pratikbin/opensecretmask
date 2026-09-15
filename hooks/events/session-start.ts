import type { EngineInterface, On } from 'claude-code'

import { scan } from '../detect'
import { looksLikeSecret, MIN_SECRET_LEN, parseEnv } from '../env'
import type { Options } from '../options'
import { load, save, type PersistPort } from '../vault/persist'
import type { Vault } from '../vault'

/**
 * Builds the exact-match layer at the start of a load.
 *
 * Two sources: the `.env` files of the session, and, when `persist` is on, the
 * fakes a previous session minted. Both are best-effort. A failure here leaves
 * the detection rules working on their own rather than stopping the session.
 */
export function registerSessionStart(on: On, vault: Vault, options: Options) {
  on('session.start', async ($, e, next) => {
    let registered = 0
    let restored = 0

    if (options.persist) {
      restored = await restorePrevious($, vault, options)
    }

    try {
      registered = await loadEnvSecrets($, vault, e.cwd, options.envFiles)
    } catch {
      registered = 0
    }

    if (options.persist && (registered > 0 || restored > 0)) {
      await save(portOf($), vault.entries())
    }

    $.ui.log(summary(registered, restored, options))
    return next(e)
  })
}

function portOf($: EngineInterface): PersistPort {
  return {
    get: (key) => $.store.get(key),
    set: (key, value) => $.store.set(key, value),
    readFile: (path) => $.fs.read(path),
  }
}

async function restorePrevious(
  $: EngineInterface,
  vault: Vault,
  options: Options,
): Promise<number> {
  try {
    const { pairs, entries } = await load(portOf($), options.retentionDays)
    const byFake = new Map(entries.map((entry) => [entry.fake, entry]))
    for (const [fake, secret] of pairs) {
      const entry = byFake.get(fake)
      vault.adopt(
        fake,
        secret,
        entry?.kind === 'env'
          ? { kind: 'env', file: entry.file, key: entry.key }
          : { kind: 'literal' },
      )
    }
    return pairs.length
  } catch {
    return 0
  }
}

/**
 * Registers the credentials in the session's `.env` files.
 *
 * A value qualifies on its name (`*_KEY`, `*_TOKEN`, …) or on its shape, so a
 * credential with an unremarkable name is still caught and `PORT=3000` is not.
 * The origin records the file and key, which lets the persistence layer store
 * a pointer instead of the secret itself.
 */
async function loadEnvSecrets(
  $: EngineInterface,
  vault: Vault,
  cwd: string,
  files: readonly string[],
): Promise<number> {
  let count = 0
  for (const file of files) {
    const path = `${cwd}/${file}`
    if (!(await $.fs.exists(path).catch(() => false))) continue
    const text = await $.fs.read(path).catch(() => '')
    for (const [key, value] of parseEnv(text)) {
      if (value.length < MIN_SECRET_LEN) continue
      if (!looksLikeSecret(key) && scan(value).length === 0) continue
      const before = vault.size
      vault.register(value, { kind: 'env', file: path, key })
      if (vault.size > before) count++
    }
  }
  return count
}

function summary(registered: number, restored: number, options: Options): string {
  const parts: string[] = []
  if (registered > 0) {
    parts.push(`${registered} from ${options.envFiles.join(', ')}`)
  }
  if (restored > 0) parts.push(`${restored} restored`)
  if (parts.length === 0) {
    return 'osm: masking on, no registered secrets (detection rules still apply)'
  }
  return `osm: masking ${parts.join(', ')}`
}
