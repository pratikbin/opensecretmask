import type { EngineInterface, On } from 'claude-code'

import { RULES, scanValues } from '../detect'
import { looksLikeSecret, MIN_SECRET_LEN, parseEnv } from '../env'
import type { Options } from '../options'
import type { PersistPort } from '../vault/persist'
import { load, save } from '../vault/persist'
import { startLine, statusLine } from '../status'
import type { Vault } from '../vault'

/**
 * Builds the exact-match layer at the start of a load.
 *
 * Two sources: the fakes a previous session minted, when `persist` is on, and
 * the `.env` files of the session. Restoring first keeps a fake stable across
 * a resume, because `register` then finds the mapping already present.
 *
 * Both are best-effort. A failure leaves the detection rules working on their
 * own rather than stopping the session.
 */
export function registerSessionStart(on: On, vault: Vault, options: Options) {
  on('session.start', async ($, e, next) => {
    const restored = options.persist ? await restorePrevious($, vault, options) : 0
    const registered = await loadEnvSecrets($, vault, e.cwd, options.envFiles)

    if (options.persist && vault.size > restored) {
      await save(portOf($), vault.entries())
    }

    $.ui.log(startLine(registered, restored, RULES.length, options))
    const line = statusLine(vault.stats)
    if (line) $.ui.status(line)
    return next(e)
  })
}

async function restorePrevious(
  $: EngineInterface,
  vault: Vault,
  options: Options,
): Promise<number> {
  const resolved = await load(portOf($), options.retentionDays)
  for (const { entry, secret } of resolved) {
    vault.adopt(
      entry.fake,
      secret,
      entry.kind === 'env' ? { file: entry.file, key: entry.key } : undefined,
    )
  }
  return resolved.length
}

/**
 * Registers the credentials in the session's `.env` files.
 *
 * A value qualifies on its name (`*_KEY`, `*_TOKEN`, …) or on its shape, so a
 * credential with an unremarkable name is still caught and `PORT=3000` is not.
 * The source records the file and key, which lets the persistence layer store
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
      if (!looksLikeSecret(key) && scanValues(value).size === 0) continue
      const before = vault.size
      vault.register(value, { file: path, key })
      if (vault.size > before) count++
    }
  }
  return count
}

/** Built here, not imported: the hook validator follows `$` only within a file. */
function portOf($: EngineInterface): PersistPort {
  return {
    get: (key) => $.store.get(key),
    set: (key, value) => $.store.set(key, value),
    readFile: (path) => $.fs.read(path),
  }
}
