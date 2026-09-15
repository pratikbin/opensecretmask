import type {
  EngineInterface,
  On,
  PluginOptions,
  ToolCallInput,
  ToolCallResult,
} from 'claude-code'

import { DEFAULT_DETECT, scan, type DetectConfig } from './detect'
import { Vault } from './vault'

/**
 * The substitution, done at the tool boundary.
 *
 * Outbound (`prompt.submit`, `prompt.section`, and a tool's result on its way
 * up) a secret is swapped for a format-preserving fake, so the model only ever
 * reads the fake. Inbound (a tool's arguments on their way down) the fake is
 * swapped back, so a `Bash` command or a `Write` the model composed still
 * carries the real credential.
 *
 * Nothing is persisted: the map lives in the session and dies with it.
 *
 * @param on the engine's registrar
 * @param options the plugin's settings (`entropy`, `envFiles`, …)
 */
export function register(on: On, options: PluginOptions) {
  const vault = new Vault(detectConfig(options))

  on('session.start', async ($, e, next) => {
    const count = await loadEnvSecrets($, vault, e.cwd, envFiles(options)).catch(() => 0)
    $.ui.log(
      count > 0
        ? `osm: masking ${count} registered secret${count === 1 ? '' : 's'} from ${envFiles(options).join(', ')}`
        : 'osm: masking on, no .env secrets registered (detection rules still apply)',
    )
    return next(e)
  })

  // The fake goes down to the tool as the real thing; the real thing comes
  // back up as the fake.
  on('tool.call', async ($, e, next) => {
    let down: ToolCallInput
    try {
      down = unmaskArgs(vault, e)
    } catch {
      return { deny: DENY_UNMASK }
    }

    const up = await next(down)

    try {
      return maskResult(vault, up)
    } catch {
      // Fail closed: an unmaskable result is denied, not handed to the model.
      return { deny: DENY_MASK }
    }
  })

  on('prompt.submit', ($, e, next) => {
    try {
      return next({
        ...e,
        text: vault.mask(e.text),
        context: e.context?.map((block) => vault.mask(block)),
      })
    } catch {
      return { drop: DENY_MASK }
    }
  })

  // CLAUDE.md and the other memory files reach the model through here.
  on('prompt.section', async ($, e, next) => {
    const { text } = await next(e)
    return { text: typeof text === 'string' ? vault.mask(text) : text }
  })
}

const DENY_MASK = 'osm: blocked — the result could not be masked, so it was not shown to the model.'
const DENY_UNMASK = 'osm: blocked — the arguments could not be unmasked, so the tool was not run.'

// `tool`, `tool_use_id` and `agentId` are reserved: a rewrite of any is refused.
const RESERVED = new Set(['tool', 'tool_use_id', 'agentId'])

/** `e` with every fake in its arguments restored to the secret it stands for. */
function unmaskArgs(vault: Vault, e: ToolCallInput): ToolCallInput {
  let changed = false
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(e)) {
    if (RESERVED.has(key)) {
      out[key] = value
      continue
    }
    const next = vault.unmaskDeep(value)
    if (next !== value) changed = true
    out[key] = next
  }
  return changed ? (out as ToolCallInput) : e
}

/** The tool's answer with every secret in it replaced by its fake. */
function maskResult(vault: Vault, up: ToolCallResult): ToolCallResult {
  if (up.deny !== undefined) {
    const deny = vault.mask(up.deny)
    return deny === up.deny ? up : { deny }
  }

  const result = vault.maskDeep(up.result)
  const text = up.text === undefined ? undefined : vault.mask(up.text)
  if (result === up.result && text === up.text) return up

  // `ref` names the messages core already produced for this call. Returning it
  // makes core use those verbatim — the unmasked ones. Drop it so core builds
  // the messages from what this hook answers.
  const { ref: _ref, ...rest } = up as ToolCallResult & { ref?: number }
  return { ...rest, result, text } as ToolCallResult
}

// ------------------------------------------------------------------ options

function detectConfig(options: PluginOptions): DetectConfig {
  return {
    entropy: options.entropy === true || options.entropy === 'true',
    entropyThreshold: Number(options.entropyThreshold) || DEFAULT_DETECT.entropyThreshold,
    entropyMinLen: Number(options.entropyMinLen) || DEFAULT_DETECT.entropyMinLen,
  }
}

function envFiles(options: PluginOptions): string[] {
  const given = options.envFiles
  if (Array.isArray(given)) return [...given]
  if (typeof given === 'string') return given.split(',').map((f) => f.trim()).filter(Boolean)
  return ['.env', '.env.local']
}

// ------------------------------------------------- registered-secret sources

const ENV_LINE = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/
const SECRETISH =
  /KEY|TOKEN|SECRET|PASSWORD|PASSWD|PWD|CREDENTIAL|PRIVATE|AUTH|DSN|SALT|SIGNATURE|CERT/i

/**
 * Registers the credentials in the session's `.env` files, the guaranteed
 * exact-match layer.
 *
 * A value qualifies when its name reads like a credential's or when a
 * detection rule recognises its shape — so `PORT=3000` and
 * `NODE_ENV=development` stay legible to the model.
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
    for (const line of text.split('\n')) {
      if (line.trimStart().startsWith('#')) continue
      const m = ENV_LINE.exec(line)
      if (!m) continue
      const name = m[1]!
      const value = unquote(m[2]!.trim())
      if (value.length < 8) continue
      if (!SECRETISH.test(name) && scan(value).length === 0) continue
      const before = vault.size
      vault.register(value)
      if (vault.size > before) count++
    }
  }
  return count
}

function unquote(value: string): string {
  const first = value[0]
  if ((first === '"' || first === "'") && value.endsWith(first) && value.length > 1) {
    return value.slice(1, -1)
  }
  return value
}
