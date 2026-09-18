import type { PluginOptions } from 'claude-code'

import { DEFAULT_DETECT, type DetectConfig } from './detect'

export type Options = {
  detect: DetectConfig
  envFiles: string[]
  /** Carry the map across a resume or a reload. On by default: see persist.ts. */
  persist: boolean
  /** How long a literal secret survives in the store. Env entries never expire. */
  retentionDays: number
}

const DEFAULT_ENV_FILES = ['.env', '.env.local']
// Mirrors `userConfig` in .claude-plugin/plugin.json. Move both together.
const DEFAULT_PERSIST = true
const DEFAULT_RETENTION_DAYS = 120

/**
 * A plugin option may arrive as a real boolean or as the string form.
 *
 * `fallback` is what the manifest declares, not what the module would prefer.
 * The engine fills a declared option from `userConfig` before `register()`
 * sees it, so this only fires when the manifest is absent — a `--plugin-dir`
 * run, a test harness. Disagreeing with the manifest there means the code
 * behaves one way in development and another in production.
 */
function bool(v: unknown, fallback: boolean): boolean {
  if (v === undefined || v === null || v === '') return fallback
  return v === true || v === 'true'
}

function list(v: unknown, fallback: string[]): string[] {
  if (Array.isArray(v)) return v.map(String)
  if (typeof v === 'string') {
    const parts = v.split(',').map((s) => s.trim()).filter(Boolean)
    if (parts.length > 0) return parts
  }
  return fallback
}

export function readOptions(options: PluginOptions): Options {
  return {
    detect: {
      entropy: bool(options.entropy, false),
      entropyThreshold: Number(options.entropyThreshold) || DEFAULT_DETECT.entropyThreshold,
      entropyMinLen: Number(options.entropyMinLen) || DEFAULT_DETECT.entropyMinLen,
    },
    envFiles: list(options.envFiles, DEFAULT_ENV_FILES),
    persist: bool(options.persist, DEFAULT_PERSIST),
    retentionDays: Number(options.retentionDays) || DEFAULT_RETENTION_DAYS,
  }
}
