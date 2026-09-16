// The plugin's entry point is ./register.ts, named by hooks.json. This barrel
// exists only for a consumer importing the package by name; each module is
// otherwise imported by path.
export { register } from './register.js'
export { Vault } from './vault'
export { scan, scanValues, RULES } from './detect'
export type { DetectConfig, Finding, Rule } from './detect'
export { readOptions } from './options'
export type { Options } from './options'

export * as default from '.'
