import type { Rule } from '../rule'

import { builtinRules } from './builtin'
import { chatRules } from './chat'
import { cloudRules } from './cloud'
import { devtoolsRules } from './devtools'
import { gitRules } from './git'
import { llmRules } from './llm'

export { builtinRules, chatRules, cloudRules, devtoolsRules, gitRules, llmRules }

/**
 * Every rule, in group order. When two rules claim the same value the first
 * one wins, so a specific vendor rule beats a generic shape.
 *
 * Adding a source is one file here plus one entry below. No registry, no
 * init-time side effects.
 */
export const RULES: readonly Rule[] = [
  ...builtinRules,
  ...llmRules,
  ...cloudRules,
  ...chatRules,
  ...gitRules,
  ...devtoolsRules,
]
