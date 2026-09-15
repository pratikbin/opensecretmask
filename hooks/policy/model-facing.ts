// Which tool arguments must KEEP their fakes.
//
// The plugin restores a fake to the real secret on the way into a tool,
// because the tool is where the credential is actually used: a `Bash` curl or
// a `Write` of a config file needs the real value.
//
// That assumption breaks for an argument whose consumer is another MODEL.
// `Agent.prompt` is the task text handed to a subagent, so restoring it hands
// that subagent the real credential and defeats the plugin for every piece of
// delegated work. The same holds for the description shown alongside it.
//
// The rule: restore at an external-operation boundary, never at a model-facing
// one.

/** Keys the engine owns. A rewrite of any of them is refused. */
export const RESERVED = new Set(['tool', 'tool_use_id', 'agentId'])

/**
 * Argument names that reach a model rather than an external operation,
 * by tool.
 */
const MODEL_FACING: Record<string, ReadonlySet<string>> = {
  Agent: new Set(['prompt', 'description', 'name']),
  // The question and its options are rendered for the person, who does not
  // need the real value on screen to answer.
  AskUserQuestion: new Set(['questions']),
}

/** Whether `key` on `tool` must keep its fakes instead of being restored. */
export function isModelFacing(tool: string, key: string): boolean {
  return MODEL_FACING[tool]?.has(key) ?? false
}

/** Whether this tool has any model-facing argument at all. */
export function hasModelFacingArgs(tool: string): boolean {
  return tool in MODEL_FACING
}
