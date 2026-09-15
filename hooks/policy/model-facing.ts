// Where a restored credential must NOT go.
//
// The plugin restores a fake to the real secret on the way into a tool,
// because the tool is where the credential gets used: a `Bash` curl or a
// `Write` of a config file needs the real value.
//
// That breaks wherever the consumer is another MODEL. The general answer is
// the `agent.spawn` hook, which every subagent dispatch funnels through
// whatever tool triggered it — see events/agent-spawn.ts. A per-tool-name
// table cannot be that answer, because the next model-facing tool (an MCP
// server taking a `prompt`, a message-passing tool) is one nobody listed.
//
// What stays here is the narrow case the spawn hook does not cover: a tool
// whose argument is rendered on SCREEN rather than executed. That is a
// different invariant from the model-facing one and it is bounded, because
// the engine owns the components that draw.

/** Keys the engine owns. A rewrite of any of them is refused. */
export const RESERVED = new Set(['tool', 'tool_use_id', 'agentId'])

/**
 * Arguments that are read rather than executed.
 *
 * `Agent` is here as well as behind the `agent.spawn` hook, and both are
 * wanted. The spawn hook is the general guarantee; this entry stops the real
 * value from ever materialising in the Agent tool's recorded arguments on the
 * way there, because the transcript keeps what a tool was called with.
 *
 * `AskUserQuestion` is drawn on screen. The person knows their own
 * credentials, so a fake costs them nothing and keeps what they read
 * consistent with what the model read.
 */
const KEEP_FAKES: Record<string, ReadonlySet<string>> = {
  Agent: new Set(['prompt', 'description']),
  AskUserQuestion: new Set(['questions']),
}

/** Whether `key` on `tool` must keep its fakes instead of being restored. */
export function isModelFacing(tool: string, key: string): boolean {
  return KEEP_FAKES[tool]?.has(key) ?? false
}
