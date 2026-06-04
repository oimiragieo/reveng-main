/**
 * Reconstructed pseudo-source module for the `tools` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "tools" as const;
export const title = "Tools" as const;
export const description = "Built-in tools, tool runtime, shell operations, and tool result handling." as const;
export const evidenceCount = 0 as const;
export const inferredResponsibilities = ["Built-in tools, tool runtime, shell operations, and tool result handling."] as const;
export const preferredTopics = ["tools_and_permissions", "agent_runtime_and_prompts"] as const;
export const sourceTopics = [] as const;
export const notableTokens = ["tool_use", "tool_result", "bash", "readfile", "writefile", "search", "apply_patch", "./lib/greet", "--name", "/greet", "/lib"] as const;
export const cliFlags = ["--name"] as const;
export const evidenceExcerpts = [] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
