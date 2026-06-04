/**
 * Reconstructed pseudo-source module for the `tools` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "tools" as const;
export const title = "Tools" as const;
export const description = "Built-in tools, tool runtime, shell operations, and tool result handling." as const;
export const evidenceCount = 1 as const;
export const inferredResponsibilities = ["Built-in tools, tool runtime, shell operations, and tool result handling."] as const;
export const preferredTopics = ["tools_and_permissions", "agent_runtime_and_prompts"] as const;
export const sourceTopics = [] as const;
export const notableTokens = ["tool_use", "tool_result", "bash", "readfile", "writefile", "search", "apply_patch"] as const;
export const cliFlags = [] as const;
export const evidenceExcerpts = ["const flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${\nname}\n\\n`, \"utf8\");"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
