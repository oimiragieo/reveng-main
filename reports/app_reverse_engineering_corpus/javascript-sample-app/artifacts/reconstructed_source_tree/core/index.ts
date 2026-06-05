/**
 * Reconstructed pseudo-source module for the `core` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "core" as const;
export const title = "Core" as const;
export const description = "Main application runtime, agent loop orchestration, and control flow." as const;
export const evidenceCount = 1 as const;
export const inferredResponsibilities = ["Main application runtime, agent loop orchestration, and control flow."] as const;
export const preferredTopics = ["runtime_architecture", "agent_runtime_and_prompts"] as const;
export const sourceTopics = ["runtime_architecture"] as const;
export const notableTokens = ["mainloopmodel", "systemprompt", "abortcontroller", "querysource", "agent loop", "renderedsystemprompt"] as const;
export const slashCommands = [] as const;
export const evidenceExcerpts = ["#!/usr/bin/env node\n\nconst fs = require(\"fs\");\nfunction main() {\nconst flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
