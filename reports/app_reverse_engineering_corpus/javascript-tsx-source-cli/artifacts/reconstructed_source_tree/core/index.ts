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
export const notableTokens = ["mainloopmodel", "systemprompt", "abortcontroller", "querysource", "agent loop", "renderedsystemprompt", "./lib/greet", "--name", "/greet", "/lib"] as const;
export const slashCommands = ["/greet", "/lib"] as const;
export const evidenceExcerpts = ["writeGreeting }\nfrom \"./lib/greet\";\nexport function main(argv: string[] = process.argv): void {\nconst flag = argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
