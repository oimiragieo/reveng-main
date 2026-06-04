/**
 * Reconstructed pseudo-source module for the `permissions` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "permissions" as const;
export const title = "Permissions" as const;
export const description = "Permission prompts, allow/deny rules, sandboxing, and safety gates." as const;
export const evidenceCount = 0 as const;
export const inferredResponsibilities = ["Permission prompts, allow/deny rules, sandboxing, and safety gates."] as const;
export const preferredTopics = ["tools_and_permissions"] as const;
export const sourceTopics = [] as const;
export const notableTokens = ["permission", "allowed-tools", "disallowed-tools", "sandbox", "deny", "allow", "auto mode", "./lib/greet", "--name", "/greet", "/lib"] as const;
export const cliFlags = ["--name"] as const;
export const evidenceExcerpts = [] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
