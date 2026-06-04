/**
 * Reconstructed pseudo-source module for the `permissions` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "permissions" as const;
export const title = "Permissions" as const;
export const description = "Permission prompts, allow/deny rules, sandboxing, and safety gates." as const;
export const evidenceCount = 1 as const;
export const inferredResponsibilities = ["Permission prompts, allow/deny rules, sandboxing, and safety gates."] as const;
export const preferredTopics = ["tools_and_permissions"] as const;
export const sourceTopics = ["tools_and_permissions"] as const;
export const notableTokens = ["permission", "allowed-tools", "disallowed-tools", "sandbox", "deny", "allow", "auto mode"] as const;
export const cliFlags = [] as const;
export const evidenceExcerpts = ["const flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${\nname}\n\\n`, \"utf8\");"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
