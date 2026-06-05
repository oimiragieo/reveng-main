/**
 * Reconstructed pseudo-source module for the `auth` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "auth" as const;
export const title = "Auth" as const;
export const description = "Login, logout, token, OAuth, and account lifecycle flows." as const;
export const evidenceCount = 1 as const;
export const inferredResponsibilities = ["Login, logout, token, OAuth, and account lifecycle flows."] as const;
export const preferredTopics = ["cli_surface", "integrations_and_networking"] as const;
export const sourceTopics = ["cli_surface"] as const;
export const notableTokens = ["auth", "login", "logout", "oauth", "token", "claudeai", "console"] as const;
export const relatedUrls = [] as const;
export const evidenceExcerpts = ["#!/usr/bin/env node\n\nconst fs = require(\"fs\");\nfunction main() {\nconst flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
