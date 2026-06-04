/**
 * Reconstructed pseudo-source module for the `sdk` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "sdk" as const;
export const title = "SDK" as const;
export const description = "SDK mode, agent SDK integration, and machine-oriented I/O surfaces." as const;
export const evidenceCount = 1 as const;
export const inferredResponsibilities = ["SDK mode, agent SDK integration, and machine-oriented I/O surfaces."] as const;
export const preferredTopics = ["cli_surface", "dependencies_and_binaries"] as const;
export const sourceTopics = ["cli_surface"] as const;
export const notableTokens = ["sdk", "agent-sdk", "stream-json", "output-format", "enable-auth-status"] as const;
export const slashCommands = [] as const;
export const evidenceExcerpts = ["#!/usr/bin/env node\n\nconst fs = require(\"fs\");\nfunction main() {\nconst flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
