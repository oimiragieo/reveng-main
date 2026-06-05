/**
 * Reconstructed pseudo-source module for the `cli` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "cli" as const;
export const title = "CLI" as const;
export const description = "Command registration, flags, slash commands, and terminal entrypoints." as const;
export const evidenceCount = 2 as const;
export const inferredResponsibilities = ["Command registration, flags, slash commands, and terminal entrypoints."] as const;
export const preferredTopics = ["cli_surface"] as const;
export const sourceTopics = [] as const;
export const notableTokens = ["command(", ".command(", "process.argv", "--", "/", "usage: claude"] as const;
export const cliFlags = [] as const;
export const slashCommands = [] as const;
export const evidenceExcerpts = ["#!/usr/bin/env node\n\nconst fs = require(\"fs\");\nfunction main() {\nconst flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${", "#!/usr/bin/env node\n\nconst fs = require(\"fs\");\nfunction main() {\nconst flag = process.argv.find((value) => value.startsWith(\"--name=\"));"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
