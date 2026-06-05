/**
 * Reconstructed pseudo-source module for the `config` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "config" as const;
export const title = "Config" as const;
export const description = "Configuration loading, settings files, and project/workspace defaults." as const;
export const evidenceCount = 2 as const;
export const inferredResponsibilities = ["Configuration loading, settings files, and project/workspace defaults."] as const;
export const preferredTopics = ["storage_state_and_artifacts", "cli_surface"] as const;
export const sourceTopics = ["cli_surface", "storage_state_and_artifacts"] as const;
export const notableTokens = ["config", "settings", "flagsettings", ".claude", "localsettings", "projectroot"] as const;
export const evidenceExcerpts = ["#!/usr/bin/env node\n\nconst fs = require(\"fs\");\nfunction main() {\nconst flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${", "const flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${\nname}\n\\n`, \"utf8\");"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
