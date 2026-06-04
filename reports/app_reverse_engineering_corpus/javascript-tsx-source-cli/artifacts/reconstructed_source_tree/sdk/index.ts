/**
 * Reconstructed pseudo-source module for the `sdk` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "sdk" as const;
export const title = "SDK" as const;
export const description = "SDK mode, agent SDK integration, and machine-oriented I/O surfaces." as const;
export const evidenceCount = 2 as const;
export const inferredResponsibilities = ["SDK mode, agent SDK integration, and machine-oriented I/O surfaces."] as const;
export const preferredTopics = ["cli_surface", "dependencies_and_binaries"] as const;
export const sourceTopics = ["cli_surface", "dependencies_and_binaries"] as const;
export const notableTokens = ["sdk", "agent-sdk", "stream-json", "output-format", "enable-auth-status", "./lib/greet", "--name", "/greet", "/lib"] as const;
export const slashCommands = ["/greet", "/lib"] as const;
export const evidenceExcerpts = ["writeGreeting }\nfrom \"./lib/greet\";\nexport function main(argv: string[] = process.argv): void {\nconst flag = argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";", "from \"./lib/greet\";\nexport function main(argv: string[] = process.argv): void {\nconst flag = argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nwriteGreeting(name);"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
