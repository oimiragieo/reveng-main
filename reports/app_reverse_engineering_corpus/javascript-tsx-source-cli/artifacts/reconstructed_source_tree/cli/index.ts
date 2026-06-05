/**
 * Reconstructed pseudo-source module for the `cli` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "cli" as const;
export const title = "CLI" as const;
export const description = "Command registration, flags, slash commands, and terminal entrypoints." as const;
export const evidenceCount = 5 as const;
export const inferredResponsibilities = ["Command registration, flags, slash commands, and terminal entrypoints."] as const;
export const preferredTopics = ["cli_surface"] as const;
export const sourceTopics = [] as const;
export const notableTokens = ["command(", ".command(", "process.argv", "--", "/", "usage: claude", "./lib/greet", "--name", "/greet", "/lib"] as const;
export const cliFlags = ["--name"] as const;
export const slashCommands = ["/greet", "/lib"] as const;
export const evidenceExcerpts = ["writeGreeting }\nfrom \"./lib/greet\";\nexport function main(argv: string[] = process.argv): void {\nconst flag = argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";", "from \"./lib/greet\";\nexport function main(argv: string[] = process.argv): void {\nconst flag = argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nwriteGreeting(name);", "#!/usr/bin/env node\n\nimport {\nwriteGreeting }\nfrom \"./lib/greet\";", "#!/usr/bin/env node\n\nimport {\nwriteGreeting }\nfrom \"./lib/greet\";\nexport function main(argv: string[] = process.argv): void {\nconst flag = argv.find((value) => value.startsWith(\"--name=\"));", "main();\n}\n//# sourceMappingURL=sample_tsx_cli.tsx.map"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
