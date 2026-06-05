/**
 * Reconstructed pseudo-source module for the `mcp` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "mcp" as const;
export const title = "MCP" as const;
export const description = "MCP transports, server management, and remote tool connectivity." as const;
export const evidenceCount = 1 as const;
export const inferredResponsibilities = ["MCP transports, server management, and remote tool connectivity."] as const;
export const preferredTopics = ["integrations_and_networking", "cli_surface"] as const;
export const sourceTopics = ["cli_surface"] as const;
export const notableTokens = ["mcp", "sse", "websocket", "transport", "mcp-config", "toolbox", "server", "./lib/greet", "--name", "/greet", "/lib"] as const;
export const relatedUrls = [] as const;
export const evidenceExcerpts = ["writeGreeting }\nfrom \"./lib/greet\";\nexport function main(argv: string[] = process.argv): void {\nconst flag = argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
