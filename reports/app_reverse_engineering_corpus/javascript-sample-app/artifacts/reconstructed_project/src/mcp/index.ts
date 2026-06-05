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
export const notableTokens = ["mcp", "sse", "websocket", "transport", "mcp-config", "toolbox", "server"] as const;
export const relatedUrls = [] as const;
export const evidenceExcerpts = ["#!/usr/bin/env node\n\nconst fs = require(\"fs\");\nfunction main() {\nconst flag = process.argv.find((value) => value.startsWith(\"--name=\"));\nconst name = flag ? flag.split(\"=\")[1] : \"world\";\nfs.writeFileSync(\"sample_bundle_output.txt\", `hello ${"] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
