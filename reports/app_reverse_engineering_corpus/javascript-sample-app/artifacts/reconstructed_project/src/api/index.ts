/**
 * Reconstructed pseudo-source module for the `api` domain.
 * Generated from bundle evidence; not canonical upstream source.
 */

export const domain = "api" as const;
export const title = "API" as const;
export const description = "Remote API clients, auth endpoints, and service request surfaces." as const;
export const evidenceCount = 0 as const;
export const inferredResponsibilities = ["Remote API clients, auth endpoints, and service request surfaces."] as const;
export const preferredTopics = ["integrations_and_networking", "agent_runtime_and_prompts"] as const;
export const sourceTopics = [] as const;
export const notableTokens = ["api", "oauth", "token", "authorize", "bearer", "roles", "base_api_url"] as const;
export const relatedUrls = [] as const;
export const evidenceExcerpts = [] as const;

export function summarizeDomain(): string {
  return `${title}: ${description} (evidence=${evidenceCount})`;
}
