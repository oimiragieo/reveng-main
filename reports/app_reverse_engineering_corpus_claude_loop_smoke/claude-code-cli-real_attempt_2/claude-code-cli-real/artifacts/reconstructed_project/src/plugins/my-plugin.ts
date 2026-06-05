/**
 * Inferred pseudo module for `plugins/my-plugin.ts`.
 * Derived from recoverable bundle symbol names; not canonical upstream source.
 */

export const inferredSymbols = ["plugins/my-plugin"] as const;

export function describeInferredModule(): string {
  return "Inferred from bundle symbols: plugins/my-plugin";
}
