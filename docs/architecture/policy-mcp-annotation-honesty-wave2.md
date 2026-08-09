# Policy — MCP annotation honesty (Wave 2)

**Status:** `partial` — curated denylist dual-labels only. Not actlint CI parity / not product GA.

## Scope

Enterprise MCP (`REVENGEnterpriseServer`) tools in the Wave 2 denylist:

- `generate_exploit`
- `recompile_binary`

Must advertise MCP spec hints **and** proprietary risk keys:

| Key | Value |
| --- | --- |
| `destructiveHint` | `true` |
| `readOnlyHint` | `false` |
| `openWorldHint` | `true` |
| `risk_level` | `high` (preserved) |
| `requires_policy_acknowledgement` | per existing policy table |

## Rules

1. Do **not** auto-map every `risk_level == "high"` tool to `destructiveHint` (e.g. `analyze_memory_dump`, `ai_code_reconstruction` wait for later waves).
2. Under-declared MCP hints are worse than over-declared (actlint severity order).
3. Annotations remain **hints** — clients must not treat them as a sandbox.
4. Full actlint / mcp-conform CI is deferred (`R-MCP-ANNOTATION-1` stays research-adjacent until measured).

## Sources (accessed 2026-08-09)

- https://github.com/formael/actlint
- https://blog.modelcontextprotocol.io/posts/2026-03-16-tool-annotations/
