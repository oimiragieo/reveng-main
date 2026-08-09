---
name: reveng-mcp-annotation-honesty
description: >-
  States REVENG Wave 2 MCP tool-annotation honesty for denylist dual-labels and
  actlint expectations (L45). Use when editing MCP tool annotations, risk_level
  hints, generate_exploit / recompile_binary labels, denylist policy, or when
  tempted to treat annotations as enforcement or auto-map every high risk tool.
---

# REVENG MCP annotation honesty (Wave 2 / L45)

## Overview

MCP tool annotations are **advisory hints**, not a sandbox or security boundary.
Wave 2 honesty is an **explicit denylist** of dual-labels — not
`risk_level == "high"` auto-mapping.

## Rules

1. **Hints ≠ enforcement** — clients/hosts must not treat annotations as
   authorization. Cite MCP blog (see references).
2. **Wave 2 denylist only** (dual-label both MCP hints + proprietary keys):
   - `generate_exploit`
   - `recompile_binary`
3. **Do not** auto-map every `risk_level == "high"` tool to `destructiveHint`
   (e.g. `analyze_memory_dump`, `ai_code_reconstruction` wait for later waves).
4. **CI direction** — eventual `tools/list` parity with annotation tests
   (sunpeak / Closient patterns). **Full actlint CI = future wave** — do not
   claim Wave 2 closed actlint product GA.
5. Policy + tests (canonical):
   - `docs/architecture/policy-mcp-annotation-honesty-wave2.md`
   - `tests/unit/test_mcp_annotation_honesty_wave2.py`

## Anti-patterns

| Excuse | Reality |
|--------|---------|
| "Annotations are set — tools are sandboxed" | Annotations are hints only (MCP blog). |
| "All high-risk tools should get destructiveHint now" | Wave 2 = explicit denylist (L45), not auto-map. |
| "Ship full actlint in this PR — honesty incomplete otherwise" | Full actlint / mcp-conform CI is deferred; don’t overclaim. |
| "Under-declare hints to avoid noise" | Under-declared hints are worse than over-declared (actlint severity). |

## Cross-refs

- `reveng-release-honesty` (L45 one-liner)
- Pins: [references/pins.md](references/pins.md)
