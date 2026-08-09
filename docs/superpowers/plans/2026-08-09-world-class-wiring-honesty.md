# World-class wiring & honesty fix wave — Implementation Plan

> **For agentic workers:** Execute task-by-task with tests before/after. Do **not** commit unless the user asks.

**Goal:** Close the audit Top-8 (W-03, W-01, W-02, W-05, W-04, W-07, W-09, W-06) so MCP/CLI/docs stop lying and surfaces share the same honesty gates.

**Architecture:** Prefer explicit `unsupported` / `could_not_measure` tool results over silent no-ops; strip brochure % from agent-facing schemas; quarantine unwired adapters in docs; fail-closed health checks.

**Tech Stack:** Python 3.9, pytest, existing `reveng.core.result_contracts`, MkDocs markdown.

## Global Constraints

- Python 3.9 floor; `/usr/bin/python3.9` for tests
- No invented success percentages
- Match `docs/support_matrix.json`
- Do not implement RALPH-2, native GA, LibAFL, exploit expansion
- Named-path edits only; no `git stash`; **DO NOT commit unless asked**
- Update docs when behavior changes

## PLAN SUMMARY (Thinktank)

- **Intent:** Honesty + wiring for MCP enterprise silent knobs, AI disable on CLI, native adapter quarantine, java cloud NI, historical doc banners, health monitor fail-closed.
- **Risks:** Changing vuln-scan empty results may break agents that parse “No vulnerabilities found”; CLI flag must stay backward compatible (default AI behavior unchanged).
- **Out of scope:** Engine research (RALPH-2), registering NativeAppAdapter as supported, LibAFL, exploit GA.
- **Thinktank 2026-08-09:** Sol **REJECT** (hollow/one-arm tests) · Fable **APPROVE_WITH_NITS**. **Resolved:** revise tasks for bidirectional arms + schema/SoT assertions; W-01 = explicit **unsupported** (no unbounded “wire real behavior”); then execute.

**Audit source:** `docs/architecture/opus-world-class-audit-2026-08-09.md`

---

### Task 1 — W-03 Strip MCP brochure % claims

- [x] Grep enterprise MCP for accuracy `%` in tool descriptions
- [x] Test scans **serialized tool schemas** (not only source text); assert ≥N tools scanned; inject `90%` fixture → red; clean → green
- [x] Edit descriptions; update `docs/reference/mcp-tools.md`
- [x] Verify: `python3.9 -m pytest tests/unit/test_mcp_tool_description_honesty.py -q --no-cov`

### Task 2 — W-01 `unbundle_webpack` → explicit unsupported

- [x] Choose **unsupported** (do not invent webpack unbundle impl this wave)
- [x] Bidirectional: `False` → no unsupported warning / no applied claim; `True` → unsupported warning in result (not silent success-as-applied)
- [x] Docs: mcp-tools.md
- [x] Pytest both arms

### Task 3 — W-02 `find_vulnerabilities` hollow clean

- [x] Unused knobs (`vulnerability_types`, `use_ai_analysis`) → explicit unsupported or executed
- [x] Skipped measurement path → `could_not_measure` / skip reasons — **never** “No vulnerabilities found” as proven empty
- [x] Bidirectional: real executed path with zero findings may still report clean **measured**; skipped path must not
- [x] Docs: mcp-tools.md compat note for agents parsing old empty string
- [x] Pytest knob combos

### Task 4 — W-05 CLI / core MCP `enable_ai` gate

- [x] Add `--no-ai` to analyze CLI; pass into REVENGAnalyzer; expose on core MCP
- [x] Bidirectional: default/`True` → AI path invoked (spy); `False` → skipped; assert MCP schema exposes param
- [x] Docs: reference/cli.md
- [x] Pytest CLI + MCP

### Task 5 — W-04 Quarantine NativeAppAdapter

- [x] Docs + module docstring: unwired / not CUJ
- [x] Regression pin: `create_default_framework` languages exclude `native`; MCP language enum excludes `native`
- [x] Do **not** claim supported in support_matrix.json
- [x] Label test as pin

### Task 6 — W-07 java_ai cloud providers

- [x] OpenAI + Anthropic → clear unsupported **preflight** (both providers tested)
- [x] Positive control: local/ollama path still callable (or skip if tool absent with explicit skip)
- [x] Docs: explanation/ai-providers.md

### Task 7 — W-09 Historical doc honesty

- [x] Banner on changelogs v4–v6 + system paper
- [x] Qualify/remove searchable `95%` brochure lines in those files OR wrap as “historical claim, not validated”
- [x] Fix dead entry paths in system paper intro

### Task 8 — W-06 Health monitor fail-closed

- [x] Target: `CoreREVENGHealthChecker` / `enhanced_health_monitor.py` consumers
- [x] Replace dead imports with real `reveng.*` probes
- [x] Bidirectional: healthy imports → ok; missing → fail-closed status; exception → fail-closed (not NI crash)
- [x] Decide: implement minimal checks (chosen) — not leave “or remove” ambiguous

### Task 9 — Lint / format / docs index

- [x] black/isort on touched Python
- [x] Link audit + plan from `docs/ops/README.md`
- [x] Run new unit tests
