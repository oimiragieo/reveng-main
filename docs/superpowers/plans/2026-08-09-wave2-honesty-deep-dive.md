# Wave 2 Honesty Deep-Dive Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans. Checkbox steps for tracking.

**Goal:** Close Wave-2-scoped honesty items only — MCP annotation honesty (R-MCP-ANNOTATION-1 partial), path-separator CI test hygiene, unicorn/angr macos **slim-install** mitigation — without claiming all backlog / RALPH-2 / #101 / angr capability green.

**Architecture:** Evidence-first after Wave 1 (PR #132). Dual-label MCP hints (spec + proprietary risk) for an **explicit two-tool denylist** only. Posix-aware asserts. MacOS matrix legs **retained** with deterministic slim requirements (no angr/unicorn) — never `matrix.exclude` that drops macos coverage.

**Tech Stack:** Python 3.9, pytest TDD, black/isort 100, GitHub Actions YAML, root `backlog.md`.

**Thinktank:** Round 1 **REJECT** (TDD incomplete; high→destructive derivation unsafe; both workflows; no matrix.exclude). This revision addresses R1.

**Research inputs (2026-08-09):**
- Subagents: MCP annotation, path-sep, unicorn triage
- Web (Exa MCP unavailable): MCP annotations blog; actlint; unicorn#2263

## Global Constraints

- L33 wave-scope; L34 disposition ≠ shipped; release-honesty skill
- Prefer `/usr/bin/python3.9` locally; GHA uses setup-python `python`
- Named-path commits; no stash across worktrees
- No exploit expansion; no native `required:true`; no #101 renderer
- Never claim angr matrix green; CI-UNICORN → at most **mitigated**

## PLAN SUMMARY

| ID | Slice | Backlog target |
| --- | --- | --- |
| W2-1 | Explicit denylist MCP hints + dual-label TDD | R-MCP-ANNOTATION-1 → **partial** |
| W2-2 | Path-sep assert hygiene | soft-red reduction (no GA claim) |
| W2-3 | MacOS slim requirements (both test.yml + tests.yml) | CI-UNICORN-BUILD-1 → **mitigated** |

**Out of scope:** full actlint CI, RALPH-2, #101, phases 6–13, docs-link root cause, angr green, dropping macos matrix legs.

---

### Task W2-1 — MCP annotation honesty

**Files:**
- Create: `docs/architecture/policy-mcp-annotation-honesty-wave2.md`
- Create: `tests/unit/test_mcp_annotation_honesty_wave2.py`
- Modify: `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py`
- Modify: `backlog.md`

**Denylist (explicit — do NOT map all `risk_level=="high"`):**
- `generate_exploit`
- `recompile_binary`

**Required annotations after `_apply_tool_policies` (dual-label):**
- MCP: `destructiveHint: true`, `readOnlyHint: false`, `openWorldHint: true`
- Proprietary preserved: `risk_level`, `requires_policy_acknowledgement` (exploit True / recompile False)

**TDD fail-first (must be RED on main today):**
```python
from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import REVENGEnterpriseServer

DENYLIST = {
    "generate_exploit": {"requires_policy_acknowledgement": True},
    "recompile_binary": {"requires_policy_acknowledgement": False},
}

def test_denylist_tools_dual_label_mcp_hints():
    srv = REVENGEnterpriseServer()
    for name, expect in DENYLIST.items():
        ann = srv.tools[name].to_dict().get("annotations") or {}
        assert ann.get("destructiveHint") is True, name
        assert ann.get("readOnlyHint") is False, name
        assert ann.get("openWorldHint") is True, name
        assert ann.get("risk_level") == "high", name
        assert ann.get("requires_policy_acknowledgement") is expect[
            "requires_policy_acknowledgement"
        ], name
```

**Implement:** In `_apply_tool_policies`, for denylist names only, merge MCP hints into annotations (keep proprietary keys). Do **not** auto-derive from every high-risk tool (`analyze_memory_dump`, `ai_code_reconstruction` stay Wave-2+).

- [ ] RED test → implement → policy doc → backlog partial → commit

### Task W2-2 — Path-separator test hygiene

**Files:**
- `tests/unit/test_generate_skip_inventory.py`
- `tests/unit/test_bun_sample_matrix.py`
- `tests/unit/test_bun_extractor.py`
- Optional: `scripts/generate_skip_inventory.py` posix normalize

Prefer `Path(...).as_posix().endswith("root/droid.exe")`.

- [ ] Fix asserts → pytest green on Linux → commit

### Task W2-3 — Unicorn/angr macos slim install (both workflows)

**Files (BOTH required):**
- `.github/workflows/test.yml`
- `.github/workflows/tests.yml`
- Create: `requirements-ci-macos-slim.txt` (deterministic: runtime deps **without** angr/unicorn/claripy lines; comment cites unicorn#2263 accessed 2026-08-09)
- `backlog.md` → CI-UNICORN-BUILD-1 **mitigated**

**Rules:**
- **Retain** macos matrix legs (3.11/3.12 as today)
- On `runner.os == macOS` (or `matrix.os` macos-*), install slim file instead of full `requirements.txt`+dev that pulls angr
- Ubuntu/Windows keep full install (or unchanged)
- **Forbidden:** `matrix.exclude` that removes macos coverage; claiming angr green; status `done`

**Validation:** `python -c 'import yaml; yaml.safe_load(open(...))'` on both workflows; dogfood note that slim file has zero `angr`/`unicorn` lines (`rg` count 0).

- [ ] Slim reqs + both YAMLs + backlog mitigated → commit

### Task W2-4 — Sol audit + PR

- [ ] black/isort; dogfood W2 tests
- [ ] Codex Sol verdict with HEAD SHA → PASS / PASS_WITH_NITS
- [ ] PR; after merge, note CI receipt for macos slim (mitigated evidence)

---

## Explicitly deferred

Full actlint CI, mcp-conform productization, filesystem `write_file` annotations (Wave 2+), RALPH-2, #101, docs-link 200+ errors, phases 6–13.
