# Scope C Phase-Next Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close near-term Scope C research + M3 MCP validation surface honesty without Ghidra/Windows/RALPH-2 engine work.

**Architecture:** Land durable research artifacts for native/TSX decisions; optionally probe with `tsx` when present; expose top-level `validation_grade` and `capability_report` on MCP `reverse_engineer_app` responses (simple + enterprise) so agents need not dig only into nested `app_result`.

**Tech Stack:** Python 3.9 (`/usr/bin/python3.9`), pytest, existing MCP servers + `build_mcp_tool_response`, `capability_report.py`.

## Global Constraints

- Work only in worktree `/mnt/c/dev/projects/reveng-main/.worktrees/scope-c-phase-next` on branch `feat/scope-c-phase-next`.
- Interpreter: `/usr/bin/python3.9` for all pytest/scripts.
- Pytest: `/usr/bin/python3.9 -m pytest <paths> -q --no-cov`.
- No exploit expansion; keep EXPERIMENTAL watermarks.
- No Ghidra requirement for managed languages; no Windows-only fixtures as GA claims.
- Stage **named paths only** for git commits (DrvFS hang lesson).
- Conventional commits; author via `git -c user.name=… -c user.email=…` matching `git log -1` without rewriting git config.
- YAGNI: no RALPH-2 recall engine rewrite; no full pipeline package merge.
- Honesty: research docs must not claim GA for native corpus.

---

### Task 1: R-NATIVE-1 Linux-hermetic native inventory (docs)

**Files:**
- Create: `docs/architecture/research-r-native-1-linux-hermetic-candidates.md`
- Modify: `backlog.md` (mark R-NATIVE-1 researched; M1-NATIVE-FAM notes pointer)

**Interfaces:**
- Consumes: none
- Produces: research doc listing ≥5 candidate CLIs across ≥3 families with Linux hermeticity notes; backlog status `research`→`done` for R-NATIVE-1 only (M1-NATIVE-FAM stays open)

- [ ] **Step 1: Write the research doc** with sections: Purpose, Candidate table (name, language/family, license, hermetic build notes, GA readiness), Non-goals, Recommendation (do not claim GA until fixtures land).

Include at least these candidates (adjust after quick path checks under `external/ga_sources/` if present): `hexyl` (Rust), `fd` (Rust), `hyperfine` (Rust), `ripgrep` (Rust), one C or Go sample if present — note when only Windows binaries exist.

- [ ] **Step 2: Update backlog.md** — R-NATIVE-1 status `done` with path to doc; M1-NATIVE-FAM notes cite the doc; keep M1-NATIVE-FAM `open`.

- [ ] **Step 3: Commit**

```bash
git add -- docs/architecture/research-r-native-1-linux-hermetic-candidates.md backlog.md
git -c user.name="$(git log -1 --format='%an')" -c user.email="$(git log -1 --format='%ae')" commit -m "$(cat <<'EOF'
docs(research): inventory Linux-hermetic native GA candidates (R-NATIVE-1)

EOF
)"
```

---

### Task 2: R-TSX-1 optional tsx behavior probe (TDD)

**Files:**
- Modify: `src/reveng/app_reverse_engineering/capability_report.py`
- Create: `tests/unit/test_tsx_behavior_probe.py`
- Modify: `docs/architecture/reveng-capability-hardening-plan.md` (P3-BP-1 / R-TSX-1 status)
- Modify: `backlog.md` (R-TSX-1 done; P3-BP-1 partial→done if probe lands)

**Interfaces:**
- Consumes: existing `run_javascript_behavior_probe`, `_resolve_package_cli_entry`
- Produces: `run_javascript_behavior_probe` may try `tsx <entry> --help` when Node entry is absent but a `.ts`/`.tsx` main exists AND `which("tsx")` finds a binary; records `runner: "tsx"` in the probe section; if tsx missing, reason `tsx_not_found` and keep smoke-stub path unchanged

- [ ] **Step 1: Write failing tests** in `tests/unit/test_tsx_behavior_probe.py`:

```python
"""Optional tsx runner for TS package main (R-TSX-1 / P3-BP-1)."""
from __future__ import annotations
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from reveng.app_reverse_engineering.capability_report import run_javascript_behavior_probe

def test_tsx_probe_used_when_main_is_typescript(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "main": "src/cli.ts"}), encoding="utf-8"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "cli.ts").write_text("export {}\n", encoding="utf-8")
    def fake_which(name: str):
        return "/fake/tsx" if name == "tsx" else None
    with patch("reveng.app_reverse_engineering.capability_report.which", side_effect=fake_which):
        with patch(
            "reveng.app_reverse_engineering.capability_report.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="Usage: cli\n", stderr=""),
        ) as run:
            out = run_javascript_behavior_probe(tmp_path, run_probe=True, timeout_sec=5.0)
    assert out["skipped"] is False
    assert out["tier"] == 2
    assert out.get("runner") == "tsx"
    assert run.call_args[0][0][:2] == ["/fake/tsx", "src/cli.ts"]

def test_tsx_missing_records_reason_without_crash(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "main": "app.ts"}), encoding="utf-8"
    )
    (tmp_path / "app.ts").write_text("export {}\n", encoding="utf-8")
    with patch("reveng.app_reverse_engineering.capability_report.which", return_value=None):
        out = run_javascript_behavior_probe(tmp_path, run_probe=True)
    assert out["skipped"] is True
    assert out["reason"] in {"tsx_not_found", "no_cli_entry", "node_not_found"}
```

- [ ] **Step 2: Run tests — expect FAIL**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_tsx_behavior_probe.py -q --no-cov
```

- [ ] **Step 3: Implement** — extend `_resolve_package_cli_entry` or add `_resolve_typescript_cli_entry` accepting `.ts`/`.tsx`; in `run_javascript_behavior_probe`, if JS entry missing, resolve TS entry and if `which("tsx")` then run `[tsx, rel, "--help"]` and set `runner="tsx"`. Prefer existing `reveng.behavior_probe_main` / bin / `.js` paths first (no regression).

- [ ] **Step 4: Run tests — expect PASS** (also re-run `tests/unit/test_capability_report.py`)

- [ ] **Step 5: Update hardening plan + backlog; commit named paths**

---

### Task 3: M3 — top-level MCP validation fields (simple server)

**Files:**
- Modify: `src/reveng/agent_sdk/mcp/servers/reveng_server.py` (`reverse_engineer_app` payload)
- Modify: `tests/unit/test_mcp_contracts.py` (`test_simple_mcp_reverse_engineer_app_returns_versioned_contract`)

**Interfaces:**
- Consumes: `AppReverseEngineeringResult.validation_grade`, `result.metadata.get("capability_report")`
- Produces: MCP payload keys `validation_grade: str` and `capability_report: dict | None` at top level beside `app_result`

- [ ] **Step 1: Extend existing test** to assert:

```python
assert result["validation_grade"] == "evidence_backed"
assert "capability_report" in result
# fake metadata should include capability_report key when provided by fake result
```

Ensure the fake `AppReverseEngineeringResult` / metadata in the test includes `capability_report={"schema_version": "1.0", "headline": "test"}`.

- [ ] **Step 2: Run test — expect FAIL**

```bash
/usr/bin/python3.9 -m pytest tests/unit/test_mcp_contracts.py::test_simple_mcp_reverse_engineer_app_returns_versioned_contract -q --no-cov
```

- [ ] **Step 3: Implement** payload fields in `reveng_server.reverse_engineer_app`:

```python
payload={
    "language": result.language,
    "analysis_file": str(result.analysis_file),
    "validation_grade": result.validation_grade,
    "capability_report": (result.metadata or {}).get("capability_report"),
    "app_result": result.metadata,
},
```

- [ ] **Step 4: PASS test; commit**

---

### Task 4: M3 — top-level MCP validation fields (enterprise server)

**Files:**
- Modify: `src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py`
- Modify: `tests/unit/test_mcp_contracts.py` (`test_enterprise_mcp_reverse_engineer_app_returns_contract`)

**Interfaces:** Same as Task 3 for enterprise `reverse_engineer_app`.

- [ ] **Step 1: Extend enterprise test** with same top-level assertions + fake capability_report.
- [ ] **Step 2: FAIL then implement payload parity; PASS.**
- [ ] **Step 3: Commit**

---

### Task 5: Backlog + CEO phase note

**Files:**
- Modify: `backlog.md` (M3 partial progress; phase-next note)
- Create: `docs/architecture/ceo-update-phase-next-2026-08-06.md` (5–10 lines: what landed)

- [ ] **Step 1: Write short CEO note** listing Tasks 1–4 outcomes and remaining RALPH-2 / M1-NATIVE-FAM / hexyl.
- [ ] **Step 2: Sync backlog statuses** for R-TSX-1, R-NATIVE-1, P3-BP-1, M3 note.
- [ ] **Step 3: Commit; run**

```bash
/usr/bin/python3.9 scripts/verify_ga_readiness.py --profile ga
```

Expected: Overall status: pass

---

## Self-Review

1. **Spec coverage:** Research (R-NATIVE-1, R-TSX-1), M3 MCP spine (simple+enterprise), backlog/CEO — covered. Explicitly excluded: RALPH-2 engine, hexyl, pipeline merge, SEC-1.
2. **Placeholders:** None intended; implementers must not invent GA native claims.
3. **Type consistency:** `validation_grade: str`, `capability_report: Mapping | None` on both MCP servers.
