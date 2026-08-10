"""Wave 3 honesty: R-RALPH-2 packaging re-baseline (fail-first tokens)."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RESEARCH = REPO_ROOT / "docs" / "architecture" / "research-r-ralph-2.md"
REPORT = REPO_ROOT / "reports" / "js_oracle_ralph_tracked" / "wave3_ralph_report.json"
BACKLOG = REPO_ROOT / "backlog.md"

_INV = REPO_ROOT / "tests" / "unit" / "test_backlog_wave_a_invariants.py"
_spec = importlib.util.spec_from_file_location("wave_a_backlog_invariants", _INV)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_backlog_status = _mod._backlog_status


def test_research_r_ralph_2_doc_exists_and_records_packaging_shift() -> None:
    assert RESEARCH.is_file(), (
        "Missing docs/architecture/research-r-ralph-2.md — Wave 3 must record "
        "the npm packaging shift before any Phase-6 engine spend"
    )
    text = RESEARCH.read_text(encoding="utf-8").lower()
    assert "cli.js" in text
    assert "obsolete" in text or "no longer" in text or "does not ship" in text
    assert "claude.exe" in text or "native" in text
    assert "@anthropic-ai/claude-code" in text or "claude-code" in text
    assert "js_tracked_bundle_artifact" in text
    assert "instrument" in text or "non-discriminat" in text or "does not prove" in text
    # Must not greenwash Phase 6 / RALPH-2 complete
    forbidden = (
        "ralph-2 complete",
        "ralph-2 done",
        "phase 6 complete",
        "phase 6 done",
        "enterprise ga",
    )
    for token in forbidden:
        assert token not in text, f"greenwash token present: {token}"


def test_tracked_ralph_report_scored_not_invented() -> None:
    assert REPORT.is_file(), (
        "Missing reports/js_oracle_ralph_tracked/wave3_ralph_report.json — "
        "Wave 3 needs a frozen scored harness report (live Wave 4 report is separate)"
    )
    data = json.loads(REPORT.read_text(encoding="utf-8"))
    assert "best_project_file_recall" in data
    recall = float(data["best_project_file_recall"])
    assert recall == 0.0
    assert data.get("completion_reason") == "max_attempts_reached"
    assert int(data.get("max_attempts_limit") or 0) == 1
    notes = (data.get("best_benchmark_scorecard") or {}).get("notes") or []
    assert "no_recovered_root" in notes
    assert "no_recovered_project_files" in notes
    # Input must be the interim tracked surface (basename ok if absolute host path)
    input_path = str(data.get("input_path") or "")
    assert "js_tracked_bundle_artifact" in input_path.replace("\\", "/")
    assert str(data.get("oracle_dir") or "").replace("\\", "/").endswith(
        "js_tracked_bundle_source"
    ) or "js_tracked_bundle_source" in str(data.get("oracle_dir") or "").replace("\\", "/")
    honesty = data.get("wave3_honesty") or {}
    assert honesty.get("not_cli_js") is True
    assert honesty.get("harness_exit_code") == 2


def test_r_ralph_2_remains_open() -> None:
    status = _backlog_status("R-RALPH-2")
    assert status == "open", f"R-RALPH-2 must stay open after Wave 3 honesty; got {status!r}"


def test_r_ralph_2_baseline_row_stays_done() -> None:
    assert _backlog_status("R-RALPH-2-BASELINE") == "done"
