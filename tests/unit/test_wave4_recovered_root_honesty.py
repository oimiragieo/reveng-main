"""Wave 4 honesty: recovered-root materialization on tracked JS bundle."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
REPORT = REPO_ROOT / "reports" / "js_oracle_ralph_tracked" / "ralph_report.json"
WAVE3 = REPO_ROOT / "reports" / "js_oracle_ralph_tracked" / "wave3_ralph_report.json"
MISMATCH = REPO_ROOT / "reports" / "js_oracle_ralph_tracked" / "mismatch_control.md"
RESEARCH = REPO_ROOT / "docs" / "architecture" / "research-wave4-js-recovered-root-2026-08-09.md"
EVIDENCE = REPO_ROOT / "docs" / "architecture" / "research-wave4-tracked-ralph-evidence.md"
OPERATOR = REPO_ROOT / "docs" / "architecture" / "operator_local_claude.md"
TIP1_NAMES = REPO_ROOT / "docs" / "architecture" / "sol-wave4-tip1-name-status.txt"

_INV = REPO_ROOT / "tests" / "unit" / "test_backlog_wave_a_invariants.py"
_spec = importlib.util.spec_from_file_location("wave_a_backlog_invariants", _INV)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_backlog_status = _mod._backlog_status


def test_wave4_treatment_report_source_map_recall_positive() -> None:
    assert REPORT.is_file()
    data = json.loads(REPORT.read_text(encoding="utf-8"))
    recall = float(data["best_project_file_recall"])
    assert recall > 0.0
    notes = (data.get("best_benchmark_scorecard") or {}).get("notes") or []
    assert "no_recovered_root" not in notes
    assert any(str(n).startswith("materialization_mode:source_map") for n in notes)
    honesty = data.get("wave4_honesty") or {}
    assert honesty.get("tracked_surface") is True
    assert honesty.get("not_cli_js") is True


def test_wave3_frozen_baseline_still_zero() -> None:
    assert WAVE3.is_file(), "Wave 3 baseline must remain frozen beside the live Wave 4 report"
    data = json.loads(WAVE3.read_text(encoding="utf-8"))
    assert float(data["best_project_file_recall"]) == 0.0
    notes = (data.get("best_benchmark_scorecard") or {}).get("notes") or []
    assert "no_recovered_root" in notes


def test_mismatch_control_doc_discriminates() -> None:
    text = MISMATCH.read_text(encoding="utf-8")
    low = text.lower()
    assert "discriminat" in low
    assert "source_map" in low
    # Parse arm recalls from the markdown table (not substring-only).
    treatment = None
    mismatch = None
    for line in text.splitlines():
        cells = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cells) < 4:
            continue
        arm = cells[0].lower()
        recall_cell = cells[3]
        try:
            recall = float(recall_cell)
        except ValueError:
            continue
        if arm == "treatment":
            treatment = recall
        elif arm == "mismatch":
            mismatch = recall
    assert treatment is not None and mismatch is not None, (
        "mismatch_control.md must table Treatment and Mismatch recall floats"
    )
    assert treatment > 0.0
    assert mismatch < treatment


def test_wave4_docs_present_no_ga_claim() -> None:
    for path in (RESEARCH, EVIDENCE, OPERATOR):
        assert path.is_file(), f"missing {path}"
        low = path.read_text(encoding="utf-8").lower()
        for token in ("enterprise ga", "phase 6 complete", "ralph-2 done", "ralph-2 complete"):
            assert token not in low, f"{path.name} greenwash: {token}"


def test_r_ralph_2_still_open_after_wave4() -> None:
    assert _backlog_status("R-RALPH-2") == "open"


def test_tip1_name_status_has_no_anthropic_tree() -> None:
    assert TIP1_NAMES.is_file()
    text = TIP1_NAMES.read_text(encoding="utf-8").lower()
    assert "8923ab7f" in text
    forbidden = (
        "claude-code-main",
        "claude_bun_extract",
        "/tmp/claude",
        "entrypoints/cli.js",
    )
    for token in forbidden:
        assert token not in text, f"Anthropic/local extract path in tip1 list: {token}"
