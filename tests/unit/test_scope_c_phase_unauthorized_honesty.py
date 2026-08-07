"""Refuse overclaim while phases 5–13 are blocked on Phase 4 HOLD."""

from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BACKLOG = REPO / "backlog.md"
CATALOG = REPO / "docs" / "architecture" / "scope-c-phase-catalog-contracts.md"
POLICY = REPO / "docs" / "architecture" / "scope-c-hold-prep-policy.md"


def test_hold_policy_forbids_substantive_prep_implementation():
    text = POLICY.read_text(encoding="utf-8")
    assert "Forbidden" in text or "Still forbidden" in text
    assert "sol stop/go" in text.lower() or "stop/go" in text.lower()


def test_catalog_marks_phases_5_plus_blocked_or_unauthorized():
    text = CATALOG.read_text(encoding="utf-8")
    assert "unauthorized" in text.lower() or "await Sol stop/go" in text.lower()
    assert "scope c complete" not in text.lower()


def test_backlog_phase_rows_5_to_13_await_sol():
    text = BACKLOG.read_text(encoding="utf-8")
    for n in range(5, 14):
        m = re.search(rf"^\|\s*{n}\s\|[^\n]+$", text, re.M)
        assert m, f"missing phase {n} row"
        row = m.group(0).lower()
        assert "await sol stop/go" in row, f"phase {n} not awaiting Sol: {row}"


def test_backlog_does_not_claim_scope_c_complete():
    text = BACKLOG.read_text(encoding="utf-8").lower()
    assert "scope c complete" not in text
    assert "phases 5–13 done" not in text
    assert "phases 5-13 done" not in text


def test_tier3_rows_remain_parked():
    text = BACKLOG.read_text(encoding="utf-8")
    rows = re.findall(r"^\|\s*(T3-[A-Z0-9-]+)\s\|[^\n]+$", text, re.M)
    assert rows, "expected T3-* rows in backlog"
    for tid in rows:
        full = re.search(rf"^\|\s*{re.escape(tid)}\s\|[^\n]+$", text, re.M)
        assert full and "parked" in full.group(0).lower(), full.group(0) if full else tid
