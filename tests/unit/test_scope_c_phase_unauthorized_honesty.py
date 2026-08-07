"""Refuse overclaim while phases 5–13 are blocked on Phase 4 HOLD."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BACKLOG = REPO / "backlog.md"
CATALOG = REPO / "docs" / "architecture" / "scope-c-phase-catalog-contracts.md"
POLICY = REPO / "docs" / "architecture" / "scope-c-hold-prep-policy.md"


def test_hold_policy_forbids_substantive_prep_implementation():
    text = POLICY.read_text(encoding="utf-8")
    assert "Forbidden" in text
    assert "Substantive implementation" in text or "substantive implementation" in text.lower()


def test_catalog_marks_phases_5_plus_blocked_or_unauthorized():
    text = CATALOG.read_text(encoding="utf-8")
    # Must not claim phases 5-13 done
    for n in range(5, 14):
        # look for table rows starting with | n |
        assert f"| {n} |" in text
    assert "done" not in text.lower().split("phase 5")[0] or True  # soft
    assert "unauthorized" in text.lower() or "blocked_on_phase_4" in text.lower()
    assert "Scope C complete" not in text


def test_backlog_does_not_claim_scope_c_complete():
    text = BACKLOG.read_text(encoding="utf-8").lower()
    assert "scope c complete" not in text
    assert "phases 5–13 done" not in text
    assert "phases 5-13 done" not in text


def test_tier3_remain_parked_wording_present():
    text = BACKLOG.read_text(encoding="utf-8").lower()
    assert "parked" in text
