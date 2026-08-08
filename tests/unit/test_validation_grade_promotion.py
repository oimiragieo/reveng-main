"""Validation grade promotion from JS behavior probe (P3-BP-3)."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering.contracts import (
    build_validation_summary,
    promote_grade_from_capability,
)


def test_build_validation_summary_baseline_without_capability():
    summary = build_validation_summary(
        source_count=2,
        warnings=[],
        topic_match_counts={"a": 2},
        primary_artifacts={"reconstructed_project": Path("x")},
        evidence_count=3,
    )
    assert summary["grade"] == "partial_recovery"


def test_promote_grade_tier2_syntax_ok_bumps_partial_to_evidence_backed():
    capability = {
        "dimensions": {
            "javascript_behavior_probe": {"tier": 2, "summary": "cli_help_exit_zero"},
            "javascript_smoke": {"syntax_summary": "all_checked_ok"},
        }
    }
    grade, reason = promote_grade_from_capability(
        "partial_recovery",
        capability_report=capability,
        source_count=2,
    )
    assert grade == "evidence_backed"
    assert "behavior_tier_2" in reason


def test_promote_grade_does_not_overclaim_from_tier1():
    capability = {
        "dimensions": {
            "javascript_behavior_probe": {"tier": 1},
            "javascript_smoke": {"syntax_summary": "all_checked_ok"},
        }
    }
    grade, reason = promote_grade_from_capability(
        "partial_recovery",
        capability_report=capability,
        source_count=2,
    )
    assert grade == "partial_recovery"
    assert reason == ""


def test_build_validation_summary_applies_capability_promotion():
    capability = {
        "dimensions": {
            "javascript_behavior_probe": {"tier": 2, "summary": "cli_help_exit_zero"},
            "javascript_smoke": {"syntax_summary": "all_checked_ok"},
        }
    }
    summary = build_validation_summary(
        source_count=2,
        warnings=[],
        topic_match_counts={"a": 2},
        primary_artifacts={"reconstructed_project": Path("x")},
        evidence_count=3,
        capability_report=capability,
    )
    assert summary["grade"] == "evidence_backed"
    assert summary.get("grade_promotion")
