"""Wave 5 honesty: stale-map fingerprint transfer (Thinktank APPROVE_WITH_NITS)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESEARCH = REPO / "docs" / "architecture" / "research-stale-map-fingerprint-transfer-2026-08-09.md"
SYNTHESIS = REPO / "docs" / "architecture" / "thinktank-stale-map-fingerprint-transfer-2026-08-09.md"
CEO = REPO / "docs" / "architecture" / "ceo-update-2026-08-09-wave5.md"
PLAN = REPO / "docs" / "superpowers" / "plans" / "2026-08-09-wave5-stale-map-fingerprint.md"
MODULE = REPO / "src" / "reveng" / "app_reverse_engineering" / "js_stale_map_transfer.py"
SPIKE = REPO / "docs" / "architecture" / "research-wave5-bun-unpack-spike.md"

_INV = REPO / "tests" / "unit" / "test_backlog_wave_a_invariants.py"
_spec = importlib.util.spec_from_file_location("wave_a_backlog_invariants", _INV)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_backlog_status = _mod._backlog_status


def test_wave5_docs_and_module_exist() -> None:
    for path in (RESEARCH, SYNTHESIS, CEO, PLAN, MODULE, SPIKE):
        assert path.is_file(), f"missing {path}"


def test_forbidden_decode_exe_claims_absent_from_wave5_docs() -> None:
    for path in (RESEARCH, SYNTHESIS, CEO, PLAN, MODULE):
        text = path.read_text(encoding="utf-8").lower()
        # Must document the boundary, not claim decode
        assert "not" in text or "does not" in text or "≠" in text or "!=" in text or "forbid" in text
        for bad in (
            "decoded the new exe",
            "decompiled claude.exe",
            "enterprise ga complete",
            "phase 6 complete",
            "ralph-2 done",
            "ralph-2 complete",
        ):
            assert bad not in text, f"{path.name} contains greenwash/false friend: {bad}"


def test_module_source_forbids_llm_ship_path() -> None:
    text = MODULE.read_text(encoding="utf-8")
    assert "llm_used" in text
    assert "False" in text
    assert "not_decoded_exe" in text or "decoded_exe_claim" in text


def test_r_ralph_2_still_open_after_wave5() -> None:
    assert _backlog_status("R-RALPH-2") == "open"
