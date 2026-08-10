"""Wave 7 honesty: JS recovery toolkit bounds."""

from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RESEARCH = REPO / "docs" / "architecture" / "research-js-recovery-toolkit-2026-08-09.md"
CEO = REPO / "docs" / "architecture" / "ceo-update-2026-08-09-wave7.md"
PKG = REPO / "src" / "reveng" / "app_reverse_engineering" / "js_recovery_toolkit" / "pipeline.py"

_INV = REPO / "tests" / "unit" / "test_backlog_wave_a_invariants.py"
_spec = importlib.util.spec_from_file_location("wave_a_backlog_invariants", _INV)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_backlog_status = _mod._backlog_status


def test_wave7_docs_exist() -> None:
    assert RESEARCH.is_file()
    assert CEO.is_file()
    assert PKG.is_file()


def test_research_pins_external_tools() -> None:
    text = RESEARCH.read_text(encoding="utf-8").lower()
    for needle in ("wakaru", "webcrack", "bun-demincer", "unbun", "553"):
        assert needle in text


def test_forbids_ga_close_language() -> None:
    for path in (RESEARCH, CEO):
        text = path.read_text(encoding="utf-8").lower()
        for bad in ("enterprise ga complete", "phase 6 complete", "ralph-2 done"):
            assert bad not in text


def test_r_ralph_2_still_open() -> None:
    assert _backlog_status("R-RALPH-2") == "open"
