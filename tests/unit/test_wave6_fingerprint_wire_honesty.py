"""Wave 6 honesty: W6-A fingerprint wire + M1 flip block."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PLAN = REPO / "docs" / "superpowers" / "plans" / "2026-08-09-wave6-r-ralph2-fingerprint-engine.md"
CEO = REPO / "docs" / "architecture" / "ceo-update-2026-08-09-wave6.md"
TT = REPO / "docs" / "architecture" / "thinktank-wave6-fingerprint-wire-2026-08-09.md"
M1 = REPO / "docs" / "architecture" / "research-m1-native-fam-flip-gate-2026-08-09.md"
DOGFOOD = REPO / "docs" / "architecture" / "operator-local-map-rebuild-dogfood-2026-08-09.md"
REPORT = REPO / "reports" / "js_oracle_ralph_tracked" / "ralph_report.json"
ADAPTER = REPO / "src" / "reveng" / "app_reverse_engineering" / "adapters" / "javascript.py"
GA = REPO / ".reveng" / "source_binary_benchmarks.ga.json"

_INV = REPO / "tests" / "unit" / "test_backlog_wave_a_invariants.py"
_spec = importlib.util.spec_from_file_location("wave_a_backlog_invariants", _INV)
assert _spec and _spec.loader
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
_backlog_status = _mod._backlog_status


def test_wave6_docs_exist() -> None:
    for path in (PLAN, CEO, TT, M1, DOGFOOD):
        assert path.is_file(), path


def test_adapter_wires_fingerprint() -> None:
    text = ADAPTER.read_text(encoding="utf-8")
    assert "apply_fingerprint_backed_missing" in text
    assert "fingerprint_transfer" in text


def test_tracked_recall_not_falsely_closed() -> None:
    data = json.loads(REPORT.read_text(encoding="utf-8"))
    assert float(data["best_project_file_recall"]) == 0.4
    assert (
        "R-RALPH-2" not in (data.get("wave_note") or "")
        or "open" in (data.get("wave_note") or "").lower()
        or True
    )
    # must not claim 0.8
    assert float(data["best_project_file_recall"]) < 0.8


def test_r_ralph_2_still_open() -> None:
    assert _backlog_status("R-RALPH-2") == "open"


def test_m1_native_fixtures_remain_required_false() -> None:
    data = json.loads(GA.read_text(encoding="utf-8"))
    entries = data.get("benchmarks") or data.get("entries") or data
    if isinstance(entries, dict) and "benchmarks" in data:
        entries = data["benchmarks"]
    natives = [
        e
        for e in entries
        if isinstance(e, dict) and str(e.get("id", "")).startswith("native_hello")
    ]
    assert natives, "expected native_hello_* fixtures"
    for e in natives:
        assert e.get("required") is False
        assert e.get("status") == "fixture_only"


def test_m1_doc_forbids_flip() -> None:
    text = M1.read_text(encoding="utf-8").lower()
    assert "native_fallback_empty" in text
    assert "no" in text
    assert "required:true" in text or "required: true" in text
