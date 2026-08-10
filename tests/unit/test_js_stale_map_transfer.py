"""Wave 5 Tier A — stale-map fingerprint transfer (fail-first / hermetic)."""

from __future__ import annotations

import json
from pathlib import Path

from reveng.app_reverse_engineering.js_stale_map_transfer import (
    build_index_from_sourcemap,
    index_has_raw_secret_literals,
    scan_bundle,
)

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "test_samples" / "js_stale_map_transfer"
MAP = FIX / "stale.map.json"
POSITIVE = FIX / "targets" / "positive.js"
MISMATCH = FIX / "targets" / "mismatch.js"

SECRETS = (
    "ALPHA_UNIQUE_FINGERPRINT_TOKEN_W5",
    "BETA_UNIQUE_FINGERPRINT_TOKEN_W5",
    "LEFTPAD_VENDOR_ONLY_TOKEN_SHOULD_EXCLUDE",
)


def test_mismatch_control_confirms_zero_first_party() -> None:
    """Bidirectional oracle arm B: unrelated bundle must not confirm paths."""
    index = build_index_from_sourcemap(MAP)
    result = scan_bundle(index, MISMATCH.read_text(encoding="utf-8"))
    assert result.metrics["first_party_confirmed_count"] == 0
    assert result.confirmed == []
    assert result.llm_used is False
    assert result.to_serializable()["decoded_exe_claim"] is False


def test_positive_control_confirms_alpha_with_two_signals() -> None:
    index = build_index_from_sourcemap(MAP)
    result = scan_bundle(index, POSITIVE.read_text(encoding="utf-8"))
    assert result.metrics["first_party_confirmed_count"] >= 1
    paths = {c.source_path for c in result.confirmed}
    assert any("alpha" in p for p in paths)
    alpha = next(c for c in result.confirmed if "alpha" in c.source_path)
    assert alpha.signal_count >= 2
    assert alpha.provenance_confidence > 0.0
    # name recovery not applied on hermetic path
    ser = result.to_serializable()
    assert all(row["name_recovery_confidence"] == 0.0 for row in ser["confirmed"])
    assert ser["metrics"]["name_recovery_confidence_mean"] == 0.0


def test_serialized_index_omits_raw_literals() -> None:
    index = build_index_from_sourcemap(MAP)
    payload = index.to_serializable()
    assert payload["entry_count"] > 0
    assert index_has_raw_secret_literals(payload, SECRETS) is False
    assert "hashed_fingerprints_only" in payload["notes"]


def test_vendor_signals_not_indexed() -> None:
    index = build_index_from_sourcemap(MAP)
    # Vendor token must not appear as any source_path owner
    assert all("node_modules" not in p for p in index.digest_to_path.values())
    # Shared boilerplate "application/json" must not uniquely index
    blob = json.dumps(index.to_serializable())
    assert "application/json" not in blob


def test_deterministic_repeat() -> None:
    index = build_index_from_sourcemap(MAP)
    text = POSITIVE.read_text(encoding="utf-8")
    a = scan_bundle(index, text).to_serializable()
    b = scan_bundle(index, text).to_serializable()
    assert a == b
