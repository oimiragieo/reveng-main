"""Manifest honesty for native fixture registration."""

from __future__ import annotations

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MANIFEST = REPO / ".reveng" / "source_binary_benchmarks.ga.json"
FORBIDDEN_STATUS = {"ga", "verified", "supported"}


def _load():
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_manifest_parses_and_every_entry_has_required_and_status():
    data = _load()
    benches = data["benchmarks"]
    assert isinstance(benches, list)
    assert len(benches) >= 3
    for entry in benches:
        assert isinstance(entry.get("required"), bool), entry.get("id")
        if entry["required"] is False:
            assert entry.get("status"), entry.get("id")
            assert entry.get("status_note"), entry.get("id")


def test_native_fixture_entries_are_not_required():
    by_id = {e["id"]: e for e in _load()["benchmarks"]}
    for fid in ("native_hello_c", "native_hello_go"):
        assert fid in by_id
        assert by_id[fid]["required"] is False
        assert by_id[fid]["status"] == "fixture_only"


def test_fixture_entry_must_not_claim_ga():
    by_id = {e["id"]: e for e in _load()["benchmarks"]}
    for fid in ("native_hello_c", "native_hello_go"):
        assert by_id[fid]["status"] not in FORBIDDEN_STATUS
