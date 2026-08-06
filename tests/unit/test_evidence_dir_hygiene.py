"""M0: native_analyze_probe evidence dir — exactly one stamp byte-identical to latest."""

from __future__ import annotations

from pathlib import Path

PROBE_DIR = Path(__file__).resolve().parents[2] / "reports" / "native_analyze_probe"
LATEST = PROBE_DIR / "latest.json"


def _stamp_paths() -> list[Path]:
    """Timestamped siblings only (`20*.json`); ignore job files and other JSON."""
    return sorted(PROBE_DIR.glob("20*.json"))


def test_probe_dir_exists():
    assert PROBE_DIR.is_dir()


def test_latest_json_present():
    assert LATEST.is_file(), "latest.json missing — evidence dir is incomplete"


def test_exactly_one_timestamped_stamp():
    stamps = _stamp_paths()
    assert stamps, "stamp missing — latest.json has no timestamped sibling"
    assert len(stamps) == 1, (
        f"extra stamp(s) — expected exactly one 20*.json, found " f"{[s.name for s in stamps]}"
    )


def test_latest_bytes_match_sole_stamp():
    stamps = _stamp_paths()
    assert LATEST.is_file(), "latest.json missing"
    assert len(stamps) == 1, "need exactly one stamp to compare bytes"
    stamp = stamps[0]
    assert (
        stamp.read_bytes() == LATEST.read_bytes()
    ), f"bytes differ — {LATEST.name} is not byte-identical to {stamp.name}"
