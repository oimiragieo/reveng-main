"""Unit tests for bounded native analyze probe."""

from __future__ import annotations

import sys
from pathlib import Path

from scripts.probe_native_analyze_timeout import main, probe_one


def test_probe_records_completed_when_command_exits_zero(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(binary, ["true"], timeout_s=5.0, now_iso="2026-08-06T00:00:00Z")
    assert out["status"] == "completed"
    assert out["measured"] is True


def test_probe_records_timeout_when_command_exceeds_budget(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_s=0.5,
        now_iso="2026-08-06T00:00:00Z",
    )
    assert out["status"] == "timeout"
    assert out["timeout_budget_s"] == 0.5
    assert out["measured"] is True


def test_probe_records_could_not_measure_when_binary_absent(tmp_path: Path):
    missing = tmp_path / "nope"
    out = probe_one(missing, ["true"], timeout_s=1.0, now_iso="2026-08-06T00:00:00Z")
    assert out["status"] == "could_not_measure"
    assert out["measured"] is False
    assert str(missing) in (out["reason"] or "")


def test_could_not_measure_exits_two(tmp_path: Path):
    missing = tmp_path / "missing_bin"
    try:
        main(
            ["--binary", str(missing), "--out-dir", str(tmp_path / "out"), "--analyze-cmd", "true"]
        )
        raised = None
    except SystemExit as exc:
        raised = exc
    assert raised is not None
    assert raised.code == 2


def test_systemexit_string_exits_one_premise():
    """Premise control: SystemExit with a string exits 1, not 2."""
    try:
        raise SystemExit("2: message")
    except SystemExit as exc:
        # Calling code that treats string as exit code is wrong; document premise.
        assert isinstance(exc.code, str)
