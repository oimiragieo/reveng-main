"""Unit tests for bounded native analyze probe."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.probe_native_analyze_timeout import main, probe_one

PROBE_MOD = Path(__file__).resolve().parents[2] / "scripts" / "probe_native_analyze_timeout.py"


def test_probe_records_completed_when_command_exits_zero(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(binary, ["true"], timeout_s=5.0, now_iso="2026-08-06T00:00:00Z")
    assert out["status"] == "completed"
    assert out["measured"] is True


def test_probe_records_could_not_measure_on_nonzero_exit(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(binary, ["false"], timeout_s=5.0, now_iso="2026-08-06T00:00:00Z")
    assert out["status"] == "could_not_measure"
    assert out["measured"] is True
    assert out["reason"] == "nonzero_exit:1"
    assert out["returncode"] == 1


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


def test_process_missing_binary_exits_two(tmp_path: Path):
    """Process-level: missing binary → OS returncode 2."""
    missing = tmp_path / "missing_bin"
    out_dir = tmp_path / "out"
    proc = subprocess.run(
        [
            sys.executable,
            str(PROBE_MOD),
            "--binary",
            str(missing),
            "--out-dir",
            str(out_dir),
            "--analyze-cmd",
            "true",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2


def test_process_timeout_exits_zero(tmp_path: Path):
    """Process-level: wall timeout is a successful measurement → exit 0."""
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out_dir = tmp_path / "out"
    sleep_cmd = f"{sys.executable} -c 'import time; time.sleep(5)'"
    proc = subprocess.run(
        [
            sys.executable,
            str(PROBE_MOD),
            "--binary",
            str(binary),
            "--out-dir",
            str(out_dir),
            "--timeout-s",
            "0.4",
            "--analyze-cmd",
            sleep_cmd,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0


def test_process_nonzero_analyze_exits_two(tmp_path: Path):
    """Process-level: analyze nonzero → could_not_measure → exit 2."""
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out_dir = tmp_path / "out"
    proc = subprocess.run(
        [
            sys.executable,
            str(PROBE_MOD),
            "--binary",
            str(binary),
            "--out-dir",
            str(out_dir),
            "--analyze-cmd",
            "false",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 2


def test_systemexit_string_exits_one_premise():
    """Premise control: SystemExit with a string exits 1, not 2."""
    try:
        raise SystemExit("2: message")
    except SystemExit as exc:
        assert isinstance(exc.code, str)

    # Process-level confirmation of the premise (not decorative).
    proc = subprocess.run(
        [sys.executable, "-c", "raise SystemExit('2: message')"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1
