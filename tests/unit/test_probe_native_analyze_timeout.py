"""Unit tests for bounded native analyze probe."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from scripts.probe_native_analyze_timeout import (
    PROBE_VERSION,
    load_job,
    main,
    probe_one,
    write_report,
)

PROBE_MOD = Path(__file__).resolve().parents[2] / "scripts" / "probe_native_analyze_timeout.py"

# Known semantic field path for native_fallback_empty (see probe module comment).
NATIVE_FALLBACK_EMPTY_PATH = ("native_analysis", "fallback_empty")


def test_probe_version_is_1_2():
    assert PROBE_VERSION == "1.2"


def test_probe_records_completed_when_command_exits_zero(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        ["true"],
        timeout_s=5.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=tmp_path / "out",
        result_id="completed_arm",
    )
    assert out["status"] == "completed"
    assert out["measured"] is True
    assert out["reason"] is None
    assert out["stderr_tail"] is not None or out["stderr_tail"] == ""
    assert "stderr_tail" in out
    assert "stdout_tail" in out
    assert out["semantic"]["process_status"] == "completed"
    assert out["semantic"]["job_output_dir"] is not None


def test_probe_records_could_not_measure_on_nonzero_exit(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        ["false"],
        timeout_s=5.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=tmp_path / "out",
        result_id="nonzero_arm",
    )
    assert out["status"] == "could_not_measure"
    assert out["measured"] is True
    assert out["reason"] == "nonzero_exit:1"
    assert out["returncode"] == 1
    assert out["semantic"]["process_status"] == "could_not_measure"


def test_probe_records_timeout_when_command_exceeds_budget(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout_s=0.5,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=tmp_path / "out",
        result_id="timeout_arm",
    )
    assert out["status"] == "timeout"
    assert out["timeout_budget_s"] == 0.5
    assert out["measured"] is True
    assert out["reason"] == "timeout"
    assert out["semantic"]["process_status"] == "timeout"


def test_probe_records_input_absent_when_binary_missing(tmp_path: Path):
    missing = tmp_path / "nope"
    out = probe_one(missing, ["true"], timeout_s=1.0, now_iso="2026-08-06T00:00:00Z")
    assert out["status"] == "could_not_measure"
    assert out["measured"] is False
    assert out["reason"] == f"input_absent:{missing}"
    assert out["stderr_tail"] is None
    assert out["stdout_tail"] is None
    assert out["semantic"]["process_status"] == "could_not_measure"
    assert out["semantic"]["analysis_report_present"] is None
    assert out["semantic"]["native_fallback_empty"] is None
    assert out["semantic"]["job_output_dir"] is None


def test_probe_reports_tool_absent_when_analyze_executable_missing(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        ["definitely-not-a-real-tool-xyz"],
        timeout_s=5.0,
        now_iso="2026-08-06T00:00:00Z",
    )
    assert out["status"] == "could_not_measure"
    assert out["measured"] is False
    assert out["reason"] == "tool_absent:definitely-not-a-real-tool-xyz"
    assert out["semantic"]["process_status"] == "could_not_measure"


def test_probe_tool_absent_is_distinguishable_from_nonzero_exit(tmp_path: Path):
    """Positive control: a tool that EXISTS and fails must not read as absent."""
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    present = probe_one(
        binary,
        [sys.executable, "-c", "raise SystemExit(1)"],
        timeout_s=10.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=tmp_path / "out",
        result_id="present_fail",
    )
    assert present["reason"] == "nonzero_exit:1"
    assert present["measured"] is True


def test_probe_hexyl_style_tool_absent_with_present_binary(tmp_path: Path):
    """Hexyl arm: present subject + missing analyze tool → tool_absent, not input_absent."""
    binary = tmp_path / "hello_go"
    binary.write_bytes(b"\x7fELF")
    out = probe_one(
        binary,
        ["hexyl"],
        timeout_s=30.0,
        now_iso="2026-08-06T00:00:00Z",
    )
    assert out["reason"] == "tool_absent:hexyl"
    assert not (out["reason"] or "").startswith("input_absent:")


def test_probe_records_os_error_reason(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    # Existing non-executable file → not tool_absent; spawn raises OSError/PermissionError.
    bad_exe = tmp_path / "not_executable"
    bad_exe.write_bytes(b"\x7fELF")
    bad_exe.chmod(0o644)
    out = probe_one(
        binary,
        [str(bad_exe)],
        timeout_s=5.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=tmp_path / "out",
        result_id="os_err",
    )
    assert out["status"] == "could_not_measure"
    assert out["measured"] is False
    assert (out["reason"] or "").startswith("os_error:")
    assert out["semantic"]["process_status"] == "could_not_measure"


def test_probe_captures_stderr_and_stdout_tails_on_nonzero_exit(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        [
            sys.executable,
            "-c",
            "import sys; sys.stdout.write('OUT-marker\\n'); "
            "sys.stderr.write('BOOM-marker\\n'); raise SystemExit(1)",
        ],
        timeout_s=10.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=tmp_path / "out",
        result_id="tails",
    )
    assert out["status"] == "could_not_measure"
    assert "BOOM-marker" in (out["stderr_tail"] or "")
    assert "OUT-marker" in (out["stdout_tail"] or "")


def test_probe_tails_bounded_to_2000(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out = probe_one(
        binary,
        [
            sys.executable,
            "-c",
            "import sys; sys.stderr.write('z' * 50000); sys.stdout.write('y' * 50000); "
            "raise SystemExit(3)",
        ],
        timeout_s=10.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=tmp_path / "out",
        result_id="bound",
    )
    assert len(out["stderr_tail"]) == 2000
    assert len(out["stdout_tail"]) == 2000


def test_probe_sanitizes_secrets_before_truncate(tmp_path: Path):
    """
    Truncate-first would keep a long secret line's tail (no key= prefix left);
    sanitize-first must strip the whole line so SECRET payload cannot leak.
    """
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    # One line matching the secret regex, longer than the 2000-char tail budget.
    secret_payload = "S" * 3000
    code = (
        "import sys; "
        f"sys.stderr.write('api_key={secret_payload}\\n'); "
        "sys.stdout.write('token=LEAKME\\n'); "
        "raise SystemExit(1)"
    )
    out = probe_one(
        binary,
        [sys.executable, "-c", code],
        timeout_s=10.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=tmp_path / "out",
        result_id="sanitize",
    )
    assert "SECRET" not in (out["stderr_tail"] or "")
    assert secret_payload[:50] not in (out["stderr_tail"] or "")
    assert "LEAKME" not in (out["stdout_tail"] or "")
    assert "api_key" not in (out["stderr_tail"] or "").lower()
    assert "token=" not in (out["stdout_tail"] or "").lower()


def test_probe_semantic_from_new_nested_json(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out_dir = tmp_path / "out"
    result_id = "nested_json"
    # Writer creates nested JSON under the probe-assigned job_output_dir via env.
    writer = (
        "import json, os, pathlib, sys; "
        "d = pathlib.Path(os.environ['REVENG_PROBE_OUT']); "
        "(d / 'nested').mkdir(parents=True); "
        "payload = {'native_analysis': {'fallback_empty': True}, 'ok': 1}; "
        "(d / 'nested' / 'report.json').write_text(json.dumps(payload)); "
        "sys.exit(0)"
    )
    out = probe_one(
        binary,
        [sys.executable, "-c", writer],
        timeout_s=10.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=out_dir,
        result_id=result_id,
    )
    assert out["status"] == "completed"
    sem = out["semantic"]
    assert sem["analysis_report_present"] is True
    assert sem["native_fallback_empty"] is True
    assert sem["job_output_dir"] is not None
    assert Path(sem["job_output_dir"]).is_dir()
    # Stale pre-existing JSON must not count.
    assert NATIVE_FALLBACK_EMPTY_PATH[0] in ("native_analysis",)


def test_probe_ignores_stale_preexisting_json(tmp_path: Path):
    binary = tmp_path / "bin"
    binary.write_bytes(b"x")
    out_dir = tmp_path / "out"
    result_id = "stale"
    # Create job dir early with stale JSON; probe must recreate empty or only count new files.
    stale_dir = out_dir / "runs" / result_id
    stale_dir.mkdir(parents=True)
    (stale_dir / "old.json").write_text('{"native_analysis": {"fallback_empty": false}}')
    out = probe_one(
        binary,
        ["true"],
        timeout_s=5.0,
        now_iso="2026-08-06T00:00:00Z",
        out_dir=out_dir,
        result_id=result_id,
    )
    # Fresh empty dir before spawn → no new JSON from `true`.
    assert out["semantic"]["analysis_report_present"] is False
    assert out["semantic"]["native_fallback_empty"] is None


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

    proc = subprocess.run(
        [sys.executable, "-c", "raise SystemExit('2: message')"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 1


def test_job_and_binary_are_mutually_exclusive(tmp_path: Path):
    job = tmp_path / "job.json"
    job.write_text(
        json.dumps(
            {
                "version": 1,
                "results": [
                    {
                        "id": "a",
                        "binary": str(tmp_path / "b"),
                        "analyze_cmd": "true",
                        "timeout_s": 1,
                    }
                ],
            }
        )
    )
    try:
        main(["--job", str(job), "--binary", str(tmp_path / "b"), "--out-dir", str(tmp_path / "o")])
        raised = None
    except SystemExit as exc:
        raised = exc
    assert raised is not None
    assert raised.code == 2


def test_load_job_rejects_duplicate_ids(tmp_path: Path):
    job = tmp_path / "job.json"
    job.write_text(
        json.dumps(
            {
                "version": 1,
                "results": [
                    {
                        "id": "same",
                        "binary": str(tmp_path / "b"),
                        "analyze_cmd": "true",
                        "timeout_s": 1,
                    },
                    {
                        "id": "same",
                        "binary": str(tmp_path / "b2"),
                        "analyze_cmd": "true",
                        "timeout_s": 1,
                    },
                ],
            }
        )
    )
    try:
        load_job(job)
        raised = None
    except SystemExit as exc:
        raised = exc
    assert raised is not None
    assert raised.code == 2


def test_load_job_rejects_unsafe_id(tmp_path: Path):
    job = tmp_path / "job.json"
    job.write_text(
        json.dumps(
            {
                "version": 1,
                "results": [
                    {
                        "id": "../escape",
                        "binary": str(tmp_path / "b"),
                        "analyze_cmd": "true",
                        "timeout_s": 1,
                    }
                ],
            }
        )
    )
    try:
        load_job(job)
        raised = None
    except (SystemExit, ValueError) as exc:
        raised = exc
    assert raised is not None


def test_load_job_accepts_valid_schema(tmp_path: Path):
    binary = tmp_path / "hello_go"
    binary.write_bytes(b"x")
    job = tmp_path / "wave_a_job.json"
    job.write_text(
        json.dumps(
            {
                "version": 1,
                "results": [
                    {
                        "id": "hello_go_analyze",
                        "binary": str(binary),
                        "analyze_cmd": "true",
                        "timeout_s": 120,
                    },
                    {
                        "id": "hexyl_tool_absent",
                        "binary": str(binary),
                        "analyze_cmd": "hexyl",
                        "timeout_s": 30,
                    },
                ],
            }
        )
    )
    entries = load_job(job)
    assert len(entries) == 2
    assert entries[0]["id"] == "hello_go_analyze"


def test_main_job_runs_multiple_results(tmp_path: Path):
    binary = tmp_path / "hello_go"
    binary.write_bytes(b"x")
    out_dir = tmp_path / "probe_out"
    job = tmp_path / "wave_a_job.json"
    job.write_text(
        json.dumps(
            {
                "version": 1,
                "results": [
                    {
                        "id": "hello_go_analyze",
                        "binary": str(binary),
                        "analyze_cmd": "true",
                        "timeout_s": 5,
                    },
                    {
                        "id": "hexyl_tool_absent",
                        "binary": str(binary),
                        "analyze_cmd": "hexyl",
                        "timeout_s": 5,
                    },
                ],
            }
        )
    )
    try:
        code = main(["--job", str(job), "--out-dir", str(out_dir)])
    except SystemExit as exc:
        code = exc.code
    # hexyl tool_absent → could_not_measure → exit 2
    assert code == 2
    latest = json.loads((out_dir / "latest.json").read_text(encoding="utf-8"))
    assert latest["probe_version"] == "1.2"
    assert len(latest["results"]) == 2
    reasons = {r["id"]: r["reason"] for r in latest["results"] if "id" in r}
    # Results may carry id at top level from job; also check reasons list.
    all_reasons = [r.get("reason") for r in latest["results"]]
    assert any(r == "tool_absent:hexyl" for r in all_reasons)
    assert any(r is None for r in all_reasons)  # completed true arm


def test_write_report_exactly_one_stamp_and_latest(tmp_path: Path):
    out_dir = tmp_path / "reports"
    out_dir.mkdir()
    (out_dir / "README.md").write_text("keep\n")
    (out_dir / "wave_a_job.json").write_text("{}\n")
    (out_dir / "runs").mkdir()
    # Orphan stamps from prior runs
    (out_dir / "2026-08-06T035133Z.json").write_text("{}\n")
    (out_dir / "2026-08-06T131213Z.json").write_text("{}\n")

    results = [{"status": "completed", "probe_version": "1.2"}]
    latest = write_report(results, out_dir, "2026-08-06T15:00:00Z")
    assert latest.name == "latest.json"
    stamps = sorted(out_dir.glob("20*.json"))
    assert len(stamps) == 1
    assert stamps[0].name == "2026-08-06T150000Z.json"
    assert latest.read_text(encoding="utf-8") == stamps[0].read_text(encoding="utf-8")
    assert (out_dir / "README.md").is_file()
    assert (out_dir / "wave_a_job.json").is_file()
    assert (out_dir / "runs").is_dir()


def test_write_report_payload_probe_version_1_2(tmp_path: Path):
    out_dir = tmp_path / "out"
    write_report([{"status": "timeout"}], out_dir, "2026-08-06T00:00:00Z")
    payload = json.loads((out_dir / "latest.json").read_text(encoding="utf-8"))
    assert payload["probe_version"] == "1.2"


def test_safe_id_pattern():
    from scripts.probe_native_analyze_timeout import SAFE_RESULT_ID

    assert re.fullmatch(SAFE_RESULT_ID, "hello_go_analyze")
    assert re.fullmatch(SAFE_RESULT_ID, "hexyl_tool_absent")
    assert re.fullmatch(SAFE_RESULT_ID, "../x") is None
    assert re.fullmatch(SAFE_RESULT_ID, "a/b") is None
