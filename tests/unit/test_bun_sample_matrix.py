from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "scripts" / "run_bun_sample_matrix.py"


def _load_module(name: str, path: Path):
    assert path.exists(), f"Expected module at {path}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop(name, None)
    spec.loader.exec_module(module)
    return module


def test_load_matrix_config_resolves_relative_paths(tmp_path: Path):
    runner = _load_module("test_bun_sample_matrix_config", RUNNER_PATH)
    config_path = tmp_path / "bun_sample_matrix.json"
    config_path.write_text(
        (
            "{\n"
            '  "min_live_bun_samples_for_pass": 3,\n'
            '  "samples": [\n'
            '    {"id": "control", "path": "test_samples\\\\sample.exe", "kind": "negative_control"}\n'
            "  ]\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    config = runner.load_matrix_config(config_path)

    assert config["min_live_bun_samples_for_pass"] == 3
    assert Path(config["samples"][0]["path"]).as_posix().endswith("test_samples/sample.exe")
    assert Path(config["samples"][0]["path"]).is_absolute()


def test_rollup_matrix_status_reports_pass_with_limitations():
    runner = _load_module("test_bun_sample_matrix_rollup_limits", RUNNER_PATH)

    rollup = runner._rollup_matrix_status(
        [
            {
                "kind": "bun_live_sample",
                "row_status": "completed",
                "rebuild_report": {"verification": {"status": "pass"}},
            },
            {
                "kind": "negative_control",
                "row_status": "completed",
            },
        ],
        min_live_bun_samples_for_pass=2,
    )

    assert rollup["matrix_status"] == "pass_with_limitations"
    assert rollup["live_bun_sample_count"] == 1
    assert rollup["successful_rebuild_count"] == 1
    assert rollup["hard_failure_count"] == 0


def test_rollup_matrix_status_counts_pass_with_warnings_as_success():
    runner = _load_module("test_bun_sample_matrix_rollup_warnings", RUNNER_PATH)

    rollup = runner._rollup_matrix_status(
        [
            {
                "kind": "bun_live_sample",
                "row_status": "completed",
                "rebuild_report": {"verification": {"status": "pass_with_warnings"}},
            }
        ],
        min_live_bun_samples_for_pass=2,
    )

    assert rollup["matrix_status"] == "pass_with_limitations"
    assert rollup["successful_rebuild_count"] == 1


def test_rollup_matrix_status_reports_fail_for_required_sample_failure():
    runner = _load_module("test_bun_sample_matrix_rollup_fail", RUNNER_PATH)

    rollup = runner._rollup_matrix_status(
        [
            {
                "kind": "bun_live_sample",
                "row_status": "missing_required_sample",
                "rebuild_report": {"verification": {"status": None}},
            }
        ],
        min_live_bun_samples_for_pass=1,
    )

    assert rollup["matrix_status"] == "fail"
    assert rollup["hard_failure_count"] == 1


def test_evaluate_expectations_checks_rebuild_equivalence_level():
    runner = _load_module("test_bun_sample_matrix_expectations", RUNNER_PATH)
    row = {
        "detection": {"is_bun_executable": True},
        "analyze_report": {"route": "bun", "recovery_mode": "module_graph"},
        "rebuild_report": {
            "route": "bun_node_sea",
            "verification": {"status": "pass"},
            "differential_validation": {"status": "pass"},
            "equivalence_validation": {"equivalence_level": "semantic_candidate"},
        },
    }

    result = runner._evaluate_expectations(
        row,
        {
            "detection": {"is_bun_executable": True},
            "analyze": {"route": "bun", "recovery_mode": "module_graph"},
            "rebuild": {
                "route": "bun_node_sea",
                "verification_status": "pass",
                "differential_status": "pass",
                "equivalence_level": "semantic_candidate",
            },
        },
    )

    assert result["passed"] is True
    assert result["failures"] == []


def test_evaluate_expectations_checks_smoke_parity():
    runner = _load_module("test_bun_sample_matrix_smoke", RUNNER_PATH)
    row = {
        "smoke_validation": {
            "original": {"valid": True},
            "rebuilt": {"valid": True},
            "parity": {"matched": True},
        }
    }

    result = runner._evaluate_expectations(
        row,
        {
            "smoke": {
                "original_valid": True,
                "rebuilt_valid": True,
                "parity_matched": True,
            }
        },
    )

    assert result["passed"] is True
    assert result["failures"] == []


def test_evaluate_expectations_handles_missing_nested_rebuild_sections():
    runner = _load_module("test_bun_sample_matrix_missing_nested_sections", RUNNER_PATH)
    row = {
        "rebuild_report": {
            "route": "bun_node_sea",
            "verification": None,
            "differential_validation": None,
            "equivalence_validation": None,
        }
    }

    result = runner._evaluate_expectations(
        row,
        {
            "rebuild": {
                "route": "bun_node_sea",
                "verification_status": "pass_with_warnings",
                "differential_status": "pass",
                "equivalence_level": "structural_candidate",
            }
        },
    )

    assert result["passed"] is False
    assert "rebuild.verification_status" in result["failures"][0]


def test_normalize_smoke_output_strips_ansi_and_normalizes_newlines():
    runner = _load_module("test_bun_sample_matrix_output_normalization", RUNNER_PATH)

    normalized = runner._normalize_smoke_output("\x1b[2Khello\r\nworld  \r\n")

    assert normalized == "hello\nworld"


def test_run_smoke_test_captures_timeout_output_and_marks_timeout(tmp_path: Path):
    runner = _load_module("test_bun_sample_matrix_timeout_capture", RUNNER_PATH)
    binary_path = tmp_path / "sample.exe"
    binary_path.write_bytes(b"stub")
    smoke_test = runner.SmokeTest(args=[], timeout=1, description="timeout case")

    timeout = subprocess.TimeoutExpired(
        cmd=[str(binary_path)],
        timeout=1,
        output=b"\x1b[2Kloading\r\n",
        stderr=b"still running\r\n",
    )
    with patch.object(runner.subprocess, "run", side_effect=timeout):
        result = runner._run_smoke_test(binary_path, smoke_test)

    assert result["passed"] is False
    assert result["timed_out"] is True
    assert result["error"] == "Timeout after 1s"
    assert result["output"] == "\x1b[2Kloading\r\nstill running\r\n"
    assert result["normalized_output"] == "loading\nstill running"


def test_build_smoke_parity_requires_output_and_timeout_match():
    runner = _load_module("test_bun_sample_matrix_parity_details", RUNNER_PATH)

    parity = runner._build_smoke_parity(
        {
            "test_results": [
                {
                    "description": "help",
                    "args": ["--help"],
                    "passed": True,
                    "exit_code": 0,
                    "timed_out": False,
                    "normalized_output": "usage text",
                    "error": None,
                }
            ]
        },
        {
            "test_results": [
                {
                    "description": "help",
                    "args": ["--help"],
                    "passed": True,
                    "exit_code": 0,
                    "timed_out": False,
                    "normalized_output": "different usage text",
                    "error": None,
                }
            ]
        },
    )

    assert parity["matched"] is False
    assert parity["comparisons"][0]["output_matched"] is False
    assert parity["comparisons"][0]["matched"] is False
