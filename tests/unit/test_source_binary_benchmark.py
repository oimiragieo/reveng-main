from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "scripts" / "run_source_binary_benchmark.py"


def _load_module(name: str, path: Path):
    assert path.exists(), f"Expected module at {path}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop(name, None)
    spec.loader.exec_module(module)
    return module


def test_load_benchmark_config_resolves_relative_paths(tmp_path: Path):
    runner = _load_module("test_source_binary_benchmark_config", RUNNER_PATH)
    config_path = tmp_path / "source_binary_benchmarks.json"
    config_path.write_text(
        (
            "{\n"
            '  "benchmarks": [\n'
            "    {\n"
            '      "id": "demo",\n'
            '      "source_repo": "external\\\\demo",\n'
            '      "binary_path": "build\\\\demo.exe",\n'
            '      "output_dir": "reports\\\\demo",\n'
            '      "commands": [{"id": "version", "args": ["--version"]}]\n'
            "    }\n"
            "  ]\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    config = runner.load_benchmark_config(config_path)

    benchmark = config["benchmarks"][0]
    assert Path(benchmark["source_repo"]).is_absolute()
    assert Path(benchmark["binary_path"]).is_absolute()
    assert Path(benchmark["output_dir"]).is_absolute()
    assert benchmark["commands"][0]["timeout"] == 10
    assert benchmark["analyze_ghidra_timeout"] == 900
    assert benchmark["recompile_ghidra_timeout"] == 900


def test_build_reveng_command_uses_module_entry_not_removed_launcher():
    runner = _load_module("test_source_binary_benchmark_entry", RUNNER_PATH)
    analyze_cmd = runner._build_reveng_command(
        subcommand="analyze",
        binary_path=Path("/tmp/sample.bin"),
        output_dir=Path("/tmp/out"),
        ghidra_timeout=120,
    )
    assert analyze_cmd[0] == sys.executable
    assert analyze_cmd[1:3] == ["-m", "reveng"]
    assert "reveng.py" not in " ".join(analyze_cmd)
    assert analyze_cmd.index("--output-dir") < analyze_cmd.index("analyze")

    recompile_cmd = runner._build_reveng_command(
        subcommand="recompile",
        binary_path=Path("/tmp/sample.bin"),
        output_dir=Path("/tmp/out"),
        ghidra_timeout=120,
    )
    assert recompile_cmd.index("recompile") < recompile_cmd.index("--output-dir")
    assert "--ghidra-timeout" in recompile_cmd


def test_normalize_output_strips_ansi_and_normalizes_newlines():
    runner = _load_module("test_source_binary_benchmark_normalize", RUNNER_PATH)

    normalized = runner._normalize_output("\x1b[2Khello\r\nworld  \r\n")

    assert normalized == "hello\nworld"


def test_compare_behavior_results_honors_output_and_exit_code_flags():
    runner = _load_module("test_source_binary_benchmark_compare", RUNNER_PATH)

    comparison = runner._compare_behavior_results(
        {"returncode": 0, "normalized_output": "abc", "timed_out": False},
        {"returncode": 1, "normalized_output": "xyz", "timed_out": False},
        {
            "id": "version",
            "description": "Print version",
            "compare_output": False,
            "compare_exit_code": True,
        },
    )

    assert comparison["matched"] is False
    assert comparison["exit_code_matched"] is False
    assert comparison["output_matched"] is False


def test_rollup_status_reports_analyze_ok_when_recompile_fails_with_report():
    runner = _load_module("test_source_binary_benchmark_rollup_analyze_ok", RUNNER_PATH)

    status = runner._rollup_benchmark_status(
        {
            "analyze_command": {"returncode": 0},
            "recompile_command": {"returncode": 1},
            "analyze_report_exists": True,
            "rebuilt_binary_path": None,
            "original_behavior": [],
            "rebuilt_behavior": [],
            "behavior_comparisons": [],
        }
    )

    assert status == "analyze_ok_recompile_failed"


def test_analyze_report_exists_detects_unified_report(tmp_path: Path):
    runner = _load_module("test_source_binary_benchmark_report_detect", RUNNER_PATH)
    analyze_dir = tmp_path / "analyze"
    reports = analyze_dir / "reports"
    reports.mkdir(parents=True)
    (reports / "unified_analysis_report.json").write_text("{}", encoding="utf-8")
    assert runner._analyze_report_exists(analyze_dir) is True


def test_rollup_status_reports_rebuilt_binary_missing():
    runner = _load_module("test_source_binary_benchmark_rollup", RUNNER_PATH)

    status = runner._rollup_benchmark_status(
        {
            "analyze_command": {"returncode": 0},
            "recompile_command": {"returncode": 0},
            "rebuilt_binary_path": None,
            "original_behavior": [],
            "rebuilt_behavior": [],
            "behavior_comparisons": [],
        }
    )

    assert status == "rebuilt_binary_missing"


def test_run_behavior_case_uses_full_output_for_expectation_checks(monkeypatch: pytest.MonkeyPatch):
    runner = _load_module("test_source_binary_benchmark_behavior", RUNNER_PATH)
    fixture_binary = REPO_ROOT / "test_samples" / "sample.exe"
    expected = "A command-line hex viewer"
    long_stdout = expected + "\n" + ("x" * 5000)

    def fake_run(command, cwd, capture_output, text, timeout, check):
        return SimpleNamespace(returncode=0, stdout=long_stdout.encode("utf-8"), stderr=b"")

    monkeypatch.setattr(runner.subprocess, "run", fake_run)

    result = runner._run_behavior_case(
        fixture_binary,
        {
            "id": "help",
            "args": ["--help"],
            "timeout": 5,
            "expected_exit_code": 0,
            "expected_output_contains": expected,
        },
        {},
    )

    assert result["passed"] is True
    assert result["stdout"].startswith(expected)
    assert result["stdout_tail"] == long_stdout[-4000:]


def test_build_reveng_command_appends_ghidra_timeout():
    runner = _load_module("test_source_binary_benchmark_command", RUNNER_PATH)

    command = runner._build_reveng_command(
        subcommand="recompile",
        binary_path=Path("C:\\demo\\sample.exe"),
        output_dir=Path("C:\\demo\\out"),
        ghidra_timeout=900,
    )

    assert command[-2:] == ["--ghidra-timeout", "900"]
