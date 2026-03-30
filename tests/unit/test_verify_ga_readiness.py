from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "scripts" / "verify_ga_readiness.py"


def _load_module(name: str, path: Path):
    assert path.exists(), f"Expected module at {path}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop(name, None)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: dict) -> Path:
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def test_baseline_profile_passes_with_current_minimum_shapes(tmp_path: Path):
    runner = _load_module("test_verify_ga_readiness_baseline", RUNNER_PATH)
    source_report = _write_json(
        tmp_path / "source.json",
        {
            "benchmark_count": 1,
            "benchmarks": [{"id": "hexyl", "status": "analyze_failed"}],
        },
    )
    bun_report = _write_json(
        tmp_path / "bun.json",
        {
            "matrix_status": "pass_with_limitations",
            "live_bun_sample_count": 1,
            "hard_failure_count": 0,
            "rows": [{"id": "sample-control", "required": True}],
        },
    )
    app_report = _write_json(
        tmp_path / "app.json",
        {
            "summary": {"matrix_status": "pass", "total_entries": 7},
            "rows": [
                {"name": "python-sample-app", "tags": ["smoke", "python", "source"]},
                {"name": "dotnet-sample-app", "tags": ["smoke", "dotnet", "synthetic"]},
            ],
        },
    )
    support_matrix = _write_json(
        tmp_path / "support_matrix.json",
        {
            "workflows": [
                {"id": "app_reverse_engineering", "status": "supported"},
                {"id": "cli_triage", "status": "supported"},
            ]
        },
    )

    readiness = runner.build_readiness_report(
        profile="baseline",
        source_report_path=source_report,
        bun_report_path=bun_report,
        app_report_path=app_report,
        support_matrix_path=support_matrix,
    )

    assert readiness["summary"]["overall_status"] == "pass"
    assert readiness["summary"]["failed_gate_count"] == 0


def test_ga_profile_fails_when_ga_thresholds_are_not_met(tmp_path: Path):
    runner = _load_module("test_verify_ga_readiness_ga_fail", RUNNER_PATH)
    source_report = _write_json(
        tmp_path / "source.json",
        {
            "benchmark_count": 2,
            "benchmarks": [
                {"id": "hexyl", "status": "analyze_failed"},
                {"id": "demo", "status": "completed"},
            ],
        },
    )
    bun_report = _write_json(
        tmp_path / "bun.json",
        {
            "matrix_status": "pass_with_limitations",
            "live_bun_sample_count": 1,
            "hard_failure_count": 0,
            "rows": [{"id": "sample-control", "required": True}],
        },
    )
    app_report = _write_json(
        tmp_path / "app.json",
        {
            "summary": {"matrix_status": "pass", "total_entries": 7},
            "rows": [{"name": "dotnet-sample-app", "tags": ["smoke", "dotnet", "synthetic"]}],
        },
    )
    support_matrix = _write_json(
        tmp_path / "support_matrix.json",
        {
            "workflows": [
                {"id": "app_reverse_engineering", "status": "supported"},
                {"id": "cli_triage", "status": "supported"},
            ]
        },
    )

    readiness = runner.build_readiness_report(
        profile="ga",
        source_report_path=source_report,
        bun_report_path=bun_report,
        app_report_path=app_report,
        support_matrix_path=support_matrix,
    )

    assert readiness["summary"]["overall_status"] == "fail"
    failing_gate_ids = {gate["id"] for gate in readiness["gates"] if gate["status"] == "fail"}
    assert "multi-codebase-validation-breadth" in failing_gate_ids
    assert "bun-live-sample-depth" in failing_gate_ids
    assert "app-corpus-non-synthetic" in failing_gate_ids


def test_ga_profile_fails_when_reports_are_not_generated_from_strict_ga_configs(tmp_path: Path):
    runner = _load_module("test_verify_ga_readiness_ga_config_provenance", RUNNER_PATH)
    source_report = _write_json(
        tmp_path / "source.json",
        {
            "config_path": ".reveng/source_binary_benchmarks.json",
            "benchmark_count": 5,
            "benchmarks": [{"id": "hexyl", "status": "completed"}],
        },
    )
    bun_report = _write_json(
        tmp_path / "bun.json",
        {
            "config_path": ".reveng/bun_sample_matrix.json",
            "matrix_status": "pass",
            "live_bun_sample_count": 2,
            "hard_failure_count": 0,
            "rows": [{"id": "sample-control", "required": True}],
        },
    )
    app_report = _write_json(
        tmp_path / "app.json",
        {
            "config_path": ".reveng/app_reverse_engineering_corpus.json",
            "summary": {"matrix_status": "pass", "total_entries": 7},
            "rows": [
                {"name": "python-sample-app", "tags": ["smoke", "python", "source"]},
                {"name": "dotnet-sample-app", "tags": ["smoke", "dotnet", "release", "managed"]},
            ],
        },
    )
    support_matrix = _write_json(
        tmp_path / "support_matrix.json",
        {
            "workflows": [
                {"id": "app_reverse_engineering", "status": "supported"},
                {"id": "cli_triage", "status": "supported"},
            ]
        },
    )

    readiness = runner.build_readiness_report(
        profile="ga",
        source_report_path=source_report,
        bun_report_path=bun_report,
        app_report_path=app_report,
        support_matrix_path=support_matrix,
    )

    assert readiness["summary"]["overall_status"] == "fail"
    failing_gate_ids = {gate["id"] for gate in readiness["gates"] if gate["status"] == "fail"}
    assert "strict-ga-input-provenance" in failing_gate_ids


def test_main_writes_readiness_report_and_returns_zero_for_baseline(tmp_path: Path):
    runner = _load_module("test_verify_ga_readiness_main", RUNNER_PATH)
    source_report = _write_json(tmp_path / "source.json", {"benchmark_count": 1, "benchmarks": []})
    bun_report = _write_json(
        tmp_path / "bun.json",
        {"matrix_status": "pass_with_limitations", "live_bun_sample_count": 1, "hard_failure_count": 0},
    )
    app_report = _write_json(
        tmp_path / "app.json",
        {"summary": {"matrix_status": "pass", "total_entries": 7}, "rows": []},
    )
    support_matrix = _write_json(
        tmp_path / "support_matrix.json",
        {"workflows": [{"id": "app_reverse_engineering", "status": "supported"}]},
    )
    output_path = tmp_path / "ga_readiness.json"

    exit_code = runner.main(
        [
            "--profile",
            "baseline",
            "--source-report",
            str(source_report),
            "--bun-report",
            str(bun_report),
            "--app-report",
            str(app_report),
            "--support-matrix",
            str(support_matrix),
            "--output",
            str(output_path),
        ]
    )

    assert exit_code == 0
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["result_type"] == "ga_readiness_report"
    assert written["summary"]["overall_status"] == "pass"


def test_baseline_profile_fails_without_supported_workflows(tmp_path: Path):
    runner = _load_module("test_verify_ga_readiness_support_gate", RUNNER_PATH)
    source_report = _write_json(tmp_path / "source.json", {"benchmark_count": 1, "benchmarks": []})
    bun_report = _write_json(
        tmp_path / "bun.json",
        {"matrix_status": "pass_with_limitations", "live_bun_sample_count": 1, "hard_failure_count": 0},
    )
    app_report = _write_json(
        tmp_path / "app.json",
        {"summary": {"matrix_status": "pass", "total_entries": 7}, "rows": []},
    )
    support_matrix = _write_json(tmp_path / "support_matrix.json", {"workflows": []})

    readiness = runner.build_readiness_report(
        profile="baseline",
        source_report_path=source_report,
        bun_report_path=bun_report,
        app_report_path=app_report,
        support_matrix_path=support_matrix,
    )

    assert readiness["summary"]["overall_status"] == "fail"
    failing_gate_ids = {gate["id"] for gate in readiness["gates"] if gate["status"] == "fail"}
    assert "documented-support-surface" in failing_gate_ids
