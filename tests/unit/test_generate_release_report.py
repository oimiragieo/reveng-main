from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RUNNER_PATH = REPO_ROOT / "scripts" / "generate_release_report.py"


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


def test_generate_release_report_writes_json_and_markdown(tmp_path: Path):
    runner = _load_module("test_generate_release_report", RUNNER_PATH)

    baseline = _write_json(
        tmp_path / "baseline.json",
        {
            "summary": {"overall_status": "pass", "failed_gate_count": 0},
            "gates": [],
        },
    )
    strict_ga = _write_json(
        tmp_path / "ga.json",
        {
            "summary": {"overall_status": "pass", "failed_gate_count": 0},
            "gates": [],
        },
    )
    app_report = _write_json(
        tmp_path / "app.json",
        {
            "summary": {"matrix_status": "pass", "total_entries": 7},
        },
    )
    source_report = _write_json(
        tmp_path / "source.json",
        {
            "benchmark_count": 5,
            "benchmarks": [
                {"id": "hexyl", "status": "completed"},
                {"id": "winsw", "status": "completed"},
            ],
        },
    )
    bun_report = _write_json(
        tmp_path / "bun.json",
        {
            "matrix_status": "pass",
            "live_bun_sample_count": 2,
            "hard_failure_count": 0,
        },
    )
    support_matrix = _write_json(
        tmp_path / "support_matrix.json",
        {
            "workflows": [
                {"id": "cli_triage", "status": "supported"},
                {"id": "app_reverse_engineering", "status": "supported"},
                {"id": "native_analysis", "status": "limited"},
            ]
        },
    )
    skip_inventory = _write_json(
        tmp_path / "skip_inventory.json",
        {
            "summary": {
                "total_skip_sites": 3,
                "by_category": {"external_tooling": 2, "service_environment": 1},
            }
        },
    )
    output_json = tmp_path / "release_report.json"
    output_md = tmp_path / "release_report.md"

    report = runner.build_release_report(
        baseline_report_path=baseline,
        ga_report_path=strict_ga,
        app_report_path=app_report,
        source_report_path=source_report,
        bun_report_path=bun_report,
        support_matrix_path=support_matrix,
        skip_inventory_path=skip_inventory,
    )
    runner.write_release_report(
        report, json_output_path=output_json, markdown_output_path=output_md
    )

    written_json = json.loads(output_json.read_text(encoding="utf-8"))
    written_markdown = output_md.read_text(encoding="utf-8")

    assert written_json["summary"]["ship_status"] == "ready"
    assert written_json["support"]["supported_workflow_count"] == 2
    assert written_json["test_policy"]["skip_inventory"]["total_skip_sites"] == 3
    assert written_json["validation"]["app_corpus"]["total_entries"] == 7
    assert "REVENG Release Report" in written_markdown
    assert "Strict GA readiness: `pass`" in written_markdown
    assert "Supported workflows: `2`" in written_markdown
    assert "Skip-lane sites: `3`" in written_markdown


def test_generate_release_report_marks_not_ready_when_strict_ga_fails(tmp_path: Path):
    runner = _load_module("test_generate_release_report_not_ready", RUNNER_PATH)

    baseline = _write_json(
        tmp_path / "baseline.json",
        {
            "summary": {"overall_status": "pass", "failed_gate_count": 0},
            "gates": [],
        },
    )
    strict_ga = _write_json(
        tmp_path / "ga.json",
        {
            "summary": {"overall_status": "fail", "failed_gate_count": 2},
            "gates": [
                {"id": "strict-ga-input-provenance", "status": "fail"},
                {"id": "app-corpus-non-synthetic", "status": "fail"},
            ],
        },
    )
    app_report = _write_json(
        tmp_path / "app.json", {"summary": {"matrix_status": "pass", "total_entries": 7}}
    )
    source_report = _write_json(tmp_path / "source.json", {"benchmark_count": 5, "benchmarks": []})
    bun_report = _write_json(
        tmp_path / "bun.json",
        {"matrix_status": "pass", "live_bun_sample_count": 2, "hard_failure_count": 0},
    )
    support_matrix = _write_json(
        tmp_path / "support_matrix.json",
        {"workflows": [{"id": "app_reverse_engineering", "status": "supported"}]},
    )
    skip_inventory = _write_json(
        tmp_path / "skip_inventory.json",
        {"summary": {"total_skip_sites": 1, "by_category": {"known_gap": 1}}},
    )

    report = runner.build_release_report(
        baseline_report_path=baseline,
        ga_report_path=strict_ga,
        app_report_path=app_report,
        source_report_path=source_report,
        bun_report_path=bun_report,
        support_matrix_path=support_matrix,
        skip_inventory_path=skip_inventory,
    )

    assert report["summary"]["ship_status"] == "not_ready"
    assert report["summary"]["blocking_gate_ids"] == [
        "strict-ga-input-provenance",
        "app-corpus-non-synthetic",
    ]


def test_generate_release_report_main_resolves_relative_paths_from_repo_root(tmp_path: Path):
    runner = _load_module("test_generate_release_report_relative_paths", RUNNER_PATH)
    runner.REPO_ROOT = tmp_path

    reports_dir = tmp_path / "reports"
    docs_dir = tmp_path / "docs"
    reports_dir.mkdir()
    docs_dir.mkdir()
    (tmp_path / "VERSION").write_text("9.9.9", encoding="utf-8")

    _write_json(
        reports_dir / "ga_readiness_baseline.json",
        {"summary": {"overall_status": "pass"}, "gates": []},
    )
    _write_json(
        reports_dir / "ga_readiness_target.json",
        {"summary": {"overall_status": "pass"}, "gates": []},
    )
    _write_json(
        reports_dir / "app_reverse_engineering_corpus_report.json",
        {"summary": {"matrix_status": "pass", "total_entries": 7}},
    )
    _write_json(
        reports_dir / "source_binary_benchmarks_report.json",
        {"benchmark_count": 5, "benchmarks": []},
    )
    _write_json(
        reports_dir / "bun_sample_matrix.json",
        {"matrix_status": "pass", "live_bun_sample_count": 2, "hard_failure_count": 0},
    )
    _write_json(
        reports_dir / "skip_inventory.json",
        {"summary": {"total_skip_sites": 4, "by_category": {"external_tooling": 4}}},
    )
    _write_json(
        docs_dir / "support_matrix.json",
        {"workflows": [{"id": "app_reverse_engineering", "status": "supported"}]},
    )

    json_output = "reports/release_report.json"
    markdown_output = "reports/release_report.md"
    exit_code = runner.main(["--json-output", json_output, "--markdown-output", markdown_output])

    assert exit_code == 0
    assert (reports_dir / "release_report.json").exists()
    assert (reports_dir / "release_report.md").exists()
