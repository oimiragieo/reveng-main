from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASELINE_REPORT = REPO_ROOT / "reports" / "ga_readiness_baseline.json"
DEFAULT_GA_REPORT = REPO_ROOT / "reports" / "ga_readiness_target.json"
DEFAULT_APP_REPORT = REPO_ROOT / "reports" / "app_reverse_engineering_corpus_report.json"
DEFAULT_SOURCE_REPORT = REPO_ROOT / "reports" / "source_binary_benchmarks_report.json"
DEFAULT_BUN_REPORT = REPO_ROOT / "reports" / "bun_sample_matrix.json"
DEFAULT_SUPPORT_MATRIX = REPO_ROOT / "docs" / "support_matrix.json"
DEFAULT_SKIP_INVENTORY = REPO_ROOT / "reports" / "skip_inventory.json"
DEFAULT_JSON_OUTPUT = REPO_ROOT / "reports" / "release_report.json"
DEFAULT_MARKDOWN_OUTPUT = REPO_ROOT / "reports" / "release_report.md"
VERSION_FILE = REPO_ROOT / "VERSION"
SCHEMA_VERSION = "1.0"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_version() -> str:
    version_file = REPO_ROOT / "VERSION"
    if version_file.exists():
        return version_file.read_text(encoding="utf-8").strip()
    return "unknown"


def _repo_path(value: str | Path) -> Path:
    path = value if isinstance(value, Path) else Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


def _supported_workflows(support_matrix: dict[str, Any]) -> list[dict[str, Any]]:
    return [workflow for workflow in support_matrix.get("workflows", []) if workflow.get("status") == "supported"]


def _failing_gate_ids(report: dict[str, Any]) -> list[str]:
    return [gate.get("id", "unknown") for gate in report.get("gates", []) if gate.get("status") == "fail"]


def build_release_report(
    *,
    baseline_report_path: Path = DEFAULT_BASELINE_REPORT,
    ga_report_path: Path = DEFAULT_GA_REPORT,
    app_report_path: Path = DEFAULT_APP_REPORT,
    source_report_path: Path = DEFAULT_SOURCE_REPORT,
    bun_report_path: Path = DEFAULT_BUN_REPORT,
    support_matrix_path: Path = DEFAULT_SUPPORT_MATRIX,
    skip_inventory_path: Path = DEFAULT_SKIP_INVENTORY,
) -> dict[str, Any]:
    baseline = _load_json(baseline_report_path)
    strict_ga = _load_json(ga_report_path)
    app_report = _load_json(app_report_path)
    source_report = _load_json(source_report_path)
    bun_report = _load_json(bun_report_path)
    support_matrix = _load_json(support_matrix_path)
    skip_inventory = _load_json(skip_inventory_path)

    baseline_status = baseline.get("summary", {}).get("overall_status", "unknown")
    strict_ga_status = strict_ga.get("summary", {}).get("overall_status", "unknown")
    blocking_gate_ids = _failing_gate_ids(strict_ga)
    ship_status = "ready" if baseline_status == "pass" and strict_ga_status == "pass" else "not_ready"

    supported = _supported_workflows(support_matrix)
    source_failed = {
        benchmark.get("id", "unknown"): benchmark.get("status", "unknown")
        for benchmark in source_report.get("benchmarks", [])
        if str(benchmark.get("status", "")).endswith("failed")
    }

    return {
        "schema_version": SCHEMA_VERSION,
        "result_type": "release_report",
        "generated_at": _utc_now(),
        "version": _load_version(),
        "summary": {
            "ship_status": ship_status,
            "baseline_readiness": baseline_status,
            "strict_ga_readiness": strict_ga_status,
            "blocking_gate_ids": blocking_gate_ids,
        },
        "support": {
            "supported_workflow_count": len(supported),
            "supported_workflows": [
                {"id": workflow.get("id"), "status": workflow.get("status")} for workflow in supported
            ],
        },
        "test_policy": {
            "skip_inventory": {
                "total_skip_sites": int(skip_inventory.get("summary", {}).get("total_skip_sites", 0)),
                "by_category": dict(skip_inventory.get("summary", {}).get("by_category", {})),
            }
        },
        "validation": {
            "app_corpus": {
                "matrix_status": app_report.get("summary", {}).get("matrix_status", "unknown"),
                "total_entries": int(app_report.get("summary", {}).get("total_entries", 0)),
                "config_path": app_report.get("config_path"),
            },
            "source_benchmarks": {
                "benchmark_count": int(source_report.get("benchmark_count", 0)),
                "config_path": source_report.get("config_path"),
                "failed_statuses": source_failed,
            },
            "bun_matrix": {
                "matrix_status": bun_report.get("matrix_status", "unknown"),
                "live_bun_sample_count": int(bun_report.get("live_bun_sample_count", 0)),
                "hard_failure_count": int(bun_report.get("hard_failure_count", 0)),
                "config_path": bun_report.get("config_path"),
            },
        },
        "inputs": {
            "baseline_report": str(baseline_report_path),
            "ga_report": str(ga_report_path),
            "app_report": str(app_report_path),
            "source_report": str(source_report_path),
            "bun_report": str(bun_report_path),
            "support_matrix": str(support_matrix_path),
            "skip_inventory": str(skip_inventory_path),
        },
    }


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    support = report["support"]
    validation = report["validation"]
    test_policy = report["test_policy"]
    lines = [
        "# REVENG Release Report",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Version: `{report['version']}`",
        f"- Ship status: `{summary['ship_status']}`",
        f"- Baseline readiness: `{summary['baseline_readiness']}`",
        f"- Strict GA readiness: `{summary['strict_ga_readiness']}`",
        f"- Supported workflows: `{support['supported_workflow_count']}`",
        f"- Skip-lane sites: `{test_policy['skip_inventory']['total_skip_sites']}`",
        "",
        "## Validation",
        "",
        f"- App corpus: `{validation['app_corpus']['matrix_status']}` across `{validation['app_corpus']['total_entries']}` entries",
        f"- Source benchmarks: `{validation['source_benchmarks']['benchmark_count']}` tracked rows",
        f"- Bun matrix: `{validation['bun_matrix']['matrix_status']}` with `{validation['bun_matrix']['live_bun_sample_count']}` live samples",
    ]
    blocking_gate_ids = summary.get("blocking_gate_ids", [])
    if blocking_gate_ids:
        lines.extend(["", "## Blocking Gates", ""])
        lines.extend([f"- `{gate_id}`" for gate_id in blocking_gate_ids])
    return "\n".join(lines) + "\n"


def write_release_report(
    report: dict[str, Any],
    *,
    json_output_path: Path = DEFAULT_JSON_OUTPUT,
    markdown_output_path: Path = DEFAULT_MARKDOWN_OUTPUT,
) -> None:
    json_output_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_output_path.parent.mkdir(parents=True, exist_ok=True)
    json_output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_output_path.write_text(_render_markdown(report), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate a machine-readable and Markdown release report.")
    parser.add_argument("--baseline-report", default=str(DEFAULT_BASELINE_REPORT))
    parser.add_argument("--ga-report", default=str(DEFAULT_GA_REPORT))
    parser.add_argument("--app-report", default=str(DEFAULT_APP_REPORT))
    parser.add_argument("--source-report", default=str(DEFAULT_SOURCE_REPORT))
    parser.add_argument("--bun-report", default=str(DEFAULT_BUN_REPORT))
    parser.add_argument("--support-matrix", default=str(DEFAULT_SUPPORT_MATRIX))
    parser.add_argument("--skip-inventory", default=str(DEFAULT_SKIP_INVENTORY))
    parser.add_argument("--json-output", default=str(DEFAULT_JSON_OUTPUT))
    parser.add_argument("--markdown-output", default=str(DEFAULT_MARKDOWN_OUTPUT))
    args = parser.parse_args(argv)

    report = build_release_report(
        baseline_report_path=_repo_path(args.baseline_report),
        ga_report_path=_repo_path(args.ga_report),
        app_report_path=_repo_path(args.app_report),
        source_report_path=_repo_path(args.source_report),
        bun_report_path=_repo_path(args.bun_report),
        support_matrix_path=_repo_path(args.support_matrix),
        skip_inventory_path=_repo_path(args.skip_inventory),
    )
    write_release_report(
        report,
        json_output_path=_repo_path(args.json_output),
        markdown_output_path=_repo_path(args.markdown_output),
    )

    print(f"Ship status: {report['summary']['ship_status']}")
    print(f"Baseline readiness: {report['summary']['baseline_readiness']}")
    print(f"Strict GA readiness: {report['summary']['strict_ga_readiness']}")
    print(f"JSON report: {args.json_output}")
    print(f"Markdown report: {args.markdown_output}")
    return 0 if report["summary"]["ship_status"] == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
