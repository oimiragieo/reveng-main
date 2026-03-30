from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE_REPORT = REPO_ROOT / "reports" / "source_binary_benchmarks_report.json"
DEFAULT_BUN_REPORT = REPO_ROOT / "reports" / "bun_sample_matrix.json"
DEFAULT_APP_REPORT = REPO_ROOT / "reports" / "app_reverse_engineering_corpus_report.json"
DEFAULT_SUPPORT_MATRIX = REPO_ROOT / "docs" / "support_matrix.json"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "ga_readiness_report.json"
SCHEMA_VERSION = "1.0"
STRICT_GA_CONFIGS = {
    "source_report": ".reveng/source_binary_benchmarks.ga.json",
    "bun_report": ".reveng/bun_sample_matrix.ga.json",
    "app_report": ".reveng/app_reverse_engineering_corpus.ga.json",
}


@dataclass(frozen=True)
class GateResult:
    id: str
    status: str
    summary: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status,
            "summary": self.summary,
            "details": self.details,
        }


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _tags_from_rows(rows: Iterable[dict[str, Any]]) -> set[str]:
    tags: set[str] = set()
    for row in rows:
        for tag in row.get("tags", []):
            if isinstance(tag, str):
                tags.add(tag)
    return tags


def _has_synthetic_rows(rows: Iterable[dict[str, Any]]) -> bool:
    for row in rows:
        tags = row.get("tags", [])
        if isinstance(tags, list) and "synthetic" in tags:
            return True
    return False


def _normalized_config_path(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return value.replace("\\", "/").strip()


def _uses_expected_config(report: dict[str, Any], expected_config_path: str) -> bool:
    return _normalized_config_path(report.get("config_path")) == expected_config_path


def _gate(id: str, passed: bool, summary: str, **details: Any) -> GateResult:
    return GateResult(
        id=id,
        status="pass" if passed else "fail",
        summary=summary,
        details=details,
    )


def build_readiness_report(
    *,
    profile: str,
    source_report_path: Path = DEFAULT_SOURCE_REPORT,
    bun_report_path: Path = DEFAULT_BUN_REPORT,
    app_report_path: Path = DEFAULT_APP_REPORT,
    support_matrix_path: Path = DEFAULT_SUPPORT_MATRIX,
) -> dict[str, Any]:
    source_report = _load_json(source_report_path)
    bun_report = _load_json(bun_report_path)
    app_report = _load_json(app_report_path)
    support_matrix = _load_json(support_matrix_path)

    source_benchmarks = list(source_report.get("benchmarks", []))
    source_count = int(source_report.get("benchmark_count", len(source_benchmarks)))
    source_failed_statuses = {
        benchmark.get("id", "unknown"): benchmark.get("status", "unknown")
        for benchmark in source_benchmarks
        if str(benchmark.get("status", "")).endswith("failed")
    }

    bun_matrix_status = str(bun_report.get("matrix_status", "unknown"))
    bun_live_count = int(bun_report.get("live_bun_sample_count", 0))
    bun_hard_failures = int(bun_report.get("hard_failure_count", 0))

    app_summary = dict(app_report.get("summary", {}))
    app_rows = list(app_report.get("rows", []))
    app_total_entries = int(app_summary.get("total_entries", len(app_rows)))
    app_matrix_status = str(app_summary.get("matrix_status", "unknown"))
    app_tags = sorted(_tags_from_rows(app_rows))
    source_backed_validation_rows = source_count + bun_live_count + app_total_entries
    supported_workflows = [
        workflow
        for workflow in support_matrix.get("workflows", [])
        if workflow.get("status") == "supported"
    ]

    gates: list[GateResult] = []

    gates.append(
        _gate(
            "documented-support-surface",
            len(supported_workflows) >= 1,
            "A machine-readable support matrix with at least one supported workflow must exist.",
            support_matrix_path=str(support_matrix_path),
            supported_workflow_count=len(supported_workflows),
        )
    )
    gates.append(
        _gate(
            "app-corpus-baseline",
            app_matrix_status == "pass" and app_total_entries >= 7,
            "App reverse-engineering corpus must pass with at least 7 tracked rows.",
            matrix_status=app_matrix_status,
            total_entries=app_total_entries,
        )
    )
    gates.append(
        _gate(
            "native-benchmark-baseline",
            source_count >= 1,
            "At least one tracked source-backed source-vs-binary benchmark report must exist.",
            benchmark_count=source_count,
            failed_statuses=source_failed_statuses,
        )
    )
    gates.append(
        _gate(
            "bun-matrix-baseline",
            bun_matrix_status in {"pass", "pass_with_limitations"} and bun_live_count >= 1,
            "Tracked Bun matrix must exist with at least one live sample and no hard failures.",
            matrix_status=bun_matrix_status,
            live_bun_sample_count=bun_live_count,
            hard_failure_count=bun_hard_failures,
        )
    )

    if profile == "ga":
        gates.extend(
            [
                _gate(
                    "strict-ga-input-provenance",
                    _uses_expected_config(source_report, STRICT_GA_CONFIGS["source_report"])
                    and _uses_expected_config(bun_report, STRICT_GA_CONFIGS["bun_report"])
                    and _uses_expected_config(app_report, STRICT_GA_CONFIGS["app_report"]),
                    "GA requires benchmark, Bun, and app-corpus reports to be generated from the strict .ga.json inputs.",
                    source_config_path=source_report.get("config_path"),
                    expected_source_config_path=STRICT_GA_CONFIGS["source_report"],
                    bun_config_path=bun_report.get("config_path"),
                    expected_bun_config_path=STRICT_GA_CONFIGS["bun_report"],
                    app_config_path=app_report.get("config_path"),
                    expected_app_config_path=STRICT_GA_CONFIGS["app_report"],
                ),
                _gate(
                    "multi-codebase-validation-breadth",
                    source_backed_validation_rows >= 12
                    and source_count >= 1
                    and bun_matrix_status == "pass"
                    and app_matrix_status == "pass",
                    "GA requires broad source-backed validation coverage across tracked benchmark, Bun, and app corpus surfaces.",
                    benchmark_count=source_count,
                    live_bun_sample_count=bun_live_count,
                    app_entry_count=app_total_entries,
                    total_source_backed_rows=source_backed_validation_rows,
                    failed_statuses=source_failed_statuses,
                ),
                _gate(
                    "bun-live-sample-depth",
                    bun_matrix_status == "pass" and bun_live_count >= 2 and bun_hard_failures == 0,
                    "GA requires a clean Bun matrix with at least 2 live samples and no hard failures.",
                    matrix_status=bun_matrix_status,
                    live_bun_sample_count=bun_live_count,
                    hard_failure_count=bun_hard_failures,
                ),
                _gate(
                    "app-corpus-non-synthetic",
                    app_matrix_status == "pass" and not _has_synthetic_rows(app_rows),
                    "GA requires the app corpus to pass without synthetic rows in the required set.",
                    matrix_status=app_matrix_status,
                    total_entries=app_total_entries,
                    tags=app_tags,
                ),
            ]
        )

    failed_gate_count = sum(1 for gate in gates if gate.status == "fail")
    overall_status = "pass" if failed_gate_count == 0 else "fail"

    return {
        "schema_version": SCHEMA_VERSION,
        "result_type": "ga_readiness_report",
        "generated_at": _utc_now(),
        "profile": profile,
        "inputs": {
            "source_report": str(source_report_path),
            "bun_report": str(bun_report_path),
            "app_report": str(app_report_path),
            "support_matrix": str(support_matrix_path),
        },
        "summary": {
            "overall_status": overall_status,
            "gate_count": len(gates),
            "failed_gate_count": failed_gate_count,
            "passed_gate_count": len(gates) - failed_gate_count,
        },
        "gates": [gate.to_dict() for gate in gates],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify REVENG GA-readiness against tracked reports.")
    parser.add_argument("--profile", choices=["baseline", "ga"], default="baseline")
    parser.add_argument("--source-report", default=str(DEFAULT_SOURCE_REPORT))
    parser.add_argument("--bun-report", default=str(DEFAULT_BUN_REPORT))
    parser.add_argument("--app-report", default=str(DEFAULT_APP_REPORT))
    parser.add_argument("--support-matrix", default=str(DEFAULT_SUPPORT_MATRIX))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    args = parser.parse_args(argv)

    report = build_readiness_report(
        profile=args.profile,
        source_report_path=Path(args.source_report),
        bun_report_path=Path(args.bun_report),
        app_report_path=Path(args.app_report),
        support_matrix_path=Path(args.support_matrix),
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    summary = report["summary"]
    print(f"Profile: {report['profile']}")
    print(f"Overall status: {summary['overall_status']}")
    print(f"Passed gates: {summary['passed_gate_count']}")
    print(f"Failed gates: {summary['failed_gate_count']}")
    print(f"Report written to: {output_path}")
    return 0 if summary["overall_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
