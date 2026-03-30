from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(1, str(REPO_ROOT))

from reveng.tools.anti_analysis.bun_extractor import BunExecutableExtractor  # noqa: E402
from reveng.tools.binary.validation_config import SmokeTest  # noqa: E402


REVENG_PY = REPO_ROOT / "reveng.py"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "bun_sample_matrix.json"
DEFAULT_WORKSPACE = REPO_ROOT / "reports" / "bun_sample_matrix"
DEFAULT_CONFIG = REPO_ROOT / ".reveng" / "bun_sample_matrix.json"
DEFAULT_VALIDATION_POLICY = REPO_ROOT / ".reveng" / "validation_policy.json"
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")


def _run_reveng(args: list[str], timeout: int = 600) -> dict[str, Any]:
    completed = subprocess.run(
        [sys.executable, str(REVENG_PY), "--no-ollama-check", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    return {
        "command": " ".join([sys.executable, str(REVENG_PY), "--no-ollama-check", *args]),
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-4000:],
        "stderr_tail": completed.stderr[-4000:],
    }


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _slug(path: Path) -> str:
    return path.stem.lower().replace(" ", "-") or "sample"


def _resolve_config_path(value: str, base_dir: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (base_dir / path)


def load_matrix_config(config_path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    raw = _load_json(config_path)
    if raw is None:
        raise FileNotFoundError(f"Matrix config not found: {config_path}")
    base_dir = config_path.parent

    samples = []
    for sample in raw.get("samples", []):
        sample_copy = dict(sample)
        sample_copy["path"] = str(_resolve_config_path(sample["path"], base_dir))
        sample_copy.setdefault("required", False)
        sample_copy.setdefault("kind", "bun_live_sample")
        sample_copy.setdefault("timeout", 900 if sample_copy["kind"] == "bun_live_sample" else 60)
        sample_copy.setdefault("expectations", {})
        samples.append(sample_copy)

    return {
        "version": raw.get("version", "1.0"),
        "min_live_bun_samples_for_pass": raw.get("min_live_bun_samples_for_pass", 2),
        "notes": raw.get("notes", []),
        "samples": samples,
    }


def _summarize_detection(binary_path: Path) -> dict[str, Any]:
    info = BunExecutableExtractor().detect(str(binary_path))
    return {
        "exists": binary_path.exists(),
        "is_bun_executable": info.is_bun_executable,
        "section_name": info.section_name,
        "bundle_size": info.bundle_size,
        "javascript_start_offset": info.javascript_start_offset,
        "indicators": info.indicators,
    }


def _run_bun_row(binary_path: Path, workspace_root: Path) -> dict[str, Any]:
    row_name = _slug(binary_path)
    row_workspace = workspace_root / row_name
    analyze_dir = row_workspace / "analyze"
    recompile_dir = row_workspace / "recompile"
    shutil.rmtree(row_workspace, ignore_errors=True)
    analyze_dir.mkdir(parents=True, exist_ok=True)
    recompile_dir.mkdir(parents=True, exist_ok=True)

    analyze_result = _run_reveng(
        ["--output-dir", str(analyze_dir), "analyze", str(binary_path)]
    )
    analyze_report = _load_json(analyze_dir / "bun_analysis.json")

    recompile_result = _run_reveng(
        ["recompile", str(binary_path), "--output-dir", str(recompile_dir)],
        timeout=900,
    )
    rebuild_report = _load_json(recompile_dir / "bun_sea_build.json")

    return {
        "sample": str(binary_path),
        "kind": "bun_live_sample",
        "workspace": str(row_workspace),
        "analyze_command": analyze_result,
        "recompile_command": recompile_result,
        "analyze_report": {
            "route": analyze_report.get("route") if analyze_report else None,
            "canonical_recompilation_input": (
                analyze_report.get("canonical_recompilation_input") if analyze_report else None
            ),
            "report_severity": analyze_report.get("report_severity") if analyze_report else None,
            "runtime_escalation": analyze_report.get("runtime_escalation") if analyze_report else None,
            "recovery_mode": (
                analyze_report.get("bunfs_recovery", {}).get("mode") if analyze_report else None
            ),
            "module_layout": (
                analyze_report.get("bunfs_recovery", {}).get("module_layout")
                if analyze_report
                else None
            ),
        },
        "rebuild_report": {
            "route": rebuild_report.get("route") if rebuild_report else None,
            "report_severity": rebuild_report.get("report_severity") if rebuild_report else None,
            "runtime_escalation": rebuild_report.get("runtime_escalation") if rebuild_report else None,
            "equivalence_validation": (
                rebuild_report.get("equivalence_validation") if rebuild_report else None
            ),
            "differential_validation": (
                rebuild_report.get("differential_validation") if rebuild_report else None
            ),
            "verification": (
                rebuild_report.get("sea_build", {}).get("verification")
                if rebuild_report
                else None
            ),
        },
    }


def _load_smoke_tests(policy_binary_name: str) -> list[SmokeTest]:
    policy = _load_json(DEFAULT_VALIDATION_POLICY) or {}
    config_dict = policy.get("binary_policies", {}).get(
        policy_binary_name,
        policy.get("default_policy", {}),
    )
    return [SmokeTest.from_dict(test) for test in config_dict.get("smoke_tests", [])]


def _decode_process_output(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _normalize_smoke_output(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = ANSI_ESCAPE_RE.sub("", value).replace("\r\n", "\n").replace("\r", "\n")
    normalized_lines = [line.rstrip() for line in normalized.split("\n")]
    return "\n".join(normalized_lines).strip()


def _run_smoke_test(binary_path: Path, test: SmokeTest) -> dict[str, Any]:
    test_result = {
        "description": test.description,
        "args": list(test.args),
        "passed": False,
        "output": None,
        "normalized_output": None,
        "exit_code": None,
        "error": None,
        "timed_out": False,
    }
    try:
        result = subprocess.run(
            [str(binary_path), *test.args],
            capture_output=True,
            text=False,
            timeout=test.timeout,
            check=False,
        )
        combined_output = (result.stdout or b"") + (result.stderr or b"")
        decoded_output = combined_output.decode("utf-8", errors="replace")
        test_result["output"] = decoded_output[-4000:]
        test_result["normalized_output"] = _normalize_smoke_output(test_result["output"])
        test_result["exit_code"] = result.returncode

        if test.expected_exit_code is None or result.returncode == test.expected_exit_code:
            test_result["passed"] = True
        else:
            test_result["error"] = (
                f"Exit code {result.returncode}, expected {test.expected_exit_code}"
            )

        if test.expected_output and test_result["passed"]:
            if test.expected_output not in decoded_output:
                test_result["passed"] = False
                test_result["error"] = "Expected output not found"
    except subprocess.TimeoutExpired as exc:
        test_result["timed_out"] = True
        combined_output = (_decode_process_output(getattr(exc, "stdout", None)) or "") + (
            _decode_process_output(getattr(exc, "stderr", None)) or ""
        )
        if combined_output:
            test_result["output"] = combined_output[-4000:]
            test_result["normalized_output"] = _normalize_smoke_output(test_result["output"])
        test_result["error"] = f"Timeout after {test.timeout}s"
    except FileNotFoundError:
        test_result["error"] = "Binary not executable or not found"
    except Exception as exc:
        test_result["error"] = str(exc)
    return test_result


def _run_smoke_validation(binary_path: Path, policy_binary_name: str) -> dict[str, Any]:
    smoke_tests = _load_smoke_tests(policy_binary_name)
    test_results = [_run_smoke_test(binary_path, test) for test in smoke_tests]
    tests_passed = sum(1 for result in test_results if result["passed"])
    tests_failed = len(test_results) - tests_passed
    return {
        "valid": tests_failed == 0 if test_results else True,
        "mode": "smoke_test",
        "tests_run": len(test_results),
        "tests_passed": tests_passed,
        "tests_failed": tests_failed,
        "warnings": [],
        "errors": [],
        "test_results": test_results,
    }


def _build_smoke_parity(
    original_validation: dict[str, Any],
    rebuilt_validation: dict[str, Any],
) -> dict[str, Any]:
    original_tests = original_validation.get("test_results", [])
    rebuilt_tests = rebuilt_validation.get("test_results", [])
    comparisons: list[dict[str, Any]] = []
    matched = True

    for index, original in enumerate(original_tests):
        rebuilt = rebuilt_tests[index] if index < len(rebuilt_tests) else None
        comparison = {
            "description": original.get("description"),
            "args": original.get("args"),
            "original_passed": original.get("passed"),
            "rebuilt_passed": rebuilt.get("passed") if rebuilt else None,
            "original_exit_code": original.get("exit_code"),
            "rebuilt_exit_code": rebuilt.get("exit_code") if rebuilt else None,
            "original_timed_out": original.get("timed_out"),
            "rebuilt_timed_out": rebuilt.get("timed_out") if rebuilt else None,
            "output_matched": rebuilt is not None
            and original.get("normalized_output") == rebuilt.get("normalized_output"),
            "error_matched": rebuilt is not None and original.get("error") == rebuilt.get("error"),
            "matched": rebuilt is not None
            and original.get("passed") == rebuilt.get("passed")
            and original.get("exit_code") == rebuilt.get("exit_code")
            and original.get("timed_out") == rebuilt.get("timed_out")
            and original.get("normalized_output") == rebuilt.get("normalized_output")
            and original.get("error") == rebuilt.get("error"),
        }
        comparisons.append(comparison)
        if not comparison["matched"]:
            matched = False

    return {
        "matched": matched,
        "comparisons": comparisons,
    }


def _run_negative_control(binary_path: Path) -> dict[str, Any]:
    return {
        "sample": str(binary_path),
        "kind": "negative_control",
        "detection": _summarize_detection(binary_path),
    }


def _as_mapping(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _evaluate_expectations(row: dict[str, Any], expectations: dict[str, Any]) -> dict[str, Any]:
    failures: list[str] = []
    detection = _as_mapping(row.get("detection", {}))
    analyze_report = _as_mapping(row.get("analyze_report", {}))
    rebuild_report = _as_mapping(row.get("rebuild_report", {}))

    for key, expected in expectations.get("detection", {}).items():
        if detection.get(key) != expected:
            failures.append(f"detection.{key}: expected {expected!r}, got {detection.get(key)!r}")

    for key, expected in expectations.get("analyze", {}).items():
        if analyze_report.get(key) != expected:
            failures.append(f"analyze.{key}: expected {expected!r}, got {analyze_report.get(key)!r}")

    rebuild_expectations = expectations.get("rebuild", {})
    for key, expected in rebuild_expectations.items():
        if key == "verification_status":
            actual = _as_mapping(rebuild_report.get("verification")).get("status")
        elif key == "differential_status":
            actual = _as_mapping(rebuild_report.get("differential_validation")).get("status")
        elif key == "equivalence_level":
            actual = _as_mapping(rebuild_report.get("equivalence_validation")).get(
                "equivalence_level"
            )
        else:
            actual = rebuild_report.get(key)
        if actual != expected:
            failures.append(f"rebuild.{key}: expected {expected!r}, got {actual!r}")

    smoke_expectations = expectations.get("smoke", {})
    smoke_validation = _as_mapping(row.get("smoke_validation", {}))
    for key, expected in smoke_expectations.items():
        if key == "parity_matched":
            actual = _as_mapping(smoke_validation.get("parity")).get("matched")
        elif key == "rebuilt_valid":
            actual = _as_mapping(smoke_validation.get("rebuilt")).get("valid")
        elif key == "original_valid":
            actual = _as_mapping(smoke_validation.get("original")).get("valid")
        else:
            actual = smoke_validation.get(key)
        if actual != expected:
            failures.append(f"smoke.{key}: expected {expected!r}, got {actual!r}")

    return {
        "passed": not failures,
        "failures": failures,
    }


def _rollup_matrix_status(rows: list[dict[str, Any]], min_live_bun_samples_for_pass: int) -> dict[str, Any]:
    bun_rows = [row for row in rows if row.get("kind") == "bun_live_sample"]
    successful_rebuilds = [
        row
        for row in bun_rows
        if row.get("rebuild_report", {}).get("verification", {}).get("status")
        in {"pass", "pass_with_warnings"}
    ]
    hard_failures = [
        row
        for row in rows
        if row.get("row_status") in {"missing_required_sample", "expectation_failed", "command_failed"}
    ]

    if hard_failures:
        matrix_status = "fail"
    elif len(successful_rebuilds) >= min_live_bun_samples_for_pass:
        matrix_status = "pass"
    elif successful_rebuilds:
        matrix_status = "pass_with_limitations"
    else:
        matrix_status = "insufficient_live_bun_samples"

    return {
        "matrix_status": matrix_status,
        "live_bun_sample_count": len(bun_rows),
        "successful_rebuild_count": len(successful_rebuilds),
        "hard_failure_count": len(hard_failures),
    }


def _build_configured_row(sample: dict[str, Any], workspace_root: Path) -> dict[str, Any]:
    binary_path = Path(sample["path"])
    row = {
        "id": sample.get("id"),
        "sample": str(binary_path),
        "kind": sample["kind"],
        "required": sample.get("required", False),
    }

    if not binary_path.exists():
        row["detection"] = {"exists": False}
        row["row_status"] = "missing_required_sample" if row["required"] else "missing_optional_sample"
        row["expectation_results"] = _evaluate_expectations(row, sample.get("expectations", {}))
        return row

    detection = _summarize_detection(binary_path)
    row["detection"] = detection

    if sample["kind"] == "bun_live_sample" and detection["is_bun_executable"]:
        row.update(_run_bun_row(binary_path, workspace_root))
        if (
            row.get("analyze_command", {}).get("returncode") != 0
            or row.get("recompile_command", {}).get("returncode") != 0
        ):
            row["row_status"] = "command_failed"
        else:
            row["row_status"] = "completed"
            smoke_policy = sample.get("smoke_validation", {})
            policy_binary_name = smoke_policy.get("policy_binary_name", binary_path.name)
            rebuilt_output_path = (
                Path(row["workspace"]) / "recompile" / "normalized_project" / "bun-sea.exe"
            )
            if smoke_policy.get("enabled") and rebuilt_output_path.exists():
                original_validation = _run_smoke_validation(binary_path, policy_binary_name)
                rebuilt_validation = _run_smoke_validation(rebuilt_output_path, policy_binary_name)
                row["smoke_validation"] = {
                    "policy_binary_name": policy_binary_name,
                    "original": original_validation,
                    "rebuilt": rebuilt_validation,
                    "parity": _build_smoke_parity(original_validation, rebuilt_validation),
                }
    elif sample["kind"] == "negative_control":
        row.update(_run_negative_control(binary_path))
        row["row_status"] = "completed"
    else:
        row["row_status"] = "unexpected_non_bun" if sample["kind"] == "bun_live_sample" else "completed"

    row["expectation_results"] = _evaluate_expectations(row, sample.get("expectations", {}))
    if row["row_status"] == "completed" and not row["expectation_results"]["passed"]:
        row["row_status"] = "expectation_failed"
    return row


def build_matrix(
    additional_binaries: list[str] | None = None,
    config_path: Path = DEFAULT_CONFIG,
) -> dict[str, Any]:
    config = load_matrix_config(config_path)
    rows: list[dict[str, Any]] = []
    workspace_root = DEFAULT_WORKSPACE
    workspace_root.mkdir(parents=True, exist_ok=True)

    for sample in config["samples"]:
        rows.append(_build_configured_row(sample, workspace_root))

    for value in additional_binaries or []:
        binary_path = Path(value)
        detection = _summarize_detection(binary_path)
        sample = {
            "id": _slug(binary_path),
            "path": str(binary_path),
            "kind": "bun_live_sample" if detection["is_bun_executable"] else "negative_control",
            "required": False,
            "expectations": {
                "detection": {"is_bun_executable": detection["is_bun_executable"]},
            },
        }
        rows.append(_build_configured_row(sample, workspace_root))

    rollup = _rollup_matrix_status(rows, config["min_live_bun_samples_for_pass"])
    return {
        "config_path": str(config_path),
        "matrix_status": rollup["matrix_status"],
        "live_bun_sample_count": rollup["live_bun_sample_count"],
        "successful_rebuild_count": rollup["successful_rebuild_count"],
        "hard_failure_count": rollup["hard_failure_count"],
        "rows": rows,
        "notes": config["notes"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Bun real-sample validation matrix.")
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Output JSON report path.",
    )
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="Matrix config JSON path.",
    )
    parser.add_argument(
        "--binary",
        action="append",
        default=[],
        help="Additional binary path to include in the matrix. Can be provided multiple times.",
    )
    args = parser.parse_args()

    report = build_matrix(args.binary, config_path=Path(args.config))
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Matrix status: {report['matrix_status']}")
    print(f"Live Bun samples: {report['live_bun_sample_count']}")
    print(f"Successful rebuilds: {report['successful_rebuild_count']}")
    print(f"Hard failures: {report['hard_failure_count']}")
    print(f"Report written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
