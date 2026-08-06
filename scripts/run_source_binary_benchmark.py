from __future__ import annotations

import argparse
import json
import re
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

REVENG_MODULE = "reveng"
DEFAULT_CONFIG = REPO_ROOT / ".reveng" / "source_binary_benchmarks.json"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "source_binary_benchmarks_report.json"
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
MAX_BEHAVIOR_OUTPUT_CHARS = 20000


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_config_path(value: str, base_dir: Path) -> Path:
    # Configs may carry Windows-style separators from cross-platform checkouts.
    normalized = value.replace("\\", "/")
    path = Path(normalized)
    return path if path.is_absolute() else (base_dir / path).resolve()


def _normalize_output(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = ANSI_ESCAPE_RE.sub("", value).replace("\r\n", "\n").replace("\r", "\n")
    normalized_lines = [line.rstrip() for line in normalized.split("\n")]
    return "\n".join(normalized_lines).strip()


def _decode_process_output(value: str | bytes | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _expand_template(value: str, variables: dict[str, str]) -> str:
    expanded = value
    for key, replacement in variables.items():
        expanded = expanded.replace("{" + key + "}", replacement)
    return expanded


def load_benchmark_config(config_path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    raw = _load_json(config_path)
    if raw is None:
        raise FileNotFoundError(f"Benchmark config not found: {config_path}")

    base_dir = config_path.parent
    benchmarks: list[dict[str, Any]] = []
    for benchmark in raw.get("benchmarks", []):
        benchmark_copy = dict(benchmark)
        benchmark_copy["source_repo"] = str(
            _resolve_config_path(benchmark["source_repo"], base_dir)
        )
        benchmark_copy["binary_path"] = str(
            _resolve_config_path(benchmark["binary_path"], base_dir)
        )
        benchmark_copy["output_dir"] = str(_resolve_config_path(benchmark["output_dir"], base_dir))
        benchmark_copy.setdefault("analyze_timeout", 900)
        benchmark_copy.setdefault("recompile_timeout", 900)
        benchmark_copy.setdefault("analyze_ghidra_timeout", benchmark_copy["analyze_timeout"])
        benchmark_copy.setdefault("recompile_ghidra_timeout", benchmark_copy["recompile_timeout"])
        benchmark_copy.setdefault("rebuilt_binary_glob", "**/*.exe")
        commands: list[dict[str, Any]] = []
        for command in benchmark.get("commands", []):
            command_copy = dict(command)
            command_copy.setdefault("timeout", 10)
            command_copy.setdefault("compare_output", True)
            command_copy.setdefault("compare_exit_code", True)
            commands.append(command_copy)
        benchmark_copy["commands"] = commands
        benchmarks.append(benchmark_copy)

    return {
        "version": raw.get("version", "1.0"),
        "benchmarks": benchmarks,
    }


def _run_process(command: list[str], timeout: int, cwd: Path | None = None) -> dict[str, Any]:
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=False,
            timeout=timeout,
            check=False,
        )
        stdout = _decode_process_output(completed.stdout) or ""
        stderr = _decode_process_output(completed.stderr) or ""
        return {
            "command": command,
            "returncode": completed.returncode,
            "stdout_tail": stdout[-4000:],
            "stderr_tail": stderr[-4000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_process_output(exc.stdout) or ""
        stderr = _decode_process_output(exc.stderr) or ""
        return {
            "command": command,
            "returncode": None,
            "stdout_tail": stdout[-4000:],
            "stderr_tail": stderr[-4000:],
            "timed_out": True,
            "error": f"Timeout after {timeout}s",
        }


def _run_reveng(
    subcommand: str, binary_path: Path, output_dir: Path, timeout: int
) -> dict[str, Any]:
    return _run_process(
        _build_reveng_command(
            subcommand=subcommand,
            binary_path=binary_path,
            output_dir=output_dir,
        ),
        timeout=timeout,
        cwd=REPO_ROOT,
    )


def _build_reveng_command(
    *,
    subcommand: str,
    binary_path: Path,
    output_dir: Path,
    ghidra_timeout: int | None = None,
) -> list[str]:
    # Repo-root reveng.py was removed; use the package module entry point.
    command = [
        sys.executable,
        "-m",
        REVENG_MODULE,
        "--no-ollama-check",
        "--output-dir",
        str(output_dir),
        subcommand,
        str(binary_path),
    ]
    if ghidra_timeout is not None:
        command.extend(["--ghidra-timeout", str(ghidra_timeout)])
    return command


def _run_reveng_with_ghidra_timeout(
    subcommand: str,
    binary_path: Path,
    output_dir: Path,
    timeout: int,
    ghidra_timeout: int,
) -> dict[str, Any]:
    return _run_process(
        _build_reveng_command(
            subcommand=subcommand,
            binary_path=binary_path,
            output_dir=output_dir,
            ghidra_timeout=ghidra_timeout,
        ),
        timeout=timeout,
        cwd=REPO_ROOT,
    )


def _run_behavior_case(
    binary_path: Path, command_config: dict[str, Any], variables: dict[str, str]
) -> dict[str, Any]:
    args = [_expand_template(arg, variables) for arg in command_config.get("args", [])]
    command = [str(binary_path), *args]
    try:
        completed = subprocess.run(
            command,
            cwd=REPO_ROOT,
            capture_output=True,
            text=False,
            timeout=command_config["timeout"],
            check=False,
        )
        stdout = _decode_process_output(completed.stdout) or ""
        stderr = _decode_process_output(completed.stderr) or ""
        result = {
            "command": command,
            "returncode": completed.returncode,
            "stdout": stdout[:MAX_BEHAVIOR_OUTPUT_CHARS],
            "stderr": stderr[:MAX_BEHAVIOR_OUTPUT_CHARS],
            "stdout_tail": stdout[-4000:],
            "stderr_tail": stderr[-4000:],
            "timed_out": False,
        }
    except subprocess.TimeoutExpired as exc:
        stdout = _decode_process_output(exc.stdout) or ""
        stderr = _decode_process_output(exc.stderr) or ""
        result = {
            "command": command,
            "returncode": None,
            "stdout": stdout[:MAX_BEHAVIOR_OUTPUT_CHARS],
            "stderr": stderr[:MAX_BEHAVIOR_OUTPUT_CHARS],
            "stdout_tail": stdout[-4000:],
            "stderr_tail": stderr[-4000:],
            "timed_out": True,
            "error": f"Timeout after {command_config['timeout']}s",
        }

    combined_output = (result.get("stdout") or "") + (result.get("stderr") or "")
    normalized_output = _normalize_output(combined_output)
    expected_exit_code = command_config.get("expected_exit_code")
    expected_output_contains = command_config.get("expected_output_contains")
    passed = not result.get("timed_out", False)
    error: str | None = result.get("error")

    if expected_exit_code is not None and result.get("returncode") != expected_exit_code:
        passed = False
        error = f"Exit code {result.get('returncode')}, expected {expected_exit_code}"
    if (
        expected_output_contains
        and passed
        and expected_output_contains not in (normalized_output or "")
    ):
        passed = False
        error = f"Expected output fragment not found: {expected_output_contains!r}"

    return {
        "id": command_config["id"],
        "description": command_config.get("description"),
        "args": args,
        "expected_exit_code": expected_exit_code,
        "expected_output_contains": expected_output_contains,
        "returncode": result.get("returncode"),
        "timed_out": result.get("timed_out", False),
        "stdout": result.get("stdout"),
        "stderr": result.get("stderr"),
        "stdout_tail": result.get("stdout_tail"),
        "stderr_tail": result.get("stderr_tail"),
        "normalized_output": normalized_output,
        "passed": passed,
        "error": error,
    }


def _compare_behavior_results(
    original: dict[str, Any], rebuilt: dict[str, Any], command_config: dict[str, Any]
) -> dict[str, Any]:
    compare_exit_code = command_config.get("compare_exit_code", True)
    compare_output = command_config.get("compare_output", True)
    exit_code_matched = original.get("returncode") == rebuilt.get("returncode")
    output_matched = original.get("normalized_output") == rebuilt.get("normalized_output")
    timeout_matched = original.get("timed_out") == rebuilt.get("timed_out")
    matched = timeout_matched
    if compare_exit_code:
        matched = matched and exit_code_matched
    if compare_output:
        matched = matched and output_matched

    return {
        "id": command_config["id"],
        "description": command_config.get("description"),
        "matched": matched,
        "exit_code_matched": exit_code_matched,
        "output_matched": output_matched,
        "timeout_matched": timeout_matched,
        "original_returncode": original.get("returncode"),
        "rebuilt_returncode": rebuilt.get("returncode"),
        "original_timed_out": original.get("timed_out"),
        "rebuilt_timed_out": rebuilt.get("timed_out"),
    }


def _find_rebuilt_binary(
    recompile_dir: Path, glob_pattern: str, original_binary_path: Path
) -> Path | None:
    candidates = [
        path
        for path in recompile_dir.glob(glob_pattern)
        if path.is_file() and path.suffix.lower() == original_binary_path.suffix.lower()
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda path: (len(path.parts), path.name.lower(), str(path).lower()))
    return candidates[0]


def _rollup_benchmark_status(benchmark_report: dict[str, Any]) -> str:
    analyze_command = benchmark_report.get("analyze_command", {})
    recompile_command = benchmark_report.get("recompile_command", {})
    if analyze_command.get("returncode") not in {0}:
        return "analyze_failed"
    if recompile_command.get("returncode") not in {0}:
        # Analyze produced a usable artifact even when recompile failed.
        if benchmark_report.get("analyze_report_exists"):
            return "analyze_ok_recompile_failed"
        return "recompile_failed"
    if not benchmark_report.get("rebuilt_binary_path"):
        return "rebuilt_binary_missing"

    original_results = benchmark_report.get("original_behavior", [])
    rebuilt_results = benchmark_report.get("rebuilt_behavior", [])
    if any(not result.get("passed") for result in original_results):
        return "original_behavior_failed"
    if any(not result.get("passed") for result in rebuilt_results):
        return "rebuilt_behavior_failed"
    comparisons = benchmark_report.get("behavior_comparisons", [])
    if comparisons and all(comparison.get("matched") for comparison in comparisons):
        return "matched"
    if comparisons:
        return "behavior_mismatch"
    return "completed_without_behavior_checks"


def _analyze_report_exists(analyze_dir: Path) -> bool:
    candidates = (
        analyze_dir / "analysis_report.json",
        analyze_dir / "universal_analysis_report.json",
        analyze_dir / "reports" / "unified_analysis_report.json",
        analyze_dir / "reports" / "universal_analysis_report.json",
        analyze_dir / "e2e_pipeline_execution.json",
    )
    return any(path.exists() for path in candidates)


def _recompile_report_exists(recompile_dir: Path) -> bool:
    candidates = (
        recompile_dir / "recompilation_report.json",
        recompile_dir / "reconstruction_results.json",
        recompile_dir / "recompilation" / "reconstruction_results.json",
        recompile_dir / "reports" / "unified_analysis_report.json",
    )
    return any(path.exists() for path in candidates)


def run_benchmark(benchmark: dict[str, Any]) -> dict[str, Any]:
    binary_path = Path(benchmark["binary_path"])
    output_dir = Path(benchmark["output_dir"])
    analyze_dir = output_dir / "analyze"
    recompile_dir = output_dir / "recompile"
    analyze_dir.mkdir(parents=True, exist_ok=True)
    recompile_dir.mkdir(parents=True, exist_ok=True)

    variables = {
        "repo_root": str(REPO_ROOT),
        "source_repo": benchmark["source_repo"],
        "binary_path": benchmark["binary_path"],
        "output_dir": benchmark["output_dir"],
    }

    original_behavior = [
        _run_behavior_case(binary_path, command_config, variables)
        for command_config in benchmark.get("commands", [])
    ]
    analyze_command = _run_reveng_with_ghidra_timeout(
        "analyze",
        binary_path,
        analyze_dir,
        benchmark["analyze_timeout"],
        benchmark["analyze_ghidra_timeout"],
    )
    recompile_command = _run_reveng_with_ghidra_timeout(
        "recompile",
        binary_path,
        recompile_dir,
        benchmark["recompile_timeout"],
        benchmark["recompile_ghidra_timeout"],
    )
    rebuilt_binary_path = None
    rebuilt_behavior: list[dict[str, Any]] = []
    comparisons: list[dict[str, Any]] = []
    if recompile_command.get("returncode") == 0:
        rebuilt_binary = _find_rebuilt_binary(
            recompile_dir, benchmark["rebuilt_binary_glob"], binary_path
        )
        if rebuilt_binary is not None:
            rebuilt_binary_path = str(rebuilt_binary)
            rebuilt_behavior = [
                _run_behavior_case(rebuilt_binary, command_config, variables)
                for command_config in benchmark.get("commands", [])
            ]
            comparisons = [
                _compare_behavior_results(original, rebuilt, command_config)
                for original, rebuilt, command_config in zip(
                    original_behavior, rebuilt_behavior, benchmark.get("commands", [])
                )
            ]

    report = {
        "id": benchmark["id"],
        "source_repo": benchmark["source_repo"],
        "binary_path": benchmark["binary_path"],
        "output_dir": benchmark["output_dir"],
        "analyze_command": analyze_command,
        "recompile_command": recompile_command,
        "analyze_report_exists": _analyze_report_exists(analyze_dir),
        "recompile_report_exists": _recompile_report_exists(recompile_dir),
        "original_behavior": original_behavior,
        "rebuilt_binary_path": rebuilt_binary_path,
        "rebuilt_behavior": rebuilt_behavior,
        "behavior_comparisons": comparisons,
    }
    report["status"] = _rollup_benchmark_status(report)
    return report


def build_report(
    config_path: Path = DEFAULT_CONFIG, selected_ids: list[str] | None = None
) -> dict[str, Any]:
    config = load_benchmark_config(config_path)
    benchmarks = config["benchmarks"]
    if selected_ids:
        selected = set(selected_ids)
        benchmarks = [benchmark for benchmark in benchmarks if benchmark["id"] in selected]

    benchmark_reports = [run_benchmark(benchmark) for benchmark in benchmarks]
    return {
        "config_path": str(config_path),
        "benchmark_count": len(benchmark_reports),
        "benchmarks": benchmark_reports,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run source-vs-binary benchmarks.")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG),
        help="Benchmark config JSON path.",
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT),
        help="Output report JSON path.",
    )
    parser.add_argument(
        "--benchmark",
        action="append",
        default=[],
        help="Benchmark ID to run. Can be provided multiple times.",
    )
    args = parser.parse_args()

    report = build_report(Path(args.config), selected_ids=args.benchmark)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(f"Benchmarks run: {report['benchmark_count']}")
    for benchmark in report["benchmarks"]:
        print(f"{benchmark['id']}: {benchmark['status']}")
    print(f"Report written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
