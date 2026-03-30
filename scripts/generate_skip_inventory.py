from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TESTS_ROOT = REPO_ROOT / "tests"
DEFAULT_JSON_OUTPUT = REPO_ROOT / "reports" / "skip_inventory.json"
DEFAULT_MARKDOWN_OUTPUT = REPO_ROOT / "reports" / "skip_inventory.md"
SCHEMA_VERSION = "1.0"
DEFAULT_EXCLUDED_RELATIVE_PATHS = {"tests/unit/test_generate_skip_inventory.py"}

SKIP_RE = re.compile(r"@pytest\.mark\.skip\s*\((?P<args>.*)\)")
SKIPIF_RE = re.compile(r"@pytest\.mark\.skipif\s*\((?P<args>.*)\)")
RUNTIME_SKIP_RE = re.compile(r"pytest\.skip\s*\((?P<args>.*)\)")
REASON_RE = re.compile(r"reason\s*=\s*['\"](?P<reason>[^'\"]+)['\"]")
STRING_RE = re.compile(r"['\"](?P<reason>[^'\"]+)['\"]")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _repo_path(value: str | Path) -> Path:
    path = value if isinstance(value, Path) else Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


def _extract_reason(args: str) -> str:
    match = REASON_RE.search(args)
    if match:
        return match.group("reason")
    match = STRING_RE.search(args)
    if match:
        return match.group("reason")
    return "unspecified"


def _categorize_reason(reason: str) -> str:
    normalized = reason.lower()
    if any(term in normalized for term in ("not implemented", "api mismatch", "known bug", "future", "not ready")):
        return "known_gap"
    if any(
        term in normalized
        for term in (
            "ghidra",
            "ilspy",
            "pyi-archive_viewer",
            "compiler",
            "toolchain",
            "cache",
            "llm4decompile",
            "angr",
            "java",
            "dependency",
            "dependencies",
        )
    ):
        return "external_tooling"
    if any(term in normalized for term in ("service unavailable", "network", "timeout", "environment")):
        return "service_environment"
    if any(term in normalized for term in ("not found", "missing", "sample", "fixture", "examples", "readme")):
        return "asset_or_fixture"
    if any(term in normalized for term in ("windows", "linux", "unix", "platform", "win32")):
        return "platform_specific"
    if any(term in normalized for term in ("optional",)):
        return "optional_capability"
    return "uncategorized"


def _scan_file(path: Path, repo_root: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        for kind, pattern in (
            ("skip", SKIP_RE),
            ("skipif", SKIPIF_RE),
            ("runtime_skip", RUNTIME_SKIP_RE),
        ):
            match = pattern.search(line)
            if not match:
                continue
            reason = _extract_reason(match.group("args"))
            entries.append(
                {
                    "path": str(path.relative_to(repo_root)),
                    "line": lineno,
                    "kind": kind,
                    "reason": reason,
                    "category": _categorize_reason(reason),
                }
            )
    return entries


def build_skip_inventory_report(
    *,
    tests_root: Path = DEFAULT_TESTS_ROOT,
    repo_root: Path = REPO_ROOT,
    excluded_relative_paths: set[str] | None = None,
) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    excluded_relative_paths = excluded_relative_paths or set()
    for path in sorted(tests_root.rglob("test_*.py")):
        relative_path = path.relative_to(repo_root if tests_root.is_relative_to(repo_root) else tests_root.parent)
        normalized_relative = str(relative_path).replace("\\", "/")
        if normalized_relative in excluded_relative_paths:
            continue
        entries.extend(_scan_file(path, repo_root if tests_root.is_relative_to(repo_root) else tests_root.parent))

    by_kind = Counter(entry["kind"] for entry in entries)
    by_category = Counter(entry["category"] for entry in entries)

    return {
        "schema_version": SCHEMA_VERSION,
        "result_type": "skip_inventory_report",
        "generated_at": _utc_now(),
        "tests_root": str(tests_root),
        "summary": {
            "total_skip_sites": len(entries),
            "by_kind": dict(sorted(by_kind.items())),
            "by_category": dict(sorted(by_category.items())),
        },
        "entries": entries,
    }


def _render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    lines = [
        "# REVENG Skip-Lane Inventory",
        "",
        f"- Generated at: `{report['generated_at']}`",
        f"- Tests root: `{report['tests_root']}`",
        f"- Total skip sites: `{summary['total_skip_sites']}`",
        "",
        "## Category Summary",
        "",
    ]
    for category, count in summary["by_category"].items():
        lines.append(f"- `{category}`: `{count}`")
    lines.extend(["", "## Kind Summary", ""])
    for kind, count in summary["by_kind"].items():
        lines.append(f"- `{kind}`: `{count}`")
    lines.extend(["", "## Skip Sites", ""])
    for entry in report["entries"]:
        lines.append(
            f"- `{entry['path']}:{entry['line']}` `{entry['kind']}` `{entry['category']}`: {entry['reason']}"
        )
    return "\n".join(lines) + "\n"


def write_skip_inventory_report(
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
    parser = argparse.ArgumentParser(description="Generate a skip-lane inventory for the REVENG test suite.")
    parser.add_argument("--tests-root", default=str(DEFAULT_TESTS_ROOT))
    parser.add_argument("--json-output", default=str(DEFAULT_JSON_OUTPUT))
    parser.add_argument("--markdown-output", default=str(DEFAULT_MARKDOWN_OUTPUT))
    args = parser.parse_args(argv)

    report = build_skip_inventory_report(
        tests_root=_repo_path(args.tests_root),
        repo_root=REPO_ROOT,
        excluded_relative_paths=DEFAULT_EXCLUDED_RELATIVE_PATHS,
    )
    write_skip_inventory_report(
        report,
        json_output_path=_repo_path(args.json_output),
        markdown_output_path=_repo_path(args.markdown_output),
    )
    print(f"Total skip sites: {report['summary']['total_skip_sites']}")
    print(f"JSON report: {args.json_output}")
    print(f"Markdown report: {args.markdown_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
