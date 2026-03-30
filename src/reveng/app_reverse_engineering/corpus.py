"""Corpus runner for app reverse-engineering workflows."""

from __future__ import annotations

import asyncio
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from reveng.result_contracts import RESULT_SCHEMA_VERSION

from .framework import AppReverseEngineeringFramework


@dataclass
class AppCorpusEntry:
    """One app reverse-engineering corpus row."""

    name: str
    input_path: str
    language: str = "auto"
    required: bool = True
    tags: List[str] = field(default_factory=list)


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def select_app_corpus_entries(
    entries: Sequence[AppCorpusEntry],
    selected_names: Optional[Iterable[str]] = None,
) -> List[AppCorpusEntry]:
    """Filter corpus entries by name while preserving manifest order."""
    if not selected_names:
        return list(entries)
    selected = {name for name in selected_names if name}
    return [entry for entry in entries if entry.name in selected]


async def run_app_corpus(
    entries: Sequence[AppCorpusEntry],
    output_dir: str,
    *,
    framework: Optional[AppReverseEngineeringFramework] = None,
    max_snippets: int = 12,
    snippet_context: int = 2,
) -> Dict[str, Any]:
    """Run a corpus of app reverse-engineering entries and write a rollup report."""
    from . import create_default_framework

    runner = framework or create_default_framework()
    output_root = Path(output_dir).expanduser().resolve()
    output_root.mkdir(parents=True, exist_ok=True)

    rows: List[Dict[str, Any]] = []
    completed = 0
    failed = 0
    required_failed = 0

    for entry in entries:
        entry_input = Path(entry.input_path).expanduser().resolve()
        row_output_dir = output_root / entry.name
        try:
            result = await runner.reverse_engineer(
                str(entry_input),
                str(row_output_dir),
                language=entry.language,
                max_snippets=max_snippets,
                snippet_context=snippet_context,
            )
            rows.append(
                {
                    "name": entry.name,
                    "input_path": str(entry_input),
                    "language": result.language,
                    "requested_language": entry.language,
                    "required": entry.required,
                    "tags": list(entry.tags),
                    "status": "completed",
                    "validation_grade": result.validation_grade,
                    "result_type": result.result_type,
                    "analysis_file": str(result.analysis_file),
                    "source_count": result.source_count,
                    "warning_count": len(result.warnings),
                }
            )
            completed += 1
        except Exception as exc:
            rows.append(
                {
                    "name": entry.name,
                    "input_path": str(entry_input),
                    "language": entry.language,
                    "requested_language": entry.language,
                    "required": entry.required,
                    "tags": list(entry.tags),
                    "status": "failed",
                    "error": str(exc),
                }
            )
            failed += 1
            if entry.required:
                required_failed += 1

    matrix_status = "pass" if failed == 0 else ("fail" if required_failed > 0 else "pass_with_limitations")
    report = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "result_type": "app_reverse_engineering_corpus_report",
        "generated_at": _utc_timestamp(),
        "output_dir": str(output_root),
        "summary": {
            "total_entries": len(entries),
            "completed_entries": completed,
            "failed_entries": failed,
            "required_failed_entries": required_failed,
            "matrix_status": matrix_status,
        },
        "rows": rows,
    }
    (output_root / "app_corpus_report.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    return report


def run_app_corpus_sync(
    entries: Sequence[AppCorpusEntry],
    output_dir: str,
    *,
    framework: Optional[AppReverseEngineeringFramework] = None,
    max_snippets: int = 12,
    snippet_context: int = 2,
) -> Dict[str, Any]:
    """Synchronous wrapper for the async corpus runner."""
    return asyncio.run(
        run_app_corpus(
            entries,
            output_dir,
            framework=framework,
            max_snippets=max_snippets,
            snippet_context=snippet_context,
        )
    )


__all__ = [
    "AppCorpusEntry",
    "run_app_corpus",
    "run_app_corpus_sync",
    "select_app_corpus_entries",
]
