from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(1, str(REPO_ROOT))

from reveng.app_reverse_engineering import AppCorpusEntry, run_app_corpus_sync

DEFAULT_CONFIG = REPO_ROOT / ".reveng" / "app_reverse_engineering_corpus.json"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "app_reverse_engineering_corpus_report.json"


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_config_path(value: str, base_dir: Path) -> Path:
    # Configs may carry Windows-style separators from cross-platform checkouts.
    normalized = value.replace("\\", "/")
    path = Path(normalized)
    return path if path.is_absolute() else (base_dir / path).resolve()


def load_app_corpus_config(config_path: Path = DEFAULT_CONFIG) -> dict[str, Any]:
    raw = _load_json(config_path)
    if raw is None:
        raise FileNotFoundError(f"App corpus config not found: {config_path}")

    base_dir = config_path.parent
    entries: list[dict[str, Any]] = []
    for entry in raw.get("entries", []):
        item = dict(entry)
        item["input_path"] = str(_resolve_config_path(entry["input_path"], base_dir))
        item.setdefault("language", "auto")
        item.setdefault("required", True)
        item.setdefault("tags", [])
        entries.append(item)

    return {
        "version": raw.get("version", "1.0"),
        "notes": raw.get("notes", []),
        "entries": entries,
    }


def build_report(
    config_path: Path = DEFAULT_CONFIG,
    selected_names: list[str] | None = None,
    *,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    config = load_app_corpus_config(config_path)
    entries = config["entries"]
    if selected_names:
        selected = set(selected_names)
        entries = [entry for entry in entries if entry["name"] in selected]

    corpus_entries = [AppCorpusEntry(**entry) for entry in entries]
    resolved_output_dir = output_dir or (REPO_ROOT / "reports" / "app_reverse_engineering_corpus")
    report = run_app_corpus_sync(corpus_entries, str(resolved_output_dir))
    report["config_path"] = str(config_path)
    report["notes"] = list(config.get("notes", []))
    report["selected_entry_count"] = len(corpus_entries)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Run app reverse-engineering corpus smoke validation.")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG), help="App corpus config JSON path.")
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output report JSON path.")
    parser.add_argument(
        "--entry",
        action="append",
        default=[],
        help="Corpus entry name to run. Can be provided multiple times.",
    )
    args = parser.parse_args()

    report = build_report(Path(args.config), selected_names=args.entry)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    summary = report["summary"]
    print(f"Corpus entries run: {report['selected_entry_count']}")
    print(f"Matrix status: {summary['matrix_status']}")
    for row in report["rows"]:
        print(f"{row['name']}: {row['status']}")
    print(f"Report written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
