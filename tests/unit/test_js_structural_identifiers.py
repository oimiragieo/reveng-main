"""Wave 4 structural identifier hints (JSON only; no rewrite)."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering.js_structural_identifiers import (
    collect_structural_identifier_hints,
)


def test_collect_hints_export_and_function_names(tmp_path: Path) -> None:
    src = tmp_path / "sample.js"
    src.write_text(
        "export function greet(name) { return name; }\n"
        "function helper() { return 1; }\n"
        "const table = { greetKey: 1, 'otherKey': 2 };\n"
        "exports.shipped = true;\n",
        encoding="utf-8",
    )
    payload = collect_structural_identifier_hints(src)
    assert payload["rewrite_applied"] is False
    assert "greet" in payload["hints"]["export_like_names"]
    assert "shipped" in payload["hints"]["export_like_names"]
    assert "helper" in payload["hints"]["function_names"]
    assert "otherKey" in payload["hints"]["string_object_keys"]
    assert "hints_only_no_rewrite" in payload["notes"]


def test_collect_hints_missing_file_is_empty(tmp_path: Path) -> None:
    payload = collect_structural_identifier_hints(tmp_path / "missing.js")
    assert payload["rewrite_applied"] is False
    assert payload["hints"]["export_like_names"] == []
    assert "source_missing" in payload["notes"]
