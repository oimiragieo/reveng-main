"""Optional tsx runner for TS package main (R-TSX-1 / P3-BP-1)."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reveng.app_reverse_engineering.capability_report import run_javascript_behavior_probe


def test_tsx_probe_used_when_main_is_typescript(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "main": "src/cli.ts"}), encoding="utf-8"
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "cli.ts").write_text("export {}\n", encoding="utf-8")

    def fake_which(name: str):
        return "/fake/tsx" if name == "tsx" else None

    with patch("reveng.app_reverse_engineering.capability_report.which", side_effect=fake_which):
        with patch(
            "reveng.app_reverse_engineering.capability_report.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="Usage: cli\n", stderr=""),
        ) as run:
            out = run_javascript_behavior_probe(tmp_path, run_probe=True, timeout_sec=5.0)
    assert out["skipped"] is False
    assert out["tier"] == 2
    assert out.get("runner") == "tsx"
    assert run.call_args[0][0][:2] == ["/fake/tsx", "src/cli.ts"]


def test_tsx_missing_records_reason_without_crash(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "t", "main": "app.ts"}), encoding="utf-8"
    )
    (tmp_path / "app.ts").write_text("export {}\n", encoding="utf-8")
    with patch("reveng.app_reverse_engineering.capability_report.which", return_value=None):
        out = run_javascript_behavior_probe(tmp_path, run_probe=True)
    assert out["skipped"] is True
    assert out["reason"] in {"tsx_not_found", "no_cli_entry", "node_not_found"}
