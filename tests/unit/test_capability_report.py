"""Unit tests for app reverse-engineering capability reporting."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from reveng.app_reverse_engineering.capability_report import (
    analyze_js_reconstructed_project,
    build_capability_report,
    run_javascript_behavior_probe,
    run_javascript_npm_lifecycle_probe,
)


def test_build_capability_report_includes_oracle_slice(tmp_path: Path) -> None:
    recon = tmp_path / "reconstructed_project"
    recon.mkdir()
    primary = {"reconstructed_project": recon}
    report = build_capability_report(
        language="javascript",
        primary_artifacts=primary,
        adapter_metadata={
            "benchmark_scorecard": {
                "project_file_recall": 0.5,
                "project_file_precision": 0.25,
                "reconstruction_mode": "test_mode",
            }
        },
        run_js_syntax_check=False,
    )
    assert report["schema_version"] == "1.0"
    assert "recall=0.5000" in report["headline"]
    oa = report["dimensions"]["oracle_alignment"]
    assert oa["present"] is True
    assert oa["project_file_recall"] == 0.5


def test_analyze_js_reconstructed_project_package_and_syntax(tmp_path: Path) -> None:
    proj = tmp_path / "rp"
    proj.mkdir()
    (proj / "package.json").write_text(
        json.dumps({"main": "entry.js", "name": "x"}),
        encoding="utf-8",
    )
    (proj / "entry.js").write_text("exports.x = 1;\n", encoding="utf-8")
    (proj / "other.cjs").write_text("module.exports = {};\n", encoding="utf-8")

    with patch("reveng.app_reverse_engineering.capability_report.which", return_value="/fake/node"):
        with patch(
            "reveng.app_reverse_engineering.capability_report.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stderr=""),
        ):
            out = analyze_js_reconstructed_project(proj, max_syntax_files=5, run_syntax_checks=True)

    assert out["package_json"]["parse_ok"] is True
    assert out["syntax_summary"] == "all_checked_ok"
    assert len(out["syntax_checks"]) >= 1


def test_run_javascript_behavior_probe_disabled(tmp_path: Path) -> None:
    proj = tmp_path / "rp"
    proj.mkdir()
    out = run_javascript_behavior_probe(proj, run_probe=False)
    assert out["skipped"] is True
    assert out["reason"] == "disabled"


def test_run_javascript_behavior_probe_uses_reveng_behavior_probe_main(tmp_path: Path) -> None:
    proj = tmp_path / "rp"
    proj.mkdir()
    (proj / "reveng_behavior_smoke.cjs").write_text(
        "if (process.argv.includes('--help')) { console.log('Usage: smoke'); process.exit(0); }\n"
        "process.exit(1);\n",
        encoding="utf-8",
    )
    (proj / "package.json").write_text(
        json.dumps(
            {
                "name": "x",
                "main": "src/app.ts",
                "reveng": {"behavior_probe_main": "reveng_behavior_smoke.cjs"},
            }
        ),
        encoding="utf-8",
    )
    (proj / "src").mkdir()
    (proj / "src" / "app.ts").write_text("export {}\n", encoding="utf-8")
    with patch("reveng.app_reverse_engineering.capability_report.which", return_value="/fake/node"):
        with patch(
            "reveng.app_reverse_engineering.capability_report.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="Usage: smoke\n", stderr=""),
        ):
            out = run_javascript_behavior_probe(proj, run_probe=True, timeout_sec=5.0)
    assert out["skipped"] is False
    assert out["tier"] == 2
    assert out["entry_relative"] == "reveng_behavior_smoke.cjs"


def test_run_javascript_behavior_probe_cli_help_exit_zero(tmp_path: Path) -> None:
    proj = tmp_path / "rp"
    proj.mkdir()
    (proj / "package.json").write_text(
        json.dumps({"name": "t", "main": "cli.js"}),
        encoding="utf-8",
    )
    (proj / "cli.js").write_text(
        "if (process.argv.includes('--help')) { console.log('Usage: cli [options]'); process.exit(0); }\n"
        "process.exit(1);\n",
        encoding="utf-8",
    )
    with patch("reveng.app_reverse_engineering.capability_report.which", return_value="/fake/node"):
        with patch(
            "reveng.app_reverse_engineering.capability_report.subprocess.run",
            return_value=SimpleNamespace(returncode=0, stdout="Usage: cli\n", stderr=""),
        ):
            out = run_javascript_behavior_probe(proj, run_probe=True, timeout_sec=5.0)
    assert out["skipped"] is False
    assert out["tier"] == 2
    assert out["exit_code"] == 0
    assert out["summary"] == "cli_help_exit_zero"


def test_build_capability_report_includes_behavior_dimension(tmp_path: Path) -> None:
    recon = tmp_path / "reconstructed_project"
    recon.mkdir()
    (recon / "package.json").write_text(json.dumps({"main": "x.js"}), encoding="utf-8")
    (recon / "x.js").write_text("//\n", encoding="utf-8")
    primary = {"reconstructed_project": recon}
    with patch("reveng.app_reverse_engineering.capability_report.which", return_value=None):
        report = build_capability_report(
            language="javascript",
            primary_artifacts=primary,
            adapter_metadata={},
            run_js_syntax_check=False,
            run_js_behavior_probe=True,
        )
    beh = report["dimensions"]["javascript_behavior_probe"]
    assert isinstance(beh, dict)
    assert beh.get("skipped") is True
    assert beh.get("reason") == "node_not_found"


def test_run_javascript_npm_lifecycle_probe_disabled(tmp_path: Path) -> None:
    proj = tmp_path / "rp"
    proj.mkdir()
    out = run_javascript_npm_lifecycle_probe(proj, run_probe=False)
    assert out["skipped"] is True
    assert out["reason"] == "disabled"
    assert out["tier"] == 0


def test_run_javascript_npm_lifecycle_probe_dry_run_ok(tmp_path: Path) -> None:
    proj = tmp_path / "rp"
    proj.mkdir()
    (proj / "package.json").write_text(
        json.dumps({"name": "t", "version": "1.0.0"}), encoding="utf-8"
    )
    with patch("reveng.app_reverse_engineering.capability_report.which", return_value="/fake/npm"):
        with patch(
            "reveng.app_reverse_engineering.capability_report.subprocess.run",
            return_value=SimpleNamespace(
                returncode=0,
                stdout="npm notice\nfilename: t-1.0.0.tgz\n",
                stderr="",
            ),
        ):
            out = run_javascript_npm_lifecycle_probe(proj, run_probe=True, timeout_sec=5.0)
    assert out["skipped"] is False
    assert out["tier"] == 2
    assert out["summary"] == "npm_pack_dry_run_ok"


def test_build_capability_report_includes_npm_dimension_when_enabled(tmp_path: Path) -> None:
    recon = tmp_path / "reconstructed_project"
    recon.mkdir()
    (recon / "package.json").write_text(
        json.dumps({"name": "x", "version": "0.0.1"}), encoding="utf-8"
    )
    primary = {"reconstructed_project": recon}
    with patch("reveng.app_reverse_engineering.capability_report.which", return_value=None):
        report = build_capability_report(
            language="javascript",
            primary_artifacts=primary,
            adapter_metadata={},
            run_js_syntax_check=False,
            run_js_behavior_probe=False,
            run_js_npm_lifecycle_probe=True,
        )
    npm = report["dimensions"]["javascript_npm_lifecycle_probe"]
    assert isinstance(npm, dict)
    assert npm.get("reason") == "npm_not_found"


def test_analyze_js_reconstructed_project_skips_when_no_node(tmp_path: Path) -> None:
    proj = tmp_path / "rp"
    proj.mkdir()
    (proj / "a.js").write_text("1;\n", encoding="utf-8")
    with patch("reveng.app_reverse_engineering.capability_report.which", return_value=None):
        out = analyze_js_reconstructed_project(proj, run_syntax_checks=True)
    assert out["syntax_summary"] == "node_unavailable"
