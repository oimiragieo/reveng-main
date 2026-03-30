"""
End-to-end tests for supported complete REVENG workflows.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_BASE = [sys.executable, str(REPO_ROOT / "reveng.py")]
PYTHON = sys.executable


def _adapter_name(analysis: dict) -> str | None:
    if "adapter_name" in analysis:
        return analysis["adapter_name"]
    tools = analysis.get("provenance", {}).get("tools", [])
    return tools[0] if tools else None


class TestCompleteWorkflow:
    """Exercise shipped end-to-end workflows instead of stale mock-only flows."""

    def test_complete_jvm_reverse_engineering_workflow(self, tmp_path):
        output_dir = tmp_path / "analysis_java"
        sample_path = REPO_ROOT / "test_samples" / "HelloWorld.java"

        result = subprocess.run(
            [
                *CLI_BASE,
                "--output-dir",
                str(output_dir),
                "reverse-engineer-app",
                str(sample_path),
                "--language",
                "jvm",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        analysis = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert analysis["language"] == "jvm"
        assert _adapter_name(analysis) == "jvm_app_workflow"
        assert (output_dir / "SPECS").is_dir()

    def test_complete_python_reverse_engineering_workflow(self, tmp_path):
        output_dir = tmp_path / "analysis_python"
        sample_path = REPO_ROOT / "test_samples" / "sample_app.py"

        result = subprocess.run(
            [
                *CLI_BASE,
                "--output-dir",
                str(output_dir),
                "reverse-engineer-app",
                str(sample_path),
                "--language",
                "python",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        analysis = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert analysis["language"] == "python"
        assert _adapter_name(analysis) == "python_app_workflow"
        assert analysis["validation"]["grade"]

    def test_complete_javascript_reverse_engineering_workflow(self, tmp_path):
        output_dir = tmp_path / "analysis_javascript"
        sample_path = REPO_ROOT / "test_samples" / "sample_bundle.js"

        result = subprocess.run(
            [
                *CLI_BASE,
                "--output-dir",
                str(output_dir),
                "reverse-engineer-app",
                str(sample_path),
                "--language",
                "javascript",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        analysis = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert _adapter_name(analysis) == "javascript_bundle_workflow"
        assert (output_dir / "artifacts").is_dir()

    def test_complete_dotnet_reverse_engineering_workflow(self, tmp_path):
        output_dir = tmp_path / "analysis_dotnet"
        sample_path = REPO_ROOT / "test_samples" / "sample_dotnet.dll"

        result = subprocess.run(
            [
                *CLI_BASE,
                "--output-dir",
                str(output_dir),
                "reverse-engineer-app",
                str(sample_path),
                "--language",
                "dotnet",
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        analysis = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert _adapter_name(analysis) == "dotnet_app_workflow"
        assert "evidence" in analysis

    def test_complete_app_corpus_workflow(self, tmp_path):
        report_path = tmp_path / "app_reverse_engineering_corpus_report.json"

        result = subprocess.run(
            [
                PYTHON,
                "scripts/run_app_reverse_engineering_corpus.py",
                "--config",
                ".reveng/app_reverse_engineering_corpus.ga.json",
                "--output",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=240,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["summary"]["matrix_status"] == "pass"
        assert report["summary"]["total_entries"] >= 7

    def test_complete_bun_sample_matrix_report_contract(self):
        report = json.loads((REPO_ROOT / "reports" / "bun_sample_matrix.json").read_text(encoding="utf-8"))
        assert report["matrix_status"] == "pass"
        assert report["live_bun_sample_count"] >= 2

    def test_complete_baseline_ga_readiness_workflow(self, tmp_path):
        report_path = tmp_path / "ga_readiness_baseline.json"

        result = subprocess.run(
            [
                PYTHON,
                "scripts/verify_ga_readiness.py",
                "--profile",
                "baseline",
                "--output",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["summary"]["overall_status"] == "pass"

    def test_complete_strict_ga_readiness_workflow(self, tmp_path):
        report_path = tmp_path / "ga_readiness_target.json"

        result = subprocess.run(
            [
                PYTHON,
                "scripts/verify_ga_readiness.py",
                "--profile",
                "ga",
                "--output",
                str(report_path),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["summary"]["overall_status"] == "pass"
