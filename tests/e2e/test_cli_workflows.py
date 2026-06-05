"""
End-to-end smoke tests for the supported REVENG CLI wrappers.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_BASE = [sys.executable, str(REPO_ROOT / "src" / "reveng" / "cli" / "reveng.py")]


class TestCLIWorkflows:
    """Smoke coverage for the supported top-level CLI wrapper."""

    def test_help_command(self):
        result = subprocess.run(
            [*CLI_BASE, "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        assert "REVENG - Universal Reverse Engineering Platform" in result.stdout
        assert "reverse-engineer-app" in result.stdout

    def test_version_command(self):
        result = subprocess.run(
            [*CLI_BASE, "--version"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        assert "REVENG v4.0.0" in result.stdout

    def test_analyze_help_command(self):
        result = subprocess.run(
            [*CLI_BASE, "analyze", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        assert "Run comprehensive binary analysis" in result.stdout

    def test_reverse_engineer_app_help_command(self):
        result = subprocess.run(
            [*CLI_BASE, "reverse-engineer-app", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )

        assert result.returncode == 0
        assert "Generate a SPECS library" in result.stdout
        assert "--language {auto,javascript,jvm,python,dotnet}" in result.stdout

    def test_invalid_command(self):
        result = subprocess.run(
            [*CLI_BASE, "invalid_command"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=REPO_ROOT,
        )

        assert result.returncode != 0
        assert "invalid choice" in result.stderr

    def test_analyze_binary_not_found(self, tmp_path):
        result = subprocess.run(
            [*CLI_BASE, "analyze", "nonexistent.exe"],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=tmp_path,
        )

        assert result.returncode == 1
        assert "Binary not found" in result.stdout

    def test_reverse_engineer_app_java_sample(self, tmp_path):
        output_dir = tmp_path / "analysis_java_sample"
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
        assert (output_dir / "analysis.json").exists()
        analysis = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert analysis["validation"]["grade"] in {
            "behavior-matched",
            "partial-equivalent",
            "structural",
            "compile-only",
            "evidence_backed",
        }

    def test_serve_command_dependency_or_running_server(self, tmp_path):
        process = subprocess.Popen(
            [*CLI_BASE, "serve", "--port", "3012"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=tmp_path,
        )

        try:
            time.sleep(5)
            if process.poll() is None:
                try:
                    response = requests.get("http://127.0.0.1:3012", timeout=5)
                    assert response.status_code < 500
                except requests.exceptions.RequestException:
                    pass
            else:
                stdout = process.stdout.read() if process.stdout else ""
                stderr = process.stderr.read() if process.stderr else ""
                combined = f"{stdout}\n{stderr}"
                assert process.returncode == 1
                assert "Web interface not available" in combined
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
