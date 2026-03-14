"""Integration tests for the current REVENG CLI entrypoints."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from reveng.version import get_version_string


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = REPO_ROOT / "src" / "reveng" / "cli" / "reveng.py"
LANGUAGE_DETECTOR_SCRIPT = REPO_ROOT / "src" / "reveng" / "tools" / "languages" / "language_detector.py"
SAMPLE_BINARY = REPO_ROOT / "test_samples" / "HelloWorld.java"


def _build_env() -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def run_cli(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=_build_env(),
        timeout=timeout,
    )


def run_script(script: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=_build_env(),
        timeout=timeout,
    )


class TestCLI:
    """Test the current command-line wrapper end to end."""

    def test_help_command(self):
        result = run_cli("--help")

        assert result.returncode == 0, f"Help command failed: {result.stderr}"
        assert "REVENG - Universal Reverse Engineering Platform" in result.stdout
        assert "generate-exploit" in result.stdout

    def test_version_command(self):
        result = run_cli("--version")

        assert result.returncode == 0, f"Version command failed: {result.stderr}"
        assert get_version_string() in result.stdout

    def test_invalid_binary(self):
        result = run_cli("--no-ollama-check", "analyze", "nonexistent.exe")
        combined_output = f"{result.stdout}\n{result.stderr}"

        assert result.returncode == 1
        assert "Binary not found" in combined_output

    def test_java_sample_analysis(self, tmp_path: Path):
        if not SAMPLE_BINARY.exists():
            pytest.skip("Java sample not found")

        output_dir = tmp_path / "analysis_out"
        result = run_cli(
            "--no-ollama-check",
            "--output-dir",
            str(output_dir),
            "analyze",
            str(SAMPLE_BINARY),
            timeout=180,
        )

        assert result.returncode in [0, 1], f"Analysis failed unexpectedly: {result.stderr}"
        assert output_dir.exists(), "Output directory not created"

    def test_verbose_output(self, tmp_path: Path):
        if not SAMPLE_BINARY.exists():
            pytest.skip("Java sample not found")

        output_dir = tmp_path / "verbose_out"
        result = run_cli(
            "--verbose",
            "--no-ollama-check",
            "--output-dir",
            str(output_dir),
            "analyze",
            str(SAMPLE_BINARY),
            timeout=180,
        )
        combined_output = f"{result.stdout}\n{result.stderr}"

        assert result.returncode in [0, 1], f"Verbose analysis failed: {result.stderr}"
        assert combined_output.strip(), "No output produced"


class TestToolCLI:
    """Smoke-test tool scripts that are still exposed as standalone CLIs."""

    def test_language_detector_cli(self):
        if not SAMPLE_BINARY.exists():
            pytest.skip("Java sample not found")

        result = run_script(LANGUAGE_DETECTOR_SCRIPT, str(SAMPLE_BINARY))

        assert result.returncode == 0, f"Language detector failed: {result.stderr}"
        assert "Language:" in result.stdout


class TestBootstrapScripts:
    """Test bootstrap script presence and shell syntax where applicable."""

    def test_windows_bootstrap(self):
        bootstrap_script = REPO_ROOT / "scripts" / "bootstrap_windows.bat"
        if not bootstrap_script.exists():
            pytest.skip("Windows bootstrap script not found")

        assert bootstrap_script.exists()

    def test_linux_bootstrap(self):
        bootstrap_script = REPO_ROOT / "scripts" / "bootstrap_linux.sh"
        if not bootstrap_script.exists():
            pytest.skip("Linux bootstrap script not found")

        result = subprocess.run(
            ["bash", "-n", str(bootstrap_script)],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"Bootstrap script syntax error: {result.stderr}"


class TestUtilityScripts:
    """Test utility script entrypoints."""

    def test_cleanup_script(self):
        cleanup_script = REPO_ROOT / "scripts" / "cleanup_legacy.py"
        if not cleanup_script.exists():
            pytest.skip("Cleanup script not found")

        result = run_script(cleanup_script, "--help")

        assert result.returncode == 0, f"Cleanup script failed: {result.stderr}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
