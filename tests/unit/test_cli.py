"""Unit tests for the current REVENG CLI surface."""

from __future__ import annotations

import os
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import reveng.cli as cli
from reveng.version import get_version_string


REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = REPO_ROOT / "src" / "reveng" / "cli" / "reveng.py"


def make_analyze_args(binary_path: str, **overrides: object) -> Namespace:
    """Build a Namespace matching the analyze command surface."""
    defaults = {
        "binary_path": binary_path,
        "no_ollama_check": True,
        "config": None,
        "no_enhanced": False,
        "no_corporate": False,
        "no_vuln": False,
        "no_threat": False,
        "no_reconstruction": False,
        "no_demo": False,
        "output_dir": None,
        "verbose": False,
        "quiet": False,
        "log_file": None,
    }
    defaults.update(overrides)
    return Namespace(**defaults)


def run_cli(*args: str, timeout: int = 30) -> subprocess.CompletedProcess[str]:
    """Execute the real CLI wrapper as a subprocess."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    return subprocess.run(
        [sys.executable, str(CLI_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        timeout=timeout,
    )


class TestCLIParser:
    """Test parser construction for the current CLI."""

    def test_create_parser(self):
        parser = cli.create_parser()

        assert parser.prog == "reveng"
        assert parser.description == "REVENG - Universal Reverse Engineering Platform"

    def test_parser_help_lists_current_commands(self):
        help_text = cli.create_parser().format_help()

        assert "analyze" in help_text
        assert "decompile" in help_text
        assert "generate-exploit" in help_text
        assert "--version" in help_text

    def test_parser_analyze_command_accepts_current_global_flags(self):
        args = cli.create_parser().parse_args(
            ["--no-enhanced", "--no-ollama-check", "--output-dir", "analysis_out", "analyze", "sample.exe"]
        )

        assert args.command == "analyze"
        assert args.binary_path == "sample.exe"
        assert args.no_enhanced is True
        assert args.no_ollama_check is True
        assert args.output_dir == "analysis_out"

    def test_parser_serve_command(self):
        args = cli.create_parser().parse_args(
            ["serve", "--host", "0.0.0.0", "--port", "13370", "--reload"]
        )

        assert args.command == "serve"
        assert args.host == "0.0.0.0"
        assert args.port == 13370
        assert args.reload is True

    def test_parser_decompile_command(self):
        args = cli.create_parser().parse_args(
            ["decompile", "sample.exe", "--language", "python", "--enhance"]
        )

        assert args.command == "decompile"
        assert args.binary_path == "sample.exe"
        assert args.language == "python"
        assert args.enhance is True


class TestCLIHandlers:
    """Test direct command handlers with current behavior."""

    def test_handle_analyze_command_success(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]):
        binary_path = tmp_path / "sample.exe"
        binary_path.write_bytes(b"MZ" + b"\0" * 64)
        analysis_dir = tmp_path / "analysis_out"
        analyzer = SimpleNamespace(binary_path=str(binary_path), analysis_folder=analysis_dir)

        with (
            patch.object(cli, "REVENGAnalyzer", return_value=analyzer) as mock_analyzer_class,
            patch.object(
                cli,
                "run_end_to_end_analysis",
                return_value={
                    "status": "success",
                    "output_dir": str(analysis_dir),
                    "report_path": str(analysis_dir / "report.json"),
                    "summary": {
                        "behavioral_anomaly_score": 0.25,
                        "memory_anomaly_score": 0.5,
                    },
                },
            ) as mock_runner,
        ):
            result = cli.handle_analyze_command(make_analyze_args(str(binary_path)))

        captured = capsys.readouterr().out
        assert result == 0
        assert "REVENG analysis completed successfully" in captured
        mock_analyzer_class.assert_called_once()
        mock_runner.assert_called_once()
        call_kwargs = mock_runner.call_args.kwargs
        assert call_kwargs["binary_path"] == str(binary_path)
        assert call_kwargs["output_dir"] == str(analysis_dir)
        assert call_kwargs["enhanced_features"].enable_enhanced_analysis is True

    def test_handle_analyze_command_missing_binary(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        missing_binary = tmp_path / "missing.exe"
        analyzer = SimpleNamespace(binary_path=str(missing_binary), analysis_folder=tmp_path / "analysis")

        with patch.object(cli, "REVENGAnalyzer", return_value=analyzer):
            result = cli.handle_analyze_command(make_analyze_args(str(missing_binary)))

        captured = capsys.readouterr().out
        assert result == 1
        assert "Binary not found" in captured
        assert str(missing_binary) in captured

    def test_handle_analyze_command_failure(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ):
        binary_path = tmp_path / "sample.exe"
        binary_path.write_bytes(b"MZ" + b"\0" * 64)
        analyzer = SimpleNamespace(binary_path=str(binary_path), analysis_folder=tmp_path / "analysis")

        with (
            patch.object(cli, "REVENGAnalyzer", return_value=analyzer),
            patch.object(cli, "run_end_to_end_analysis", side_effect=RuntimeError("pipeline boom")),
        ):
            result = cli.handle_analyze_command(make_analyze_args(str(binary_path)))

        captured = capsys.readouterr().out
        assert result == 1
        assert "REVENG analysis failed" in captured
        assert "pipeline boom" in captured

    def test_create_enhanced_features_applies_cli_flags(self):
        features = cli.create_enhanced_features(
            Namespace(
                no_enhanced=False,
                no_corporate=True,
                no_vuln=False,
                no_threat=True,
                no_reconstruction=False,
                no_demo=True,
                config=None,
            )
        )

        assert features.enable_enhanced_analysis is True
        assert features.enable_corporate_exposure is False
        assert features.enable_vulnerability_discovery is True
        assert features.enable_threat_intelligence is False
        assert features.enable_enhanced_reconstruction is True
        assert features.enable_demonstration_generation is False

    def test_handle_serve_command_import_error(self, capsys: pytest.CaptureFixture[str]):
        result = cli.handle_serve_command(Namespace(host="localhost", port=13370, reload=False))

        captured = capsys.readouterr().out
        assert result == 1
        assert "Web interface not available" in captured

    def test_create_enhanced_features_loads_json_config(self, tmp_path: Path):
        config_path = tmp_path / "config.json"
        config_path.write_text(
            '{"enhanced_analysis": {"enable_vulnerability_discovery": false}}',
            encoding="utf-8",
        )

        features = cli.create_enhanced_features(
            Namespace(
                no_enhanced=False,
                no_corporate=False,
                no_vuln=False,
                no_threat=False,
                no_reconstruction=False,
                no_demo=False,
                config=str(config_path),
            )
        )

        assert features.enable_vulnerability_discovery is False


class TestCLIMain:
    """Test main() routing against the current parser/handlers."""

    def test_main_routes_analyze_command(self):
        with (
            patch.object(cli, "handle_analyze_command", return_value=0) as mock_handler,
            patch.object(sys, "argv", ["reveng", "--no-ollama-check", "analyze", "sample.exe"]),
        ):
            result = cli.main()

        assert result == 0
        mock_handler.assert_called_once()
        args = mock_handler.call_args.args[0]
        assert args.command == "analyze"
        assert args.binary_path == "sample.exe"
        assert args.no_ollama_check is True

    def test_main_routes_serve_command(self):
        with (
            patch.object(cli, "handle_serve_command", return_value=0) as mock_handler,
            patch.object(sys, "argv", ["reveng", "serve", "--host", "127.0.0.1", "--port", "13370"]),
        ):
            result = cli.main()

        assert result == 0
        mock_handler.assert_called_once()
        args = mock_handler.call_args.args[0]
        assert args.command == "serve"
        assert args.host == "127.0.0.1"
        assert args.port == 13370

    def test_main_no_command(self, capsys: pytest.CaptureFixture[str]):
        with patch.object(sys, "argv", ["reveng"]):
            result = cli.main()

        captured = capsys.readouterr().out
        assert result == 1
        assert "usage:" in captured.lower()

    def test_main_unknown_command(self, capsys: pytest.CaptureFixture[str]):
        with patch.object(sys, "argv", ["reveng", "unknown"]):
            with pytest.raises(SystemExit) as exc_info:
                cli.main()

        captured = capsys.readouterr().err
        assert exc_info.value.code == 2
        assert "invalid choice" in captured


class TestCLIIntegration:
    """Exercise the real CLI wrapper through subprocesses."""

    def test_help_command(self):
        result = run_cli("--help")

        assert result.returncode == 0, result.stderr
        assert "REVENG - Universal Reverse Engineering Platform" in result.stdout
        assert "analyze" in result.stdout
        assert "generate-exploit" in result.stdout

    def test_version_command(self):
        result = run_cli("--version")

        assert result.returncode == 0, result.stderr
        assert get_version_string() in result.stdout

    def test_analyze_command_missing_binary(self, tmp_path: Path):
        missing_binary = tmp_path / "missing.exe"
        result = run_cli("--no-ollama-check", "analyze", str(missing_binary))

        assert result.returncode == 1
        assert "Binary not found" in result.stdout
        assert str(missing_binary) in result.stdout

    def test_analyze_help_command(self):
        result = run_cli("analyze", "--help")

        assert result.returncode == 0, result.stderr
        assert "Run comprehensive binary analysis on the specified file" in result.stdout
        assert "binary_path" in result.stdout
