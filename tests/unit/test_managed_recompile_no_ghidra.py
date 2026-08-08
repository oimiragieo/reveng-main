"""Managed-language recompile must not require Ghidra."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from reveng.recompile_command import (
    MANAGED_LANGUAGE_EXTENSIONS,
    is_managed_language_input,
    run_recompile_command,
)


def test_pyc_is_managed_language_input():
    assert is_managed_language_input(Path("sample.pyc")) is True
    assert is_managed_language_input(Path("HelloWorld.class")) is True
    assert is_managed_language_input(Path("app.exe")) is False


def test_managed_recompile_skips_ghidra(tmp_path: Path):
    binary = tmp_path / "sample.pyc"
    binary.write_bytes(b"\x16\x0d\x0d\x0a" + b"\x00" * 16)
    output_dir = tmp_path / "out"

    fake_result = MagicMock()
    fake_result.language = "python"
    fake_result.adapter_name = "python_app"
    fake_result.analysis_file = output_dir / "analysis.json"
    fake_result.source_count = 1
    fake_result.validation_grade = "syntax_ok"
    fake_result.primary_artifacts = {"reconstructed_project": output_dir / "project"}
    fake_result.warnings = []

    with patch("reveng.integrations.ghidra.ghidra_engine.GhidraEngine") as ghidra_cls:
        with patch("reveng.app_reverse_engineering.create_default_framework") as create_fw:
            framework = MagicMock()
            framework.reverse_engineer = AsyncMock(return_value=fake_result)
            create_fw.return_value = framework

            # Create artifact tree so report writer can copy/link
            project = output_dir / "project"
            project.mkdir(parents=True, exist_ok=True)
            rebuilt = project / "sample.pyc"
            rebuilt.write_bytes(binary.read_bytes())
            fake_result.primary_artifacts = {"reconstructed_project": project}
            fake_result.analysis_file.parent.mkdir(parents=True, exist_ok=True)
            fake_result.analysis_file.write_text("{}", encoding="utf-8")

            rc = run_recompile_command(
                binary_path=str(binary),
                output_dir=str(output_dir),
                use_gemini=False,
            )

    assert rc == 0
    ghidra_cls.assert_not_called()
    report = output_dir / "recompilation_report.json"
    assert report.exists()
    assert (output_dir / "rebuilt" / "sample.pyc").exists()


def test_managed_extensions_cover_java_python_dotnet():
    assert ".jar" in MANAGED_LANGUAGE_EXTENSIONS
    assert ".pyz" in MANAGED_LANGUAGE_EXTENSIONS
    assert ".dll" in MANAGED_LANGUAGE_EXTENSIONS
