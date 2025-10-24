"""Tests for the .NET analyzer module."""

from pathlib import Path
from unittest.mock import patch

import pytest

from reveng.analyzers.dotnet_analyzer import (
    AssemblyInfo,
    DotNetAnalysisResult,
    DotNetAnalyzer,
)


def _create_binary(tmp_path: Path) -> Path:
    binary = tmp_path / "sample.exe"
    binary.write_bytes(b"MZ" + b"\x00" * 128)
    return binary


def test_analyze_assembly_returns_result(tmp_path: Path):
    analyzer = DotNetAnalyzer()
    binary = _create_binary(tmp_path)

    with (
        patch.object(
            analyzer,
            "_get_assembly_info",
            return_value=AssemblyInfo("App", "1.0", "", "", "x86"),
        ),
        patch.object(analyzer, "_detect_framework_version", return_value="4.8"),
        patch.object(analyzer, "_detect_runtime_version", return_value="4.8.0"),
        patch.object(analyzer, "_detect_gui_framework", return_value="Windows Forms"),
        patch.object(
            analyzer, "_extract_dependencies", return_value=["System.Windows.Forms"]
        ),
        patch.object(
            analyzer, "_extract_embedded_resources", return_value={"icons": []}
        ),
        patch.object(analyzer, "_find_entry_points", return_value=["Main"]),
        patch.object(
            analyzer,
            "_extract_business_logic",
            return_value={"application_domain": "security"},
        ),
        patch.object(analyzer, "_detect_packing", return_value=False),
        patch.object(analyzer, "_analyze_obfuscation", return_value="None"),
        patch.object(analyzer, "_extract_api_calls", return_value=["CreateFile"]),
        patch.object(analyzer, "_analyze_pe_sections", return_value={"text": {}}),
    ):
        result = analyzer.analyze_assembly(str(binary))

    assert isinstance(result, DotNetAnalysisResult)
    assert result.framework_version == "4.8"
    assert result.gui_framework == "Windows Forms"
    assert result.dependencies == ["System.Windows.Forms"]


@pytest.mark.parametrize(
    "indicators,expected",
    [
        (["System.Windows.Forms", "Button"], "Windows Forms"),
        (["System.Windows", "XAML"], "Windows Presentation Foundation"),
        (["Console.WriteLine"], "Console Application"),
        (["SomethingElse"], "Unknown"),
    ],
)
def test_detect_gui_framework_uses_string_indicators(indicators, expected):
    analyzer = DotNetAnalyzer()
    with patch.object(analyzer, "_extract_strings", return_value=indicators):
        assert analyzer._detect_gui_framework("binary") == expected


def test_analyze_obfuscation_categories():
    analyzer = DotNetAnalyzer()
    with patch.object(
        analyzer, "_extract_strings", return_value=["obfuscated", "packed"]
    ):
        assert analyzer._analyze_obfuscation("binary") == "High"
    with patch.object(analyzer, "_extract_strings", return_value=["base64", "xor"]):
        assert analyzer._analyze_obfuscation("binary") == "Medium"
    with patch.object(analyzer, "_extract_strings", return_value=["normal", "hello"]):
        assert analyzer._analyze_obfuscation("binary") in {"Low", "None"}


def test_calculate_analysis_confidence():
    analyzer = DotNetAnalyzer()
    score = analyzer._calculate_analysis_confidence(
        "4.8",
        "Windows Forms",
        {"application_domain": "security", "data_flows": True},
    )

    assert 0.5 <= score <= 1.0
