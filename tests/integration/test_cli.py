"""Integration tests for the current REVENG CLI entrypoints."""

from __future__ import annotations

import os
import json
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from reveng.version import get_version_string

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI_SCRIPT = REPO_ROOT / "src" / "reveng" / "cli" / "reveng.py"
LANGUAGE_DETECTOR_SCRIPT = (
    REPO_ROOT / "src" / "reveng" / "tools" / "languages" / "language_detector.py"
)
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
        encoding="utf-8",
        errors="replace",
        cwd=REPO_ROOT,
        env=_build_env(),
        timeout=timeout,
    )


def run_script(script: Path, *args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        cwd=REPO_ROOT,
        env=_build_env(),
        timeout=timeout,
    )


def _build_pe_with_bun_section(section_data: bytes) -> bytes:
    dos_header = bytearray(0x80)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    optional_header = bytearray(0xE0)
    optional_header[0:2] = struct.pack("<H", 0x10B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x2000)
    optional_header[28:32] = struct.pack("<I", 0x400000)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)
    optional_header[56:60] = struct.pack("<I", 0x2000)
    optional_header[60:64] = struct.pack("<I", 0x200)
    optional_header[68:70] = struct.pack("<H", 3)
    optional_header[92:96] = struct.pack("<I", 16)

    pe_header = bytearray()
    pe_header.extend(b"PE\x00\x00")
    pe_header.extend(struct.pack("<H", 0x14C))
    pe_header.extend(struct.pack("<H", 1))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<H", 0xE0))
    pe_header.extend(struct.pack("<H", 0x010F))
    pe_header.extend(optional_header)

    pointer_to_raw_data = 0x200
    raw_size = ((len(section_data) + 0x1FF) // 0x200) * 0x200
    section_header = bytearray(40)
    section_header[:8] = b".bun\x00\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", len(section_data))
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", raw_size)
    section_header[20:24] = struct.pack("<I", pointer_to_raw_data)
    section_header[36:40] = struct.pack("<I", 0x40000040)

    headers = bytes(dos_header) + bytes(pe_header) + bytes(section_header)
    headers = headers.ljust(pointer_to_raw_data, b"\x00")
    return headers + section_data.ljust(raw_size, b"\x00")


def _build_dotnet_pe() -> bytes:
    dos_header = bytearray(0x80)
    dos_header[:2] = b"MZ"
    dos_header[0x3C:0x40] = struct.pack("<I", 0x80)

    optional_header = bytearray(0xE0)
    optional_header[0:2] = struct.pack("<H", 0x10B)
    optional_header[16:20] = struct.pack("<I", 0x1000)
    optional_header[20:24] = struct.pack("<I", 0x1000)
    optional_header[24:28] = struct.pack("<I", 0x2000)
    optional_header[28:32] = struct.pack("<I", 0x400000)
    optional_header[32:36] = struct.pack("<I", 0x1000)
    optional_header[36:40] = struct.pack("<I", 0x200)
    optional_header[56:60] = struct.pack("<I", 0x2000)
    optional_header[60:64] = struct.pack("<I", 0x200)
    optional_header[68:70] = struct.pack("<H", 3)
    optional_header[92:96] = struct.pack("<I", 16)
    com_descriptor_offset = 96 + (8 * 14)
    optional_header[com_descriptor_offset : com_descriptor_offset + 8] = struct.pack("<II", 0x1100, 0x48)

    pe_header = bytearray()
    pe_header.extend(b"PE\x00\x00")
    pe_header.extend(struct.pack("<H", 0x14C))
    pe_header.extend(struct.pack("<H", 1))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<I", 0))
    pe_header.extend(struct.pack("<H", 0xE0))
    pe_header.extend(struct.pack("<H", 0x010F))
    pe_header.extend(optional_header)

    section_header = bytearray(40)
    section_header[:8] = b".text\x00\x00\x00"
    section_header[8:12] = struct.pack("<I", 0x200)
    section_header[12:16] = struct.pack("<I", 0x1000)
    section_header[16:20] = struct.pack("<I", 0x200)
    section_header[20:24] = struct.pack("<I", 0x200)
    section_header[36:40] = struct.pack("<I", 0x60000020)

    headers = bytes(dos_header) + bytes(pe_header) + bytes(section_header)
    headers = headers.ljust(0x200, b"\x00")
    return headers + (b"\x00" * 0x200)


def _write_bun_cli_fixture(tmp_path: Path) -> Path:
    virtual_path = b"B:/~BUN/root/app.js"
    raw_bytes = (
        virtual_path
        + b"\x00"
        + b"// @bun\n"
        + b'import WebSocket from "ws";\n'
        + b'const fs = import.meta.require("fs");\n'
        + b"await Promise.resolve();\n"
        + b"console.log('hello from bun cli', WebSocket, fs);\n"
        + b"//# sourceMappingURL=app.js.map\n"
    )
    module_record = struct.pack(
        "<IIIIIIII4B",
        0,
        len(virtual_path),
        len(virtual_path) + 1,
        len(raw_bytes) - (len(virtual_path) + 1),
        0,
        0,
        0,
        0,
        1,
        1,
        0,
        0,
    )
    byte_count = len(raw_bytes) + len(module_record)
    blob = bytearray(raw_bytes)
    modules_offset = len(blob)
    blob.extend(module_record)
    blob.extend(
        struct.pack(
            "<QIIIIII",
            byte_count,
            modules_offset,
            len(module_record),
            0,
            byte_count - 1,
            0,
            121,
        )
    )
    blob.extend(b"\n---- Bun! ----\n")
    bundle_blob = struct.pack("<I", len(blob)) + blob

    binary_path = tmp_path / "sample_bun_cli.exe"
    binary_path.write_bytes(_build_pe_with_bun_section(bundle_blob))
    return binary_path


def _assert_subset(actual, expected):
    if isinstance(expected, dict):
        for key, value in expected.items():
            assert key in actual, f"Missing key: {key}"
            _assert_subset(actual[key], value)
        return
    if isinstance(expected, list):
        assert len(actual) >= len(expected)
        for actual_item, expected_item in zip(actual, expected):
            _assert_subset(actual_item, expected_item)
        return
    assert actual == expected


def _bun_analysis_golden_subset():
    return {
        "route": "bun",
        "bundle_info": {"section_name": ".bun"},
        "bunfs_recovery": {
            "success": True,
            "mode": "module_graph",
            "module_layout": "short",
        },
        "normalized_project": {
            "success": True,
            "inferred_dependencies": ["ws"],
            "shims_applied": [
                "createRequire import",
                "import.meta.require replacement",
            ],
            "semantic_checks": [
                {
                    "check": "dependency_import_sanity",
                }
            ],
            "postprocessing_hooks": [
                {
                    "tool": "webcrack",
                }
            ],
        },
        "native_stub": {
            "container": "pe",
            "entry_point_section": ".bun",
            "startup_classification": "mixed_or_unknown",
            "entry_point_preview": [{}],
            "runtime_readiness": {
                "breakpoints": [{}],
                "dump_points": [{}],
            },
            "dump_guidance": {
                "recommended": True,
                "actions": [{}],
            },
            "cross_references": [
                {
                    "kind": "bun_virtual_path",
                }
            ],
            "handoff_signals": [
                {
                    "kind": "embedded_bun_section",
                }
            ],
            "startup_graph": {
                "roots": ["entrypoint"],
                "nodes": [{}],
                "edges": [{}],
            },
            "startup_targets": [
                {
                    "source": "entrypoint",
                    "symbolic_label": "bun_rva_0000104b",
                    "target_section": ".bun",
                    "target_preview": [{}],
                },
            ],
        },
    }


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

    def test_reverse_engineer_app_help_command(self):
        result = run_cli("reverse-engineer-app", "--help")

        assert result.returncode == 0, f"Help command failed: {result.stderr}"
        assert "Generate a SPECS library and recovered artifacts" in result.stdout
        assert "--language" in result.stdout

    def test_decompile_missing_binary_reports_path_error(self):
        result = run_cli("decompile", "nonexistent.exe")
        combined_output = f"{result.stdout}\n{result.stderr}"

        assert result.returncode == 1
        assert "Binary not found" in combined_output
        assert "Ghidra integration not available" not in combined_output

    def test_recompile_missing_binary_does_not_fail_on_import(self):
        result = run_cli("recompile", "nonexistent.exe", "--no-gemini")
        combined_output = f"{result.stdout}\n{result.stderr}"

        assert result.returncode == 1
        assert "Recompilation engine not available" not in combined_output

    def test_build_bun_sea_missing_binary_reports_path_error(self):
        result = run_cli("build-bun-sea", "nonexistent.exe")
        combined_output = f"{result.stdout}\n{result.stderr}"

        assert result.returncode == 1
        assert "Binary not found" in combined_output

    def test_recompile_routes_bun_executable_to_node_sea(self, tmp_path: Path):
        binary_path = _write_bun_cli_fixture(tmp_path)
        output_dir = tmp_path / "bun_recompile"

        result = run_cli("recompile", str(binary_path), "--output-dir", str(output_dir), timeout=180)

        assert result.returncode == 0, result.stderr
        assert "routing recompile to Node SEA build" in result.stdout
        assert "SEA executable:" in result.stdout
        assert (output_dir / "bun_sea_build.json").exists()
        report = json.loads((output_dir / "bun_sea_build.json").read_text(encoding="utf-8"))
        assert report["report_severity"]["dimension"] == "reconstruction_risk"
        assert report["runtime_escalation"]["dimension"] == "runtime_escalation"
        assert report["equivalence_validation"]["dimension"] == "equivalence_validation"
        assert report["sea_build"]["verification"]["status"] in {"pass", "pass_with_warnings"}
        assert report["differential_validation"]["status"] == "pass"
        assert isinstance(report["runtime_escalation"]["next_steps"], list)
        assert isinstance(report["equivalence_validation"]["recommended_validations"], list)
        assert any(
            check["check"] == "output_binary_generated"
            for check in report["sea_build"]["verification"]["checks"]
        )
        assert any(
            check["check"] == "bun_require_rewrite_coverage"
            for check in report["differential_validation"]["checks"]
        )

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

    def test_reverse_engineer_app_java_sample(self, tmp_path: Path):
        if not SAMPLE_BINARY.exists():
            pytest.skip("Java sample not found")

        output_dir = tmp_path / "app_analysis_out"
        result = run_cli(
            "--output-dir",
            str(output_dir),
            "reverse-engineer-app",
            str(SAMPLE_BINARY),
            "--language",
            "jvm",
            timeout=180,
        )

        assert result.returncode == 0, f"Reverse engineering failed unexpectedly: {result.stderr}"
        assert "App reverse engineering completed successfully" in result.stdout
        assert (output_dir / "analysis.json").exists()
        assert (output_dir / "SPECS" / "02-classes-and-methods.md").exists()
        report = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert report["schema_version"] == "1.0"
        assert report["result_type"] == "app_reverse_engineering_result"
        assert report["validation"]["grade"]
        assert report["provenance"]["inputs"][0]["path"] == str(SAMPLE_BINARY.resolve())
        assert report["language"] == "jvm"
        assert "HelloWorld" in report["classes"]

    def test_reverse_engineer_app_python_source_sample(self, tmp_path: Path):
        source_path = tmp_path / "sample_app.py"
        source_path.write_text(
            "\n".join(
                [
                    "import argparse",
                    "",
                    "def main():",
                    "    parser = argparse.ArgumentParser()",
                    "    parser.add_argument('--name')",
                    "",
                    "if __name__ == '__main__':",
                    "    main()",
                ]
            ),
            encoding="utf-8",
        )
        output_dir = tmp_path / "python_app_analysis"
        result = run_cli(
            "--output-dir",
            str(output_dir),
            "reverse-engineer-app",
            str(source_path),
            "--language",
            "python",
            timeout=180,
        )

        assert result.returncode == 0, f"Reverse engineering failed unexpectedly: {result.stderr}"
        assert "Language: python" in result.stdout
        assert (output_dir / "analysis.json").exists()
        report = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert report["schema_version"] == "1.0"
        assert report["result_type"] == "app_reverse_engineering_result"
        assert report["validation"]["evidence_count"] >= 1
        assert report["language"] == "python"
        assert "main" in report["entrypoints"]
        assert "argparse" in report["imports"]

    def test_reverse_engineer_app_pyinstaller_like_sample(self, tmp_path: Path):
        frozen_path = tmp_path / "sample_frozen.exe"
        frozen_path.write_bytes(
            b"MZ"
            + b"\x00" * 64
            + b"PyInstaller\x00_MEIPASS\x00pyi_rth_pkgres\x00base_library.zip\x00MEI\x0c\x0b\x0a\x0b\x0e"
        )
        output_dir = tmp_path / "pyinstaller_analysis"
        result = run_cli(
            "--output-dir",
            str(output_dir),
            "reverse-engineer-app",
            str(frozen_path),
            timeout=180,
        )

        assert result.returncode == 0, f"Reverse engineering failed unexpectedly: {result.stderr}"
        assert "Language: python" in result.stdout
        report = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert report["language"] == "python"
        assert report["packaging"] == "pyinstaller"

    def test_reverse_engineer_app_dotnet_like_sample(self, tmp_path: Path):
        assembly_path = tmp_path / "sample_dotnet.dll"
        assembly_path.write_bytes(_build_dotnet_pe())
        output_dir = tmp_path / "dotnet_app_analysis"
        result = run_cli(
            "--output-dir",
            str(output_dir),
            "reverse-engineer-app",
            str(assembly_path),
            "--language",
            "dotnet",
            timeout=180,
        )

        assert result.returncode == 0, f"Reverse engineering failed unexpectedly: {result.stderr}"
        assert "Language: dotnet" in result.stdout
        report = json.loads((output_dir / "analysis.json").read_text(encoding="utf-8"))
        assert report["language"] == "dotnet"
        assert "runtime_version" in report

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

    def test_analyze_routes_bun_executable_to_bundle_extraction(self, tmp_path: Path):
        binary_path = _write_bun_cli_fixture(tmp_path)
        output_dir = tmp_path / "bun_analysis"

        result = run_cli(
            "--no-ollama-check",
            "--output-dir",
            str(output_dir),
            "analyze",
            str(binary_path),
        )

        assert result.returncode == 0, result.stderr
        assert "routing analyze to Bun bundle extraction" in result.stdout
        assert (output_dir / "sample_bun_cli_bundle.js").exists()
        report_path = output_dir / "bun_analysis.json"
        assert report_path.exists()
        report = json.loads(report_path.read_text(encoding="utf-8"))
        assert report["route"] == "bun"
        assert report["report_severity"]["dimension"] == "reconstruction_risk"
        assert report["runtime_escalation"]["dimension"] == "runtime_escalation"
        assert report["bunfs_recovery"]["success"] is True
        assert report["bunfs_recovery"]["mode"] == "module_graph"
        assert report["bunfs_recovery"]["module_layout"] == "short"
        assert report["canonical_recompilation_input"].endswith("root\\app.js")
        assert "excludes appended bundle metadata" in report["canonical_recompilation_reason"]
        assert report["normalized_project"]["success"] is True
        assert report["normalized_project"]["entrypoint_path"].endswith("app.mjs")
        assert report["normalized_project"]["sea_entrypoint_path"].endswith("sea-entry.cjs")
        assert report["normalized_project"]["sea_config_path"].endswith("sea-config.json")
        assert report["normalized_project"]["inferred_dependencies"] == ["ws"]
        assert "import.meta.require replacement" in report["normalized_project"]["shims_applied"]
        assert report["normalized_project"]["semantic_checks"][0]["check"] == "dependency_import_sanity"
        assert report["normalized_project"]["postprocessing_hooks"][0]["tool"] == "webcrack"
        assert report["native_stub"]["container"] == "pe"
        assert ".bun" in report["native_stub"]["section_names"]
        assert isinstance(report["native_stub"]["entry_point_preview"], list)
        assert "target_address" in report["native_stub"]["entry_point_preview"][0]
        assert "import_target" in report["native_stub"]["entry_point_preview"][0]
        assert "rip_relative_address" in report["native_stub"]["entry_point_preview"][0]
        assert report["native_stub"]["tls_callback_vas"] == []
        assert report["native_stub"]["tls_callbacks"] == []
        assert report["native_stub"]["startup_classification"] == "mixed_or_unknown"
        assert isinstance(report["native_stub"]["startup_reasons"], list)
        assert isinstance(report["native_stub"]["runtime_readiness"]["breakpoints"], list)
        assert isinstance(report["native_stub"]["runtime_readiness"]["dump_points"], list)
        assert report["native_stub"]["dump_guidance"]["recommended"] is True
        assert isinstance(report["native_stub"]["dump_guidance"]["actions"], list)
        assert report["runtime_escalation"]["recommended"] is True
        assert report["runtime_escalation"]["next_steps"][0]["kind"] == "set_breakpoints"
        assert isinstance(report["native_stub"]["cross_references"], list)
        assert report["native_stub"]["cross_references"][0]["kind"] == "bun_virtual_path"
        assert isinstance(report["native_stub"]["handoff_signals"], list)
        assert report["native_stub"]["handoff_signals"][0]["kind"] == "embedded_bun_section"
        assert isinstance(report["native_stub"]["startup_targets"], list)
        assert isinstance(report["native_stub"]["startup_graph"]["nodes"], list)
        assert isinstance(report["native_stub"]["startup_graph"]["edges"], list)
        assert report["native_stub"]["startup_graph"]["roots"][0] == "entrypoint"
        assert report["native_stub"]["startup_targets"][0]["source"] == "entrypoint"
        assert "symbolic_label" in report["native_stub"]["startup_targets"][0]
        assert "target_resolution" in report["native_stub"]["startup_targets"][0]
        assert "import_target" in report["native_stub"]["startup_targets"][0]
        assert "target_preview" in report["native_stub"]["startup_targets"][0]
        assert "Embedded Bun payload section present" in report["native_stub"]["indicators"]

    def test_analyze_bun_report_matches_golden_subset(self, tmp_path: Path):
        binary_path = _write_bun_cli_fixture(tmp_path)
        output_dir = tmp_path / "bun_analysis_golden"

        result = run_cli(
            "--no-ollama-check",
            "--output-dir",
            str(output_dir),
            "analyze",
            str(binary_path),
        )

        assert result.returncode == 0, result.stderr
        report = json.loads((output_dir / "bun_analysis.json").read_text(encoding="utf-8"))
        _assert_subset(report, _bun_analysis_golden_subset())

    def test_decompile_routes_bun_executable_to_bundle_extraction(self, tmp_path: Path):
        binary_path = _write_bun_cli_fixture(tmp_path)
        output_path = tmp_path / "bundle.js"

        result = run_cli("decompile", str(binary_path), "--output", str(output_path))

        assert result.returncode == 0, result.stderr
        assert "routing decompile to Bun bundle extraction" in result.stdout
        assert output_path.exists()
        assert output_path.read_text(encoding="utf-8").startswith("// @bun")
        assert "Route: bun" in result.stdout
        assert "Preferred recompilation input:" in result.stdout
        assert "Normalized project workspace:" in result.stdout
        assert "Normalized SEA entrypoint:" in result.stdout


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
            encoding="utf-8",
            errors="replace",
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
