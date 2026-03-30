"""Tests for the generic app reverse-engineering framework."""

from __future__ import annotations

import asyncio
import py_compile
import subprocess
import zipfile
from pathlib import Path
from unittest.mock import patch

from reveng.analyzers.dotnet_analyzer import DotNetAnalysisResult
from reveng.app_reverse_engineering import create_default_framework
from reveng.tools.languages.csharp_il_analyzer import (
    CSharpILAnalyzer,
    DotNetDetector,
    ILDisassemblyResult,
)
from reveng.tools.languages.java_bytecode_analyzer import JavaBytecodeAnalyzer
from reveng.tools.languages.python_bytecode_analyzer import PythonBytecodeDetector


def _assert_shared_app_contract(result) -> None:
    report = result.metadata
    assert report["schema_version"] == "1.0"
    assert report["result_type"] == "app_reverse_engineering_result"
    assert report["validation"]["grade"]
    assert report["validation"]["summary"]
    assert report["validation"]["evidence_count"] >= 1
    assert report["validation"]["warning_count"] == len(result.warnings)
    assert report["provenance"]["inputs"][0]["path"] == str(result.input_path)
    artifact_paths = {item["path"] for item in report["provenance"]["artifacts"]}
    assert str(result.analysis_file) in artifact_paths
    assert any(item["kind"] == "spec_topic" for item in report["evidence"])
    assert any(item["kind"] == "analysis_summary" for item in report["evidence"])


def test_framework_reverse_engineers_java_source_sample(tmp_path: Path):
    framework = create_default_framework()
    sample = Path("test_samples/HelloWorld.java").resolve()
    output_dir = tmp_path / "java_source_analysis"

    result = asyncio.run(
        framework.reverse_engineer(
            str(sample),
            str(output_dir),
            language="auto",
            max_snippets=6,
        )
    )

    assert result.language == "jvm"
    assert result.source_count == 1
    assert result.analysis_file.exists()
    assert "HelloWorld.java" in result.metadata["entrypoints"][0]
    classes_spec = result.topic_files["classes_and_methods"].read_text(encoding="utf-8")
    runtime_spec = result.topic_files["build_and_runtime"].read_text(encoding="utf-8")
    assert "HelloWorld" in classes_spec
    assert "public static void main" in runtime_spec
    _assert_shared_app_contract(result)


def test_framework_recovers_sources_from_simple_jar(tmp_path: Path):
    framework = create_default_framework()
    jar_path = tmp_path / "sample-app.jar"
    with zipfile.ZipFile(jar_path, "w") as archive:
        archive.writestr(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nMain-Class: com.example.App\nImplementation-Version: 1.2.3\n",
        )
        archive.writestr("com/example/App.class", b"\xca\xfe\xba\xbe\x00\x00\x00\x34")

    output_dir = tmp_path / "jar_analysis"
    result = asyncio.run(
        framework.reverse_engineer(
            str(jar_path),
            str(output_dir),
            language="jvm",
            max_snippets=6,
        )
    )

    assert result.language == "jvm"
    assert result.analysis_file.exists()
    assert result.source_count >= 1
    recovered_sources = result.primary_artifacts["bytecode_analysis"].parent / "recovered_sources"
    assert recovered_sources.exists()
    recovered_files = list(recovered_sources.rglob("*.java"))
    assert recovered_files
    build_spec = result.topic_files["build_and_runtime"].read_text(encoding="utf-8")
    assert "Manifest preview: Manifest-Version=1.0, Main-Class=com.example.App" in build_spec
    _assert_shared_app_contract(result)


def test_java_bytecode_analyzer_uses_split_java_commands(tmp_path: Path):
    analyzer = JavaBytecodeAnalyzer(output_dir=str(tmp_path / "java_analysis"))

    for config in analyzer.decompilers.values():
        command = config["command"]
        assert isinstance(command, list)
        assert command[:2] == ["java", "-jar"]


def test_framework_reverse_engineers_python_source_sample(tmp_path: Path):
    framework = create_default_framework()
    sample = tmp_path / "sample_app.py"
    sample.write_text(
        "\n".join(
            [
                "import argparse",
                "from pathlib import Path",
                "",
                "class Greeter:",
                "    def greet(self, name: str) -> str:",
                "        return f'hello {name}'",
                "",
                "def main() -> None:",
                "    parser = argparse.ArgumentParser()",
                "    parser.add_argument('--name')",
                "    Path('out.txt').write_text(Greeter().greet('world'), encoding='utf-8')",
                "",
                "if __name__ == '__main__':",
                "    main()",
            ]
        ),
        encoding="utf-8",
    )
    output_dir = tmp_path / "python_source_analysis"

    result = asyncio.run(
        framework.reverse_engineer(
            str(sample),
            str(output_dir),
            language="python",
            max_snippets=6,
        )
    )

    assert result.language == "python"
    assert result.source_count == 1
    assert result.analysis_file.exists()
    assert "main" in result.metadata["entrypoints"]
    assert "Greeter" in result.metadata["classes"]
    spec_text = result.topic_files["cli_and_entrypoints"].read_text(encoding="utf-8")
    assert "argparse" in spec_text
    _assert_shared_app_contract(result)


def test_framework_reverse_engineers_python_bytecode_sample(tmp_path: Path):
    framework = create_default_framework()
    source_path = tmp_path / "compiled_sample.py"
    source_path.write_text(
        "\n".join(
            [
                "import json",
                "",
                "def main():",
                "    print(json.dumps({'status': 'ok'}))",
                "",
                "if __name__ == '__main__':",
                "    main()",
            ]
        ),
        encoding="utf-8",
    )
    pyc_path = tmp_path / "compiled_sample.pyc"
    py_compile.compile(str(source_path), cfile=str(pyc_path), doraise=True)

    output_dir = tmp_path / "python_bytecode_analysis"
    result = asyncio.run(
        framework.reverse_engineer(
            str(pyc_path),
            str(output_dir),
            language="python",
            max_snippets=6,
        )
    )

    assert result.language == "python"
    assert result.analysis_file.exists()
    assert result.source_count >= 1
    assert result.primary_artifacts["bytecode_disassembly"].exists()
    report = result.analysis_file.read_text(encoding="utf-8")
    assert '"source_origin": "bytecode"' in report
    runtime_spec = result.topic_files["runtime_and_packaging"].read_text(encoding="utf-8")
    assert "Python bytecode version" in runtime_spec
    _assert_shared_app_contract(result)


def test_framework_reverse_engineers_python_zipapp_sample(tmp_path: Path):
    framework = create_default_framework()
    pyz_path = tmp_path / "sample_app.pyz"
    with zipfile.ZipFile(pyz_path, "w") as archive:
        archive.writestr(
            "__main__.py",
            "\n".join(
                [
                    "import click",
                    "",
                    "@click.command()",
                    "def main():",
                    "    click.echo('hello zipapp')",
                    "",
                    "if __name__ == '__main__':",
                    "    main()",
                ]
            ),
        )
        archive.writestr("pkg/helpers.py", "def helper():\n    return 'ok'\n")

    output_dir = tmp_path / "python_zipapp_analysis"
    result = asyncio.run(
        framework.reverse_engineer(
            str(pyz_path),
            str(output_dir),
            language="auto",
            max_snippets=6,
        )
    )

    assert result.language == "python"
    assert result.analysis_file.exists()
    assert result.primary_artifacts["extracted_sources"].exists()
    assert "__main__.py" in result.metadata["entrypoints"]
    structure_spec = result.topic_files["project_structure"].read_text(encoding="utf-8")
    assert "__main__.py" in structure_spec
    _assert_shared_app_contract(result)


def test_python_bytecode_detector_recognizes_current_interpreter_magic(tmp_path: Path):
    source_path = tmp_path / "detector_sample.py"
    source_path.write_text("def main():\n    return 1\n", encoding="utf-8")
    pyc_path = tmp_path / "detector_sample.pyc"
    py_compile.compile(str(source_path), cfile=str(pyc_path), doraise=True)

    is_python, info = PythonBytecodeDetector.detect(str(pyc_path))

    assert is_python is True
    assert info is not None
    assert info.python_version


def test_framework_auto_detects_pyinstaller_frozen_python_sample(tmp_path: Path):
    framework = create_default_framework()
    frozen_path = tmp_path / "frozen_app.exe"
    frozen_path.write_bytes(
        b"MZ"
        + b"\x00" * 64
        + b"PyInstaller"
        + b"\x00"
        + b"_MEIPASS"
        + b"\x00"
        + b"pyi_rth_pkgres"
        + b"\x00"
        + b"base_library.zip"
        + b"\x00"
        + b"MEI\x0c\x0b\x0a\x0b\x0e"
    )

    output_dir = tmp_path / "pyinstaller_analysis"
    result = asyncio.run(
        framework.reverse_engineer(
            str(frozen_path),
            str(output_dir),
            language="auto",
            max_snippets=6,
        )
    )

    assert result.language == "python"
    assert result.analysis_file.exists()
    assert result.metadata["packaging"] == "pyinstaller"
    assert "PyInstaller" in result.metadata["frozen_python"]["markers"]
    runtime_spec = result.topic_files["runtime_and_packaging"].read_text(encoding="utf-8")
    assert "PyInstaller" in runtime_spec
    _assert_shared_app_contract(result)


def test_framework_uses_pyi_archive_viewer_when_available(tmp_path: Path):
    framework = create_default_framework()
    frozen_path = tmp_path / "viewer_enabled.exe"
    frozen_path.write_bytes(
        b"MZ"
        + b"\x00" * 64
        + b"PyInstaller"
        + b"\x00"
        + b"_MEIPASS"
        + b"\x00"
        + b"base_library.zip"
        + b"\x00"
        + b"pkg/main.pyc"
        + b"\x00"
    )

    archive_output = "\n".join(
        [
            "Options in 'viewer_enabled.exe' (PKG/CArchive):",
            "0, 123, 456, 'm', 'pkg/main.pyc'",
            "1, 456, 789, 'm', 'base_library.zip'",
        ]
    )
    output_dir = tmp_path / "pyinstaller_viewer_analysis"
    with (
        patch(
            "reveng.app_reverse_engineering.adapters.python.shutil.which",
            return_value="pyi-archive_viewer",
        ),
        patch(
            "reveng.app_reverse_engineering.adapters.python.subprocess.run",
            return_value=subprocess.CompletedProcess(
                args=["pyi-archive_viewer", str(frozen_path)],
                returncode=0,
                stdout=archive_output,
                stderr="",
            ),
        ),
    ):
        result = asyncio.run(
            framework.reverse_engineer(
                str(frozen_path),
                str(output_dir),
                language="python",
                max_snippets=6,
            )
        )

    assert result.metadata["frozen_python"]["archive_viewer_available"] is True
    assert any(
        "pkg/main.pyc" in entry
        for entry in result.metadata["frozen_python"]["archive_viewer_entries"]
    )
    assert result.primary_artifacts["pyi_archive_listing"].exists()
    assert not any("pyi-archive_viewer not available" in warning for warning in result.warnings)
    runtime_spec = result.topic_files["runtime_and_packaging"].read_text(encoding="utf-8")
    assert "archive viewer" in runtime_spec.lower()
    _assert_shared_app_contract(result)


def test_framework_extracts_python_entries_from_pyi_archive_viewer(tmp_path: Path):
    framework = create_default_framework()
    frozen_path = tmp_path / "viewer_extract.exe"
    frozen_path.write_bytes(
        b"MZ"
        + b"\x00" * 64
        + b"PyInstaller"
        + b"\x00"
        + b"_MEIPASS"
        + b"\x00"
        + b"pkg/app.py"
        + b"\x00"
    )

    archive_output = "\n".join(
        [
            "Options in 'viewer_extract.exe' (PKG/CArchive):",
            "0, 123, 456, 'm', 'pkg/app.py'",
        ]
    )

    def _fake_run(cmd, *args, **kwargs):
        if "-b" in cmd or "Q\n" == kwargs.get("input"):
            return subprocess.CompletedProcess(cmd, 0, stdout=archive_output, stderr="")

        stdin = kwargs.get("input", "")
        if stdin.startswith("X pkg/app.py"):
            destination = Path(stdin.splitlines()[1])
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                "def main():\n    print('hello from extracted source')\n",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(cmd, 0, stdout="extracted", stderr="")

        raise AssertionError(f"Unexpected subprocess invocation: {cmd!r} input={stdin!r}")

    output_dir = tmp_path / "pyinstaller_extract_analysis"
    with (
        patch(
            "reveng.app_reverse_engineering.adapters.python.shutil.which",
            return_value="pyi-archive_viewer",
        ),
        patch(
            "reveng.app_reverse_engineering.adapters.python.subprocess.run", side_effect=_fake_run
        ),
    ):
        result = asyncio.run(
            framework.reverse_engineer(
                str(frozen_path),
                str(output_dir),
                language="python",
                max_snippets=6,
            )
        )

    assert result.metadata["frozen_python"]["archive_viewer_available"] is True
    assert result.metadata["frozen_python"]["extracted_entries"] == ["pkg/app.py"]
    assert result.primary_artifacts["extracted_sources"].exists()
    extracted_source = result.primary_artifacts["extracted_sources"] / "pkg" / "app.py"
    assert extracted_source.exists()
    assert result.source_count >= 1
    cli_spec = result.topic_files["cli_and_entrypoints"].read_text(encoding="utf-8")
    assert "main" in cli_spec
    _assert_shared_app_contract(result)


def test_framework_reverse_engineers_dotnet_sample_with_mocked_analyzers(tmp_path: Path):
    framework = create_default_framework()
    assembly_path = tmp_path / "sample.dll"
    assembly_path.write_bytes(b"MZ" + b"\x00" * 128)
    output_dir = tmp_path / "dotnet_analysis"
    il_dir = output_dir / "artifacts" / "dotnet_analysis" / "sample"
    il_dir.mkdir(parents=True, exist_ok=True)
    il_file = il_dir / "sample.il"
    il_file.write_text(
        "\n".join(
            [
                ".assembly sample",
                "{",
                "  .ver 1:2:3:4",
                "}",
                ".namespace Demo.App",
                ".class public auto ansi beforefieldinit Demo.App.Program",
                "{",
                "  .method public static void Main() cil managed",
                "  {",
                "    .entrypoint",
                "  }",
                "}",
            ]
        ),
        encoding="utf-8",
    )
    decompiled_dir = il_dir / "decompiled_csharp"
    decompiled_dir.mkdir(parents=True, exist_ok=True)
    (decompiled_dir / "sample.csproj").write_text(
        "\n".join(
            [
                '<Project Sdk="Microsoft.NET.Sdk">',
                "  <PropertyGroup>",
                "    <TargetFramework>net8.0</TargetFramework>",
                "  </PropertyGroup>",
                "  <ItemGroup>",
                '    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />',
                '    <ProjectReference Include="..\\Shared\\Shared.csproj" />',
                "  </ItemGroup>",
                "</Project>",
            ]
        ),
        encoding="utf-8",
    )
    (decompiled_dir / "Program.cs").write_text(
        "namespace Demo.App; public static class Program { public static void Main() {} }",
        encoding="utf-8",
    )
    (decompiled_dir / "appsettings.json").write_text('{"mode": "demo"}', encoding="utf-8")

    il_result = ILDisassemblyResult(
        assembly=str(assembly_path),
        il_output_file=str(il_file),
        decompiled_output_dir=str(decompiled_dir),
        metadata={
            "has_clr_header": True,
            "architecture": "x64",
            "version": "1.2.3.4",
            "namespaces": ["Demo.App"],
            "types_count": 1,
            "methods_count": 1,
            "entry_point": "Main",
            "obfuscated": False,
            "obfuscator": None,
            "tooling": {
                "ildasm": {"available": True, "used": True, "output": str(il_file)},
                "ilspy": {"available": True, "used": True, "output_dir": str(decompiled_dir)},
            },
        },
        success=True,
        error=None,
    )
    dotnet_result = DotNetAnalysisResult(
        framework_version="8.0",
        runtime_version="8.0.0",
        assembly_name="sample",
        assembly_version="1.2.3.4",
        gui_framework="Console Application",
        dependencies=["System.Console"],
        resources={},
        entry_points=["Main"],
        business_logic={"application_domain": "cli"},
        is_packed=False,
        obfuscation_level="None",
        api_calls=["System.Console.WriteLine"],
        pe_sections={".text": {}},
        analysis_confidence=0.88,
    )

    with (
        patch(
            "reveng.app_reverse_engineering.adapters.dotnet.CSharpILAnalyzer.analyze",
            return_value=il_result,
        ),
        patch(
            "reveng.app_reverse_engineering.adapters.dotnet.DotNetAnalyzer.analyze_assembly",
            return_value=dotnet_result,
        ),
    ):
        result = asyncio.run(
            framework.reverse_engineer(
                str(assembly_path),
                str(output_dir),
                language="dotnet",
                max_snippets=6,
            )
        )

    assert result.language == "dotnet"
    assert result.analysis_file.exists()
    assert result.source_count >= 1
    assert "Main" in result.metadata["entrypoints"]
    assert "System.Console" in result.metadata["dependencies"]
    assert result.metadata["tooling"]["ilspy"]["used"] is True
    assert result.primary_artifacts["il_listing"].exists()
    assert result.primary_artifacts["decompiled_project_manifest"].exists()
    assert result.metadata["decompiled_project"]["project_file_count"] == 1
    assert result.metadata["decompiled_project"]["source_file_count"] >= 1
    assert result.metadata["decompiled_project"]["package_references"] == ["Newtonsoft.Json"]
    assert result.metadata["decompiled_project"]["project_references"] == [
        "../Shared/Shared.csproj"
    ]
    spec_text = result.topic_files["assemblies_and_types"].read_text(encoding="utf-8")
    assert "Demo.App.Program" in spec_text or "Program" in spec_text
    runtime_spec = result.topic_files["runtime_and_obfuscation"].read_text(encoding="utf-8")
    assert "ILSpy" in runtime_spec
    assert "Newtonsoft.Json" in runtime_spec
    _assert_shared_app_contract(result)


def test_framework_dotnet_adapter_emits_fallback_report_without_external_tools(tmp_path: Path):
    framework = create_default_framework()
    assembly_path = tmp_path / "fallback.dll"
    assembly_path.write_bytes(b"MZ" + b"\x00" * 128)
    output_dir = tmp_path / "fallback_dotnet_analysis"

    il_result = ILDisassemblyResult(
        assembly=str(assembly_path),
        il_output_file="",
        decompiled_output_dir=None,
        metadata={"has_clr_header": True, "architecture": "x86"},
        success=False,
        error="ildasm not available",
    )
    dotnet_result = DotNetAnalysisResult(
        framework_version="Unknown",
        runtime_version="Unknown",
        assembly_name="fallback",
        assembly_version="Unknown",
        gui_framework="Unknown",
        dependencies=[],
        resources={},
        entry_points=[],
        business_logic={},
        is_packed=False,
        obfuscation_level="Unknown",
        api_calls=[],
        pe_sections={},
        analysis_confidence=0.2,
    )

    with (
        patch(
            "reveng.app_reverse_engineering.adapters.dotnet.CSharpILAnalyzer.analyze",
            return_value=il_result,
        ),
        patch(
            "reveng.app_reverse_engineering.adapters.dotnet.DotNetAnalyzer.analyze_assembly",
            return_value=dotnet_result,
        ),
    ):
        result = asyncio.run(
            framework.reverse_engineer(
                str(assembly_path),
                str(output_dir),
                language="dotnet",
                max_snippets=6,
            )
        )

    assert result.language == "dotnet"
    assert result.analysis_file.exists()
    assert result.source_count >= 1
    assert any("ildasm not available" in warning for warning in result.warnings)
    _assert_shared_app_contract(result)


def test_dotnet_detector_recognizes_checked_in_managed_pe_fixture():
    fixture = Path("test_samples/sample_dotnet.dll").resolve()

    is_dotnet, metadata = DotNetDetector.is_dotnet_assembly(str(fixture))

    assert is_dotnet is True
    assert metadata["has_clr_header"] is True


def test_csharp_il_analyzer_records_external_tooling_status(tmp_path: Path):
    assembly_path = tmp_path / "managed.dll"
    assembly_path.write_bytes(b"MZ" + b"\x00" * 256)
    output_dir = tmp_path / "csharp_tooling"
    analyzer = CSharpILAnalyzer(output_dir=str(output_dir))

    def _fake_assembly_info(file_path: str):
        return True, {"has_clr_header": True, "architecture": "x64"}

    def _fake_disassemble(assembly: str, output_file: str) -> bool:
        Path(output_file).write_text(
            "\n".join(
                [
                    ".assembly managed",
                    "{",
                    "  .ver 1:0:0:0",
                    "}",
                    ".namespace Demo.Tooling",
                    ".class public auto ansi Demo.Tooling.Program",
                    "{",
                    "  .method public static void Main() cil managed",
                    "  {",
                    "    .entrypoint",
                    "  }",
                    "}",
                ]
            ),
            encoding="utf-8",
        )
        return True

    def _fake_decompile(assembly: str, decompiled_dir: str) -> bool:
        directory = Path(decompiled_dir)
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "Program.cs").write_text(
            "namespace Demo.Tooling; public static class Program { public static void Main() {} }",
            encoding="utf-8",
        )
        return True

    with (
        patch.object(analyzer.detector, "is_dotnet_assembly", side_effect=_fake_assembly_info),
        patch.object(analyzer.ildasm, "disassemble", side_effect=_fake_disassemble),
        patch.object(analyzer.ildasm, "ildasm_path", tmp_path / "ildasm.exe"),
        patch.object(analyzer.ilspy, "ilspy_available", True),
        patch.object(analyzer.ilspy, "decompile", side_effect=_fake_decompile),
    ):
        result = analyzer.analyze(str(assembly_path))

    assert result.success is True
    assert result.metadata["tooling"]["ildasm"]["available"] is True
    assert result.metadata["tooling"]["ildasm"]["used"] is True
    assert result.metadata["tooling"]["ilspy"]["available"] is True
    assert result.metadata["tooling"]["ilspy"]["used"] is True
    assert result.metadata["tooling"]["ilspy"]["output_dir"].endswith("decompiled_csharp")
