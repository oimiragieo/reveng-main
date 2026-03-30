"""Unit tests for the Ghidra scripting engine integration."""

from pathlib import Path
from subprocess import CompletedProcess, TimeoutExpired
from unittest.mock import MagicMock, patch

from reveng.ghidra.scripting_engine import (
    GhidraScriptingEngine,
    ScriptExecutionResult,
    ScriptResult,
)


def _make_engine(tmp_path: Path) -> GhidraScriptingEngine:
    ghidra_root = tmp_path / "ghidra"
    (ghidra_root / "support").mkdir(parents=True)
    (ghidra_root / "support" / "analyzeHeadless.bat").write_text("")

    with patch("reveng.core.dependency_manager.DependencyManager") as dm_cls:
        dm = MagicMock()
        dm.get_tool_path.return_value = str(ghidra_root)
        dm_cls.return_value = dm
        engine = GhidraScriptingEngine()

    return engine


def test_execute_python_script_success(tmp_path: Path):
    engine = _make_engine(tmp_path)
    script = str(tmp_path / "script.py")
    binary = str(tmp_path / "binary.bin")

    with patch(
        "reveng.ghidra.scripting_engine.subprocess.run",
        return_value=CompletedProcess([], 0, "ok", ""),
    ):
        result = engine.execute_python_script(script, binary)

    assert isinstance(result, ScriptExecutionResult)
    assert result.result == ScriptResult.SUCCESS
    assert result.output == "ok"


def test_execute_python_script_handles_timeout(tmp_path: Path):
    engine = _make_engine(tmp_path)
    script = str(tmp_path / "script.py")
    binary = str(tmp_path / "binary.bin")

    with patch(
        "reveng.ghidra.scripting_engine.subprocess.run",
        side_effect=TimeoutExpired(cmd=["ghidra"], timeout=1),
    ):
        result = engine.execute_python_script(script, binary)

    assert result.result == ScriptResult.TIMEOUT
    assert result.error == "Script execution timed out"


def test_execute_java_script_failure(tmp_path: Path):
    engine = _make_engine(tmp_path)
    with patch(
        "reveng.ghidra.scripting_engine.subprocess.run",
        return_value=CompletedProcess([], 1, "out", "err"),
    ):
        result = engine.execute_java_script("script.java", "binary.bin")

    assert result.result == ScriptResult.FAILURE
    assert result.error == "err"

    def test_script_engine_with_large_binary(self):
        """Test script engine with large binary"""
        # Create large test binary
        test_binary = self.temp_dir / "large.exe"
        test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000000)  # 1MB file

        # Create mock script
        script_path = self.ghidra_scripts_path / "large_script.py"
        script_path.write_text('print("Large binary processed")')

        # Execute script
        result = self.script_engine.execute_python_script(script_path, test_binary, "large_project")

        assert isinstance(result, ScriptResult)
        assert result.success is True
        assert "Large binary processed" in result.stdout
