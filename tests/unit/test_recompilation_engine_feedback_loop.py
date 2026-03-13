"""Tests for compiler-in-the-loop retry behavior in the recompilation engine."""

import os
from pathlib import Path

import pytest

from reveng.ai.recompilation_engine import BinaryRecompilationEngine


class DummyGemini:
    """Simple Gemini stub that records prompts and returns canned responses."""

    def __init__(self, responses):
        self._responses = list(responses)
        self.prompts = []

    def is_available(self) -> bool:
        return True

    async def _generate_async(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self._responses:
            raise AssertionError("No stubbed Gemini responses remaining")
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_compile_with_feedback_loop_retries_and_includes_stderr(tmp_path: Path):
    gemini = DummyGemini(["```c\nint main(void) { return 0; }\n```"])
    engine = BinaryRecompilationEngine(
        gemini_engine=gemini,
        work_dir=tmp_path,
        max_compilation_retries=2,
    )

    source_file = tmp_path / "reconstructed.c"
    source_file.write_text("int main(void) { return 0 }\n", encoding="utf-8")

    compiler_results = iter(
        [
            {
                "success": False,
                "stdout": "",
                "stderr": "reconstructed.c:1:27: error: expected ';' before '}' token",
                "returncode": 1,
                "command": ["gcc", "-o", "reconstructed_gcc", str(source_file)],
                "non_retryable": False,
            },
            {
                "success": True,
                "stdout": "",
                "stderr": "",
                "returncode": 0,
                "command": ["gcc", "-o", "reconstructed_gcc", str(source_file)],
                "non_retryable": False,
            },
        ]
    )

    async def fake_run_compiler_attempt(compiler_name: str, current_source: Path, output_binary: Path):
        return next(compiler_results)

    engine._run_compiler_attempt = fake_run_compiler_attempt  # type: ignore[method-assign]

    report = await engine._compile_with_feedback_loop(
        "gcc",
        source_file,
        tmp_path,
        {"cfg_context_text": "main has one block"},
    )

    expected_binary = tmp_path / "reconstructed_gcc"
    if os.name == "nt":
        expected_binary = expected_binary.with_suffix(".exe")

    assert report["status"] == "success"
    assert report["binary_path"] == str(expected_binary)
    assert report["total_attempts"] == 2
    assert report["attempts"][0]["stderr"].startswith("reconstructed.c:1:27")
    assert report["attempts"][0]["feedback_applied"] is True
    assert "expected ';' before '}' token" in gemini.prompts[0]
    assert source_file.read_text(encoding="utf-8") == "int main(void) { return 0; }\n"


@pytest.mark.asyncio
async def test_compile_with_feedback_loop_stops_at_retry_limit(tmp_path: Path):
    gemini = DummyGemini(
        [
            "```c\nint main(void) { return 0 }\n``'",
            "```c\nint main(void) { return 0 }\n```",
        ]
    )
    engine = BinaryRecompilationEngine(
        gemini_engine=gemini,
        work_dir=tmp_path,
        max_compilation_retries=2,
    )

    source_file = tmp_path / "reconstructed.c"
    source_file.write_text("int main(void) { return 0 }\n", encoding="utf-8")

    failures = iter(
        [
            "error: expected ';' before '}' token",
            "error: expected ';' before '}' token",
            "error: expected ';' before '}' token",
        ]
    )

    async def fake_run_compiler_attempt(compiler_name: str, current_source: Path, output_binary: Path):
        return {
            "success": False,
            "stdout": "",
            "stderr": next(failures),
            "returncode": 1,
            "command": [compiler_name, "-o", str(output_binary), str(current_source)],
            "non_retryable": False,
        }

    engine._run_compiler_attempt = fake_run_compiler_attempt  # type: ignore[method-assign]

    report = await engine._compile_with_feedback_loop("gcc", source_file, tmp_path, {})

    assert report["status"] == "failed"
    assert report["failure_reason"] == "max_retries_exceeded"
    assert report["max_retries_exceeded"] is True
    assert report["binary_path"] is None
    assert report["total_attempts"] == 3
    assert len(report["attempts"]) == 3
    assert sum(1 for attempt in report["attempts"] if attempt["feedback_applied"]) == 2


@pytest.mark.asyncio
async def test_compile_with_feedback_loop_zero_retries_stops_after_first_failure(
    tmp_path: Path,
):
    gemini = DummyGemini(["```c\nint main(void) { return 0; }\n```"])
    engine = BinaryRecompilationEngine(
        gemini_engine=gemini,
        work_dir=tmp_path,
        max_compilation_retries=0,
    )

    source_file = tmp_path / "reconstructed.c"
    source_file.write_text("int main(void) { return 0 }\n", encoding="utf-8")

    async def fake_run_compiler_attempt(compiler_name: str, current_source: Path, output_binary: Path):
        return {
            "success": False,
            "stdout": "",
            "stderr": "error: expected ';' before '}' token",
            "returncode": 1,
            "command": [compiler_name, "-o", str(output_binary), str(current_source)],
            "non_retryable": False,
        }

    engine._run_compiler_attempt = fake_run_compiler_attempt  # type: ignore[method-assign]

    report = await engine._compile_with_feedback_loop("gcc", source_file, tmp_path, {})

    assert report["status"] == "failed"
    assert report["failure_reason"] == "max_retries_exceeded"
    assert report["max_retries_exceeded"] is True
    assert report["total_attempts"] == 1
    assert report["attempts"][0]["feedback_applied"] is False
    assert gemini.prompts == []


@pytest.mark.asyncio
async def test_compile_with_feedback_loop_handles_empty_llm_response(tmp_path: Path):
    gemini = DummyGemini(["   "])
    engine = BinaryRecompilationEngine(
        gemini_engine=gemini,
        work_dir=tmp_path,
        max_compilation_retries=1,
    )

    source_file = tmp_path / "reconstructed.c"
    source_file.write_text("int main(void) { return 0 }\n", encoding="utf-8")

    async def fake_run_compiler_attempt(compiler_name: str, current_source: Path, output_binary: Path):
        return {
            "success": False,
            "stdout": "",
            "stderr": "error: expected ';' before '}' token",
            "returncode": 1,
            "command": [compiler_name, "-o", str(output_binary), str(current_source)],
            "non_retryable": False,
        }

    engine._run_compiler_attempt = fake_run_compiler_attempt  # type: ignore[method-assign]

    report = await engine._compile_with_feedback_loop(
        "gcc",
        source_file,
        tmp_path,
        {"cfg_context_text": "main has one block"},
    )

    assert report["status"] == "failed"
    assert report["failure_reason"] == "llm_feedback_unavailable"
    assert report["max_retries_exceeded"] is False
    assert report["total_attempts"] == 1
    assert report["attempts"][0]["feedback_applied"] is False
    assert "expected ';' before '}' token" in gemini.prompts[0]


@pytest.mark.asyncio
async def test_compile_with_feedback_loop_stops_on_non_retryable_failure(tmp_path: Path):
    gemini = DummyGemini(["```c\nint main(void) { return 0; }\n```"])
    engine = BinaryRecompilationEngine(
        gemini_engine=gemini,
        work_dir=tmp_path,
        max_compilation_retries=2,
    )

    source_file = tmp_path / "reconstructed.c"
    source_file.write_text("int main(void) { return 0 }\n", encoding="utf-8")

    async def fake_run_compiler_attempt(compiler_name: str, current_source: Path, output_binary: Path):
        return {
            "success": False,
            "stdout": "",
            "stderr": "GCC not found in PATH",
            "returncode": None,
            "command": [compiler_name, "-o", str(output_binary), str(current_source)],
            "non_retryable": True,
        }

    engine._run_compiler_attempt = fake_run_compiler_attempt  # type: ignore[method-assign]

    report = await engine._compile_with_feedback_loop("gcc", source_file, tmp_path, {})

    assert report["status"] == "failed"
    assert report["failure_reason"] == "compiler_unavailable"
    assert report["max_retries_exceeded"] is False
    assert report["total_attempts"] == 1
    assert report["attempts"][0]["returncode"] is None
    assert gemini.prompts == []


@pytest.mark.asyncio
async def test_full_pipeline_returns_graceful_failure_report_when_compilation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source_file = tmp_path / "reconstructed.c"
    source_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    engine = BinaryRecompilationEngine(
        ghidra_engine=object(),
        gemini_engine=None,
        work_dir=tmp_path,
        max_compilation_retries=1,
    )

    async def fake_phase1(binary_path: str, output_dir: Path):
        return {"cfg_artifacts": {}, "cfg_summary": {}, "functions": []}

    async def fake_phase2(ghidra_data, output_dir: Path):
        return {"c": str(source_file)}

    async def fake_phase3(source_files, output_dir: Path, ghidra_data=None):
        return {
            "compiled_binaries": {},
            "reports": {
                "c_gcc": {
                    "status": "failed",
                    "failure_reason": "max_retries_exceeded",
                    "max_retries_exceeded": True,
                    "attempts": [{"attempt": 1, "stderr": "error: boom"}],
                    "total_attempts": 1,
                    "binary_path": None,
                    "final_source_file": str(source_file),
                }
            },
            "source_files": source_files,
        }

    async def unexpected(*args, **kwargs):
        raise AssertionError("Later pipeline phases should not run after compilation failure")

    monkeypatch.setattr(engine, "_phase1_decompilation", fake_phase1)
    monkeypatch.setattr(engine, "_phase2_reconstruction", fake_phase2)
    monkeypatch.setattr(engine, "_phase3_compilation", fake_phase3)
    monkeypatch.setattr(engine, "_phase4_validation", unexpected)
    monkeypatch.setattr(engine, "_phase5_security_analysis", unexpected)
    monkeypatch.setattr(engine, "_phase6_exploit_generation", unexpected)

    result = await engine.full_reconstruction_pipeline("sample.exe", tmp_path / "output")

    assert result["status"] == "failed"
    assert result["error"] == "Compilation failed for all configured compilers"
    assert result["compiled_binaries"] == {}
    assert result["compilation_reports"]["c_gcc"]["failure_reason"] == "max_retries_exceeded"
