"""Tests for compiler-in-the-loop retry behavior in the recompilation engine."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from reveng.ai.recompilation_engine import BinaryRecompilationEngine
from reveng.tools.binary.validation_config import ValidationConfig, ValidationMode


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

    async def fake_run_compiler_attempt(
        compiler_name: str, current_source: Path, output_binary: Path
    ):
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

    async def fake_run_compiler_attempt(
        compiler_name: str, current_source: Path, output_binary: Path
    ):
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

    async def fake_run_compiler_attempt(
        compiler_name: str, current_source: Path, output_binary: Path
    ):
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

    async def fake_run_compiler_attempt(
        compiler_name: str, current_source: Path, output_binary: Path
    ):
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

    async def fake_run_compiler_attempt(
        compiler_name: str, current_source: Path, output_binary: Path
    ):
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
    assert result["equivalence_validation"]["equivalence_level"] == "not_recompiled"
    assert result["equivalence_validation"]["status"] == "blocked"


@pytest.mark.asyncio
async def test_full_pipeline_surfaces_differential_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    source_file = tmp_path / "reconstructed.c"
    source_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    rebuilt_binary = tmp_path / "reconstructed_gcc.exe"
    rebuilt_binary.write_bytes(b"MZ")

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
            "compiled_binaries": {"c_gcc": str(rebuilt_binary)},
            "reports": {
                "c_gcc": {
                    "status": "success",
                    "binary_path": str(rebuilt_binary),
                }
            },
            "source_files": source_files,
        }

    async def fake_phase4(original_binary: str, compiled_binaries, ghidra_data):
        return {
            "similarity_score": 1.0,
            "tests": [{"target": "c_gcc", "tests_passed": 1, "tests_failed": 0}],
            "differential_validation": {
                "status": "pass",
                "mode": "checksum",
                "summary": "Differential validation passed.",
                "checks": [],
                "targets": [],
                "evidence": {"target_count": 1},
            },
        }

    async def fake_phase5(source_files):
        return []

    async def fake_phase6(vulnerabilities, source_files, compiled_binaries):
        return []

    monkeypatch.setattr(engine, "_phase1_decompilation", fake_phase1)
    monkeypatch.setattr(engine, "_phase2_reconstruction", fake_phase2)
    monkeypatch.setattr(engine, "_phase3_compilation", fake_phase3)
    monkeypatch.setattr(engine, "_phase4_validation", fake_phase4)
    monkeypatch.setattr(engine, "_phase5_security_analysis", fake_phase5)
    monkeypatch.setattr(engine, "_phase6_exploit_generation", fake_phase6)

    result = await engine.full_reconstruction_pipeline("sample.exe", tmp_path / "output")

    assert result["status"] == "success"
    assert result["differential_validation"]["status"] == "pass"
    assert result["validation_results"]["differential_validation"]["mode"] == "checksum"


@pytest.mark.asyncio
async def test_phase4_validation_emits_native_differential_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    original_binary = tmp_path / "original.exe"
    rebuilt_binary = tmp_path / "rebuilt.exe"
    original_binary.write_bytes(b"MZOR")
    rebuilt_binary.write_bytes(b"MZRB")

    import reveng.tools.binary.validation_manifest_loader as validation_manifest_loader
    import reveng.tools.core.binary_validator as core_binary_validator

    monkeypatch.setattr(
        validation_manifest_loader,
        "load_validation_manifest",
        lambda binary_name: ValidationConfig(mode=ValidationMode.CHECKSUM),
    )
    monkeypatch.setattr(
        core_binary_validator.BinaryValidator,
        "validate_rebuild",
        lambda self, original, rebuilt, smoke_tests=None: {
            "original": {"exists": True, "size": 100},
            "rebuilt": {"exists": True, "size": 104},
            "comparison": {
                "size_match": False,
                "size_diff": 4,
                "checksum_match": False,
                "sections": {".text": "match", ".rdata": "match"},
            },
            "smoke_tests": {},
        },
    )

    validation = await engine._phase4_validation(
        str(original_binary),
        {"c_gcc": str(rebuilt_binary)},
        {"functions": []},
    )

    differential = validation["differential_validation"]

    assert differential["status"] == "pass"
    assert differential["mode"] == "checksum"
    assert differential["evidence"]["target_count"] == 1
    assert any(check["kind"] == "size_similarity" for check in differential["checks"])
    assert any(check["kind"] == "section_layout" for check in differential["checks"])


def test_recompilation_equivalence_summary_reports_compile_only_candidate(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    summary = engine._build_recompilation_equivalence_validation_summary(
        {
            "c_gcc": {
                "status": "success",
                "binary_path": str(tmp_path / "reconstructed_gcc.exe"),
            },
            "c_clang": {
                "status": "failed",
                "failure_reason": "compiler_unavailable",
            },
        },
        {},
    )

    assert summary["dimension"] == "equivalence_validation"
    assert summary["status"] == "candidate"
    assert summary["equivalence_level"] == "compile_only_candidate"
    assert summary["confidence"] == "low"
    assert summary["evidence"]["successful_compiler_count"] == 1
    assert any(
        item["kind"] == "characterization_smoke_test" for item in summary["recommended_validations"]
    )


def test_recompilation_equivalence_summary_reports_behavioral_candidate(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    summary = engine._build_recompilation_equivalence_validation_summary(
        {
            "c_gcc": {
                "status": "success",
                "binary_path": str(tmp_path / "reconstructed_gcc.exe"),
            }
        },
        {
            "similarity_score": 1.0,
            "tests": [
                {
                    "target": "c_gcc",
                    "tests_passed": 1,
                    "tests_failed": 0,
                }
            ],
        },
    )

    assert summary["status"] == "candidate"
    assert summary["equivalence_level"] == "behavioral_candidate"
    assert summary["confidence"] == "medium"


def test_recompilation_equivalence_summary_downgrades_on_differential_warnings(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    summary = engine._build_recompilation_equivalence_validation_summary(
        {
            "c_gcc": {
                "status": "success",
                "binary_path": str(tmp_path / "reconstructed_gcc.exe"),
            }
        },
        {
            "similarity_score": 1.0,
            "tests": [
                {
                    "target": "c_gcc",
                    "tests_passed": 1,
                    "tests_failed": 0,
                }
            ],
            "differential_validation": {
                "status": "pass_with_warnings",
            },
        },
    )

    assert summary["status"] == "candidate_with_warnings"
    assert summary["equivalence_level"] == "structural_candidate"
    assert summary["evidence"]["differential_status"] == "pass_with_warnings"
    assert summary["evidence"]["validation_failure_count"] == 0


@pytest.mark.asyncio
async def test_reconstruct_c_code_includes_ghidra_compatibility_prelude(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    reconstructed = await engine._reconstruct_c_code(
        {
            "functions": [
                {"name": "FUN_140001000", "signature": "undefined8 __fastcall FUN_140001000(void)"}
            ],
            "decompiled_code": {
                "0x140001000": "undefined8 __fastcall FUN_140001000(void) { return 0; }"
            },
        }
    )

    assert "#include <stdint.h>" in reconstructed
    assert "typedef uint64_t undefined8;" in reconstructed
    assert "typedef uint64_t uint7;" in reconstructed
    assert "typedef void code();" in reconstructed
    assert "typedef union {" in reconstructed
    assert "ghidra_uint128 whole;" in reconstructed
    assert "uint64_t whole;" in reconstructed
    assert "#define __fastcall" in reconstructed
    assert "#define SUB81(value, offset)" in reconstructed
    assert "#define SUB82(value, offset)" in reconstructed
    assert "#define SUB84(value, offset)" in reconstructed
    assert "#define ZEXT216(value)" in reconstructed
    assert "#define ZEXT816(value)" in reconstructed
    assert "#define SUB158(value, offset)" in reconstructed
    assert "#define SUB164(value, offset)" in reconstructed
    assert "#define ZEXT716(value)" in reconstructed
    assert "#define CONCAT11(high, low)" in reconstructed
    assert "#define CONCAT12(high, low)" in reconstructed
    assert "#define CONCAT13(high, low)" in reconstructed
    assert "#define CONCAT14(high, low)" in reconstructed
    assert "#define CONCAT15(high, low)" in reconstructed
    assert "#define CONCAT25(high, low)" in reconstructed
    assert "#define CONCAT34(high, low)" in reconstructed
    assert "#define CONCAT41(high, low)" in reconstructed
    assert "#define CONCAT52(high, low)" in reconstructed
    assert "#define CONCAT62(high, low)" in reconstructed
    assert "#define CONCAT31(high, low)" in reconstructed
    assert "#define CONCAT16(high, low)" in reconstructed
    assert "#define CONCAT21(high, low)" in reconstructed
    assert "#define CONCAT22(high, low)" in reconstructed
    assert "#define CONCAT24(high, low)" in reconstructed
    assert "#define CONCAT26(high, low)" in reconstructed
    assert "#define CONCAT35(high, low)" in reconstructed
    assert "#define CONCAT51(high, low)" in reconstructed
    assert "#define CONCAT53(high, low)" in reconstructed
    assert "#define CONCAT72(high, low)" in reconstructed
    assert "typedef struct {" in reconstructed
    assert "uint32_t LowPart;" in reconstructed
    assert "int32_t HighPart;" in reconstructed
    assert "} _struct_19;" in reconstructed
    assert "#define GHIDRA_LARGE_INTEGER(value)" in reconstructed
    assert "#define SEXT816(value)" in reconstructed
    assert "typedef uint64_t uint6;" in reconstructed
    assert "typedef uint32_t uint3;" in reconstructed
    assert "typedef int32_t int3;" in reconstructed
    assert "typedef ghidra_uint128 unkuint10;" in reconstructed
    assert "typedef int __scrt_module_type;" in reconstructed
    assert "typedef uintptr_t (*ghidra_indirect_fn_0)(void);" in reconstructed
    assert "typedef uintptr_t (*ghidra_indirect_fn)(uintptr_t, ...);" in reconstructed
    assert "#define NAN(value) (((double)(value)) != ((double)(value)))" in reconstructed
    assert "undefined8 __fastcall FUN_140001000(void);" in reconstructed


@pytest.mark.asyncio
async def test_reconstruct_c_code_sanitizes_invalid_function_identifiers(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    reconstructed = await engine._reconstruct_c_code(
        {
            "functions": [
                {
                    "name": "read_to_end<std::io::stdio::StdinRaw>",
                    "signature": "void __cdecl read_to_end<std::io::stdio::StdinRaw>(void)",
                },
                {
                    "name": ".text$unlikely",
                    "signature": "undefined __fastcall .text$unlikely(void)",
                },
                {
                    "name": "_onexit",
                    "signature": "_func___cdecl_int * __cdecl _onexit(_func___cdecl_int * param_1)",
                },
            ],
            "decompiled_code": {
                "0x1": "void __cdecl read_to_end<std::io::stdio::StdinRaw>(void) { .text$unlikely(); }",
                "0x2": "undefined __fastcall .text$unlikely(void) { return 0; }",
                "0x3": "_func___cdecl_int * __cdecl _onexit(_func___cdecl_int * param_1) { return param_1; }",
            },
        }
    )

    assert "read_to_end_std_io_stdio_StdinRaw" in reconstructed
    assert "_text_unlikely" in reconstructed
    assert "_onexit" in reconstructed
    assert "read_to_end<std::io::stdio::StdinRaw>" not in reconstructed
    assert ".text$unlikely" not in reconstructed


@pytest.mark.asyncio
async def test_reconstruct_c_code_preserves_indirect_fn_typedef_and_injects_generated_preludes(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    reconstructed = await engine._reconstruct_c_code(
        {
            "functions": [
                {
                    "name": "FUN_140001000",
                    "signature": "undefined8 __fastcall FUN_140001000(code * pcVar34)",
                }
            ],
            "decompiled_code": {
                "0x140001000": (
                    "undefined8 __fastcall FUN_140001000(code * pcVar34) {\n"
                    "  undefined8 value;\n"
                    "  value = _UNK_1400abcd;\n"
                    "  core_str_converts_from_utf8();\n"
                    "  return (*pcVar34)();\n"
                    "}\n"
                )
            },
        }
    )

    assert "typedef uintptr_t (*ghidra_indirect_fn_0)(void);" in reconstructed
    assert "typedef uintptr_t (*ghidra_indirect_fn)(uintptr_t, ...);" in reconstructed
    assert "static uint64_t _UNK_1400abcd = 0;" in reconstructed
    assert "#define core_str_converts_from_utf8(...) ((uint64_t)0)" in reconstructed
    assert "return ((ghidra_indirect_fn_0)pcVar34)();" in reconstructed


@pytest.mark.asyncio
async def test_reconstruct_c_code_skips_conflicting_and_duplicate_prototypes(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    reconstructed = await engine._reconstruct_c_code(
        {
            "functions": [
                {
                    "name": "_onexit",
                    "signature": "_func___cdecl_int * __cdecl _onexit(_func___cdecl_int * param_1)",
                },
                {
                    "name": "memcpy",
                    "signature": "void * __cdecl memcpy(void * _Dst, void * _Src, size_t _Size)",
                },
                {
                    "name": "operator delete",
                    "signature": "void __cdecl operator delete(void * param_1)",
                },
                {"name": "dup.one", "signature": "void __cdecl dup.one(void)"},
                {"name": "dup$one", "signature": "void __cdecl dup$one(void)"},
            ],
            "decompiled_code": {
                "0x1": "_func___cdecl_int * __cdecl _onexit(_func___cdecl_int * param_1) { return param_1; }",
                "0x2": "void * __cdecl memcpy(void * _Dst, void * _Src, size_t _Size) { return _Dst; }",
                "0x3": "void __cdecl operator delete(void * param_1) { }",
                "0x4": "void __cdecl dup.one(void) { }",
                "0x5": "void __cdecl dup$one(void) { }",
            },
        }
    )

    assert "_onexit(_func___cdecl_int * param_1);" not in reconstructed
    assert "memcpy(void * _Dst, void * _Src, size_t _Size);" not in reconstructed
    assert "operator_delete(void * param_1);" not in reconstructed
    assert reconstructed.count("void __cdecl dup_one(void);") == 1
    assert "void __cdecl dup_one(void) { }" in reconstructed
    assert "void __cdecl dup_one_2(void) { }" in reconstructed


@pytest.mark.asyncio
async def test_reconstruct_c_code_reports_postprocessing_stages(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    stages = []
    reconstructed = await engine._reconstruct_c_code(
        {
            "functions": [
                {"name": "FUN_140001000", "signature": "undefined8 __fastcall FUN_140001000(void)"}
            ],
            "decompiled_code": {
                "0x140001000": "undefined8 __fastcall FUN_140001000(void) { return 0; }"
            },
        },
        stage_callback=stages.append,
    )

    assert "undefined8 __fastcall FUN_140001000(void) { return 0; }" in reconstructed
    assert stages[:3] == [
        "whole_source_normalization",
        "prototype_relaxation",
        "integer_pointer_access_normalization",
    ]
    assert "helper_alias_qualification" in stages
    assert "void_pointer_index_normalization" in stages
    assert "late_pointer_param_normalization" in stages
    assert "late_uintptr_param_normalization" in stages
    assert "late_void_pointer_index_normalization" in stages
    assert "late_pointer_integer_assignment_normalization" in stages
    assert "late_non_code_pointer_retargeting" in stages
    assert "final_void_pointer_index_normalization" in stages
    assert "bare_return_normalization" in stages
    assert "uintptr_param_normalization" in stages
    assert "generated_prelude_build" in stages


@pytest.mark.asyncio
async def test_reconstruct_c_code_reports_stage_timings(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    stage_timings = {}
    reconstructed = await engine._reconstruct_c_code(
        {
            "functions": [
                {"name": "FUN_140001000", "signature": "undefined8 __fastcall FUN_140001000(void)"}
            ],
            "decompiled_code": {
                "0x140001000": "undefined8 __fastcall FUN_140001000(void) { return 0; }"
            },
        },
        stage_timing_callback=stage_timings.__setitem__,
    )

    assert "undefined8 __fastcall FUN_140001000(void) { return 0; }" in reconstructed
    assert "whole_source_normalization" in stage_timings
    assert "generated_prelude_build" in stage_timings
    assert all(duration >= 0 for duration in stage_timings.values())


@pytest.mark.asyncio
async def test_reconstruct_c_code_writes_opt_in_suspicious_function_stage_dumps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )
    monkeypatch.setenv("REVENG_DEBUG_FUNCTION_STAGES", "1")

    output_dir = tmp_path / "analysis"
    output_dir.mkdir()
    await engine._reconstruct_c_code(
        {
            "functions": [
                {"name": "FUN_140001000", "signature": "void __fastcall FUN_140001000(void)"}
            ],
            "decompiled_code": {
                "0x140001000": "void __fastcall FUN_140001000(void) { FUN_1GHIDRA_U64(); }"
            },
        },
        debug_output_dir=output_dir,
    )

    dump_dir = output_dir / "function_stage_dumps" / "0x140001000"
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["address"] == "0x140001000"
    assert manifest["reason"].startswith("suspicious_marker:")
    assert (dump_dir / "raw.c").read_text(encoding="utf-8").strip().endswith("FUN_1GHIDRA_U64(); }")
    assert (dump_dir / "semantic.c").exists()
    assert (dump_dir / "labels_restored.c").exists()


@pytest.mark.asyncio
async def test_reconstruct_c_code_writes_opt_in_whole_source_stage_dumps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )
    monkeypatch.setenv("REVENG_DEBUG_WHOLE_SOURCE_STAGES", "1")

    def inject_suspicious_marker(source: str) -> str:
        return source.replace("return 0;", "FUN_140GHIDRA_U64(); return 0;")

    monkeypatch.setattr(engine, "_qualify_unresolved_function_aliases", inject_suspicious_marker)

    output_dir = tmp_path / "analysis"
    output_dir.mkdir()
    await engine._reconstruct_c_code(
        {
            "functions": [
                {"name": "FUN_140001000", "signature": "void __fastcall FUN_140001000(void)"}
            ],
            "decompiled_code": {"0x140001000": "void __fastcall FUN_140001000(void) { return 0; }"},
        },
        debug_output_dir=output_dir,
    )

    dump_dir = output_dir / "whole_source_stage_dumps"
    manifest = json.loads((dump_dir / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["first_suspicious_stage"] == "helper_alias_qualification"
    assert manifest["reason"].startswith("suspicious_marker:")
    assert (dump_dir / "assembled.c").exists()
    assert "FUN_140GHIDRA_U64();" in (dump_dir / "helper_alias_qualification.c").read_text(
        encoding="utf-8"
    )


@pytest.mark.asyncio
async def test_reconstruct_c_code_reapplies_helper_alias_qualification_after_generated_preludes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    original_qualifier = engine._qualify_unresolved_function_aliases

    def delayed_alias(source: str) -> str:
        if "generated_marker();" not in source:
            return source
        return original_qualifier(source)

    monkeypatch.setattr(engine, "_qualify_unresolved_function_aliases", delayed_alias)
    monkeypatch.setattr(engine, "_build_generated_symbol_prelude", lambda source: "")
    monkeypatch.setattr(
        engine,
        "_build_generated_helper_prelude",
        lambda source: "void generated_marker(void);\n",
    )

    reconstructed = await engine._reconstruct_c_code(
        {
            "functions": [
                {
                    "name": "core_fmt_num_imp_impl_16_fmt",
                    "signature": "void __cdecl core_fmt_num_imp_impl_16_fmt(void)",
                },
                {
                    "name": "core_fmt_num_impl_16_fmt",
                    "signature": "void __cdecl core_fmt_num_impl_16_fmt(void)",
                },
                {
                    "name": "std_io_error_impl_16_fmt",
                    "signature": "void __cdecl std_io_error_impl_16_fmt(void)",
                },
                {
                    "name": "std_io_error_impl_0_fmt",
                    "signature": "void __cdecl std_io_error_impl_0_fmt(void)",
                },
            ],
            "decompiled_code": {
                "0x1": "void __cdecl core_fmt_num_imp_impl_16_fmt(void) { return; }",
                "0x2": "void __cdecl core_fmt_num_impl_16_fmt(void) { return; }",
                "0x3": "void __cdecl std_io_error_impl_16_fmt(void) { return; }",
                "0x4": (
                    "void __cdecl std_io_error_impl_0_fmt(void)\n"
                    "{\n"
                    "  generated_marker();\n"
                    "  impl_16_fmt();\n"
                    "}\n"
                ),
            },
        }
    )

    assert "std_io_error_impl_16_fmt();" in reconstructed
    assert " impl_16_fmt();" not in reconstructed


@pytest.mark.asyncio
async def test_reconstruct_c_code_reapplies_void_pointer_indexing_after_late_signature_changes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    def introduce_late_void_pointer_signature(source: str) -> str:
        return source.replace(
            "void FUN_1400083e0(uintptr_t param_1, ulonglong *param_2)\n",
            "void FUN_1400083e0(void *param_1, ulonglong *param_2)\n",
        )

    monkeypatch.setattr(
        engine,
        "_normalize_pointer_arguments_for_uintptr_params",
        introduce_late_void_pointer_signature,
    )

    reconstructed = await engine._reconstruct_c_code(
        {
            "functions": [
                {
                    "name": "FUN_1400083e0",
                    "signature": "void FUN_1400083e0(uintptr_t param_1, ulonglong *param_2)",
                }
            ],
            "decompiled_code": {
                "0x1400083e0": (
                    "void FUN_1400083e0(uintptr_t param_1, ulonglong *param_2)\n"
                    "{\n"
                    "  param_1[1] = 0x8000000000000000;\n"
                    "  *param_1 = 2;\n"
                    "}\n"
                )
            },
        }
    )

    assert "void FUN_1400083e0(void *param_1, ulonglong *param_2)" in reconstructed
    assert "((uintptr_t *)param_1)[1] = 0x8000000000000000;" in reconstructed
    assert "*((uintptr_t *)param_1) = 2;" in reconstructed


@pytest.mark.asyncio
async def test_phase2_reconstruction_writes_progress_artifact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    async def fake_reconstruct(
        ghidra_data,
        progress_callback=None,
        stage_callback=None,
        stage_timing_callback=None,
        debug_output_dir=None,
    ):
        assert progress_callback is not None
        assert stage_callback is not None
        assert stage_timing_callback is not None
        assert debug_output_dir == output_dir
        progress_callback(1, 2, "0x1")
        progress_callback(2, 2, "0x2")
        stage_callback("generated_prelude_build")
        stage_timing_callback("generated_prelude_build", 0.125)
        return "int main(void) { return 0; }\n"

    monkeypatch.setattr(engine, "_reconstruct_c_code", fake_reconstruct)

    output_dir = tmp_path / "analysis"
    output_dir.mkdir()
    source_files = await engine._phase2_reconstruction(
        {"decompiled_code": {"0x1": "void f1(void) {}", "0x2": "void f2(void) {}"}},
        output_dir,
    )

    progress = json.loads((output_dir / "reconstruction_progress.json").read_text(encoding="utf-8"))

    assert progress["status"] == "completed"
    assert progress["stage"] == "completed"
    assert progress["total_functions"] == 2
    assert progress["completed_functions"] == 2
    assert progress["source_file"] == str(output_dir / "reconstructed.c")
    assert progress["current_stage_elapsed_seconds"] == 0.125
    assert progress["stage_timings"]["generated_prelude_build"] == 0.125
    assert Path(source_files["c"]).exists()


def test_sanitize_generated_c_tokens_preserves_c_signature_syntax(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    signature = (
        "undefined __fastcall FUN_1400553c0("
        "ulonglong * param_1, longlong param_2, int * param_3)"
    )

    sanitized = engine._sanitize_generated_c_tokens(signature)

    assert sanitized == signature


def test_sanitize_generated_c_tokens_joins_wrapped_sanitized_call_identifiers(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "  std_sync_once_lock_OnceLock_\n"
        "  initialize_std_sync_poison_mutex_Mutex_std_io_buffered_bufreader_BufReader_std_io_stdio_StdinRaw_,std_sync_once_lock_impl_0_get_or_init_closure_env_0_std_sync_poison_mutex_Mutex_std_io_buffered_bufreader_BufReader_std_io_stdio_StdinRaw_,std_io_stdio_stdin_closure_env_0_,never_\n"
        "            ();\n"
    )

    sanitized = engine._sanitize_generated_c_tokens(source)

    assert (
        "std_sync_once_lock_OnceLock_initialize_std_sync_poison_mutex_Mutex_std_io_buffered_bufreader_BufReader_std_io_stdio_StdinRaw_"
        in sanitized
    )
    assert "\n            ();" not in sanitized
    assert sanitized.count("();") == 1


def test_sanitize_generated_c_tokens_joins_wrapped_sanitized_declarations(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "    core_ptr_\n"
        "    drop_in_place_std_sync_nonpoison_rwlock_RwLockReadGuard_enum2_std_panicking_Hook_(uintptr_t param_1, ...);\n"
    )

    sanitized = engine._sanitize_generated_c_tokens(source)

    assert (
        "core_ptr_drop_in_place_std_sync_nonpoison_rwlock_RwLockReadGuard_enum2_std_panicking_Hook_(uintptr_t param_1, ...);"
        in sanitized
    )
    assert "core_ptr_\n" not in sanitized


def test_restore_generated_labels_rehydrates_decompiler_labels(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LAB_140067b50_\n"
        "  goto joined_r0x0001400694b0;\n"
        "joined_r0x0001400694b0_\n"
        "code_r0x00014007f691_\n"
    )

    restored = engine._restore_generated_labels(source)

    assert "LAB_140067b50:" in restored
    assert "joined_r0x0001400694b0:" in restored
    assert "code_r0x00014007f691:" in restored
    assert "goto joined_r0x0001400694b0;" in restored


def test_build_generated_symbol_prelude_declares_discovered_synthetic_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "_UNK_1400ca6dc DAT_1400d3ac0 UNK_1400ca3fc UINT_1400e2550 "
        "___xmm_00000010000000100000001000000010 "
        "__xmm_12bd61d70e7773488ee2be6a73d559e0 "
        "_xmm_12bd61d70e7773488ee2be6a73d559e0_10_1_ "
        "PTR_FUN_1400d0160 core_fmt_impl_22_fmt HeapFree_exref "
        "auVar97_0_4_ local_120_1_7_"
    )

    assert "static uint64_t _UNK_1400ca6dc = 0;" in prelude
    assert "static uint64_t DAT_1400d3ac0 = 0;" in prelude
    assert "static uint64_t UNK_1400ca3fc = 0;" in prelude
    assert "static const uint64_t UINT_1400e2550 = 0;" in prelude
    assert "static code *HeapFree_exref = (code *)0;" in prelude
    assert "static uint64_t DAT_1400abcd = 0;" in engine._build_generated_symbol_prelude(
        "DAT_1400abcd = 1;"
    )
    assert "static uint64_t auVar97_0_4_ = 0;" in prelude
    assert "static uint64_t local_120_1_7_ = 0;" in prelude
    assert (
        "static const ghidra_uint128 ___xmm_00000010000000100000001000000010 = (ghidra_uint128)0;"
        in prelude
    )
    assert (
        "static const ghidra_uint128 __xmm_12bd61d70e7773488ee2be6a73d559e0 = (ghidra_uint128)0;"
        in prelude
    )
    assert "static const uint64_t _xmm_12bd61d70e7773488ee2be6a73d559e0_10_1_ = 0;" in prelude
    assert "static const uint64_t PTR_FUN_1400d0160 = 0;" in prelude
    assert "static const uint64_t core_fmt_impl_22_fmt = 0;" in prelude


def test_build_generated_symbol_prelude_declares_ptr_and_string_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "PTR_drop_in_place_alloc_string_String__1400cdbc8 "
        "s_options__________1400d2122 s_rguments__1400d2119"
    )

    assert "static const uint64_t PTR_drop_in_place_alloc_string_String__1400cdbc8 = 0;" in prelude
    assert "static const unsigned char s_options__________1400d2122[32] = {0};" in prelude
    assert "static const unsigned char s_rguments__1400d2119[32] = {0};" in prelude


def test_build_generated_symbol_prelude_declares_unresolved_lab_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "ptr = &LAB_14003d870;\n" "LAB_140067b50:\n" "goto LAB_140067b50;\n"
    )

    assert "static const uint64_t LAB_14003d870 = 0;" in prelude
    assert "LAB_140067b50" not in prelude


def test_build_generated_symbol_prelude_skips_function_names(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "void __cdecl read_to_end_std_io_stdio_StdinRaw_(void);\n"
        "read_to_end_std_io_stdio_StdinRaw_\n"
    )

    assert "static uint64_t read_to_end_std_io_stdio_StdinRaw_ = 0;" not in prelude


def test_build_generated_symbol_prelude_skips_called_helper_names(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "core_str_converts_from_utf8();\n" "alloc_raw_vec_handle_error();\n"
    )

    assert "core_str_converts_from_utf8" not in prelude
    assert "alloc_raw_vec_handle_error" not in prelude


def test_align_conflicting_function_prototypes_prefers_definition_return_type(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined __fastcall FUN_1400553c0(ulonglong * param_1, longlong param_2, int * param_3);\n"
        "void FUN_1400553c0(ulonglong *param_1,longlong param_2,int *param_3)\n"
        "{\n"
        "}\n"
    )

    normalized = engine._align_conflicting_function_prototypes(source)

    assert "void FUN_1400553c0(ulonglong *param_1,longlong param_2,int *param_3);" in normalized
    assert "undefined __fastcall FUN_1400553c0" not in normalized


def test_relax_void_fun_return_types_used_as_values(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_140042440(longlong param_1,longlong param_2);\n"
        "undefined8 value;\n"
        "void *ptr;\n"
        "value = FUN_140042440(1,2);\n"
        "ptr = (void *)FUN_140042440(3,4);\n"
        "void FUN_140042440(longlong param_1,longlong param_2)\n"
        "{\n"
        "  return;\n"
        "}\n"
    )

    normalized = engine._relax_void_return_functions_used_as_values(source)

    assert "uintptr_t FUN_140042440(longlong param_1,longlong param_2);" in normalized
    assert "uintptr_t FUN_140042440(longlong param_1,longlong param_2)" in normalized
    assert "void FUN_140042440" not in normalized


def test_relax_void_non_fun_return_types_used_as_values(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void _text_unlikely(ulonglong *param_1,void *param_2,ulonglong param_3);\n"
        "longlong value;\n"
        "value = _text_unlikely(buf,msg,5);\n"
    )

    normalized = engine._relax_void_return_functions_used_as_values(source)

    assert (
        "uintptr_t _text_unlikely(ulonglong *param_1,void *param_2,ulonglong param_3);"
        in normalized
    )
    assert "void _text_unlikely" not in normalized


def test_normalize_bare_returns_for_scalar_functions(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "uintptr_t FUN_14008c950(void *param_1,uint *param_2)\n"
        "{\n"
        "  if (*(longlong *)(param_2 + 0x30) == 0) {\n"
        "    return;\n"
        "  }\n"
        "  return 1;\n"
        "}\n"
    )

    normalized = engine._normalize_bare_returns_for_scalar_functions(source)

    assert "return (uintptr_t)0;" in normalized
    assert "return 1;" in normalized


def test_get_function_boundary_indices_detects_commented_and_multiline_functions(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "/* WARNING_ Globals starting with '_' overlap smaller symbols at the same address */\n"
        "void FUN_14008c950(void *param_1,undefined8 param_2)\n"
        "\n"
        "{\n"
        "  return;\n"
        "}\n"
        "void FUN_14008f5c0(ulonglong *param_1,ulonglong *param_2,ulonglong *param_3,\n"
        "                  ulonglong *param_4,int param_5,longlong param_6)\n"
        "{\n"
        "  return;\n"
        "}\n"
    )

    assert engine._get_function_boundary_indices(source) == [3, 8]


def test_normalize_bare_returns_for_scalar_functions_ignores_warning_comments(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void prior_helper(void)\n"
        "{\n"
        "  return;\n"
        "}\n"
        "/* WARNING_ Globals starting with '_' overlap smaller symbols at the same address */\n"
        "\n"
        "uintptr_t FUN_14008c950(void *param_1,undefined8 param_2)\n"
        "\n"
        "{\n"
        "  return;\n"
        "}\n"
    )

    normalized = engine._normalize_bare_returns_for_scalar_functions(source)

    assert "uintptr_t FUN_14008c950(void *param_1,undefined8 param_2)" in normalized
    assert "return (uintptr_t)0;" in normalized


def test_normalize_bare_returns_for_scalar_functions_recovers_local_boundary_when_cache_misses(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void prior_helper(undefined4 *param_1,longlong param_2,undefined8 param_3,undefined8 param_4)\n"
        "\n"
        "{\n"
        "  return;\n"
        "}\n"
        "/* WARNING_ Globals starting with '_' overlap smaller symbols at the same address */\n"
        "\n"
        "uintptr_t FUN_14008c950(void *param_1,undefined8 param_2)\n"
        "\n"
        "{\n"
        "  return;\n"
        "}\n"
    )

    engine._get_function_boundary_indices = lambda _source: [2]  # type: ignore[method-assign]

    normalized = engine._normalize_bare_returns_for_scalar_functions(source)

    assert "return (uintptr_t)0;" in normalized


def test_normalize_bare_returns_for_scalar_functions_uses_forward_boundary_collection_when_cache_is_stale(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "uintptr_t FUN_14008c950(void *param_1,undefined8 param_2)\n"
        "{\n"
        "  undefined8 local_10;\n"
        "  local_10 = param_2;\n"
        "  if (local_10 == 0) {\n"
        "    return;\n"
        "  }\n"
        "  return 1;\n"
        "}\n"
    )

    with patch.object(
        engine,
        "_is_function_boundary_line",
        side_effect=AssertionError("unexpected boundary fallback"),
    ):
        normalized = engine._normalize_bare_returns_for_scalar_functions(source)

    assert "return (uintptr_t)0;" in normalized


def test_extract_declared_function_names_ignores_indented_calls(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    declared = engine._extract_declared_function_names(
        "void declared_helper(void);\n"
        "  core_str_converts_from_utf8();\n"
        "  std_sys_alloc_windows_process_heap_alloc();\n"
    )

    assert "declared_helper" in declared
    assert "core_str_converts_from_utf8" not in declared
    assert "std_sys_alloc_windows_process_heap_alloc" not in declared


def test_normalize_generated_c_semantics_rewrites_ghidra_vector_arrays(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 auVar97 [16];\n"
        "auVar97 = *(undefined1 (*) [16])((longlong)ptr + -0x20);\n"
        "*(undefined1 (*) [16])((longlong)ptr + 0x20) = auVar97;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "ghidra_uint128 auVar97;" in normalized
    assert "auVar97 = *(ghidra_uint128 *)((longlong)ptr + -0x20);" in normalized
    assert "*(ghidra_uint128 *)((longlong)ptr + 0x20) = auVar97;" in normalized


def test_normalize_generated_c_semantics_preserves_indexed_vector_masks(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined1 auVar91 [16];\n" "auVar91[0] = -(pcVar58[0] == cVar49);\n"

    normalized = engine._normalize_generated_c_semantics(source)

    assert "ghidra_vec128 auVar91;" in normalized
    assert "auVar91.bytes[0] = -(pcVar58[0] == cVar49);" in normalized
    assert "ghidra_uint128 auVar91;" not in normalized


def test_normalize_generated_c_semantics_rewrites_vector_store_expression_rhs(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ghidra_uint128 auVar31;\n"
        "ghidra_uint128 auVar1;\n"
        "*(undefined1 (*) [16])((longlong)ptr + 0x20) = auVar31 | auVar1;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "*(ghidra_uint128 *)((longlong)ptr + 0x20) = auVar31 | auVar1;" in normalized


def test_normalize_generated_c_semantics_rewrites_indexed_vectors_to_union_usage(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 auVar91 [16];\n"
        "auVar91[0] = -(pcVar58[0] == cVar49);\n"
        "foo = SUB161(auVar91 >> 7,0);\n"
        "bar(auVar91);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "ghidra_vec128 auVar91;" in normalized
    assert "auVar91.bytes[0] = -(pcVar58[0] == cVar49);" in normalized
    assert "foo = SUB161(auVar91.whole >> 7,0);" in normalized
    assert "bar(auVar91.whole);" in normalized


def test_normalize_generated_c_semantics_rewrites_hex_indexed_vectors(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 auVar91 [16];\n"
        "auVar91[0xb] = flag;\n"
        "value = (ushort)(auVar91[0xf] >> 7);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "ghidra_vec128 auVar91;" in normalized
    assert "auVar91.bytes[0xb] = flag;" in normalized
    assert "value = (ushort)(auVar91.bytes[0xf] >> 7);" in normalized


def test_normalize_generated_c_semantics_generalizes_non_auvar_128bit_arrays(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 local_1a8 [16];\n"
        "undefined1 auStack_190 [16];\n"
        "local_1a8 = *(undefined1 (*) [16])ptr;\n"
        "auStack_190 = (undefined1 [16])0x0;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "ghidra_uint128 local_1a8;" in normalized
    assert "ghidra_uint128 auStack_190;" in normalized
    assert "local_1a8 = *(ghidra_uint128 *)(ptr);" in normalized
    assert "auStack_190 = GHIDRA_U128(0x0);" in normalized


def test_normalize_generated_c_semantics_rewrites_vector_whole_loads_from_pointer_arrays(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 auVar241 [16];\n"
        "undefined1 (*pauVar1) [16];\n"
        "auVar241[0] = flag;\n"
        "auVar241.whole = *pauVar1;\n"
        "auVar241.whole = pauVar1[1];\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "ghidra_vec128 auVar241;" in normalized
    assert "auVar241.whole = *(ghidra_uint128 *)(pauVar1);" in normalized
    assert "auVar241.whole = *(ghidra_uint128 *)(pauVar1[1]);" in normalized


def test_normalize_generated_c_semantics_wraps_byte_array_shifts_in_sub_helpers(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 auVar122 [15];\n"
        "undefined1 auVar150 [15];\n"
        "undefined1 auVar151 [15];\n"
        "value = SUB158(auVar122 << 0x40,7);\n"
        "value = SUB1510(auVar150 << 0x30,5);\n"
        "value = SUB1512(auVar151 << 0x20,3);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "value = SUB158(GHIDRA_U128(auVar122) << 0x40,7);" in normalized
    assert "value = SUB1510(GHIDRA_U128(auVar150) << 0x30,5);" in normalized
    assert "value = SUB1512(GHIDRA_U128(auVar151) << 0x20,3);" in normalized


def test_normalize_generated_c_semantics_casts_pointer_values_via_uintptr_for_double_comparisons(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong ********** ppppppppppuVar48;\n"
        "ulonglong *********** pppppppppppuVar65;\n"
        "if ((double)ppppppppppuVar48 < (double)*pppppppppppuVar65) {}\n"
        "while ((double)ppppppppppuVar48 < *(double *)((longlong)pppppppppppuVar36 + lVar46)) {}\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "if ((double)(uintptr_t)ppppppppppuVar48 < (double)(uintptr_t)*pppppppppppuVar65) {}"
        in normalized
    )
    assert (
        "while ((double)(uintptr_t)ppppppppppuVar48 < *(double *)((longlong)pppppppppppuVar36 + lVar46)) {}"
        in normalized
    )


def test_normalize_generated_c_semantics_rewrites_indexed_xmm_constants_to_vec_bytes(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "char cVar107;\n"
        "cVar107 = __xmm_00000000000000002020202020202020[0];\n"
        "cVar106 = ___xmm_6c77656e2d687469772d726f68747561[0xf];\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "((const ghidra_vec128 *)&__xmm_00000000000000002020202020202020)->bytes[0]" in normalized
    )
    assert (
        "((const ghidra_vec128 *)&___xmm_6c77656e2d687469772d726f68747561)->bytes[0xf]"
        in normalized
    )


def test_normalize_generated_c_semantics_rewrites_pointer_switches_to_uintptr(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "byte * local_58;\n"
        "undefined ******** pppppppppuStack_140;\n"
        "switch(local_58) {\n"
        "case (byte *)0x0:\n"
        "  break;\n"
        "}\n"
        "switch(pppppppppuStack_140) {\n"
        "case (undefined ********)0x3:\n"
        "  break;\n"
        "}\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "switch((uintptr_t)local_58) {" in normalized
    assert "case 0x0:" in normalized
    assert "switch((uintptr_t)pppppppppuStack_140) {" in normalized
    assert "case 0x3:" in normalized


def test_normalize_generated_c_semantics_restores_large_integer_split_aliases(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LARGE_INTEGER local_678;\n"
        "LARGE_INTEGER LStack_100;\n"
        "LARGE_INTEGER LVar36;\n"
        "_struct_19 _Var4;\n"
        "local_678_QuadPart = 0;\n"
        "local_678_s_LowPart = uVar7;\n"
        "local_678_s_HighPart = 0;\n"
        "_Var4_LowPart = 1;\n"
        "_Var4_HighPart = 0;\n"
        "((LARGE_INTEGER *)(ptr + 8))[LVar36_QuadPart * 4]_s = _Var4;\n"
        "LStack_100_QuadPart = (LONGLONG)&DAT_00000008;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "((LARGE_INTEGER *)&local_678)->QuadPart = 0;" in normalized
    assert "((_struct_19 *)&local_678)->LowPart = uVar7;" in normalized
    assert "((_struct_19 *)&local_678)->HighPart = 0;" in normalized
    assert "(_Var4).LowPart = 1;" in normalized
    assert "(_Var4).HighPart = 0;" in normalized
    assert (
        "(*(_struct_19 *)&((LARGE_INTEGER *)(ptr + 8))[((LARGE_INTEGER *)&LVar36)->QuadPart * 4]) = _Var4;"
        in normalized
    )
    assert "((LARGE_INTEGER *)&LStack_100)->QuadPart = (LONGLONG)&DAT_00000008;" in normalized


def test_collect_calls_for_names_skips_declarations_and_keeps_real_calls(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void foo(int param_1);\n"
        "void bar(void) {\n"
        "  foo(1);\n"
        "}\n"
        "void foo(int param_1) {\n"
        "  foo(param_1 + 1);\n"
        "}\n"
    )

    calls = engine._collect_calls_for_names(source, {"foo"})

    assert [call["name"] for call in calls] == ["foo", "foo"]
    assert calls[0]["args"] == ["1"]
    assert calls[1]["args"] == ["param_1 + 1"]


def test_collect_calls_for_names_skips_multiline_declarations_and_keeps_real_calls(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void\n"
        "foo(int param_1,\n"
        "    int param_2)\n"
        "{\n"
        "  foo(1,\n"
        "      2);\n"
        "}\n"
        "void bar(void) {\n"
        "  foo(3, 4);\n"
        "}\n"
    )

    calls = engine._collect_calls_for_names(source, {"foo"})

    assert [call["name"] for call in calls] == ["foo", "foo"]
    assert calls[0]["args"] == ["1", "2"]
    assert calls[1]["args"] == ["3", "4"]


def test_normalize_generated_c_semantics_rewrites_code_scalars_to_pointers(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "code cVar21;\n" "cVar21 = (code)0x1;\n" "*(code *)(ptr + 0x18) = (code)0x0;\n"

    normalized = engine._normalize_generated_c_semantics(source)

    assert "code *cVar21;" in normalized
    assert "cVar21 = (code *)0x1;" in normalized
    assert "*(code **)(ptr + 0x18) = (code *)0x0;" in normalized


def test_normalize_generated_c_semantics_rewrites_indexed_code_pointer_stores_to_bytes(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "((code *)(ptr + 4))[local_668] = (code *)0x6d;\n"

    normalized = engine._normalize_generated_c_semantics(source)

    assert "((byte *)(ptr + 4))[local_668] = 0x6d;" in normalized


def test_normalize_generated_c_semantics_rewrites_direct_code_pointer_byte_stores(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "code *pcVar33;\n"
        "code *pcVar15;\n"
        "code *pcVar23;\n"
        "*pcVar33 = *pcVar15;\n"
        "*pcVar23 = (code *)0x0;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "*(byte *)(uintptr_t)pcVar33 = *(byte *)(uintptr_t)pcVar15;" in normalized
    assert "*(byte *)(uintptr_t)pcVar23 = 0;" in normalized


def test_normalize_generated_c_semantics_rewrites_code_pointer_buffer_reads(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "code *local_c8;\n"
        "code *cVar1;\n"
        "byte uVar8;\n"
        "cVar1 = (code *)(uintptr_t)GHIDRA_U64(*local_c8);\n"
        "uVar8 = (byte)local_c8[1] & 0x3f;\n"
        "cVar1 = local_c8[3];\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "cVar1 = (code *)(uintptr_t)GHIDRA_U64(*(byte *)(uintptr_t)local_c8);" in normalized
    assert "uVar8 = (byte)((byte *)(uintptr_t)local_c8)[1] & 0x3f;" in normalized
    assert "cVar1 = (code *)(uintptr_t)GHIDRA_U64(((byte *)(uintptr_t)local_c8)[3]);" in normalized


def test_normalize_generated_c_semantics_rewrites_code_pointer_subscripts_in_expressions(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "code *pcVar11;\n"
        "code *cVar1;\n"
        "ulonglong local_90;\n"
        "if ((char)pcVar11[local_90] < -0x40) {\n"
        "}\n"
        "cVar1 = (code *)(uintptr_t)GHIDRA_U64((pcVar11 + local_90)[1]);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "if ((char)((byte *)(uintptr_t)pcVar11)[local_90] < -0x40) {" in normalized
    assert (
        "cVar1 = (code *)(uintptr_t)GHIDRA_U64(((byte *)(uintptr_t)(pcVar11 + local_90))[1]);"
        in normalized
    )


def test_normalize_generated_c_semantics_rewrites_plain_vector_value_loads_from_pointer_arrays(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "ghidra_uint128 auVar20;\n" "undefined1 (*pauVar6) [16];\n" "auVar20 = pauVar6[1];\n"

    normalized = engine._normalize_generated_c_semantics(source)

    assert "auVar20 = *(ghidra_uint128 *)(pauVar6[1]);" in normalized


def test_normalize_generated_c_semantics_rewrites_illegal_char_array_cast_assignments(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "char acStack_11e0 [8];\n" "acStack_11e0 = (char [8])s_aceMutex00000000_1400dd208_8_8_;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "memcpy(acStack_11e0, &s_aceMutex00000000_1400dd208_8_8_, 8);" in normalized


def test_normalize_generated_c_semantics_relaxes_readonly_local_wide_pointers_when_written(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LPCWSTR pWVar19;\n"
        "LPCWSTR pWStack_a0;\n"
        "pWVar19[1] = L';';\n"
        "*pWStack_a0 = L'_';\n"
        "memset(pWStack_a0, 0, 0x10);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "LPWSTR pWVar19;" in normalized
    assert "LPWSTR pWStack_a0;" in normalized


def test_normalize_generated_c_semantics_scalarizes_large_integer_value_uses(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LARGE_INTEGER LVar12;\n"
        "LARGE_INTEGER LVar36;\n"
        "LARGE_INTEGER local_b0;\n"
        "LARGE_INTEGER local_70;\n"
        "HeapFree(pvVar13,0,(LPVOID)LVar12);\n"
        "if (LVar36 != (LARGE_INTEGER)0x2) {}\n"
        "local_b0 = (LARGE_INTEGER)0x1;\n"
        "*(LARGE_INTEGER *)LStack_100 = (LONGLONG)local_70;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "HeapFree(pvVar13,0,(LPVOID)((LARGE_INTEGER *)&LVar12)->QuadPart);" in normalized
    assert "if (((LARGE_INTEGER *)&LVar36)->QuadPart != GHIDRA_U64(0x2)) {}" in normalized
    assert "local_b0 = GHIDRA_LARGE_INTEGER(GHIDRA_U64(0x1));" in normalized
    assert "GHIDRA_LARGE_INTEGER((LONGLONG)((LARGE_INTEGER *)&local_70)->QuadPart)" in normalized


def test_normalize_generated_c_semantics_rewrites_large_integer_indexed_quadpart_and_struct_deref(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LARGE_INTEGER LVar12;\n"
        "LARGE_INTEGER LVar36;\n"
        "LARGE_INTEGER LVar28;\n"
        "LARGE_INTEGER LVar38;\n"
        "((LARGE_INTEGER *)(base + 8))[LVar36_QuadPart * 4]_QuadPart = (LONGLONG)LVar28;\n"
        "(*(_struct_19 *)&LVar38) = *(*(_struct_19 *)&LVar28);\n"
        "if ((LARGE_INTEGER)lVar14 != (LARGE_INTEGER)((LARGE_INTEGER *)&LVar36)->QuadPart) {}\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "((LARGE_INTEGER *)(base + 8))[((LARGE_INTEGER *)&LVar36)->QuadPart * 4].QuadPart = (LONGLONG)((LARGE_INTEGER *)&LVar28)->QuadPart;"
        in normalized
    )
    assert "(*(_struct_19 *)&LVar38) = (*(_struct_19 *)&LVar28);" in normalized
    assert (
        "if (GHIDRA_U64(lVar14) != GHIDRA_U64(((LARGE_INTEGER *)&LVar36)->QuadPart)) {}"
        in normalized
    )


def test_normalize_generated_c_semantics_preserves_large_integer_aggregate_copies(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LARGE_INTEGER local_70;\n"
        "LARGE_INTEGER LVar12;\n"
        "LARGE_INTEGER local_88;\n"
        "local_70 = *(LARGE_INTEGER *)(ptr + -1);\n"
        "LVar12 = (LARGE_INTEGER)local_70;\n"
        "local_88 = (LARGE_INTEGER)((LARGE_INTEGER *)(ptr + 7))->QuadPart;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "local_70 = *(LARGE_INTEGER *)(ptr + -1);" in normalized
    assert "LVar12 = local_70;" in normalized
    assert "local_88 = GHIDRA_LARGE_INTEGER(GHIDRA_U64(" in normalized
    assert "->QuadPart));" in normalized


def test_normalize_generated_c_semantics_fixes_large_integer_call_casts_and_pointer_aliases(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LARGE_INTEGER LVar12;\n"
        "LARGE_INTEGER local_88;\n"
        "LARGE_INTEGER *pLVar31;\n"
        "local_88 = (LARGE_INTEGER)((LARGE_INTEGER *)(((LARGE_INTEGER *)&LVar12)->QuadPart + 7))->QuadPart;\n"
        "LVar12 = (LARGE_INTEGER)FUN_1400c6e80(uVar26);\n"
        "FUN_140011570(&pLVar31_QuadPart);\n"
        "return GHIDRA_U64(((LARGE_INTEGER *))&LVar12)->QuadPart;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "local_88 = GHIDRA_LARGE_INTEGER(GHIDRA_U64(((LARGE_INTEGER *)(((LARGE_INTEGER *)&LVar12)->QuadPart + 7))->QuadPart));"
        in normalized
    )
    assert "LVar12 = GHIDRA_LARGE_INTEGER(GHIDRA_U64(FUN_1400c6e80(uVar26)));" in normalized
    assert "FUN_140011570(&((LARGE_INTEGER *)pLVar31)->QuadPart);" in normalized
    assert "return LVar12;" in normalized


def test_normalize_generated_c_semantics_unwraps_large_integer_macro_misuse_and_statement_parens(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LARGE_INTEGER local_70;\n"
        "LARGE_INTEGER local_78;\n"
        "LARGE_INTEGER LVar12;\n"
        "ulonglong uVar26;\n"
        "LVar12 = GHIDRA_LARGE_INTEGER(local_70);\n"
        "uVar26 = GHIDRA_U64(local_78);\n"
        "uVar26 = GHIDRA_U64(((LARGE_INTEGER *)&LVar12)->QuadPart - (longlong)((LARGE_INTEGER *)&local_78)->QuadPart));\n"
        "return GHIDRA_U64(((LARGE_INTEGER *)&LVar12)->QuadPart);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "LVar12 = local_70;" in normalized
    assert "uVar26 = GHIDRA_U64(((LARGE_INTEGER *)&local_78)->QuadPart);" in normalized
    assert (
        "uVar26 = GHIDRA_U64(((LARGE_INTEGER *)&LVar12)->QuadPart - (longlong)((LARGE_INTEGER *)&local_78)->QuadPart);"
        in normalized
    )
    assert "return LVar12;" in normalized


def test_normalize_generated_c_semantics_scope_aware_large_integer_call_scalarization(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "uintptr_t FUN_1400c76b0(undefined8 param_1);\n"
        "uintptr_t FUN_1400ad560(undefined8 param_1,char param_2);\n"
        "void first(void)\n"
        "{\n"
        "  LARGE_INTEGER LVar12;\n"
        "  LARGE_INTEGER LVar36;\n"
        "  LARGE_INTEGER LVar38;\n"
        "  LARGE_INTEGER local_108;\n"
        "  LVar38 = GHIDRA_LARGE_INTEGER(LVar12);\n"
        "  ((LARGE_INTEGER *)&LVar36)->QuadPart = FUN_1400c76b0(LVar12);\n"
        "  ((LARGE_INTEGER *)&local_108)->QuadPart = FUN_1400ad560(LVar12,cVar39);\n"
        "}\n"
        "\n"
        "void second(void)\n"
        "{\n"
        "  undefined8 LVar12;\n"
        "  undefined8 uVar1;\n"
        "  uVar1 = FUN_1400c76b0(LVar12);\n"
        "}\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "LVar38 = LVar12;" in normalized
    assert (
        "((LARGE_INTEGER *)&LVar36)->QuadPart = FUN_1400c76b0(((LARGE_INTEGER *)&LVar12)->QuadPart);"
        in normalized
    )
    assert (
        "((LARGE_INTEGER *)&local_108)->QuadPart = FUN_1400ad560(((LARGE_INTEGER *)&LVar12)->QuadPart, cVar39);"
        in normalized
    )
    assert "uVar1 = FUN_1400c76b0(LVar12);" in normalized


def test_normalize_generated_c_semantics_rewrites_struct_value_args_for_byte_pointer_params(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 FUN_1400300d0(longlong param_1,byte *param_2,byte *param_3);\n"
        "_struct_19 local_c10;\n"
        "LARGE_INTEGER local_70;\n"
        "byte *local_c08;\n"
        "(*(_struct_19 *)&local_70) = (_struct_19)FUN_1400300d0(lVar14,(*(_struct_19 *)&local_c10),local_c08);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "((LARGE_INTEGER *)&local_70)->QuadPart = FUN_1400300d0(lVar14, (byte *)&local_c10, local_c08);"
        in normalized
    )


def test_normalize_struct_arguments_for_byte_pointer_params_keeps_adjacent_calls_intact(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 FUN_1400300d0(longlong param_1,byte *param_2,byte *param_3);\n"
        "_struct_19 local_c10;\n"
        "_struct_19 local_c20;\n"
        "void wrapper(void) {\n"
        "  FUN_1400300d0(lVar14,(*(_struct_19 *)&local_c10),(*(_struct_19 *)&local_c20));\n"
        "  FUN_1400300d0(lVar18,(*(_struct_19 *)&local_c20),(*(_struct_19 *)&local_c10));\n"
        "}\n"
    )

    normalized = engine._normalize_struct_arguments_for_byte_pointer_params(source)

    assert "FUN_1400300d0(lVar14, (byte *)&local_c10, (byte *)&local_c20);" in normalized
    assert "FUN_1400300d0(lVar18, (byte *)&local_c20, (byte *)&local_c10);" in normalized
    assert "local_c10FUN" not in normalized
    assert "local_c20FUN" not in normalized


def test_normalize_generated_c_semantics_scalarizes_large_integer_ghidra_u64_call_args(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 FUN_1400353a0(ulonglong param_1,uintptr_t param_2,void *param_3);\n"
        "LARGE_INTEGER local_70;\n"
        "LARGE_INTEGER local_78;\n"
        "ulonglong uVar26;\n"
        "uVar26 = FUN_1400353a0(((LARGE_INTEGER *)&local_70)->QuadPart, GHIDRA_U64(local_78), puVar18);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "uVar26 = FUN_1400353a0(((LARGE_INTEGER *)&local_70)->QuadPart, GHIDRA_U64(((LARGE_INTEGER *)&local_78)->QuadPart), puVar18);"
        in normalized
    )


def test_normalize_large_integer_arguments_for_scalar_params_keeps_adjacent_calls_intact(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 FUN_1400353a0(ulonglong param_1,uintptr_t param_2,void *param_3);\n"
        "LARGE_INTEGER local_70;\n"
        "LARGE_INTEGER local_78;\n"
        "ulonglong uVar26;\n"
        "ulonglong uVar27;\n"
        "uVar26 = FUN_1400353a0(local_70, GHIDRA_U64(local_78), puVar18);\n"
        "uVar27 = FUN_1400353a0(local_78, GHIDRA_U64(local_70), puVar19);\n"
    )

    normalized = engine._normalize_large_integer_arguments_for_scalar_params(source)

    assert (
        "uVar26 = FUN_1400353a0(((LARGE_INTEGER *)&local_70)->QuadPart, GHIDRA_U64(((LARGE_INTEGER *)&local_78)->QuadPart), puVar18);"
        in normalized
    )
    assert (
        "uVar27 = FUN_1400353a0(((LARGE_INTEGER *)&local_78)->QuadPart, GHIDRA_U64(((LARGE_INTEGER *)&local_70)->QuadPart), puVar19);"
        in normalized
    )
    assert "local_78uVar27" not in normalized
    assert "local_70uVar26" not in normalized


def test_normalize_generated_c_semantics_repairs_struct_cast_large_integer_returns(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "LARGE_INTEGER LVar36;\n" "return GHIDRA_U64((*(_struct_19 *))&LVar36);\n"

    normalized = engine._normalize_generated_c_semantics(source)

    assert "return LVar36;" in normalized


def test_find_nearest_declared_variable_type_ignores_control_flow_continuations(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 __fastcall FUN_140001000(void) {\n"
        "  LARGE_INTEGER local_78;\n"
        "  longlong lVar14;\n"
        "  if (SEXT816(lVar14) ==\n"
        "      SEXT816(*(longlong *)&DAT_1400cdad0)) {\n"
        "    FUN_1400353a0(0, GHIDRA_U64(local_78), 0);\n"
        "  }\n"
        "}\n"
    )

    call_pos = source.index("GHIDRA_U64(local_78)")

    assert (
        engine._find_nearest_declared_variable_type(source, "local_78", call_pos) == "LARGE_INTEGER"
    )


def test_find_nearest_declared_variable_type_falls_back_to_current_function_params(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 __fastcall FUN_140001000(void *param_1, byte *param_2) {\n"
        "  undefined8 local_68;\n"
        "  local_68 = param_2;\n"
        "}\n"
    )

    call_pos = source.index("local_68 = param_2;")

    assert engine._find_nearest_declared_variable_type(source, "param_1", call_pos) == "void *"
    assert engine._find_nearest_declared_variable_type(source, "param_2", call_pos) == "byte *"


def test_normalize_generated_c_semantics_casts_data_symbols_for_pointer_params(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "uintptr_t _text_unlikely(ulonglong *param_1,void *param_2,ulonglong param_3);\n"
        "ulonglong *buf;\n"
        "ulonglong lVar14;\n"
        "memcpy((code *)(buf + lVar14), DAT_1400ff0e0, DAT_1400ff0e8);\n"
        "lVar14 = _text_unlikely((ulonglong *)&buf, DAT_1400ff160, DAT_1400ff168);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "memcpy((code *)(buf + lVar14), (const void *)(uintptr_t)DAT_1400ff0e0, DAT_1400ff0e8);"
        in normalized
    )
    assert (
        "lVar14 = _text_unlikely((ulonglong *)&buf, (void *)(uintptr_t)DAT_1400ff160, DAT_1400ff168);"
        in normalized
    )


def test_normalize_data_symbol_arguments_for_pointer_params_keeps_adjacent_calls_intact(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void *memcpy(void *param_1,const void *param_2,size_t param_3);\n"
        "int memcmp(const void *param_1,const void *param_2,size_t param_3);\n"
        "void wrapper(void *dst,size_t size) {\n"
        "  memcpy(dst,DAT_1400ff0e0,size);\n"
        "  memcmp(DAT_1400cbfd1,DAT_1400cbff1,0x24);\n"
        "}\n"
    )

    normalized = engine._normalize_data_symbol_arguments_for_pointer_params(source)

    assert "memcpy(dst, (const void *)(uintptr_t)DAT_1400ff0e0, size);" in normalized
    assert (
        "memcmp((const void *)(uintptr_t)DAT_1400cbfd1, (const void *)(uintptr_t)DAT_1400cbff1, 0x24);"
        in normalized
    )
    assert "DAT_1400ff0e0memcmp" not in normalized
    assert "DAT_1400cbff1memcpy" not in normalized


def test_normalize_generated_c_semantics_casts_integer_expressions_for_pointer_params(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_14009c160(longlong *param_1,ulonglong param_2,LPVOID param_3);\n"
        "undefined8 local_60;\n"
        "undefined8 local_138;\n"
        "HANDLE pvVar10;\n"
        "FUN_14009c160((longlong *)&local_98, (ulonglong)((uintptr_t *)(uintptr_t)local_138)[0x29], ((uintptr_t *)(uintptr_t)local_138)[0x2a]);\n"
        "HeapFree(pvVar10, 0, local_60);\n"
        "memcpy((void *)dst, local_60, size);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "FUN_14009c160((longlong *)&local_98, (ulonglong)((uintptr_t *)(uintptr_t)local_138)[0x29], (LPVOID)(uintptr_t)((uintptr_t *)(uintptr_t)local_138)[0x2a]);"
        in normalized
    )
    assert "HeapFree(pvVar10, 0, (LPVOID)(uintptr_t)local_60);" in normalized
    assert "memcpy((void *)dst, (const void *)(uintptr_t)local_60, size);" in normalized


def test_normalize_code_pointer_byte_uses_rewrites_parenthesized_code_pointer_indexing(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void wrapper(void) {\n"
        "  code *pcVar11;\n"
        "  code *local_b0;\n"
        "  longlong local_80;\n"
        "  longlong local_90;\n"
        "  if (((byte *)(uintptr_t)pcVar11)[local_80] != (pcVar11 + (longlong)local_b0)[local_90]) break;\n"
        "}\n"
    )

    normalized = engine._normalize_code_pointer_byte_uses(source)

    assert (
        "if (((byte *)(uintptr_t)pcVar11)[local_80] != "
        "((byte *)(uintptr_t)(pcVar11 + (longlong)local_b0))[local_90]) break;"
    ) in normalized


def test_normalize_integer_arguments_for_pointer_params_keeps_adjacent_calls_intact(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void HeapFree(HANDLE param_1,DWORD param_2,LPVOID param_3);\n"
        "void *memcpy(void *param_1,const void *param_2,size_t param_3);\n"
        "undefined8 local_60;\n"
        "undefined8 local_68;\n"
        "HANDLE pvVar10;\n"
        "void *dst;\n"
        "size_t size;\n"
        "void wrapper(void) {\n"
        "  HeapFree(pvVar10,0,local_60);\n"
        "  memcpy(dst,local_68,size);\n"
        "}\n"
    )

    normalized = engine._normalize_integer_arguments_for_pointer_params(source)

    assert "HeapFree(pvVar10, 0, (LPVOID)(uintptr_t)local_60);" in normalized
    assert "memcpy(dst, (const void *)(uintptr_t)local_68, size);" in normalized
    assert "local_60memcpy" not in normalized
    assert "local_68HeapFree" not in normalized


def test_normalize_generated_c_semantics_bridges_float_backed_pointer_casts(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LPVOID pvVar4;\n"
        "double *pdVar21;\n"
        "double *local_90;\n"
        "double *local_98;\n"
        "pvVar4 = (LPVOID)*pdVar21;\n"
        "local_90 = (double *)pdVar21[idx * 3];\n"
        "local_98 = (double *)pdVar21[idx * 3 + 1];\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "pvVar4 = (LPVOID)(uintptr_t)GHIDRA_U64(*pdVar21);" in normalized
    assert "local_90 = (double *)(uintptr_t)GHIDRA_U64(pdVar21[idx * 3]);" in normalized
    assert "local_98 = (double *)(uintptr_t)GHIDRA_U64(pdVar21[idx * 3 + 1]);" in normalized


def test_normalize_generated_c_semantics_bridges_scalar_float_backed_pointer_casts(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "double dVar7;\n" "double *local_60;\n" "local_60 = (double *)dVar7;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_60 = (double *)(uintptr_t)GHIDRA_U64(dVar7);" in normalized


def test_normalize_generated_c_semantics_casts_wake_by_address_single_large_integer_args(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LARGE_INTEGER LVar12;\n" "WakeByAddressSingle(((LARGE_INTEGER *)&LVar12)->QuadPart);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "WakeByAddressSingle((PVOID)((LARGE_INTEGER *)&LVar12)->QuadPart);" in normalized


def test_normalize_generated_c_semantics_rewrites_illegal_undefined1_array_cast_assignments(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 local_7c [4];\n"
        "undefined4 *param_2;\n"
        "local_7c = (undefined1 [4])param_2[2];\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "memcpy(local_7c, &param_2[2], 4);" in normalized


def test_normalize_large_integer_split_aliases_restores_context_field_aliases(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "_CONTEXT local_598;\n"
        "if (SBORROW8(0,local_598_P1Home)) {}\n"
        "pbVar7 = (byte *)local_598_P2Home;\n"
        "ControlPc = local_598_Rip;\n"
        "local_90 = local_598_Rsp;\n"
    )

    normalized = engine._normalize_large_integer_split_aliases(source)

    assert "if (SBORROW8(0,(local_598).P1Home)) {}" in normalized
    assert "pbVar7 = (byte *)(local_598).P2Home;" in normalized
    assert "ControlPc = (local_598).Rip;" in normalized
    assert "local_90 = (local_598).Rsp;" in normalized


def test_normalize_large_integer_split_aliases_restores_security_attributes_fields(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "_SECURITY_ATTRIBUTES local_50;\n"
        "_SECURITY_ATTRIBUTES *lpSecurityAttributes;\n"
        "local_50_nLength = 0x18;\n"
        "local_50_lpSecurityDescriptor = (LPVOID)0x0;\n"
        "local_50_bInheritHandle = (BOOL)1;\n"
        "lpSecurityAttributes = (_SECURITY_ATTRIBUTES *)&local_50;\n"
        "if (lpSecurityAttributes_bInheritHandle != 0) {}\n"
    )

    normalized = engine._normalize_large_integer_split_aliases(source)

    assert "(local_50).nLength = 0x18;" in normalized
    assert "(local_50).lpSecurityDescriptor = (LPVOID)0x0;" in normalized
    assert "(local_50).bInheritHandle = (BOOL)1;" in normalized
    assert "if ((lpSecurityAttributes)->bInheritHandle != 0) {}" in normalized


def test_normalize_large_integer_split_aliases_restores_filetime_fields(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "FILETIME local_30;\n"
        "FILETIME *lpLastAccessTime;\n"
        "local_30_dwLowDateTime = 0xffffffff;\n"
        "local_30_dwHighDateTime = 0xffffffff;\n"
        "if (lpLastAccessTime_dwLowDateTime == 0) {}\n"
    )

    normalized = engine._normalize_large_integer_split_aliases(source)

    assert "(local_30).dwLowDateTime = 0xffffffff;" in normalized
    assert "(local_30).dwHighDateTime = 0xffffffff;" in normalized
    assert "if ((lpLastAccessTime)->dwLowDateTime == 0) {}" in normalized


def test_normalize_large_integer_split_aliases_restores_by_handle_file_information_fields(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "_BY_HANDLE_FILE_INFORMATION local_58;\n"
        "_BY_HANDLE_FILE_INFORMATION *param_1;\n"
        "local_58_nFileSizeHigh = 0;\n"
        "local_58_dwVolumeSerialNumber = 0;\n"
        "local_58_ftCreationTime_dwLowDateTime = 0;\n"
        "local_58_ftLastAccessTime_dwHighDateTime = 0;\n"
        "if (param_1_ftLastWriteTime_dwLowDateTime == 0) {}\n"
    )

    normalized = engine._normalize_large_integer_split_aliases(source)

    assert "(local_58).nFileSizeHigh = 0;" in normalized
    assert "(local_58).dwVolumeSerialNumber = 0;" in normalized
    assert "(local_58).ftCreationTime.dwLowDateTime = 0;" in normalized
    assert "(local_58).ftLastAccessTime.dwHighDateTime = 0;" in normalized
    assert "if ((param_1)->ftLastWriteTime.dwLowDateTime == 0) {}" in normalized


def test_normalize_large_integer_split_aliases_restores_console_structure_fields(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "_CONSOLE_SCREEN_BUFFER_INFO local_18;\n"
        "_CONSOLE_READCONSOLE_CONTROL local_78;\n"
        "_CONSOLE_SCREEN_BUFFER_INFO *param_1;\n"
        "local_18_dwSize_X = 0;\n"
        "local_18_dwCursorPosition_Y = 0;\n"
        "local_18_srWindow_Right = 0;\n"
        "local_18_dwMaximumWindowSize_Y = 0;\n"
        "local_78_nLength = 4;\n"
        "local_78_nInitialChars = 0;\n"
        "local_78_dwCtrlWakeupMask = 0;\n"
        "local_78_dwControlKeyState = 0;\n"
        "if (param_1_srWindow_Left == 0) {}\n"
    )

    normalized = engine._normalize_large_integer_split_aliases(source)

    assert "(local_18).dwSize.X = 0;" in normalized
    assert "(local_18).dwCursorPosition.Y = 0;" in normalized
    assert "(local_18).srWindow.Right = 0;" in normalized
    assert "(local_18).dwMaximumWindowSize.Y = 0;" in normalized
    assert "(local_78).nLength = 4;" in normalized
    assert "(local_78).nInitialChars = 0;" in normalized
    assert "(local_78).dwCtrlWakeupMask = 0;" in normalized
    assert "(local_78).dwControlKeyState = 0;" in normalized
    assert "if ((param_1)->srWindow.Left == 0) {}" in normalized


def test_normalize_large_integer_helpers_cover_parameters_and_array_elements(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 FUN_1400ac9b0(void *param_1,ulonglong param_2,LARGE_INTEGER param_3)\n"
        "{\n"
        "  LARGE_INTEGER local_20a8 [1024];\n"
        "  LARGE_INTEGER local_88;\n"
        "  if (param_3_QuadPart == 0) {\n"
        "    return 0;\n"
        "  }\n"
        "  if ((ulonglong)param_3 < 7) {\n"
        "    local_88 = GHIDRA_LARGE_INTEGER(param_3);\n"
        "  }\n"
        "  local_20a8[0]_QuadPart = 0;\n"
        "}\n"
    )

    split_normalized = engine._normalize_large_integer_split_aliases(source)
    value_normalized = engine._normalize_large_integer_value_uses(split_normalized)

    assert "if (((LARGE_INTEGER *)&param_3)->QuadPart == 0) {" in split_normalized
    assert "local_20a8[0].QuadPart = 0;" in split_normalized
    assert "if ((ulonglong)((LARGE_INTEGER *)&param_3)->QuadPart < 7) {" in value_normalized
    assert "local_88 = param_3;" in value_normalized


def test_normalize_pointer_integer_assignments_casts_pointer_like_unknown_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong **********pppppppppppuVar23;\n"
        "pppppppppppuVar23 = _UNK_1400cbf88;\n"
        "ulonglong *********** *ptr;\n"
        "*ptr = _DAT_1400cbf80;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "pppppppppppuVar23 = (ulonglong **********)(uintptr_t)_UNK_1400cbf88;" in normalized
    assert "*ptr = (ulonglong ***********)(uintptr_t)_DAT_1400cbf80;" in normalized


def test_normalize_pointer_integer_assignments_casts_nested_lvalue_unknown_symbol_stores(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "LARGE_INTEGER extraout_RAX_02;\n"
        "*(ulonglong ***********)((LARGE_INTEGER *)&extraout_RAX_02)->QuadPart = _DAT_1400cbf80;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "*(ulonglong ***********)((LARGE_INTEGER *)&extraout_RAX_02)->QuadPart = "
        "(ulonglong **********)(uintptr_t)_DAT_1400cbf80;"
    ) in normalized


def test_normalize_generated_c_semantics_retargets_non_code_pointer_cast_assignments(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "ulonglong *local_370;\n" "local_370 = (code *)(uintptr_t)GHIDRA_U64(param_2 + 2);\n"

    normalized = engine._normalize_generated_c_semantics(source)

    assert "local_370 = (ulonglong *)(uintptr_t)GHIDRA_U64(param_2 + 2);" in normalized


def test_retarget_non_code_pointer_cast_assignments_respects_function_scope(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void first(void)\n"
        "{\n"
        "  ulonglong *local_370;\n"
        "  local_370 = (code *)(uintptr_t)GHIDRA_U64(param_2 + 2);\n"
        "}\n"
        "\n"
        "void second(void)\n"
        "{\n"
        "  code *local_370;\n"
        "  local_370 = (code *)(uintptr_t)GHIDRA_U64(ptr);\n"
        "}\n"
    )

    normalized = engine._retarget_non_code_pointer_cast_assignments(source)

    assert (
        "ulonglong *local_370;\n  local_370 = (ulonglong *)(uintptr_t)GHIDRA_U64(param_2 + 2);"
        in normalized
    )
    assert "code *local_370;\n  local_370 = (code *)(uintptr_t)GHIDRA_U64(ptr);" in normalized


def test_retarget_non_code_pointer_cast_assignments_rewrites_integer_lhs(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_468;\n"
        "local_468 = (code *)(uintptr_t)GHIDRA_U64(GHIDRA_U64(local_78[0x18]));\n"
    )

    normalized = engine._retarget_non_code_pointer_cast_assignments(source)

    assert "local_468 = GHIDRA_U64(GHIDRA_U64(local_78[0x18]));" in normalized


def test_normalize_generated_c_semantics_balances_unclosed_ghidra_u64_lines(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 uStack_88;\n"
        "uStack_88 = GHIDRA_U64((ulonglong ***********)CONCAT44(uStack_88_4_4_,uVar53);\n"
        "uStack_88 = GHIDRA_U64((ulonglong ***********)((ulonglong)uStack_88_4_4_ << 0x20);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert (
        "uStack_88 = GHIDRA_U64((ulonglong ***********)CONCAT44(uStack_88_4_4_,uVar53));"
        in normalized
    )
    assert (
        "uStack_88 = GHIDRA_U64((ulonglong ***********)((ulonglong)uStack_88_4_4_ << 0x20));"
        in normalized
    )


def test_normalize_generated_c_semantics_repairs_top_level_comma_in_ghidra_u64(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void wrapper(void) {\n"
        "  for (ptr = items; flag = local_78, fn = (code *)(uintptr_t)GHIDRA_U64(GetProcessHeap_exref, ptr != end);\n"
        "       ptr = ptr + 1) {\n"
        "  }\n"
        "}\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "fn = (code *)(uintptr_t)GHIDRA_U64(GetProcessHeap_exref), ptr != end)" in normalized
    assert "GHIDRA_U64(GetProcessHeap_exref, ptr != end)" not in normalized


def test_normalize_generated_c_semantics_rewrites_byte_arrays_to_vec64_usage(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 local_228 [8];\n"
        "local_228[7] = flag;\n"
        "value = SUB81(local_228,0);\n"
        "other = (undefined1 [8])ptr;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "ghidra_vec64 local_228;" in normalized
    assert "local_228.bytes[7] = flag;" in normalized
    assert "value = SUB81(local_228.whole,0);" in normalized
    assert "other = GHIDRA_U64(ptr);" in normalized


def test_normalize_generated_c_semantics_rewrites_bare_vec64_value_uses(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 local_228 [8];\n"
        "undefined1 auVar9 [8];\n"
        "auVar9 = local_228;\n"
        "if (local_228 == other) {}\n"
        "foo(local_228);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "ghidra_vec64 local_228;" in normalized
    assert "ghidra_vec64 auVar9;" in normalized
    assert "auVar9.whole = local_228.whole;" in normalized
    assert "if (local_228.whole == other) {}" in normalized
    assert "foo(local_228.whole);" in normalized


def test_normalize_generated_c_semantics_rewrites_split_local_aliases_to_vec_whole(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 local_228 [8];\n"
        "_local_228 = (undefined1 [16])0x0;\n"
        "_local_228 = auVar58 << 0x40;\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "_local_228" not in normalized
    assert "local_228.whole = GHIDRA_U128(0x0);" in normalized
    assert "local_228.whole = auVar58 << 0x40;" in normalized


def test_normalize_generated_c_semantics_rewrites_indirect_code_calls(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "value = (ulonglong ***********)(*(code *)pppppppppppuVar64[2][7])(pppppppppppuVar64[1]);\n"
        "(**(code **)(lVar44 + 0x18))(&local_308,puVar59);\n"
        "(**(code **)local_98)(local_90);\n"
    )

    normalized = engine._normalize_generated_c_semantics(
        source, normalize_pointer_assignments=False
    )

    assert "((ghidra_indirect_fn)pppppppppppuVar64[2][7])(pppppppppppuVar64[1])" in normalized
    assert "(*(ghidra_indirect_fn *)(lVar44 + 0x18))(&local_308,puVar59);" in normalized
    assert "(*(ghidra_indirect_fn *)local_98)(local_90);" in normalized


def test_normalize_generated_c_semantics_rewrites_bare_code_pointer_calls(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "code * pcVar34;\n"
        "code * pcVar39;\n"
        "undefined8 uVar12;\n"
        "uVar12 = GHIDRA_U64((*pcVar39)());\n"
        "(*pcVar34)(uVar12,0,local_60);\n"
    )

    normalized = engine._normalize_generated_c_semantics(
        source, normalize_pointer_assignments=False
    )

    assert "uVar12 = GHIDRA_U64(((ghidra_indirect_fn_0)pcVar39)());" in normalized
    assert "((ghidra_indirect_fn)pcVar34)(uVar12,0,local_60);" in normalized


def test_normalize_generated_c_semantics_rewrites_parenthesized_indirect_code_calls(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        'cVar2 = GHIDRA_U64((**(code **)(((byte *)(uintptr_t)in_RDX)[1] + 0x18))(*in_RDX,"(",1));\n'
        "cVar2 = (**(code **)(((byte *)(uintptr_t)in_RDX)[1] + 0x18))"
        "(*in_RDX,&DAT_1400e1458 + *(int *)(&DAT_1400e1458 + uVar3 * 4),"
        "*(undefined8 *)(&DAT_1400e1308 + uVar3 * 8));\n"
        "(**(code **)(lVar4 + 0x18))(lVar5,pcVar6,uVar7);\n"
    )

    normalized = engine._normalize_generated_c_semantics(
        source, normalize_pointer_assignments=False
    )

    assert (
        "cVar2 = GHIDRA_U64((*(ghidra_indirect_fn *)(((byte *)(uintptr_t)in_RDX)[1] + 0x18))"
        '(*in_RDX,"(",1));'
    ) in normalized
    assert (
        "cVar2 = (*(ghidra_indirect_fn *)(((byte *)(uintptr_t)in_RDX)[1] + 0x18))"
        "(*in_RDX,&DAT_1400e1458 + *(int *)(&DAT_1400e1458 + uVar3 * 4),"
        "*(undefined8 *)(&DAT_1400e1308 + uVar3 * 8));"
    ) in normalized
    assert "(*(ghidra_indirect_fn *)(lVar4 + 0x18))(lVar5,pcVar6,uVar7);" in normalized


def test_normalize_generated_c_semantics_restores_malformed_case_labels(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "switch(cVar4) {\ncase 'Q'_\ncase '\\\\'_\ncase LABEL_\ndefault_\n}\n"

    normalized = engine._normalize_generated_c_semantics(
        source, normalize_pointer_assignments=False
    )

    assert "case 'Q':" in normalized
    assert "case '\\\\':" in normalized
    assert "case LABEL:" in normalized
    assert "default:" in normalized


def test_normalize_generated_c_semantics_keeps_ghidra_u64_calls_balanced_with_string_parens(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "cVar2 = GHIDRA_U64((*(ghidra_indirect_fn *)(((byte *)(uintptr_t)in_RDX)[1] + 0x18))"
        '(GHIDRA_U64(*in_RDX), "(",1));\n'
        "cVar2 = GHIDRA_U64((*(ghidra_indirect_fn *)(((byte *)(uintptr_t)in_RDX)[1] + 0x18))"
        '(GHIDRA_U64(*in_RDX), "(\\n",2));\n'
    )

    normalized = engine._normalize_generated_c_semantics(
        source, normalize_pointer_assignments=False
    )

    assert (
        "cVar2 = GHIDRA_U64((*(ghidra_indirect_fn *)(((byte *)(uintptr_t)in_RDX)[1] + 0x18))"
        '(GHIDRA_U64(*in_RDX), "(",1));'
    ) in normalized
    assert (
        "cVar2 = GHIDRA_U64((*(ghidra_indirect_fn *)(((byte *)(uintptr_t)in_RDX)[1] + 0x18))"
        '(GHIDRA_U64(*in_RDX), "(\\n",2));'
    ) in normalized
    assert "1)));" not in normalized
    assert "2)));" not in normalized


def test_normalize_generated_c_semantics_fixes_malformed_vec64_cast_rewrite(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 local_228 [8];\n"
        "undefined1 auVar9 [8];\n"
        "local_228 = (undefined1 [8])((longlong)auVar9 + 1);\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "local_228.whole = GHIDRA_U64((longlong)auVar9.whole + 1);" in normalized


def test_normalize_generated_c_semantics_restores_prefixed_local_aliases(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void wrapper(uintptr_t *param_2) {\n"
        "  undefined8 local_9c;\n"
        "  undefined8 uStack_f8;\n"
        "  _local_9c = CONCAT44(0x280000, 0xa80000);\n"
        "  _uStack_f8 = param_2[1];\n"
        "}\n"
    )

    normalized = engine._normalize_generated_c_semantics(source)

    assert "_local_9c" not in normalized
    assert "_uStack_f8" not in normalized
    assert "local_9c = CONCAT44(0x280000, 0xa80000);" in normalized
    assert "uStack_f8 = param_2[1];" in normalized


def test_build_generated_helper_prelude_declares_runtime_stubs(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_helper_prelude(
        "core_str_converts_from_utf8();\n"
        "alloc_raw_vec_handle_error();\n"
        "never_();\n"
        "pcVar2 = (code *)swi(0x29);\n"
        "_tls_index;\n"
        "movmskpd(x, y);\n"
        "movmskps(x, y);\n"
        "cpuid_basic_info(0);\n"
        "cpuid_Version_info(1);\n"
        "cpuid_Extended_Feature_Enumeration_info(7);\n"
        "cpuid(0x24);\n"
        "NtReadFile(a,b,c,d,e,f,g,h,i);\n"
        "NtWriteFile(a,b,c,d,e);\n"
        "RtlNtStatusToDosError(status);\n"
        "WaitOnAddress();\n"
        "WakeByAddressAll();\n"
        "__memset_fast_string_threshold = 0x8000;\n"
        "__memset_nt_threshold = -1;\n"
        "__favor = __favor | 1;\n"
        "__isa_available = 1;\n"
        "__isa_enabled = 2;\n"
        "__isa_inverted = 0;\n"
        "__avx10_version = 3;\n"
        "if (SBORROW1(a, b)) {}\n"
        "if (SBORROW8(a, b)) {}\n"
        "if (SCARRY8(a, b)) {}\n"
        "if (CARRY8(a, b)) {}\n"
        "auVar58 = pshuflw(x, y, 0xd4);\n"
        "auVar244.whole = pshufhw(x, y, 0x1b);\n"
        "LOCK();\n"
        "UNLOCK();\n"
        "invalidInstructionException();\n"
        "void already_declared(void);\n"
    )

    assert "#define core_str_converts_from_utf8(...) ((uint64_t)0)" in prelude
    assert "#define alloc_raw_vec_handle_error(...) ((uint64_t)0)" in prelude
    assert "#define movmskpd(...) (0)" in prelude
    assert "#define movmskps(...) (0)" in prelude
    assert "#define NtReadFile(...) ((uint64_t)0)" in prelude
    assert "#define NtWriteFile(...) ((uint64_t)0)" in prelude
    assert "#define RtlNtStatusToDosError(...) ((uint64_t)0)" in prelude
    assert "#define cpuid_basic_info(...) ((uint64_t)0)" in prelude
    assert "#define cpuid_Version_info(...) ((uint64_t)0)" in prelude
    assert "#define cpuid_Extended_Feature_Enumeration_info(...) ((uint64_t)0)" in prelude
    assert "#define cpuid(...) ((uint64_t)0)" in prelude
    assert "#define WaitOnAddress(...) (0)" in prelude
    assert "#define WakeByAddressAll(...) ((uint64_t)0)" in prelude
    assert "static uint64_t __memset_fast_string_threshold = 0;" in prelude
    assert "static uint64_t __memset_nt_threshold = 0;" in prelude
    assert "static uint64_t __favor = 0;" in prelude
    assert "static uint64_t __isa_available = 0;" in prelude
    assert "static uint64_t __isa_enabled = 0;" in prelude
    assert "static uint64_t __isa_inverted = 0;" in prelude
    assert "static uint64_t __avx10_version = 0;" in prelude
    assert "static inline int SBORROW1(signed char left, signed char right)" in prelude
    assert "static inline int SBORROW8(longlong left, longlong right)" in prelude
    assert "static inline int SCARRY8(longlong left, longlong right)" in prelude
    assert "static inline int CARRY8(uint64_t left, uint64_t right)" in prelude
    assert "#define pshuflw(value, unused, mask) (GHIDRA_U128(value))" in prelude
    assert "#define pshufhw(value, unused, mask) (GHIDRA_U128(value))" in prelude
    assert "#define LOCK() ((void)0)" in prelude
    assert "#define UNLOCK() ((void)0)" in prelude
    assert "#define invalidInstructionException(...) ((uint64_t)0)" in prelude
    assert "#define never_(...) ((uint64_t)0)" in prelude
    assert "static unsigned long _tls_index = 0;" in prelude
    assert "already_declared" not in prelude


def test_build_c_type_prelude_declares_swi_stub(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_c_type_prelude()

    assert "#ifndef swi" in prelude
    assert "#define swi(...) ((uint64_t)0)" in prelude


def test_build_c_type_prelude_uses_value_context_aliases_on_windows(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_c_type_prelude()

    assert "typedef CONTEXT _CONTEXT;" in prelude
    assert "typedef DISPATCHER_CONTEXT _DISPATCHER_CONTEXT;" in prelude
    assert "typedef SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES;" in prelude
    assert "typedef BY_HANDLE_FILE_INFORMATION _BY_HANDLE_FILE_INFORMATION;" in prelude
    assert "typedef CONSOLE_SCREEN_BUFFER_INFO _CONSOLE_SCREEN_BUFFER_INFO;" in prelude
    assert "typedef CONSOLE_READCONSOLE_CONTROL _CONSOLE_READCONSOLE_CONTROL;" in prelude


def test_build_generated_symbol_prelude_infers_windows_pointer_like_global_types(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "HANDLE pvVar12;\n"
        "FARPROC pFVar6;\n"
        "if ((DAT_1400ff3a0 == (HMODULE)0x0) &&\n"
        '   (DAT_1400ff3a0 = LoadLibraryA("dbghelp_dll"), DAT_1400ff3a0 == (HMODULE)0x0)) {}\n'
        "pFVar6 = DAT_1400ff3a8;\n"
        "if (DAT_1400ff3a8 != (FARPROC)0x0) {}\n"
        "DAT_1400ff3a8 = pFVar6;\n"
        "if (DAT_1400ff398 != (HANDLE)0x0) {}\n"
        "pvVar12 = (HANDLE)(uintptr_t)DAT_1400ff398;\n"
        "DAT_1400ff398 = pvVar12;\n"
    )

    assert "static HMODULE DAT_1400ff3a0 = (HMODULE)0;" in prelude
    assert "static FARPROC DAT_1400ff3a8 = (FARPROC)0;" in prelude
    assert "static HANDLE DAT_1400ff398 = (HANDLE)0;" in prelude


def test_build_generated_symbol_prelude_keeps_split_fragments_scalar_even_in_handle_context(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "if (local_228_0_7_ != (HANDLE)0x0) {}\n"
        "local_228_0_7_ = some_value;\n"
        "auVar59_0_8_ = other_value;\n"
        "pvVar12 = (HANDLE)(uintptr_t)local_228_0_7_;\n"
    )

    assert "static uint64_t local_228_0_7_ = 0;" in prelude
    assert "static uint64_t auVar59_0_8_ = 0;" in prelude
    assert "static HANDLE local_228_0_7_ = (HANDLE)0;" not in prelude
    assert "static HANDLE auVar59_0_8_ = (HANDLE)0;" not in prelude


def test_build_generated_symbol_prelude_keeps_integerish_globals_scalar_without_explicit_handle_cues(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "longlong lVar16;\n"
        "undefined8 uVar35;\n"
        "lVar16 = DAT_1400ff408;\n"
        "DAT_1400ff408 = lVar16;\n"
        "uVar35 = _UNK_1400cbfa0;\n"
        "_UNK_1400cbfa0 = uVar35;\n"
    )

    assert "static uint64_t DAT_1400ff408 = 0;" in prelude
    assert "static uint64_t _UNK_1400cbfa0 = 0;" in prelude
    assert "static HANDLE DAT_1400ff408 = (HANDLE)0;" not in prelude
    assert "static HANDLE _UNK_1400cbfa0 = (HANDLE)0;" not in prelude


def test_build_generated_symbol_prelude_infers_globals_from_pointer_return_and_param_contexts(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "void FUN_1400ad510(int *param_1, uintptr_t param_2);\n"
        "void FUN_14003b740(undefined8 param_1, undefined8 param_2, undefined1 *param_3, longlong param_4);\n"
        "char * FUN_1400ad260(byte param_1, char param_2)\n"
        "{\n"
        "  if (param_2 == '\\0') {\n"
        "    return DAT_1400ff0e0;\n"
        "  }\n"
        "  FUN_1400ad510(&DAT_1400ff130, GHIDRA_U64(&PTR_FUN_1400ff118));\n"
        "  FUN_14003b740(0, 0, &DAT_1400ce2e8, 7);\n"
        "  return &DAT_1400d96cb + (ulonglong)(param_1 & 0x7f) * 0x13;\n"
        "}\n"
    )

    assert "static char * DAT_1400ff0e0 = (char *)0;" in prelude
    assert "static int DAT_1400ff130 = 0;" in prelude
    assert "static undefined1 DAT_1400ce2e8 = 0;" in prelude
    assert "static char DAT_1400d96cb = 0;" in prelude


def test_build_generated_symbol_prelude_declares_switchdata_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "uVar3 = (undefined7)((ulonglong)((longlong)&switchD_14000e3a3_switchdataD_1400e1804 +\n"
        "(longlong)(int)(&switchD_14000e3a3_switchdataD_1400e1804)[uVar1]) >> 8);\n"
    )

    assert "static const int switchD_14000e3a3_switchdataD_1400e1804[1] = {0};" in prelude


def test_build_generated_symbol_prelude_declares_stack_pseudo_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "(&stack0xffffffffffffee07)[uVar22] = cVar15;\n"
    )

    assert "static char stack0xffffffffffffee07 = 0;" in prelude


def test_build_generated_symbol_prelude_declares_ram_pseudo_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_symbol_prelude(
        "iRam00000001400ff254 = 1;\n" "uRam00000001400ff24c = 0;\n"
    )

    assert "static uint64_t iRam00000001400ff254 = 0;" in prelude
    assert "static uint64_t uRam00000001400ff24c = 0;" in prelude


def test_join_wrapped_sanitized_call_identifiers_repairs_split_function_signatures(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void __cdecl\n"
        "core_ops_function_FnOnce_\n"
        "call_once_std_sys_backtrace_print_fmt_closure_1_closure_env_0,tuple_ref_std_backtrace_rs_symbolize_Symbol_\n"
        "          (void)\n"
        "{\n"
        "}\n"
    )

    normalized = engine._join_wrapped_sanitized_call_identifiers(source)

    assert (
        "void __cdecl "
        "core_ops_function_FnOnce_call_once_std_sys_backtrace_print_fmt_closure_1_closure_env_0_"
        "tuple_ref_std_backtrace_rs_symbolize_Symbol_(void)"
    ) in normalized


def test_build_generated_helper_prelude_uses_stub_function_when_helper_is_called_and_referenced(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_helper_prelude(
        "local_3e0 = core_fmt_impl_22_fmt;\n" "core_fmt_impl_22_fmt();\n"
    )

    assert "static inline uint64_t core_fmt_impl_22_fmt()" in prelude
    assert "#define core_fmt_impl_22_fmt(...)" not in prelude


def test_build_generated_helper_prelude_keeps_indented_calls_as_macros(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_helper_prelude(
        "if (flag) {\n"
        "    core_str_converts_from_utf8();\n"
        "    std_sys_alloc_windows_process_heap_alloc();\n"
        "}\n"
    )

    assert "#define core_str_converts_from_utf8(...) ((uint64_t)0)" in prelude
    assert "#define std_sys_alloc_windows_process_heap_alloc(...) ((uint64_t)0)" in prelude


def test_build_generated_helper_prelude_skips_multiline_function_definitions(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_helper_prelude(
        "core_str_pattern_impl_31_is_contained_in();\n"
        "void __cdecl core_str_pattern_impl_31_is_contained_in(void)\n"
        "\n"
        "{\n"
        "  return;\n"
        "}\n"
    )

    assert "void __cdecl core_str_pattern_impl_31_is_contained_in(void);" in prelude
    assert "#define core_str_pattern_impl_31_is_contained_in(...)" not in prelude


def test_build_generated_helper_prelude_adds_forward_declarations_for_later_helper_definitions(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    prelude = engine._build_generated_helper_prelude(
        "core_str_converts_from_utf8();\n"
        "void __cdecl core_str_converts_from_utf8(void)\n"
        "\n"
        "{\n"
        "  return;\n"
        "}\n"
    )

    assert "void __cdecl core_str_converts_from_utf8(void);" in prelude
    assert "#define core_str_converts_from_utf8(...)" not in prelude


def test_qualify_unresolved_function_aliases_rewrites_unique_helper_suffixes(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void __cdecl core_str_pattern_StrSearcher_new(void);\n"
        "void __cdecl core_panicking_panic_bounds_check(void);\n"
        "void __cdecl core_str_pattern_simd_contains_closure_2(void);\n"
        "void wrapper(void) {\n"
        "  StrSearcher_new();\n"
        "  panicking_panic_bounds_check();\n"
        "  simd_contains_closure_2();\n"
        "}\n"
    )

    normalized = engine._qualify_unresolved_function_aliases(source)

    assert "core_str_pattern_StrSearcher_new();" in normalized
    assert "core_panicking_panic_bounds_check();" in normalized
    assert "core_str_pattern_simd_contains_closure_2();" in normalized
    assert "  StrSearcher_new();" not in normalized


def test_qualify_unresolved_function_aliases_rewrites_prefixed_calls_and_bare_callback_refs(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void __cdecl alloc_raw_vec_impl_4_reserve_do_reserve_and_handle_alloc_alloc_Global_(void);\n"
        "void __cdecl std_backtrace_rs_dbghelp_enum_loaded_modules_callback(void);\n"
        "void wrapper(void) {\n"
        "  _alloc_raw_vec_impl_4_reserve_do_reserve_and_handle_alloc_alloc_Global_();\n"
        "  ((ghidra_indirect_fn)pFVar6)(GHIDRA_U64(pvVar8), backtrace_rs_dbghelp_enum_loaded_modules_callback, &local_1f8);\n"
        "}\n"
    )

    normalized = engine._qualify_unresolved_function_aliases(source)

    assert (
        "_alloc_raw_vec_impl_4_reserve_do_reserve_and_handle_alloc_alloc_Global_();"
        not in normalized
    )
    assert "alloc_raw_vec_impl_4_reserve_do_reserve_and_handle_alloc_alloc_Global_();" in normalized
    assert "std_backtrace_rs_dbghelp_enum_loaded_modules_callback" in normalized
    assert " backtrace_rs_dbghelp_enum_loaded_modules_callback," not in normalized


def test_qualify_unresolved_function_aliases_prefers_current_function_namespace(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void __cdecl core_fmt_num_imp_impl_16_fmt(void);\n"
        "void __cdecl core_fmt_num_impl_16_fmt(void);\n"
        "void __cdecl std_io_error_impl_16_fmt(void);\n"
        "void __cdecl std_io_error_impl_0_fmt(void)\n"
        "{\n"
        "  impl_16_fmt();\n"
        "}\n"
    )

    normalized = engine._qualify_unresolved_function_aliases(source)

    assert "  std_io_error_impl_16_fmt();" in normalized
    assert "  impl_16_fmt();" not in normalized


def test_qualify_unresolved_function_aliases_ignores_nested_control_flow_heads(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void __cdecl core_fmt_num_imp_impl_16_fmt(void);\n"
        "void __cdecl core_fmt_num_impl_16_fmt(void);\n"
        "void __cdecl std_io_error_impl_16_fmt(void);\n"
        "void __cdecl std_io_error_impl_0_fmt(void)\n"
        "{\n"
        "  if (flag != 0) {\n"
        "    impl_16_fmt();\n"
        "  }\n"
        "}\n"
    )

    normalized = engine._qualify_unresolved_function_aliases(source)

    assert "    std_io_error_impl_16_fmt();" in normalized
    assert "    impl_16_fmt();" not in normalized


def test_qualify_unresolved_function_aliases_keeps_simple_local_declarations(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void __cdecl core_fmt_builders_impl_2_write_char(void);\n"
        "void __cdecl core_str_pattern_impl_31_is_contained_in(void)\n"
        "{\n"
        "  char *pcVar1;\n"
        "  char cVar2;\n"
        "  core_fmt_builders_impl_2_write_char();\n"
        "}\n"
    )

    normalized = engine._qualify_unresolved_function_aliases(source)

    assert "  char *pcVar1;" in normalized
    assert "  char cVar2;" in normalized
    assert "  core_fmt_builders_impl_2_write_char();" in normalized
    assert "  core_fmt_builders_impl_2_write_char *pcVar1;" not in normalized


def test_qualify_unresolved_function_aliases_keeps_builtin_char_casts_and_pointers(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void __cdecl core_fmt_builders_impl_2_write_char(void);\n"
        "void __cdecl wrapper(void)\n"
        "{\n"
        "  value = (char)flag;\n"
        "  ptr = (char *)buffer;\n"
        "}\n"
    )

    normalized = engine._qualify_unresolved_function_aliases(source)

    assert "  value = (char)flag;" in normalized
    assert "  ptr = (char *)buffer;" in normalized
    assert "(core_fmt_builders_impl_2_write_char)" not in normalized


def test_normalize_void_pointer_parameter_indexing_rewrites_index_and_deref_uses(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_140044810(void *param_1, void *param_2)\n"
        "{\n"
        "  uVar3 = param_2[0x46];\n"
        "  pvVar6 = (void *)param_2[0x23];\n"
        "  uVar2 = *param_1;\n"
        "  (param_1 + uVar16 * 9 + 6)[1] = uVar8;\n"
        "}\n"
    )

    normalized = engine._normalize_void_pointer_parameter_indexing(source)

    assert "uVar3 = ((uintptr_t *)param_2)[0x46];" in normalized
    assert "pvVar6 = (void *)((uintptr_t *)param_2)[0x23];" in normalized
    assert "uVar2 = *((uintptr_t *)param_1);" in normalized
    assert "(((uintptr_t *)param_1) + uVar16 * 9 + 6)[1] = uVar8;" in normalized


def test_normalize_void_pointer_parameter_indexing_rewrites_nested_offsets(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_140065c80(void *param_1,void *param_3)\n"
        "{\n"
        "  (param_3 + (longlong)puVar23 * 4 + 2)[1] = uVar6;\n"
        "  (param_3 + (longlong)puVar23 * 4)[1] = uVar5;\n"
        "}\n"
    )

    normalized = engine._normalize_void_pointer_parameter_indexing(source)

    assert "(((uintptr_t *)param_3) + (longlong)puVar23 * 4 + 2)[1] = uVar6;" in normalized
    assert "(((uintptr_t *)param_3) + (longlong)puVar23 * 4)[1] = uVar5;" in normalized


def test_normalize_void_pointer_parameter_indexing_recovers_after_brace_depth_drift(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void previous(void)\n"
        "{\n"
        '  FUN_140000100("{not a real brace balancer}");\n'
        "}\n"
        "void FUN_1400083e0(void *param_1,ulonglong *param_2)\n"
        "\n"
        "{\n"
        "  param_1[1] = 0x8000000000000000;\n"
        "  *param_1 = 2;\n"
        "}\n"
    )

    normalized = engine._normalize_void_pointer_parameter_indexing(source)

    assert "((uintptr_t *)param_1)[1] = 0x8000000000000000;" in normalized
    assert "*((uintptr_t *)param_1) = 2;" in normalized


def test_normalize_void_pointer_parameter_indexing_ignores_negative_global_brace_drift(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void previous(void)\n"
        "{\n"
        '  FUN_140000100("} stray close brace in string");\n'
        "}\n"
        "void FUN_1400083e0(void *param_1,ulonglong *param_2)\n"
        "\n"
        "{\n"
        "  param_1[1] = 0x8000000000000000;\n"
        "  *param_1 = 2;\n"
        "}\n"
    )

    normalized = engine._normalize_void_pointer_parameter_indexing(source)

    assert "((uintptr_t *)param_1)[1] = 0x8000000000000000;" in normalized
    assert "*((uintptr_t *)param_1) = 2;" in normalized


def test_normalize_void_pointer_parameter_indexing_does_not_rewrite_signature_params(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void previous(void)\n"
        "{\n"
        '  FUN_140000100("} stray close brace in string");\n'
        "}\n"
        "void FUN_1400083e0(void *param_1,ulonglong *param_2,void *param_3,size_t param_4)\n"
        "\n"
        "{\n"
        "  param_1[1] = 0x8000000000000000;\n"
        "  *param_1 = 2;\n"
        "}\n"
    )

    normalized = engine._normalize_void_pointer_parameter_indexing(source)

    assert (
        "void FUN_1400083e0(void *param_1,ulonglong *param_2,void *param_3,size_t param_4)"
        in normalized
    )
    assert (
        "void FUN_1400083e0(void *((uintptr_t *)param_1),ulonglong *param_2,void *param_3,size_t param_4)"
        not in normalized
    )
    assert "((uintptr_t *)param_1)[1] = 0x8000000000000000;" in normalized
    assert "*((uintptr_t *)param_1) = 2;" in normalized


def test_normalize_void_pointer_parameter_indexing_ignores_multiline_signature_continuations(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void previous(void *param_1)\n"
        "{\n"
        '  FUN_140000100("{ leaked brace in string");\n'
        "}\n"
        "void FUN_14008f5c0(ulonglong *param_1,ulonglong *param_2,void *param_3,\n"
        "                  ulonglong *param_4,longlong param_5)\n"
        "\n"
        "{\n"
        "  param_3[1] = 0x8000000000000000;\n"
        "  *param_3 = 2;\n"
        "}\n"
    )

    normalized = engine._normalize_void_pointer_parameter_indexing(source)

    assert "void FUN_14008f5c0(ulonglong *param_1,ulonglong *param_2,void *param_3," in normalized
    assert "                  ulonglong *param_4,longlong param_5)" in normalized
    assert "ulonglong *((uintptr_t *)param_1)" not in normalized
    assert "void *((uintptr_t *)param_3)" not in normalized
    assert "((uintptr_t *)param_3)[1] = 0x8000000000000000;" in normalized
    assert "*((uintptr_t *)param_3) = 2;" in normalized


def test_relax_mismatched_void_prototypes_when_calls_have_arguments(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined FUN_140075e00(void);\n"
        "void wrapper(void) {\n"
        "  FUN_140075e00(&local_1f8, local_b8, 0);\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_void_prototypes(source)

    assert "undefined FUN_140075e00(uintptr_t param_1, ...);" in normalized
    assert "undefined FUN_140075e00(void);" not in normalized


def test_relax_mismatched_empty_prototypes_when_calls_have_arguments(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined FUN_14004b2f0();\n" "void wrapper(void) {\n" "  FUN_14004b2f0(1, 2, 3);\n" "}\n"
    )

    normalized = engine._relax_mismatched_void_prototypes(source)

    assert "undefined FUN_14004b2f0(uintptr_t param_1, ...);" in normalized
    assert "undefined FUN_14004b2f0();" not in normalized


def test_normalize_pointer_integer_assignments_adds_explicit_casts(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_108;\n"
        "ulonglong *********** local_110;\n"
        "ulonglong *********** local_118;\n"
        "undefined8 local_120;\n"
        "local_108 = local_110;\n"
        "local_118 = local_120;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_108 = GHIDRA_U64(local_110);" in normalized
    assert "local_118 = (ulonglong ***********)(uintptr_t)local_120;" in normalized


def test_normalize_pointer_integer_assignments_rewrites_casted_pointer_expressions(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 uStack_88;\n"
        "uStack_88 = (ulonglong ***********)CONCAT44(uStack_88_4_4_,uVar53);\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "uStack_88 = GHIDRA_U64((ulonglong ***********)CONCAT44(uStack_88_4_4_,uVar53));"
        in normalized
    )


def test_normalize_generated_c_semantics_can_skip_pointer_assignment_rewrite(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_b0;\n"
        "ulonglong *********** pppppppppppuVar55;\n"
        "local_b0 = pppppppppppuVar55;\n"
    )

    normalized = engine._normalize_generated_c_semantics(
        source, normalize_pointer_assignments=False
    )

    assert "local_b0 = pppppppppppuVar55;" in normalized
    assert "GHIDRA_U64" not in normalized


def test_relax_mismatched_pointer_prototypes_from_call_sites(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "int * __fastcall FUN_140075460(undefined8 * param_1, longlong param_2, longlong param_3);\n"
        "bool __fastcall FUN_1400a7420(undefined8 param_1, longlong param_2);\n"
        "ulonglong *********** local_78;\n"
        "ulonglong *********** local_b0;\n"
        "void wrapper(void) {\n"
        "  FUN_140075460(local_78, 1, 2);\n"
        "  FUN_1400a7420(local_b0, 3);\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "FUN_140075460(void * param_1, longlong param_2, longlong param_3);" in normalized
    assert "FUN_1400a7420(uintptr_t param_1, longlong param_2);" in normalized


def test_relax_mismatched_pointer_prototypes_across_multiline_calls(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "int * __fastcall FUN_140075460(undefined8 * param_1, longlong param_2, longlong param_3);\n"
        "bool __fastcall FUN_1400a7420(undefined8 param_1, longlong param_2);\n"
        "ulonglong *********** local_78;\n"
        "ulonglong *********** local_b0;\n"
        "void wrapper(void) {\n"
        "  x = FUN_140075460(\n"
        "        local_78,\n"
        "        1,\n"
        "        2);\n"
        "  if (FUN_1400a7420(\n"
        "        local_b0,\n"
        "        3)) {\n"
        "  }\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "FUN_140075460(void * param_1, longlong param_2, longlong param_3);" in normalized
    assert "FUN_1400a7420(uintptr_t param_1, longlong param_2);" in normalized


def test_relax_mismatched_pointer_prototypes_uses_nearest_local_scope(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "bool __fastcall FUN_1400a7420(undefined8 param_1, longlong param_2);\n"
        "void first(void) {\n"
        "  ulonglong *********** local_b0;\n"
        "  if (FUN_1400a7420(\n"
        "        local_b0,\n"
        "        3)) {\n"
        "  }\n"
        "}\n"
        "void second(void) {\n"
        "  undefined8 local_b0;\n"
        "  local_b0 = 0;\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "FUN_1400a7420(uintptr_t param_1, longlong param_2);" in normalized


def test_relax_mismatched_pointer_prototypes_widens_nonfirst_pointer_params(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void * __fastcall FUN_14007c630(longlong param_1, undefined8 * param_2, longlong * param_3, longlong * param_4);\n"
        "ghidra_vec64 local_228;\n"
        "longlong local_358;\n"
        "longlong local_1f8;\n"
        "void wrapper(void) {\n"
        "  FUN_14007c630(handle,\n"
        "                &local_228,\n"
        "                &local_358,\n"
        "                &local_1f8);\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert (
        "FUN_14007c630(longlong param_1, void * param_2, longlong * param_3, longlong * param_4);"
        in normalized
    )


def test_relax_mismatched_pointer_prototypes_handles_nospace_pointer_declarations(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "bool __fastcall FUN_1400a7420(undefined8 param_1, longlong param_2);\n"
        "void wrapper(void) {\n"
        "  ulonglong ***********local_b0;\n"
        "  if (FUN_1400a7420(local_b0, 3)) {\n"
        "  }\n"
        "}\n"
        "bool FUN_1400a7420(undefined8 param_1,longlong param_2)\n"
        "{\n"
        "  return true;\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "bool __fastcall FUN_1400a7420(uintptr_t param_1, longlong param_2);" in normalized
    assert "bool FUN_1400a7420(uintptr_t param_1,longlong param_2)" in normalized


def test_relax_mismatched_pointer_prototypes_across_inner_blocks(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "bool __fastcall FUN_1400a7420(undefined8 param_1, longlong param_2);\n"
        "void wrapper(void) {\n"
        "  ulonglong ***********local_b0;\n"
        "  if (flag) {\n"
        "    if (FUN_1400a7420(local_b0, 3)) {\n"
        "    }\n"
        "  }\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "FUN_1400a7420(uintptr_t param_1, longlong param_2);" in normalized


def test_relax_mismatched_pointer_prototypes_across_multiline_inner_conditions(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "bool __fastcall FUN_1400a7420(undefined8 param_1, longlong param_2);\n"
        "void wrapper(void) {\n"
        "  ulonglong ***********local_b0;\n"
        "  ulonglong ***********local_e0;\n"
        "  if ((flag != 0) &&\n"
        "      (FUN_1400a7420(local_b0,(longlong)local_e0))) {\n"
        "  }\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "FUN_1400a7420(uintptr_t param_1, longlong param_2);" in normalized


def test_relax_mismatched_pointer_prototypes_across_multiline_inner_conditions_with_brace_line(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "bool __fastcall FUN_1400a7420(undefined8 param_1, longlong param_2);\n"
        "void wrapper(void) {\n"
        "  ulonglong ***********local_b0;\n"
        "  ulonglong ***********local_e0;\n"
        "  if ((flag != 0) &&\n"
        "      (FUN_1400a7420(local_b0,(longlong)local_e0)))\n"
        "  {\n"
        "  }\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "FUN_1400a7420(uintptr_t param_1, longlong param_2);" in normalized


def test_relax_mismatched_pointer_prototypes_widens_string_literal_arguments(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 FUN_1400065c0(undefined8 param_1,undefined8 param_2,int *param_3);\n"
        "void wrapper(void) {\n"
        '  FUN_1400065c0("no_position",0xb,(int *)&local_168);\n'
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert (
        "undefined1 FUN_1400065c0(uintptr_t param_1,undefined8 param_2,int *param_3);" in normalized
    )


def test_relax_mismatched_pointer_prototypes_widens_scalar_param_for_pointer_locals(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_1400970d0(uintptr_t param_1,undefined8 param_2,longlong param_3);\n"
        "void wrapper(undefined8 *local_138, longlong lVar26) {\n"
        "  FUN_1400970d0(GHIDRA_U64(&local_b8), local_138, lVar26);\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "void FUN_1400970d0(uintptr_t param_1,uintptr_t param_2,longlong param_3);" in normalized


def test_relax_mismatched_pointer_prototypes_treats_array_backed_args_as_pointer_like(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_1400970d0(uintptr_t param_1,undefined8 param_2,longlong param_3);\n"
        "void wrapper(longlong lVar26) {\n"
        "  undefined8 local_138[2];\n"
        "  FUN_1400970d0(GHIDRA_U64(&local_b8), local_138, lVar26);\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "void FUN_1400970d0(uintptr_t param_1,uintptr_t param_2,longlong param_3);" in normalized


def test_relax_mismatched_pointer_prototypes_reuses_pointer_like_results_for_repeated_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "bool __fastcall FUN_1400a7420(undefined8 param_1, longlong param_2);\n"
        "void wrapper(void) {\n"
        "  ulonglong ***********local_b0;\n"
        "  FUN_1400a7420(local_b0, 1);\n"
        "  FUN_1400a7420(local_b0, 2);\n"
        "  FUN_1400a7420(local_b0, 3);\n"
        "}\n"
    )

    original = engine._is_pointer_like_expression
    pointer_checks = 0

    def counting_pointer_check(source_text, expression, variable_types, before_pos):
        nonlocal pointer_checks
        pointer_checks += 1
        return original(source_text, expression, variable_types, before_pos)

    monkeypatch.setattr(engine, "_is_pointer_like_expression", counting_pointer_check)

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert "FUN_1400a7420(uintptr_t param_1, longlong param_2);" in normalized
    assert pointer_checks == 1


def test_relax_mismatched_pointer_prototypes_widens_callback_carrier_params(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong FUN_14003a9f0(uintptr_t param_1,undefined *param_2,longlong param_3,byte *param_4,ulonglong param_5)\n"
        "{\n"
        "  return ((ghidra_indirect_fn)param_2)(param_1, param_3, 0, param_4, param_5);\n"
        "}\n"
        "bool FUN_140054570(undefined8 *param_1,byte param_2,byte param_3,ulonglong param_4);\n"
        "void wrapper(void) {\n"
        "  FUN_14003a9f0(GHIDRA_U64(&local_118), FUN_140054570, local_108, (byte *)local_58, _Size);\n"
        "}\n"
    )

    relaxed = engine._relax_mismatched_pointer_prototypes(source)
    normalized = engine._normalize_pointer_arguments_for_uintptr_params(relaxed)

    assert (
        "ulonglong FUN_14003a9f0(uintptr_t param_1,uintptr_t param_2,longlong param_3,byte *param_4,ulonglong param_5)"
        in relaxed
    )
    assert (
        "FUN_14003a9f0(GHIDRA_U64(&local_118), GHIDRA_U64(FUN_140054570), local_108, (byte *)local_58, _Size);"
        in normalized
    )


def test_normalize_pointer_arguments_for_uintptr_params_casts_pointer_locals(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "bool __fastcall FUN_1400a7420(uintptr_t param_1, longlong param_2);\n"
        "ulonglong *********** local_b0;\n"
        "void wrapper(void) {\n"
        "  FUN_1400a7420(local_b0, (longlong)local_e0);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert "FUN_1400a7420(GHIDRA_U64(local_b0), (longlong)local_e0);" in normalized


def test_normalize_pointer_arguments_for_uintptr_params_handles_multiline_calls(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined __fastcall FUN_140049fa0(undefined4 * param_1, longlong param_2, uintptr_t param_3);\n"
        "ulonglong ********** ppppppppppuVar23;\n"
        "void wrapper(void) {\n"
        "  FUN_140049fa0(\n"
        "      (undefined4 *)&local_238,\n"
        "      (longlong)local_70,\n"
        "      ppppppppppuVar23 + 9);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert (
        "FUN_140049fa0((undefined4 *)&local_238, (longlong)local_70, GHIDRA_U64(ppppppppppuVar23 + 9));"
        in normalized
    )


def test_normalize_pointer_arguments_for_uintptr_params_casts_string_literals(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined1 FUN_1400065c0(uintptr_t param_1, undefined8 param_2, int *param_3);\n"
        "void wrapper(void) {\n"
        '  FUN_1400065c0("no_position", 0xb, (int *)&local_168);\n'
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert 'FUN_1400065c0(GHIDRA_U64("no_position"), 0xb, (int *)&local_168);' in normalized


def test_normalize_pointer_arguments_for_uintptr_params_casts_pointer_args_after_void_relaxation(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined FUN_140075e00(uintptr_t param_1, ...);\n"
        "void wrapper(void) {\n"
        "  FUN_140075e00(&local_1f8, local_b8, 0);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert "FUN_140075e00(GHIDRA_U64(&local_1f8), local_b8, 0);" in normalized


def test_normalize_pointer_arguments_for_uintptr_params_casts_indirect_first_args(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong ********** pppppppppppVar1;\n"
        "undefined8 local_308;\n"
        "undefined8 * puVar59;\n"
        "void wrapper(void) {\n"
        "  ((ghidra_indirect_fn)pppppppppppVar1[3])(&local_308, puVar59);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert (
        "((ghidra_indirect_fn)pppppppppppVar1[3])(GHIDRA_U64(&local_308), puVar59);" in normalized
    )


def test_normalize_pointer_arguments_for_uintptr_params_casts_indirect_pointer_cast_first_args(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_308;\n"
        "undefined8 * puVar59;\n"
        "void wrapper(longlong lVar44) {\n"
        "  (*(ghidra_indirect_fn *)(lVar44 + 0x18))(&local_308,puVar59);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert (
        "(*(ghidra_indirect_fn *)(lVar44 + 0x18))(GHIDRA_U64(&local_308), puVar59);" in normalized
    )


def test_normalize_pointer_arguments_for_uintptr_params_casts_bridge_indirect_first_args(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong *********** local_100;\n"
        "void wrapper(undefined8 uStack_88) {\n"
        "  ((ghidra_indirect_fn)*((uintptr_t *)(uintptr_t)uStack_88))(local_100);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert (
        "((ghidra_indirect_fn)*((uintptr_t *)(uintptr_t)uStack_88))(GHIDRA_U64(local_100));"
        in normalized
    )


def test_normalize_pointer_arguments_for_uintptr_params_casts_dereferenced_pointer_first_args(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void wrapper(int *****param_2) {\n"
        '  ((ghidra_indirect_fn)param_2[1][3])(*param_2,"\\n\\nCaused by_",0xc);\n'
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert (
        '((ghidra_indirect_fn)param_2[1][3])(GHIDRA_U64(*param_2), "\\n\\nCaused by_", 0xc);'
        in normalized
    )


def test_normalize_pointer_arguments_for_uintptr_params_casts_multiline_indirect_first_args(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "uint64_t * pppppppppppVar1;\n"
        "void wrapper(void) {\n"
        "  ((ghidra_indirect_fn)(&DAT_1400e24bc +\n"
        "    *(int *)(&DAT_1400e24bc + (longlong)*pppppppppppVar1 * 4)))(&DAT_1400e24bc,1);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert (
        "((ghidra_indirect_fn)(&DAT_1400e24bc +\n"
        "    *(int *)(&DAT_1400e24bc + (longlong)*pppppppppppVar1 * 4)))(GHIDRA_U64(&DAT_1400e24bc), 1);"
        in normalized
    )


def test_normalize_pointer_arguments_for_uintptr_params_preserves_global_rewrite_order_across_callees(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_1400132c0(uintptr_t param_1, uintptr_t param_2);\n"
        "undefined1 FUN_1400065c0(uintptr_t param_1, undefined8 param_2, int *param_3);\n"
        "byte local_c80[0x2c8];\n"
        "LARGE_INTEGER local_678;\n"
        "void wrapper(void) {\n"
        '  FUN_1400065c0("no_position",0xb,(int *)&local_168);\n'
        "  FUN_1400132c0(&local_c80,&local_678);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert 'FUN_1400065c0(GHIDRA_U64("no_position"), 0xb, (int *)&local_168);' in normalized
    assert "FUN_1400132c0(GHIDRA_U64(&local_c80), GHIDRA_U64(&local_678));" in normalized
    assert "FUN_140GHIDRA_U64" not in normalized
    assert "FUN_1GHIDRA_U64" not in normalized
    assert "local_678local_678" not in normalized


def test_normalize_pointer_arguments_for_uintptr_params_preserves_multiline_rewrite_order_across_callees(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_1400132c0(uintptr_t param_1, uintptr_t param_2);\n"
        "undefined __fastcall FUN_140049fa0(undefined4 * param_1, longlong param_2, uintptr_t param_3);\n"
        "ulonglong ********** ppppppppppuVar23;\n"
        "byte local_c80[0x2c8];\n"
        "LARGE_INTEGER local_678;\n"
        "void wrapper(void) {\n"
        "  FUN_140049fa0(\n"
        "      (undefined4 *)&local_238,\n"
        "      (longlong)local_70,\n"
        "      ppppppppppuVar23 + 9);\n"
        "  FUN_1400132c0(&local_c80,&local_678);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_arguments_for_uintptr_params(source)

    assert (
        "FUN_140049fa0((undefined4 *)&local_238, (longlong)local_70, GHIDRA_U64(ppppppppppuVar23 + 9));"
        in normalized
    )
    assert "FUN_1400132c0(GHIDRA_U64(&local_c80), GHIDRA_U64(&local_678));" in normalized
    assert "GHIDRA_U64(ppppppppppuVar23 + 9)0,ppppppppppuVar23 + 9" not in normalized
    assert "FUN_1GHIDRA_U64" not in normalized


def test_normalize_generated_c_semantics_rewrites_indirect_calls_with_whitespace_before_args(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "value = (ulonglong ************)\n"
        "        (*(code *)(&DAT_1400e24bc +\n"
        "                  *(int *)(&DAT_1400e24bc + (longlong)*pppppppppppuVar64 * 4)))\n"
        "                  (&DAT_1400e24bc,1);\n"
    )

    normalized = engine._normalize_generated_c_semantics(
        source, normalize_pointer_assignments=False
    )

    assert (
        "((ghidra_indirect_fn)(&DAT_1400e24bc +\n"
        "                  *(int *)(&DAT_1400e24bc + (longlong)*pppppppppppuVar64 * 4)))"
        "(&DAT_1400e24bc,1);"
    ) in normalized


def test_normalize_pointer_integer_assignments_handles_indexed_pointer_expressions(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_468;\n"
        "ulonglong *********** local_78;\n"
        "local_468 = local_78[0x18];\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_468 = GHIDRA_U64(local_78[0x18]);" in normalized


def test_normalize_pointer_integer_assignments_handles_multiline_pointer_cast_expressions(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_468;\n"
        "local_468 = (ulonglong **********)\n"
        "            CONCAT44((int)uVar60,*(undefined4 *)((longlong)local_78 + 700));\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "local_468 = GHIDRA_U64((ulonglong **********)CONCAT44((int)uVar60,*(undefined4 *)((longlong)local_78 + 700)));"
        in normalized
    )


def test_normalize_pointer_integer_assignments_handles_casted_bare_integer_values(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 uStack_88;\n"
        "longlong lVar44;\n"
        "uStack_88 = (ulonglong ***********)lVar44;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "uStack_88 = GHIDRA_U64((ulonglong ***********)lVar44);" in normalized


def test_normalize_pointer_integer_assignments_handles_address_expressions(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined8 local_308;\n" "longlong local_538;\n" "local_308 = &local_538;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_308 = GHIDRA_U64(&local_538);" in normalized


def test_normalize_pointer_integer_assignments_casts_pointer_lvalues_from_data_symbols(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined * puVar41;\n" "puVar41 = &DAT_1400ce9f8;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "puVar41 = (undefined *)&DAT_1400ce9f8;" in normalized


def test_normalize_pointer_integer_assignments_casts_code_pointer_function_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "code * local_410;\n" "local_410 = FUN_1400303b0;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_410 = (code *)FUN_1400303b0;" in normalized


def test_normalize_pointer_integer_assignments_handles_split_fragment_globals(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "static uint64_t local_1a8_8_8_ = 0;\n"
        "static uint64_t local_1a8_0_8_ = 0;\n"
        "static uint64_t auStack_190_0_8_ = 0;\n"
        "ulonglong ********** pppppppppppuVar55;\n"
        "ulonglong *********** pppppppppppuVar64;\n"
        "local_1a8_8_8_ = pppppppppppuVar55[0x17] + (longlong)pppppppppppuVar55[0x18] * 0x59;\n"
        "local_1a8_0_8_ = pppppppppppuVar55[0x17];\n"
        "auStack_190_0_8_ = pppppppppppuVar64;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "local_1a8_8_8_ = GHIDRA_U64(pppppppppppuVar55[0x17] + (longlong)pppppppppppuVar55[0x18] * 0x59);"
        in normalized
    )
    assert "local_1a8_0_8_ = GHIDRA_U64(pppppppppppuVar55[0x17]);" in normalized
    assert "auStack_190_0_8_ = GHIDRA_U64(pppppppppppuVar64);" in normalized


def test_normalize_pointer_integer_assignments_handles_undeclared_split_fragment_names(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong ********** pppppppppppuVar55;\n"
        "ulonglong *********** pppppppppppuVar64;\n"
        "local_1a8_8_8_ = pppppppppppuVar55[0x17] + (longlong)pppppppppppuVar55[0x18] * 0x59;\n"
        "local_1a8_0_8_ = pppppppppppuVar55[0x17];\n"
        "auStack_190_0_8_ = pppppppppppuVar64;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "local_1a8_8_8_ = GHIDRA_U64(pppppppppppuVar55[0x17] + (longlong)pppppppppppuVar55[0x18] * 0x59);"
        in normalized
    )
    assert "local_1a8_0_8_ = GHIDRA_U64(pppppppppppuVar55[0x17]);" in normalized
    assert "auStack_190_0_8_ = GHIDRA_U64(pppppppppppuVar64);" in normalized


def test_normalize_pointer_integer_assignments_handles_integer_array_element_stores(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 * puVar57;\n"
        "ulonglong *********** local_78;\n"
        "puVar57[uVar60 * 4 + 1] = local_78;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "puVar57[uVar60 * 4 + 1] = GHIDRA_U64(local_78);" in normalized


def test_normalize_pointer_integer_assignments_handles_integer_pointer_dereference_stores(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 * extraout_RAX_00;\n"
        "void * pvVar37;\n"
        "ulonglong * puVar68;\n"
        "*extraout_RAX_00 = pvVar37;\n"
        "extraout_RAX_00[1] = puVar68;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "*extraout_RAX_00 = GHIDRA_U64(pvVar37);" in normalized
    assert "extraout_RAX_00[1] = GHIDRA_U64(puVar68);" in normalized


def test_normalize_pointer_integer_assignments_wraps_pointer_like_string_and_symbol_values(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_1d8;\n"
        "undefined8 uStack_4a8;\n"
        'local_1d8 = "*";\n'
        "uStack_4a8 = &PTR_FUN_1400d2070;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert 'local_1d8 = GHIDRA_U64("*");' in normalized
    assert "uStack_4a8 = GHIDRA_U64(&PTR_FUN_1400d2070);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_bare_function_symbols(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined8 uStack_240;\n" "uStack_240 = FUN_1400367d0;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "uStack_240 = GHIDRA_U64(FUN_1400367d0);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_declared_helper_function_symbols(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 core_fmt_impl_22_fmt(void);\n"
        "undefined8 uStack_a8;\n"
        "uStack_a8 = core_fmt_impl_22_fmt;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "uStack_a8 = GHIDRA_U64(core_fmt_impl_22_fmt);" in normalized


def test_normalize_pointer_integer_assignments_casts_integer_locals_to_pointer_alias_lhs(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "LPVOID local_150;\n" "undefined8 uStack_140;\n" "local_150 = uStack_140;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_150 = (LPVOID)(uintptr_t)uStack_140;" in normalized


def test_normalize_pointer_integer_assignments_prefers_nearest_scope_for_duplicate_local_names(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 FUN_140001000(void) {\n"
        "  longlong local_108;\n"
        "  local_108 = 0;\n"
        "}\n"
        "undefined8 FUN_140002000(void) {\n"
        "  ulonglong ***********local_108;\n"
        "  ulonglong ***********pppppppppppuVar55;\n"
        "  local_108 = GHIDRA_U64(pppppppppppuVar55);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "local_108 = (ulonglong ***********)(uintptr_t)GHIDRA_U64(pppppppppppuVar55);" in normalized
    )


def test_normalize_pointer_integer_assignments_casts_pointer_lvalue_stores_from_ghidra_u64(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "longlong *********extraout_RAX_01;\n"
        "longlong ********src;\n"
        "*extraout_RAX_01 = GHIDRA_U64(src);\n"
        "extraout_RAX_01[1] = GHIDRA_U64(src);\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "*extraout_RAX_01 = (longlong ********)(uintptr_t)GHIDRA_U64(src);" in normalized
    assert "extraout_RAX_01[1] = (longlong ********)(uintptr_t)GHIDRA_U64(src);" in normalized


def test_normalize_pointer_integer_assignments_lvalue_stores_prefer_nearest_scope_base_type(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 FUN_140001000(void) {\n"
        "  undefined8 local_240;\n"
        "  local_240 = 0;\n"
        "}\n"
        "undefined8 FUN_140002000(void) {\n"
        "  ulonglong ***********local_240;\n"
        "  ulonglong **********src;\n"
        "  local_240[idx] = GHIDRA_U64(src);\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_240[idx] = (ulonglong **********)(uintptr_t)GHIDRA_U64(src);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_pointer_arithmetic_rhs(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 uStack_1f0;\n"
        "undefined ************ ppppppppppppuVar22;\n"
        "uStack_1f0 = ppppppppppppuVar22 + 0x4b;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "uStack_1f0 = GHIDRA_U64(ppppppppppppuVar22 + 0x4b);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_pointer_params_into_integer_locals(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 __fastcall FUN_140001000(byte *param_3) {\n"
        "  undefined8 local_68;\n"
        "  local_68 = param_3;\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_68 = GHIDRA_U64(param_3);" in normalized


def test_normalize_pointer_integer_assignments_casts_cast_deref_lvalue_stores(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined ************* puVar35;\n"
        "undefined8 local_188;\n"
        "*(undefined *************)(puVar35 + idx) = local_188;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "*(undefined *************)(puVar35 + idx) = (undefined ************)(uintptr_t)local_188;"
        in normalized
    )


def test_normalize_pointer_integer_assignments_scalarizes_pointer_cast_rhs_into_integer_lvalue_store(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong *puVar20;\n"
        "byte *local_50;\n"
        "*puVar20 = (ulonglong *)(uintptr_t)((uintptr_t *)(uintptr_t)local_50)[idx];\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "*puVar20 = GHIDRA_U64((ulonglong *)(uintptr_t)((uintptr_t *)(uintptr_t)local_50)[idx]);"
        in normalized
    )


def test_normalize_pointer_integer_assignments_retargets_code_pointer_sources_for_data_pointers(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined1 *local_150;\n" "code *pcStack_188;\n" "local_150 = pcStack_188;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_150 = (undefined1 *)(uintptr_t)GHIDRA_U64(pcStack_188);" in normalized


def test_normalize_pointer_integer_assignments_casts_incompatible_pointer_assignments(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "char **local_b8;\n" "undefined **param_1;\n" "local_b8 = param_1;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_b8 = (char **)param_1;" in normalized


def test_normalize_pointer_integer_assignments_casts_pointer_rank_mismatches(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 *******local_b8;\n" "undefined8 ********local_90;\n" "local_b8 = &local_90;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_b8 = (undefined8 *******)&local_90;" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_pointer_cast_rhs_into_integer_param_slots(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong *param_2;\n"
        "undefined8 uVar26;\n"
        "*param_2 = (int ****)(uintptr_t)uVar26;\n"
        "param_2[2] = (int ****)(uintptr_t)uVar26;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "*param_2 = GHIDRA_U64((int ****)(uintptr_t)uVar26);" in normalized
    assert "param_2[2] = GHIDRA_U64((int ****)(uintptr_t)uVar26);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_pointer_cast_rhs_into_integer_param_slots_with_multiline_signature(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_140041b00(ulonglong *******param_1,ulonglong *param_2,ulonglong *******param_3,\n"
        "                  longlong param_4)\n"
        "{\n"
        "  undefined8 uVar26;\n"
        "  *param_2 = (int ****)(uintptr_t)uVar26;\n"
        "  param_2[2] = (int ****)(uintptr_t)uVar26;\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "*param_2 = GHIDRA_U64((int ****)(uintptr_t)uVar26);" in normalized
    assert "param_2[2] = GHIDRA_U64((int ****)(uintptr_t)uVar26);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_pointer_cast_rhs_into_integer_param_slots_with_blank_line_before_brace(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_140041b00(ulonglong *******param_1,ulonglong *param_2,ulonglong *******param_3,\n"
        "                  longlong param_4)\n"
        "\n"
        "{\n"
        "  undefined8 uVar26;\n"
        "  *param_2 = (int ****)(uintptr_t)uVar26;\n"
        "  param_2[2] = (int ****)(uintptr_t)uVar26;\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "*param_2 = GHIDRA_U64((int ****)(uintptr_t)uVar26);" in normalized
    assert "param_2[2] = GHIDRA_U64((int ****)(uintptr_t)uVar26);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_pointer_params_into_integer_fragments(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void FUN_14005f6c0(longlong *param_2)\n"
        "{\n"
        "  auVar1_8_8_ = 0;\n"
        "  auVar1_0_8_ = param_2;\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "auVar1_0_8_ = GHIDRA_U64(param_2);" in normalized


def test_normalize_pointer_integer_assignments_retargets_pointer_cast_immediates_for_pointer_rank_mismatches(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined8 ***local_128;\n" "local_128 = (undefined8 ****)0x3;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_128 = (undefined8 ***)(uintptr_t)((undefined8 ****)0x3);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_pointer_alias_casts_into_integer_locals(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong local_120;\n"
        "undefined8 *local_88;\n"
        "local_120 = (LPVOID)(uintptr_t)((uintptr_t *)(uintptr_t)local_88)[1];\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "local_120 = GHIDRA_U64((LPVOID)(uintptr_t)((uintptr_t *)(uintptr_t)local_88)[1]);"
        in normalized
    )


def test_normalize_pointer_integer_assignments_scalarizes_pointer_deref_reads_into_integer_locals(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "size_t *local_a0;\n" "undefined8 uVar6;\n" "uVar6 = *local_a0;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "uVar6 = GHIDRA_U64(*local_a0);" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_casted_pointer_deref_reads_into_integer_locals(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_e8;\n"
        "longlong param_3;\n"
        "local_e8 = *(undefined8 **)(param_3 + 0x1f0);\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_e8 = GHIDRA_U64(*(undefined8 **)(param_3 + 0x1f0));" in normalized


def test_normalize_pointer_integer_assignments_rewrites_inline_symbol_assignments(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined ****ppppuVar20;\n"
        "code *pcVar23;\n"
        "if ((ppppuVar20 = ___xmm_0000002b0000002b0000002d0000002b, pcVar23 = _UNK_1400ca498,\n"
        "    flag)) {\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "ppppuVar20 = (undefined ****)(uintptr_t)&___xmm_0000002b0000002b0000002d0000002b"
        in normalized
    )
    assert "pcVar23 = (code *)(uintptr_t)GHIDRA_U64(_UNK_1400ca498)" in normalized


def test_normalize_pointer_integer_assignments_ignores_warning_comments_before_functions(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void prior_helper(void)\n"
        "{\n"
        "  return;\n"
        "}\n"
        "/* WARNING_ Type propagation algorithm not settling */\n"
        "/* WARNING_ Globals starting with '_' overlap smaller symbols at the same address */\n"
        "\n"
        "void FUN_140026a50(undefined1 *param_1,byte *param_2,byte *param_3)\n"
        "\n"
        "{\n"
        "  undefined8 local_68;\n"
        "  local_68 = param_3;\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_68 = GHIDRA_U64(param_3);" in normalized


def test_normalize_pointer_integer_assignments_recovers_local_boundary_when_cache_misses(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void prior_helper(undefined4 *param_1,longlong param_2,undefined8 param_3,undefined8 param_4)\n"
        "\n"
        "{\n"
        "  return;\n"
        "}\n"
        "/* WARNING_ Type propagation algorithm not settling */\n"
        "/* WARNING_ Globals starting with '_' overlap smaller symbols at the same address */\n"
        "\n"
        "void FUN_1400a4770(void *param_1,undefined1 *param_2,undefined8 *param_3,undefined1 *param_4,int param_5,void *param_6)\n"
        "\n"
        "{\n"
        "  undefined8 *local_60;\n"
        "  param_3 = GHIDRA_U64(local_60);\n"
        "}\n"
    )

    original = engine._get_enclosing_function_boundary_index

    def stale_then_recover(source_text: str, before_pos: int):
        if before_pos == source.index("param_3 = GHIDRA_U64(local_60);"):
            return 2
        return original(source_text, before_pos)

    engine._get_enclosing_function_boundary_index = stale_then_recover  # type: ignore[method-assign]

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "param_3 = (undefined8 *)(uintptr_t)GHIDRA_U64(local_60);" in normalized


def test_normalize_pointer_integer_assignments_rewrites_inline_byte_buffer_assignments_for_code_locals(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "code *cVar2;\n"
        "code *local_c8;\n"
        "if ((cVar2 = ((byte *)(uintptr_t)local_c8)[3], (char)cVar2 < -0x40)) {\n"
        "}\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "cVar2 = (code *)(uintptr_t)GHIDRA_U64(((byte *)(uintptr_t)local_c8)[3])" in normalized


def test_normalize_pointer_integer_assignments_retargets_lab_symbols_for_pointer_locals(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined1 *puStack_e0;\n" "puStack_e0 = &LAB_14003da00;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "puStack_e0 = (undefined1 *)&LAB_14003da00;" in normalized


def test_normalize_pointer_integer_assignments_retargets_ptr_dat_symbols_for_pointer_locals(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined **local_e8;\n" "local_e8 = &PTR_DAT_1400dab90;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_e8 = (undefined **)&PTR_DAT_1400dab90;" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_code_pointer_slot_reads_into_integer_locals(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "code *pcVar10;\n" "undefined8 local_128;\n" "local_128 = *(code **)pcVar10;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_128 = GHIDRA_U64(*(code **)pcVar10);" in normalized


def test_normalize_pointer_integer_assignments_preserves_casted_deref_comparisons(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "if (*(int *)ppppppppuVar138 == 0x68747561) {\n" "  return;\n" "}\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "*(int *)ppppppppuVar138 == 0x68747561" in normalized


def test_normalize_pointer_integer_assignments_preserves_parenthesized_comparisons(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "if (((1 < uVar60 || uVar60 != limit) & *(byte *)ptr) == 0 && flag) goto LAB;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "== 0 && flag" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_parenthesized_index_slot_pointer_stores(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 * puVar19;\n"
        "undefined8 * puStack_1b8;\n"
        "LPVOID * ppvStack_1d8;\n"
        "(puVar19 + idx)[1] = puStack_1b8;\n"
        "(puVar19 + idx2)[1] = ppvStack_1d8;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "(puVar19 + idx)[1] = GHIDRA_U64(puStack_1b8);" in normalized
    assert "(puVar19 + idx2)[1] = GHIDRA_U64(ppvStack_1d8);" in normalized


def test_normalize_pointer_integer_assignments_casts_scalar_helper_results_to_pointer_lhs(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong ************ ppppppppppppuVar11;\n"
        "ppppppppppppuVar11 = SUB168(auVar3 * auVar4,0);\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "ppppppppppppuVar11 = (ulonglong ************)(uintptr_t)SUB168(auVar3 * auVar4,0);"
        in normalized
    )


def test_normalize_integer_pointer_accesses_casts_integer_scalars_used_as_pointers(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 uStack_88;\n"
        "if (*uStack_88 != (ulonglong **********)0x0) {\n"
        "  ((ghidra_indirect_fn)*uStack_88)(local_100);\n"
        "}\n"
        "if (uStack_88[1] == (ulonglong **********)0x0) {\n"
        "  return;\n"
        "}\n"
        "FUN_140037ee0(local_100,(ulonglong)uStack_88[2]);\n"
    )

    normalized = engine._normalize_integer_pointer_accesses(source)

    assert "*((uintptr_t *)(uintptr_t)uStack_88) != (ulonglong **********)0x0" in normalized
    assert "((ghidra_indirect_fn)*((uintptr_t *)(uintptr_t)uStack_88))(local_100);" in normalized
    assert "((uintptr_t *)(uintptr_t)uStack_88)[1] == (ulonglong **********)0x0" in normalized
    assert (
        "FUN_140037ee0(local_100,(ulonglong)((uintptr_t *)(uintptr_t)uStack_88)[2]);" in normalized
    )


def test_normalize_integer_pointer_accesses_preserves_declarations(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void *extraout_RAX;\n"
        "ulonglong ***********extraout_RAX_08;\n"
        "undefined8 uStack_88;\n"
        "if (*uStack_88 != (ulonglong **********)0x0) {\n"
        "  ((ghidra_indirect_fn)*uStack_88)(local_100);\n"
        "}\n"
    )

    normalized = engine._normalize_integer_pointer_accesses(source)

    assert "void *extraout_RAX;" in normalized
    assert "ulonglong ***********extraout_RAX_08;" in normalized
    assert "void *((uintptr_t *)(uintptr_t)extraout_RAX);" not in normalized
    assert "ulonglong ***********((uintptr_t *)(uintptr_t)extraout_RAX_08);" not in normalized
    assert "((ghidra_indirect_fn)*((uintptr_t *)(uintptr_t)uStack_88))(local_100);" in normalized


def test_normalize_uintptr_bridge_accesses_wraps_pointer_stores(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong *********** extraout_RAX_18;\n"
        "((uintptr_t *)(uintptr_t)extraout_RAX_18)[2] = (ulonglong **********)CONCAT17(cStack_341,local_348);\n"
        "*((uintptr_t *)(uintptr_t)extraout_RAX_18) = (ulonglong **********)CONCAT17(local_358_7_1_,(undefined7)local_358);\n"
    )

    normalized = engine._normalize_uintptr_bridge_accesses(source)

    assert (
        "((uintptr_t *)(uintptr_t)extraout_RAX_18)[2] = GHIDRA_U64((ulonglong **********)CONCAT17(cStack_341,local_348));"
        in normalized
    )
    assert (
        "*((uintptr_t *)(uintptr_t)extraout_RAX_18) = GHIDRA_U64((ulonglong **********)CONCAT17(local_358_7_1_,(undefined7)local_358));"
        in normalized
    )


def test_normalize_uintptr_bridge_accesses_casts_pointer_reads(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong ********** ppppppppppuVar20;\n"
        "undefined8 local_88;\n"
        "ppppppppppuVar20 = ((uintptr_t *)(uintptr_t)local_88)[0x12];\n"
    )

    normalized = engine._normalize_uintptr_bridge_accesses(source)

    assert (
        "ppppppppppuVar20 = (ulonglong **********)(uintptr_t)((uintptr_t *)(uintptr_t)local_88)[0x12];"
        in normalized
    )


def test_normalize_uintptr_bridge_accesses_rewrites_nested_subscripts(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "undefined8 local_88;\n"
        "pppppppppuVar29 = ((uintptr_t *)(uintptr_t)local_88)[0x20][(longlong)ppppppppppuVar20 * 4 + 1];\n"
    )

    normalized = engine._normalize_uintptr_bridge_accesses(source)

    assert (
        "((uintptr_t *)(uintptr_t)((uintptr_t *)(uintptr_t)local_88)[0x20])[(longlong)ppppppppppuVar20 * 4 + 1]"
        in normalized
    )


def test_normalize_uintptr_bridge_accesses_casts_nested_bridge_assignment_reads(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong ********* pppppppppuVar29;\n"
        "undefined8 local_88;\n"
        "pppppppppuVar29 = ((uintptr_t *)(uintptr_t)((uintptr_t *)(uintptr_t)local_88)[0x20])[(longlong)ppppppppppuVar20 * 4 + 1];\n"
    )

    normalized = engine._normalize_uintptr_bridge_accesses(source)

    assert "pppppppppuVar29 = (ulonglong *********)(uintptr_t)" in normalized
    assert "[(longlong)ppppppppppuVar20 * 4 + 1];" in normalized


def test_normalize_uintptr_bridge_accesses_casts_inline_bridge_reads(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong ********** ppppppppppuVar20;\n"
        "undefined8 local_88;\n"
        "if ((ppppppppppuVar20 = ((uintptr_t *)(uintptr_t)local_88)[0x12], ppppppppppuVar20 != (ulonglong **********)0x0)) {\n"
        "  return;\n"
        "}\n"
    )

    normalized = engine._normalize_uintptr_bridge_accesses(source)

    assert (
        "if ((ppppppppppuVar20 = (ulonglong **********)(uintptr_t)((uintptr_t *)(uintptr_t)local_88)[0x12], ppppppppppuVar20 != (ulonglong **********)0x0)) {"
        in normalized
    )


def test_normalize_uintptr_bridge_accesses_casts_deref_bridge_reads(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong *********** local_b0;\n"
        "ulonglong ********** ppppppppppuVar20;\n"
        "ppppppppppuVar20 = *((uintptr_t *)(uintptr_t)local_b0);\n"
    )

    normalized = engine._normalize_uintptr_bridge_accesses(source)

    assert (
        "ppppppppppuVar20 = (ulonglong **********)(uintptr_t)*((uintptr_t *)(uintptr_t)local_b0);"
        in normalized
    )


def test_normalize_uintptr_bridge_accesses_casts_bridge_indirect_call_args(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong *********** local_100;\n"
        "undefined8 uStack_88;\n"
        "  ((ghidra_indirect_fn)*((uintptr_t *)(uintptr_t)uStack_88))(local_100);\n"
    )

    normalized = engine._normalize_uintptr_bridge_accesses(source)

    assert (
        "((ghidra_indirect_fn)*((uintptr_t *)(uintptr_t)uStack_88))(GHIDRA_U64(local_100));"
        in normalized
    )


def test_normalize_generated_c_semantics_repairs_default_and_switch_labels(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "switch((uintptr_t)local_58) {\n"
        "default_\n"
        "  goto switchD_140026d68_caseD_1;\n"
        "switchD_140026d68_caseD_1_\n"
        "  return;\n"
        "}\n"
    )

    normalized = engine._normalize_generated_c_semantics(
        source, normalize_pointer_assignments=False
    )

    assert "default:" in normalized
    assert "switchD_140026d68_caseD_1:" in normalized


def test_normalize_uintptr_bridge_accesses_leaves_non_bridge_lines_unchanged(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong ********** ppppppppppuVar20;\n"
        "ppppppppppuVar20 = (ulonglong **********)0x0;\n"
        "core_str_converts_from_utf8();\n"
    )

    normalized = engine._normalize_uintptr_bridge_accesses(source)

    assert normalized.splitlines() == source.splitlines()


def test_normalize_pointer_integer_assignments_handles_auvar_split_fragments(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "ulonglong *********** pppppppppppuStack_220;\n" "auVar58_0_8_ = pppppppppppuStack_220;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "auVar58_0_8_ = GHIDRA_U64(pppppppppppuStack_220);" in normalized


def test_normalize_pointer_integer_assignments_leaves_undeclared_split_fragment_scalar_stores_unchanged(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "HANDLE local_228;\n"
        "undefined7 uStack_298;\n"
        "undefined1 uStack_289;\n"
        "local_228_0_7_ = uStack_298;\n"
        "local_228_7_1_ = uStack_289;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_228_0_7_ = uStack_298;" in normalized
    assert "local_228_7_1_ = uStack_289;" in normalized


def test_normalize_pointer_integer_assignments_leaves_undeclared_split_fragment_scalar_rhs_casts_unchanged(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "HANDLE local_228;\n"
        "undefined8 uStack_298;\n"
        "local_228_0_7_ = (undefined7)uStack_298;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "local_228_0_7_ = (undefined7)uStack_298;" in normalized


def test_normalize_pointer_integer_assignments_leaves_undeclared_split_fragment_copies_scalar(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "HANDLE auVar59;\n"
        "undefined8 auVar58;\n"
        "auVar59_0_8_ = auVar58_0_8_;\n"
        "auVar59_8_4_ = auVar58_4_4_;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "auVar59_0_8_ = auVar58_0_8_;" in normalized
    assert "auVar59_8_4_ = auVar58_4_4_;" in normalized


def test_normalize_pointer_integer_assignments_scalarizes_pointer_based_split_fragment_reads_in_integer_expressions(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "longlong lVar47;\n" "HANDLE auVar59;\n" "lVar47 = lVar47 + auVar59_0_8_;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "lVar47 = GHIDRA_U64(lVar47 + auVar59_0_8_);" in normalized


def test_normalize_pointer_integer_assignments_wraps_byte_array_rhs_for_integer_fragments(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "undefined1 auVar123 [11];\n" "auVar151_0_11_ = auVar123;\n"

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert "auVar151_0_11_ = GHIDRA_U64(auVar123);" in normalized


def test_normalize_pointer_integer_assignments_prefers_explicit_scalar_fragment_declarations_over_base_pointer_types(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "static uint64_t pppppppppppuStack_220_7_1_ = 0;\n"
        "static uint64_t auVar151_0_11_ = 0;\n"
        "ulonglong *********** pppppppppppuStack_220;\n"
        "undefined1 * auVar151;\n"
        "undefined8 uStack_289;\n"
        "undefined1 * auVar123;\n"
        "pppppppppppuStack_220_7_1_ = (ulonglong ***********)(uintptr_t)uStack_289;\n"
        "auVar151_0_11_ = auVar123;\n"
    )

    normalized = engine._normalize_pointer_integer_assignments(source)

    assert (
        "pppppppppppuStack_220_7_1_ = GHIDRA_U64((ulonglong ***********)(uintptr_t)uStack_289);"
        in normalized
    )
    assert "auVar151_0_11_ = GHIDRA_U64(auVar123);" in normalized


def test_normalize_integer_pointer_accesses_does_not_rewrite_multiplication(tmp_path: Path):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = "ulonglong uVar186;\n" "uVar190 = _Size - lVar188 * uVar186;\n"

    normalized = engine._normalize_integer_pointer_accesses(source)

    assert "uVar190 = _Size - lVar188 * uVar186;" in normalized
    assert "((uintptr_t *)(uintptr_t)uVar186)" not in normalized


def test_relax_mismatched_pointer_prototypes_handles_casted_first_args_and_nonfirst_pointer_params(
    tmp_path: Path,
):
    engine = BinaryRecompilationEngine(
        ghidra_engine=None,
        gemini_engine=None,
        work_dir=tmp_path,
    )

    source = (
        "void * __fastcall FUN_14007c630(longlong param_1, undefined8 * param_2, longlong * param_3, longlong * param_4);\n"
        "ghidra_vec64 local_228;\n"
        "longlong local_358;\n"
        "longlong local_1f8;\n"
        "void wrapper(void) {\n"
        "  FUN_14007c630((longlong)pppppppppppuVar64,\n"
        "                &local_228,\n"
        "                &local_358,\n"
        "                &local_1f8);\n"
        "}\n"
    )

    normalized = engine._relax_mismatched_pointer_prototypes(source)

    assert (
        "FUN_14007c630(longlong param_1, void * param_2, longlong * param_3, longlong * param_4);"
        in normalized
    )
