#!/usr/bin/env python3
"""
Deterministic integration tests for the LLM4Decompile integration layer.

These checks exercise prompt formatting, code extraction, and ensemble wiring
without requiring the external model weights to be available locally.
"""

from reveng.ai.llm4decompile_engine import (
    DecompilationResult,
    LLM4DecompileEngine,
    MultiModelEnsemble,
)


def test_llm4decompile_formats_optimization_aware_prompt():
    engine = LLM4DecompileEngine()

    prompt = engine._format_prompt("mov %eax, %ebx", "O2", "add_numbers")

    assert "gcc -O2" in prompt
    assert "Function: add_numbers" in prompt
    assert "mov %eax, %ebx" in prompt
    assert "```asm" in prompt
    assert "```c" in prompt


def test_llm4decompile_extracts_code_from_fenced_output():
    engine = LLM4DecompileEngine()

    code = engine._extract_code(
        "Decompiled C code:\n```c\nint add(int a, int b) {\n    return a + b;\n}\n```"
    )

    assert code == "int add(int a, int b) {\n    return a + b;\n}"


def test_multimodel_ensemble_initializes_lazy_members():
    ensemble = MultiModelEnsemble()

    assert isinstance(ensemble.llm4decompile, LLM4DecompileEngine)
    assert ensemble.gemini is None
    assert ensemble.gpt4 is None
    assert ensemble.claude is None


def test_multimodel_ensemble_combines_successful_functions():
    ensemble = MultiModelEnsemble()

    combined = ensemble._combine_functions(
        {
            "helper": DecompilationResult(
                success=True,
                source_code="int helper(void) { return 7; }",
                optimization_level="O0",
            ),
            "broken": DecompilationResult(
                success=False,
                source_code="",
                optimization_level="O0",
                error="model failure",
            ),
            "main": DecompilationResult(
                success=True,
                source_code="int main(void) { return helper(); }",
                optimization_level="O0",
            ),
        }
    )

    assert "#include <stdio.h>" in combined
    assert "int helper(void) { return 7; }" in combined
    assert "int main(void) { return helper(); }" in combined
    assert "model failure" not in combined
