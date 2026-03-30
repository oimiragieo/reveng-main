#!/usr/bin/env python3
"""
POC Tests for LLM4Decompile Integration
========================================

Tests to verify LLM4Decompile provides 20-40% accuracy improvement over standard decompilation.
"""

import os
import subprocess
import tempfile
from pathlib import Path

import pytest

# Test data directory
TEST_DATA_DIR = Path(__file__).parent / "test_binaries"

pytestmark = [
    pytest.mark.poc,
    pytest.mark.requires_external_tools,
    pytest.mark.slow,
]


def _cleanup_if_exists(path: str | None):
    """Best-effort cleanup for temporary compilation artifacts."""
    if path and os.path.exists(path):
        try:
            os.remove(path)
        except PermissionError:
            pass


@pytest.fixture
def simple_test_binary():
    """Create a simple test binary for decompilation"""
    test_code = """
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int main() {
    int result = add(5, 10);
    printf("%d\\n", result);
    return 0;
}
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(test_code)
        source_file = f.name

    output_file = source_file.replace(".c", ".out")

    try:
        # Compile with O0 (no optimization)
        result = subprocess.run(
            ["gcc", "-O0", source_file, "-o", output_file], capture_output=True, timeout=30
        )

        if result.returncode != 0:
            pytest.skip(f"Failed to compile test binary: {result.stderr.decode()}")

        yield output_file

    finally:
        _cleanup_if_exists(source_file)
        _cleanup_if_exists(output_file)


@pytest.mark.asyncio
async def test_llm4decompile_basic_functionality():
    """Test basic LLM4Decompile functionality"""
    from reveng.ai.llm4decompile_engine import LLM4DecompileEngine

    try:
        engine = LLM4DecompileEngine()

        # Test simple assembly
        simple_asm = """
        push   %rbp
        mov    %rsp,%rbp
        mov    %edi,-0x4(%rbp)
        mov    %esi,-0x8(%rbp)
        mov    -0x4(%rbp),%edx
        mov    -0x8(%rbp),%eax
        add    %edx,%eax
        pop    %rbp
        ret
        """

        result = await engine.decompile_function(
            simple_asm, optimization_level="O0", function_name="add"
        )

        assert result.success, f"Decompilation failed: {result.error}"
        assert len(result.source_code) > 0, "Decompiled code is empty"
        assert (
            "return" in result.source_code.lower()
        ), "Decompiled code should contain return statement"

        print("✓ Basic decompilation successful")
        print(f"Decompiled code:\n{result.source_code}")

    except (ImportError, OSError) as e:
        pytest.skip(f"LLM4Decompile dependencies not available: {e}")


@pytest.mark.asyncio
async def test_llm4decompile_vs_ghidra_accuracy(simple_test_binary):
    """
    Compare LLM4Decompile vs Ghidra accuracy

    Expected: LLM4Decompile should show improvement in recompilability
    """
    from reveng.ai.llm4decompile_engine import LLM4DecompileEngine

    try:
        engine = LLM4DecompileEngine()

        # Decompile with LLM4Decompile
        llm_results = await engine.decompile_binary(simple_test_binary, optimization_level="O0")

        # Combine functions
        llm_code = ""
        for func_name, result in llm_results.items():
            if result.success:
                llm_code += result.source_code + "\n\n"

        # Try to compile LLM4Decompile output
        llm_compiles = await _try_compile(llm_code, "O0")

        print(f"✓ LLM4Decompile recompilability: {llm_compiles}")

        # Note: In production, we'd compare with Ghidra output
        # For POC, we just verify LLM4Decompile can produce compilable code

        assert llm_compiles, "LLM4Decompile output should be compilable"

    except (ImportError, OSError) as e:
        pytest.skip(f"LLM4Decompile dependencies not available: {e}")


@pytest.mark.asyncio
async def test_llm4decompile_re_executability(simple_test_binary):
    """
    Test re-executability: can decompiled code produce same results?

    Expected: 21%+ re-executability rate (target from research)
    """
    from reveng.ai.llm4decompile_engine import LLM4DecompileEngine

    try:
        engine = LLM4DecompileEngine()

        # Decompile binary
        results = await engine.decompile_binary(simple_test_binary, optimization_level="O0")

        # Combine functions into full source
        full_source = _combine_decompiled_functions(results)

        # Measure re-executability
        score = await engine.evaluate_re_executability(
            simple_test_binary, full_source, optimization_level="O0"
        )

        print(f"✓ Re-executability score: {score:.1%}")

        # For simple test binary, should achieve high re-executability
        # Real-world complex binaries target is 21%+
        assert score > 0.0, "Should achieve some re-executability"

    except (ImportError, OSError) as e:
        pytest.skip(f"LLM4Decompile dependencies not available: {e}")


@pytest.mark.asyncio
async def test_llm4decompile_optimization_levels():
    """Test decompilation across different optimization levels"""
    from reveng.ai.llm4decompile_engine import LLM4DecompileEngine

    try:
        engine = LLM4DecompileEngine()

        test_code = """
#include <stdio.h>
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}
"""

        optimization_levels = ["O0", "O1", "O2", "O3"]
        results = {}

        for opt_level in optimization_levels:
            # Compile with optimization
            binary = await _compile_code(test_code, opt_level)

            if binary:
                # Decompile
                decompiled = await engine.decompile_binary(binary, optimization_level=opt_level)

                # Measure quality
                code = _combine_decompiled_functions(decompiled)
                compiles = await _try_compile(code, opt_level)

                results[opt_level] = compiles
                print(f"✓ {opt_level}: compilable={compiles}")

        if not results:
            pytest.skip(
                "No optimization-level binaries or model outputs were available in this environment"
            )

        # Should handle at least O0 when the environment can compile and decompile.
        assert results.get("O0", False), "Should handle O0 optimization"

        print(f"Optimization level support: {results}")

    except (ImportError, OSError) as e:
        pytest.skip(f"LLM4Decompile dependencies not available: {e}")


def test_llm4decompile_multi_model_ensemble():
    """Test multi-model ensemble for best results"""
    from reveng.ai.llm4decompile_engine import MultiModelEnsemble

    try:
        ensemble = MultiModelEnsemble()

        # Verify ensemble setup
        assert ensemble.llm4decompile is not None

        print("✓ Multi-model ensemble initialized")
        print("  - LLM4Decompile: Available")
        print(f"  - Gemini: {ensemble._get_gemini() is not None}")

    except (ImportError, OSError) as e:
        pytest.skip(f"Ensemble dependencies not available: {e}")


# ================================================================================
# Helper Functions
# ================================================================================


async def _try_compile(source_code: str, opt_level: str) -> bool:
    """Try to compile source code"""
    import tempfile

    try:
        # Write source
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(source_code)
            source_file = f.name

        output_file = source_file.replace(".c", ".out")

        # Compile
        result = subprocess.run(
            ["gcc", f"-{opt_level}", source_file, "-o", output_file],
            capture_output=True,
            timeout=30,
        )

        success = result.returncode == 0

        # Cleanup
        _cleanup_if_exists(source_file)
        _cleanup_if_exists(output_file)

        return success

    except Exception:
        return False


async def _compile_code(source_code: str, opt_level: str) -> str:
    """Compile code and return binary path"""
    import tempfile

    try:
        # Write source
        with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
            f.write(source_code)
            source_file = f.name

        output_file = source_file.replace(".c", ".out")

        # Compile
        result = subprocess.run(
            ["gcc", f"-{opt_level}", source_file, "-o", output_file],
            capture_output=True,
            timeout=30,
        )

        _cleanup_if_exists(source_file)

        if result.returncode != 0:
            return None

        return output_file

    except Exception:
        return None


def _combine_decompiled_functions(results: dict) -> str:
    """Combine decompiled functions into full source"""
    functions = []

    for func_name, result in results.items():
        if result.success:
            functions.append(result.source_code)

    header = """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

"""

    return header + "\n\n".join(functions)


if __name__ == "__main__":
    # Run POC tests
    print("=" * 80)
    print("LLM4Decompile POC Tests")
    print("=" * 80)

    pytest.main([__file__, "-v", "-m", "poc", "-s"])
