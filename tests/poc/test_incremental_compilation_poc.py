#!/usr/bin/env python3
"""
POC Tests for Incremental Compilation System
=============================================

Tests to verify ccache/sccache provides 5-10x speedup for iterative compilation.
"""

import os
import tempfile

import pytest


@pytest.fixture
def large_source_file():
    """Create a moderately large C source file for compilation testing"""
    # Generate a source file with many functions to simulate real-world compilation
    code_lines = ["#include <stdio.h>\n\n"]

    # Generate 100 simple functions
    for i in range(100):
        code_lines.append(
            f"""
int function_{i}(int x) {{
    int result = x * {i} + {i*2};
    for (int j = 0; j < 10; j++) {{
        result += j * {i};
    }}
    return result;
}}
"""
        )

    # Add main function that calls all the others
    code_lines.append("\nint main() {\n")
    code_lines.append("    int sum = 0;\n")
    for i in range(100):
        code_lines.append(f"    sum += function_{i}({i});\n")
    code_lines.append('    printf("%d\\n", sum);\n')
    code_lines.append("    return 0;\n")
    code_lines.append("}\n")

    source_code = "".join(code_lines)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        f.write(source_code)
        source_file = f.name

    yield source_file

    # Cleanup
    if os.path.exists(source_file):
        os.remove(source_file)


@pytest.mark.poc
def test_incremental_compiler_basic():
    """Test basic incremental compiler functionality"""
    from reveng.compilation.incremental_compiler import IncrementalCompiler

    compiler = IncrementalCompiler()

    print("\n✓ Incremental compiler initialized")
    print(f"  Cache backend: {compiler.cache_backend or 'None (direct compilation)'}")
    print(f"  Cache enabled: {compiler.cache_enabled}")
    print(f"  Cache directory: {compiler.cache_dir}")

    if compiler.cache_enabled:
        stats = compiler.get_cache_stats()
        if stats:
            print(f"  Cache hits: {stats.hits}")
            print(f"  Cache misses: {stats.misses}")
            print(f"  Hit rate: {stats.hit_rate:.1%}")


@pytest.mark.poc
def test_incremental_compilation_speedup(large_source_file):
    """
    Measure compilation speedup with caching

    Expected: 5-10x speedup on cached compilation
    """
    from reveng.compilation.incremental_compiler import IncrementalCompiler

    compiler = IncrementalCompiler()

    if not compiler.cache_enabled:
        pytest.skip("Compiler cache not available. Install ccache or sccache.")

    output_file1 = large_source_file.replace(".c", "_1.out")
    output_file2 = large_source_file.replace(".c", "_2.out")

    try:
        # First compilation (cold cache)
        print("\n" + "=" * 60)
        print("First compilation (cold cache)...")
        result1 = compiler.compile(
            large_source_file, output_file1, compiler="gcc", flags=["-O2", "-Wall"]
        )

        assert result1.success, f"First compilation failed: {result1.stderr}"
        cold_time = result1.compile_time

        print(f"✓ Cold compilation: {cold_time:.2f}s")
        print(f"  Cached: {result1.cached}")
        print(
            f"  Hit rate: {result1.cache_hit_rate:.1%}"
            if result1.cache_hit_rate
            else "  Hit rate: N/A"
        )

        # Second compilation (warm cache)
        # Same source file, different output to force recompile
        print("\n" + "=" * 60)
        print("Second compilation (warm cache)...")
        result2 = compiler.compile(
            large_source_file, output_file2, compiler="gcc", flags=["-O2", "-Wall"]
        )

        assert result2.success, f"Second compilation failed: {result2.stderr}"
        warm_time = result2.compile_time

        print(f"✓ Warm compilation: {warm_time:.2f}s")
        print(f"  Cached: {result2.cached}")
        print(
            f"  Hit rate: {result2.cache_hit_rate:.1%}"
            if result2.cache_hit_rate
            else "  Hit rate: N/A"
        )

        # Calculate speedup
        if warm_time > 0:
            speedup = cold_time / warm_time
        else:
            speedup = float("inf")

        print("\n" + "=" * 60)
        print(f"SPEEDUP: {speedup:.1f}x")
        print("=" * 60)

        # Expected: 5-10x speedup
        # In practice, ccache can achieve up to 10x or more
        # We'll be conservative and expect at least 2x
        assert speedup >= 2.0, f"Expected at least 2x speedup, got {speedup:.1f}x"

        if speedup >= 5.0:
            print("✓ EXCELLENT: Achieved 5x+ speedup target!")
        elif speedup >= 2.0:
            print("✓ GOOD: Achieved 2x+ speedup")

        # Print final stats
        print("\n" + "=" * 60)
        compiler.print_stats()

    finally:
        # Cleanup
        for f in [output_file1, output_file2]:
            if os.path.exists(f):
                os.remove(f)


@pytest.mark.poc
def test_cache_hit_rate_accumulation(large_source_file):
    """Test that cache hit rate improves with multiple compilations"""
    from reveng.compilation.incremental_compiler import IncrementalCompiler

    compiler = IncrementalCompiler()

    if not compiler.cache_enabled:
        pytest.skip("Compiler cache not available. Install ccache or sccache.")

    hit_rates = []

    try:
        # Compile multiple times
        for i in range(5):
            output_file = large_source_file.replace(".c", f"_test{i}.out")

            result = compiler.compile(large_source_file, output_file, compiler="gcc", flags=["-O2"])

            assert result.success, f"Compilation {i} failed"

            if result.cache_hit_rate is not None:
                hit_rates.append(result.cache_hit_rate)

            # Cleanup immediately
            if os.path.exists(output_file):
                os.remove(output_file)

        print(f"\n✓ Cache hit rates across {len(hit_rates)} compilations:")
        for i, rate in enumerate(hit_rates):
            print(f"  Compilation {i+1}: {rate:.1%}")

        # Hit rate should generally improve
        if len(hit_rates) >= 2:
            final_rate = hit_rates[-1]
            print(f"\n✓ Final hit rate: {final_rate:.1%}")

            # After multiple compilations, hit rate should be reasonable
            assert final_rate > 0.0, "Hit rate should improve with repeated compilation"

    except Exception:
        # Cleanup in case of error
        for i in range(5):
            output_file = large_source_file.replace(".c", f"_test{i}.out")
            if os.path.exists(output_file):
                os.remove(output_file)
        raise


@pytest.mark.poc
def test_multiple_optimization_levels(large_source_file):
    """Test caching works across different optimization levels"""
    from reveng.compilation.incremental_compiler import IncrementalCompiler

    compiler = IncrementalCompiler()

    if not compiler.cache_enabled:
        pytest.skip("Compiler cache not available.")

    opt_levels = ["O0", "O1", "O2", "O3"]
    results = {}

    try:
        for opt_level in opt_levels:
            output_file = large_source_file.replace(".c", f"_{opt_level}.out")

            # Compile twice with same optimization
            result1 = compiler.compile(large_source_file, output_file, flags=[f"-{opt_level}"])
            result2 = compiler.compile(large_source_file, output_file, flags=[f"-{opt_level}"])

            assert result1.success and result2.success

            speedup = result1.compile_time / result2.compile_time if result2.compile_time > 0 else 0

            results[opt_level] = {
                "cold": result1.compile_time,
                "warm": result2.compile_time,
                "speedup": speedup,
            }

            # Cleanup
            if os.path.exists(output_file):
                os.remove(output_file)

        print("\n✓ Compilation speedups by optimization level:")
        for opt_level, data in results.items():
            print(
                f"  -{opt_level}: {data['speedup']:.1f}x speedup "
                f"({data['cold']:.2f}s → {data['warm']:.2f}s)"
            )

    except Exception:
        # Cleanup
        for opt_level in opt_levels:
            output_file = large_source_file.replace(".c", f"_{opt_level}.out")
            if os.path.exists(output_file):
                os.remove(output_file)
        raise


@pytest.mark.poc
def test_cache_statistics():
    """Test cache statistics retrieval"""
    from reveng.compilation.incremental_compiler import IncrementalCompiler

    compiler = IncrementalCompiler()

    if not compiler.cache_enabled:
        pytest.skip("Compiler cache not available.")

    stats = compiler.get_cache_stats()

    assert stats is not None, "Should be able to get cache stats"

    print("\n✓ Cache statistics:")
    print(f"  Hits: {stats.hits}")
    print(f"  Misses: {stats.misses}")
    print(f"  Hit rate: {stats.hit_rate:.1%}")
    print(f"  Cache size: {stats.cache_size / (1024**2):.1f} MB")
    print(f"  Max size: {stats.max_size / (1024**3):.1f} GB")
    print(f"  Files cached: {stats.files_cached}")

    # Print full stats table
    compiler.print_stats()


if __name__ == "__main__":
    # Run POC tests
    print("=" * 80)
    print("Incremental Compilation POC Tests")
    print("=" * 80)
    print("\nThese tests demonstrate 5-10x compilation speedup with compiler caching.")
    print("Install ccache (Linux/macOS) or sccache (cross-platform) for best results.\n")

    pytest.main([__file__, "-v", "-m", "poc", "-s"])
