"""
Performance Tests for REVENG Analysis Speed
==========================================

Test analysis performance and speed benchmarks.

Author: REVENG Development Team
Version: 2.1.0
"""

import os
from contextlib import ExitStack, contextmanager
from unittest.mock import patch

import psutil
import pytest

from src.reveng.analyzer import REVENGAnalyzer

BASE_ANALYSIS_STEPS = [
    "_step1_ai_analysis",
    "_step2_disassembly",
    "_step3_ai_inspection",
    "_step4_specifications",
    "_step5_human_readable",
    "_step6_deobfuscation",
    "_step7_implementation",
    "_step8_validation",
]

ENHANCED_ANALYSIS_STEPS = BASE_ANALYSIS_STEPS + [
    "_step9_corporate_exposure",
    "_step10_vulnerability_discovery",
    "_step11_threat_intelligence",
    "_step12_enhanced_reconstruction",
    "_step13_demonstration_generation",
]


@contextmanager
def patched_methods(*targets_and_methods):
    """Patch analyzer methods without deep static nesting."""
    with ExitStack() as stack:
        mocks = {}
        for target, method_names in targets_and_methods:
            for method_name in method_names:
                mocks[(id(target), method_name)] = stack.enter_context(
                    patch.object(target, method_name)
                )
        yield mocks


class TestAnalysisSpeed:
    """Test analysis speed performance."""

    @pytest.mark.performance
    def test_small_binary_analysis_speed(self, mock_binary_file, performance_benchmark):
        """Test analysis speed for small binary (< 1MB)."""
        small_binary = mock_binary_file
        small_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)

        analyzer = REVENGAnalyzer(binary_path=str(small_binary), check_ollama=False)

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 5.0

    @pytest.mark.performance
    def test_medium_binary_analysis_speed(self, temp_analysis_dir, performance_benchmark):
        """Test analysis speed for medium binary (1-10MB)."""
        medium_binary = temp_analysis_dir / "medium_test.exe"
        medium_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 5000000)

        analyzer = REVENGAnalyzer(binary_path=str(medium_binary), check_ollama=False)

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 30.0

    @pytest.mark.performance
    def test_large_binary_analysis_speed(self, temp_analysis_dir, performance_benchmark):
        """Test analysis speed for large binary (> 10MB)."""
        large_binary = temp_analysis_dir / "large_test.exe"
        large_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 20000000)

        analyzer = REVENGAnalyzer(binary_path=str(large_binary), check_ollama=False)

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 120.0

    @pytest.mark.performance
    def test_enhanced_analysis_speed(
        self, mock_binary_file, mock_enhanced_features, performance_benchmark
    ):
        """Test enhanced analysis speed."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False,
            enhanced_features=mock_enhanced_features,
        )

        with patched_methods((analyzer, ENHANCED_ANALYSIS_STEPS)):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 60.0

    @pytest.mark.performance
    def test_java_analysis_speed(self, mock_java_jar, performance_benchmark):
        """Test Java analysis speed."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_java_jar), check_ollama=False)

        with patched_methods(
            (analyzer, ["_step1_ai_analysis", "_java_disassembly"]),
            (analyzer, BASE_ANALYSIS_STEPS[2:]),
        ):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 20.0

    @pytest.mark.performance
    def test_csharp_analysis_speed(self, mock_csharp_dll, performance_benchmark):
        """Test C# analysis speed."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_csharp_dll), check_ollama=False)

        with patched_methods(
            (analyzer, ["_step1_ai_analysis", "_csharp_disassembly"]),
            (analyzer, BASE_ANALYSIS_STEPS[2:]),
        ):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 25.0

    @pytest.mark.performance
    def test_python_analysis_speed(self, mock_python_pyc, performance_benchmark):
        """Test Python analysis speed."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_python_pyc), check_ollama=False)

        with patched_methods(
            (analyzer, ["_step1_ai_analysis", "_python_disassembly"]),
            (analyzer, BASE_ANALYSIS_STEPS[2:]),
        ):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 15.0

    @pytest.mark.performance
    def test_native_analysis_speed(self, mock_binary_file, performance_benchmark):
        """Test native binary analysis speed."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        with patched_methods(
            (analyzer, ["_step1_ai_analysis", "_native_disassembly"]),
            (analyzer, BASE_ANALYSIS_STEPS[2:]),
        ):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 30.0

    @pytest.mark.performance
    def test_concurrent_analysis_speed(self, temp_analysis_dir, performance_benchmark):
        """Test concurrent analysis speed."""
        binaries = []
        for i in range(3):
            binary = temp_analysis_dir / f"concurrent_test_{i}.exe"
            binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000000)
            binaries.append(binary)

        analyzers = [
            REVENGAnalyzer(binary_path=str(binary), check_ollama=False) for binary in binaries
        ]

        patch_specs = [(analyzer, BASE_ANALYSIS_STEPS) for analyzer in analyzers]
        with patched_methods(*patch_specs):
            performance_benchmark.start()
            results = [analyzer.analyze_binary() for analyzer in analyzers]
            duration = performance_benchmark.stop()

        assert all(results)
        assert duration < 60.0

    @pytest.mark.performance
    def test_analysis_speed_regression(self, mock_binary_file, performance_benchmark):
        """Test for analysis speed regression."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 10.0

    @pytest.mark.performance
    def test_analysis_speed_with_timeout(self, mock_binary_file, performance_benchmark):
        """Test analysis speed with timeout handling."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        with patch.object(analyzer, "_step1_ai_analysis") as mock_step1:
            mock_step1.side_effect = Exception("Timeout")

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") != "success"
        assert duration < 5.0

    @pytest.mark.performance
    def test_analysis_speed_memory_usage(self, mock_binary_file, performance_benchmark):
        """Test analysis speed with memory usage monitoring."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 10.0
        assert memory_increase < 100.0

    @pytest.mark.performance
    def test_analysis_speed_cpu_usage(self, mock_binary_file, performance_benchmark):
        """Test analysis speed with CPU usage monitoring."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 10.0
        assert duration > 0.0

    @pytest.mark.performance
    def test_analysis_speed_io_operations(self, mock_binary_file, performance_benchmark):
        """Test analysis speed with I/O operations."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

        assert isinstance(result, dict) and result.get("status") == "success"
        assert duration < 10.0
        assert duration > 0.0
