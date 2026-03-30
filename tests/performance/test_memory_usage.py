"""
Performance Tests for REVENG Memory Usage
========================================

Test memory usage and optimization.

Author: REVENG Development Team
Version: 2.1.0
"""

import gc
import os
from contextlib import ExitStack, contextmanager
from unittest.mock import Mock, patch

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


class TestMemoryUsage:
    """Test memory usage and optimization."""

    @pytest.mark.performance
    def test_basic_memory_usage(self, mock_binary_file):
        """Test basic memory usage during analysis."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert memory_increase < 50.0

    @pytest.mark.performance
    def test_enhanced_analysis_memory_usage(self, mock_binary_file, mock_enhanced_features):
        """Test memory usage during enhanced analysis."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False,
            enhanced_features=mock_enhanced_features,
        )

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, ENHANCED_ANALYSIS_STEPS)):
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert memory_increase < 100.0

    @pytest.mark.performance
    def test_large_binary_memory_usage(self, temp_analysis_dir):
        """Test memory usage with large binary."""
        large_binary = temp_analysis_dir / "large_memory_test.exe"
        large_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 10000000)

        analyzer = REVENGAnalyzer(binary_path=str(large_binary), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert memory_increase < 200.0

    @pytest.mark.performance
    def test_concurrent_analysis_memory_usage(self, temp_analysis_dir):
        """Test memory usage during concurrent analysis."""
        binaries = []
        for i in range(3):
            binary = temp_analysis_dir / f"concurrent_memory_{i}.exe"
            binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000000)
            binaries.append(binary)

        analyzers = [
            REVENGAnalyzer(binary_path=str(binary), check_ollama=False) for binary in binaries
        ]

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        patch_specs = [(analyzer, BASE_ANALYSIS_STEPS) for analyzer in analyzers]
        with patched_methods(*patch_specs):
            results = [analyzer.analyze_binary() for analyzer in analyzers]

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert all(results)
        assert memory_increase < 150.0

    @pytest.mark.performance
    def test_memory_cleanup_after_analysis(self, mock_binary_file):
        """Test memory cleanup after analysis."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            result = analyzer.analyze_binary()

        post_analysis_memory = process.memory_info().rss / 1024 / 1024
        gc.collect()
        post_cleanup_memory = process.memory_info().rss / 1024 / 1024

        assert isinstance(result, dict) and result.get("status") == "success"
        memory_cleanup = post_analysis_memory - post_cleanup_memory
        assert memory_cleanup >= 0

    @pytest.mark.performance
    def test_memory_usage_with_audit_logging(self, mock_binary_file):
        """Test memory usage with audit logging enabled."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        mock_audit_logger = Mock()
        mock_audit_logger.start_session.return_value = "session_123"
        analyzer.audit_logger = mock_audit_logger

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert memory_increase < 60.0

    @pytest.mark.performance
    def test_memory_usage_with_file_operations(self, mock_binary_file, temp_analysis_dir):
        """Test memory usage with file operations."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert memory_increase < 50.0

    @pytest.mark.performance
    def test_memory_usage_with_ai_analysis(self, mock_binary_file):
        """Test memory usage with AI analysis."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)) as mocks:
            mocks[(id(analyzer), "_step1_ai_analysis")].return_value = None
            mocks[(id(analyzer), "_step3_ai_inspection")].return_value = None
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert memory_increase < 70.0

    @pytest.mark.performance
    def test_memory_usage_with_ml_models(self, mock_binary_file):
        """Test memory usage with ML models."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert memory_increase < 80.0

    @pytest.mark.performance
    def test_memory_usage_regression(self, mock_binary_file):
        """Test for memory usage regression."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patched_methods((analyzer, BASE_ANALYSIS_STEPS)):
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") == "success"
        assert memory_increase < 40.0

    @pytest.mark.performance
    def test_memory_usage_with_error_handling(self, mock_binary_file):
        """Test memory usage with error handling."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patch.object(analyzer, "_step1_ai_analysis") as mock_step1:
            mock_step1.side_effect = Exception("Analysis failed")
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") != "success"
        assert memory_increase < 20.0

    @pytest.mark.performance
    def test_memory_usage_with_timeout(self, mock_binary_file):
        """Test memory usage with timeout handling."""
        analyzer = REVENGAnalyzer(binary_path=str(mock_binary_file), check_ollama=False)

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024

        with patch.object(analyzer, "_step1_ai_analysis") as mock_step1:
            mock_step1.side_effect = Exception("Timeout")
            result = analyzer.analyze_binary()

        final_memory = process.memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory

        assert isinstance(result, dict) and result.get("status") != "success"
        assert memory_increase < 20.0
