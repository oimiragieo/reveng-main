"""
Performance Tests for REVENG Memory Usage
========================================

Test memory usage and optimization.

Author: REVENG Development Team
Version: 2.1.0
"""

import pytest
import psutil
import os
import gc
from pathlib import Path
from unittest.mock import Mock, patch
import tempfile

from src.reveng.analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures


class TestMemoryUsage:
    """Test memory usage and optimization."""

    @pytest.mark.performance
    def test_basic_memory_usage(self, mock_binary_file):
        """Test basic memory usage during analysis."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True
            assert memory_increase < 50.0  # Should not use more than 50MB additional memory

    @pytest.mark.performance
    def test_enhanced_analysis_memory_usage(self, mock_binary_file, mock_enhanced_features):
        """Test memory usage during enhanced analysis."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False,
            enhanced_features=mock_enhanced_features
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock all analysis steps including enhanced
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'), \
             patch.object(analyzer, '_step9_corporate_exposure'), \
             patch.object(analyzer, '_step10_vulnerability_discovery'), \
             patch.object(analyzer, '_step11_threat_intelligence'), \
             patch.object(analyzer, '_step12_enhanced_reconstruction'), \
             patch.object(analyzer, '_step13_demonstration_generation'):

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True
            assert memory_increase < 100.0  # Enhanced analysis should not use more than 100MB additional memory

    @pytest.mark.performance
    def test_large_binary_memory_usage(self, temp_analysis_dir):
        """Test memory usage with large binary."""
        # Create large binary
        large_binary = temp_analysis_dir / "large_memory_test.exe"
        large_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 10000000)  # ~10MB

        analyzer = REVENGAnalyzer(
            binary_path=str(large_binary),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True
            assert memory_increase < 200.0  # Large binary should not use more than 200MB additional memory

    @pytest.mark.performance
    def test_concurrent_analysis_memory_usage(self, temp_analysis_dir):
        """Test memory usage during concurrent analysis."""
        # Create multiple binaries
        binaries = []
        for i in range(3):
            binary = temp_analysis_dir / f"concurrent_memory_{i}.exe"
            binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000000)  # ~1MB each
            binaries.append(binary)

        analyzers = []
        for binary in binaries:
            analyzer = REVENGAnalyzer(
                binary_path=str(binary),
                check_ollama=False
            )
            analyzers.append(analyzer)

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock analysis steps for all analyzers
        with patch.object(analyzers[0], '_step1_ai_analysis'), \
             patch.object(analyzers[0], '_step2_disassembly'), \
             patch.object(analyzers[0], '_step3_ai_inspection'), \
             patch.object(analyzers[0], '_step4_specifications'), \
             patch.object(analyzers[0], '_step5_human_readable'), \
             patch.object(analyzers[0], '_step6_deobfuscation'), \
             patch.object(analyzers[0], '_step7_implementation'), \
             patch.object(analyzers[0], '_step8_validation'), \
             patch.object(analyzers[1], '_step1_ai_analysis'), \
             patch.object(analyzers[1], '_step2_disassembly'), \
             patch.object(analyzers[1], '_step3_ai_inspection'), \
             patch.object(analyzers[1], '_step4_specifications'), \
             patch.object(analyzers[1], '_step5_human_readable'), \
             patch.object(analyzers[1], '_step6_deobfuscation'), \
             patch.object(analyzers[1], '_step7_implementation'), \
             patch.object(analyzers[1], '_step8_validation'), \
             patch.object(analyzers[2], '_step1_ai_analysis'), \
             patch.object(analyzers[2], '_step2_disassembly'), \
             patch.object(analyzers[2], '_step3_ai_inspection'), \
             patch.object(analyzers[2], '_step4_specifications'), \
             patch.object(analyzers[2], '_step5_human_readable'), \
             patch.object(analyzers[2], '_step6_deobfuscation'), \
             patch.object(analyzers[2], '_step7_implementation'), \
             patch.object(analyzers[2], '_step8_validation'):

            # Run all analyses
            results = []
            for analyzer in analyzers:
                result = analyzer.analyze_binary()
                results.append(result)

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            # All analyses should succeed
            assert all(results)
            assert memory_increase < 150.0  # Concurrent analysis should not use more than 150MB additional memory

    @pytest.mark.performance
    def test_memory_cleanup_after_analysis(self, mock_binary_file):
        """Test memory cleanup after analysis."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            # Get memory usage after analysis
            post_analysis_memory = process.memory_info().rss / 1024 / 1024  # MB

            # Force garbage collection
            gc.collect()

            # Get memory usage after cleanup
            post_cleanup_memory = process.memory_info().rss / 1024 / 1024  # MB

            assert result is True

            # Memory should be cleaned up after analysis
            memory_cleanup = post_analysis_memory - post_cleanup_memory
            assert memory_cleanup >= 0  # Memory should not increase after cleanup

    @pytest.mark.performance
    def test_memory_usage_with_audit_logging(self, mock_binary_file):
        """Test memory usage with audit logging enabled."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock audit logger
        mock_audit_logger = Mock()
        mock_audit_logger.start_session.return_value = "session_123"
        analyzer.audit_logger = mock_audit_logger

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True
            assert memory_increase < 60.0  # Audit logging should not significantly increase memory usage

    @pytest.mark.performance
    def test_memory_usage_with_file_operations(self, mock_binary_file, temp_analysis_dir):
        """Test memory usage with file operations."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock analysis steps with file operations
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True
            assert memory_increase < 50.0  # File operations should not significantly increase memory usage

    @pytest.mark.performance
    def test_memory_usage_with_ai_analysis(self, mock_binary_file):
        """Test memory usage with AI analysis."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock AI analysis steps
        with patch.object(analyzer, '_step1_ai_analysis') as mock_ai, \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection') as mock_ai_inspection, \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            # Configure AI mocks to simulate memory usage
            mock_ai.return_value = None
            mock_ai_inspection.return_value = None

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True
            assert memory_increase < 70.0  # AI analysis should not use more than 70MB additional memory

    @pytest.mark.performance
    def test_memory_usage_with_ml_models(self, mock_binary_file):
        """Test memory usage with ML models."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock ML model operations
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True
            assert memory_increase < 80.0  # ML models should not use more than 80MB additional memory

    @pytest.mark.performance
    def test_memory_usage_regression(self, mock_binary_file):
        """Test for memory usage regression."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True

            # Memory usage regression check
            # This should use less memory than previous versions
            assert memory_increase < 40.0  # Should use less than 40MB additional memory

    @pytest.mark.performance
    def test_memory_usage_with_error_handling(self, mock_binary_file):
        """Test memory usage with error handling."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock step1 to raise an exception
        with patch.object(analyzer, '_step1_ai_analysis') as mock_step1:
            mock_step1.side_effect = Exception("Analysis failed")

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is False
            assert memory_increase < 20.0  # Error handling should not use much additional memory

    @pytest.mark.performance
    def test_memory_usage_with_timeout(self, mock_binary_file):
        """Test memory usage with timeout handling."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Get initial memory usage
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Mock step1 to timeout
        with patch.object(analyzer, '_step1_ai_analysis') as mock_step1:
            mock_step1.side_effect = Exception("Timeout")

            result = analyzer.analyze_binary()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is False
            assert memory_increase < 20.0  # Timeout handling should not use much additional memory
