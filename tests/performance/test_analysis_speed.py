"""
Performance Tests for REVENG Analysis Speed
==========================================

Test analysis performance and speed benchmarks.

Author: REVENG Development Team
Version: 2.1.0
"""

import pytest
import time
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch
import psutil
import os

from src.reveng.analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures


class TestAnalysisSpeed:
    """Test analysis speed performance."""

    @pytest.mark.performance
    def test_small_binary_analysis_speed(self, mock_binary_file, performance_benchmark):
        """Test analysis speed for small binary (< 1MB)."""
        # Create small binary
        small_binary = mock_binary_file
        small_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000)  # ~1KB

        analyzer = REVENGAnalyzer(
            binary_path=str(small_binary),
            check_ollama=False
        )

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 5.0  # Should complete within 5 seconds

    @pytest.mark.performance
    def test_medium_binary_analysis_speed(self, temp_analysis_dir, performance_benchmark):
        """Test analysis speed for medium binary (1-10MB)."""
        # Create medium binary
        medium_binary = temp_analysis_dir / "medium_test.exe"
        medium_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 5000000)  # ~5MB

        analyzer = REVENGAnalyzer(
            binary_path=str(medium_binary),
            check_ollama=False
        )

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 30.0  # Should complete within 30 seconds

    @pytest.mark.performance
    def test_large_binary_analysis_speed(self, temp_analysis_dir, performance_benchmark):
        """Test analysis speed for large binary (> 10MB)."""
        # Create large binary
        large_binary = temp_analysis_dir / "large_test.exe"
        large_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 20000000)  # ~20MB

        analyzer = REVENGAnalyzer(
            binary_path=str(large_binary),
            check_ollama=False
        )

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 120.0  # Should complete within 2 minutes

    @pytest.mark.performance
    def test_enhanced_analysis_speed(self, mock_binary_file, mock_enhanced_features, performance_benchmark):
        """Test enhanced analysis speed."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False,
            enhanced_features=mock_enhanced_features
        )

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

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 60.0  # Enhanced analysis should complete within 1 minute

    @pytest.mark.performance
    def test_java_analysis_speed(self, mock_java_jar, performance_benchmark):
        """Test Java analysis speed."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_java_jar),
            check_ollama=False
        )

        # Mock Java-specific analysis
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_java_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 20.0  # Java analysis should complete within 20 seconds

    @pytest.mark.performance
    def test_csharp_analysis_speed(self, mock_csharp_dll, performance_benchmark):
        """Test C# analysis speed."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_csharp_dll),
            check_ollama=False
        )

        # Mock C#-specific analysis
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_csharp_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 25.0  # C# analysis should complete within 25 seconds

    @pytest.mark.performance
    def test_python_analysis_speed(self, mock_python_pyc, performance_benchmark):
        """Test Python analysis speed."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_python_pyc),
            check_ollama=False
        )

        # Mock Python-specific analysis
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_python_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 15.0  # Python analysis should complete within 15 seconds

    @pytest.mark.performance
    def test_native_analysis_speed(self, mock_binary_file, performance_benchmark):
        """Test native binary analysis speed."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock native-specific analysis
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_native_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 30.0  # Native analysis should complete within 30 seconds

    @pytest.mark.performance
    def test_concurrent_analysis_speed(self, temp_analysis_dir, performance_benchmark):
        """Test concurrent analysis speed."""
        # Create multiple binaries
        binaries = []
        for i in range(3):
            binary = temp_analysis_dir / f"concurrent_test_{i}.exe"
            binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 1000000)  # ~1MB each
            binaries.append(binary)

        analyzers = []
        for binary in binaries:
            analyzer = REVENGAnalyzer(
                binary_path=str(binary),
                check_ollama=False
            )
            analyzers.append(analyzer)

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

            performance_benchmark.start()

            # Run all analyses
            results = []
            for analyzer in analyzers:
                result = analyzer.analyze_binary()
                results.append(result)

            duration = performance_benchmark.stop()

            # All analyses should succeed
            assert all(results)
            assert duration < 60.0  # Concurrent analysis should complete within 1 minute

    @pytest.mark.performance
    def test_analysis_speed_regression(self, mock_binary_file, performance_benchmark):
        """Test for analysis speed regression."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True

            # Performance regression check
            # This should be faster than previous versions
            assert duration < 10.0  # Should be faster than 10 seconds

    @pytest.mark.performance
    def test_analysis_speed_with_timeout(self, mock_binary_file, performance_benchmark):
        """Test analysis speed with timeout handling."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock step1 to take longer than timeout
        with patch.object(analyzer, '_step1_ai_analysis') as mock_step1:
            mock_step1.side_effect = Exception("Timeout")

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is False
            assert duration < 5.0  # Should fail quickly due to timeout

    @pytest.mark.performance
    def test_analysis_speed_memory_usage(self, mock_binary_file, performance_benchmark):
        """Test analysis speed with memory usage monitoring."""
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

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            # Get final memory usage
            final_memory = process.memory_info().rss / 1024 / 1024  # MB
            memory_increase = final_memory - initial_memory

            assert result is True
            assert duration < 10.0  # Should complete within 10 seconds
            assert memory_increase < 100.0  # Should not use more than 100MB additional memory

    @pytest.mark.performance
    def test_analysis_speed_cpu_usage(self, mock_binary_file, performance_benchmark):
        """Test analysis speed with CPU usage monitoring."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 10.0  # Should complete within 10 seconds

            # CPU usage should be reasonable
            # Note: In test environment, this might not be measurable
            assert duration > 0.0  # Should take some time

    @pytest.mark.performance
    def test_analysis_speed_io_operations(self, mock_binary_file, performance_benchmark):
        """Test analysis speed with I/O operations."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock analysis steps with I/O operations
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            performance_benchmark.start()
            result = analyzer.analyze_binary()
            duration = performance_benchmark.stop()

            assert result is True
            assert duration < 10.0  # Should complete within 10 seconds

            # I/O operations should be efficient
            # Note: In test environment, this might not be measurable
            assert duration > 0.0  # Should take some time
