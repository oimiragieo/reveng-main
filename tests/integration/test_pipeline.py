"""
Integration Tests for REVENG Analysis Pipeline
=============================================

Test the complete analysis pipeline integration.

Author: REVENG Development Team
Version: 2.1.0
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import shutil
import json

from src.reveng.analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures


class TestAnalysisPipeline:
    """Test the complete analysis pipeline."""

    @pytest.mark.integration
    def test_full_pipeline_java_jar(self, mock_java_jar, temp_analysis_dir):
        """Test full pipeline with Java JAR file."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_java_jar),
            check_ollama=False
        )

        # Mock the analysis steps
        with patch.object(analyzer, '_step1_ai_analysis') as mock_step1, \
             patch.object(analyzer, '_step2_disassembly') as mock_step2, \
             patch.object(analyzer, '_step3_ai_inspection') as mock_step3, \
             patch.object(analyzer, '_step4_specifications') as mock_step4, \
             patch.object(analyzer, '_step5_human_readable') as mock_step5, \
             patch.object(analyzer, '_step6_deobfuscation') as mock_step6, \
             patch.object(analyzer, '_step7_implementation') as mock_step7, \
             patch.object(analyzer, '_step8_validation') as mock_step8:

            # Configure mocks
            mock_step1.return_value = None
            mock_step2.return_value = None
            mock_step3.return_value = None
            mock_step4.return_value = None
            mock_step5.return_value = None
            mock_step6.return_value = None
            mock_step7.return_value = None
            mock_step8.return_value = None

            # Run analysis
            result = analyzer.analyze_binary()

            assert result is True

            # Verify all steps were called
            mock_step1.assert_called_once()
            mock_step2.assert_called_once()
            mock_step3.assert_called_once()
            mock_step4.assert_called_once()
            mock_step5.assert_called_once()
            mock_step6.assert_called_once()
            mock_step7.assert_called_once()
            mock_step8.assert_called_once()

    @pytest.mark.integration
    def test_full_pipeline_with_enhanced_features(self, mock_binary_file, mock_enhanced_features):
        """Test full pipeline with enhanced features enabled."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False,
            enhanced_features=mock_enhanced_features
        )

        # Mock the analysis steps
        with patch.object(analyzer, '_step1_ai_analysis') as mock_step1, \
             patch.object(analyzer, '_step2_disassembly') as mock_step2, \
             patch.object(analyzer, '_step3_ai_inspection') as mock_step3, \
             patch.object(analyzer, '_step4_specifications') as mock_step4, \
             patch.object(analyzer, '_step5_human_readable') as mock_step5, \
             patch.object(analyzer, '_step6_deobfuscation') as mock_step6, \
             patch.object(analyzer, '_step7_implementation') as mock_step7, \
             patch.object(analyzer, '_step8_validation') as mock_step8, \
             patch.object(analyzer, '_step9_corporate_exposure') as mock_step9, \
             patch.object(analyzer, '_step10_vulnerability_discovery') as mock_step10, \
             patch.object(analyzer, '_step11_threat_intelligence') as mock_step11, \
             patch.object(analyzer, '_step12_enhanced_reconstruction') as mock_step12, \
             patch.object(analyzer, '_step13_demonstration_generation') as mock_step13:

            # Configure mocks
            for mock_step in [mock_step1, mock_step2, mock_step3, mock_step4,
                            mock_step5, mock_step6, mock_step7, mock_step8,
                            mock_step9, mock_step10, mock_step11, mock_step12, mock_step13]:
                mock_step.return_value = None

            # Run analysis
            result = analyzer.analyze_binary()

            assert result is True

            # Verify enhanced steps were called
            mock_step9.assert_called_once()
            mock_step10.assert_called_once()
            mock_step11.assert_called_once()
            mock_step12.assert_called_once()
            mock_step13.assert_called_once()

    @pytest.mark.integration
    def test_pipeline_error_handling(self, mock_binary_file):
        """Test pipeline error handling."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock step1 to raise an exception
        with patch.object(analyzer, '_step1_ai_analysis') as mock_step1:
            mock_step1.side_effect = Exception("Analysis failed")

            result = analyzer.analyze_binary()

            assert result is False

    @pytest.mark.integration
    def test_pipeline_with_audit_logging(self, mock_binary_file):
        """Test pipeline with audit logging enabled."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock audit logger
        mock_audit_logger = Mock()
        mock_audit_logger.start_session.return_value = "session_123"
        analyzer.audit_logger = mock_audit_logger

        # Mock the analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            assert result is True

            # Verify audit logging was called
            mock_audit_logger.start_session.assert_called_once()
            mock_audit_logger.end_session.assert_called_once_with(status='completed')

    @pytest.mark.integration
    def test_pipeline_file_type_detection(self, mock_java_jar):
        """Test pipeline with file type detection."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_java_jar),
            check_ollama=False
        )

        # Mock file type detection
        mock_file_type = Mock()
        mock_file_type.language = "java"
        mock_file_type.format = "jar"
        mock_file_type.confidence = 0.95
        analyzer.file_type = mock_file_type

        # Mock the analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_java_disassembly') as mock_java_disassembly, \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            assert result is True

            # Verify Java-specific disassembly was called
            mock_java_disassembly.assert_called_once()

    @pytest.mark.integration
    def test_pipeline_csharp_analysis(self, mock_csharp_dll):
        """Test pipeline with C# analysis."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_csharp_dll),
            check_ollama=False
        )

        # Mock file type detection
        mock_file_type = Mock()
        mock_file_type.language = "csharp"
        mock_file_type.format = "dll"
        mock_file_type.confidence = 0.90
        analyzer.file_type = mock_file_type

        # Mock the analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_csharp_disassembly') as mock_csharp_disassembly, \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            assert result is True

            # Verify C#-specific disassembly was called
            mock_csharp_disassembly.assert_called_once()

    @pytest.mark.integration
    def test_pipeline_python_analysis(self, mock_python_pyc):
        """Test pipeline with Python analysis."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_python_pyc),
            check_ollama=False
        )

        # Mock file type detection
        mock_file_type = Mock()
        mock_file_type.language = "python"
        mock_file_type.format = "pyc"
        mock_file_type.confidence = 0.85
        analyzer.file_type = mock_file_type

        # Mock the analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_python_disassembly') as mock_python_disassembly, \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            assert result is True

            # Verify Python-specific disassembly was called
            mock_python_disassembly.assert_called_once()

    @pytest.mark.integration
    def test_pipeline_native_analysis(self, mock_binary_file):
        """Test pipeline with native binary analysis."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock file type detection
        mock_file_type = Mock()
        mock_file_type.language = "native"
        mock_file_type.format = "exe"
        mock_file_type.confidence = 0.80
        analyzer.file_type = mock_file_type

        # Mock the analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_native_disassembly') as mock_native_disassembly, \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'):

            result = analyzer.analyze_binary()

            assert result is True

            # Verify native-specific disassembly was called
            mock_native_disassembly.assert_called_once()

    @pytest.mark.integration
    def test_pipeline_final_report_generation(self, mock_binary_file):
        """Test pipeline final report generation."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Set up some results
        analyzer.results = {
            'step1': {'status': 'success'},
            'step2': {'status': 'success'},
            'step3': {'status': 'success'},
            'step4': {'status': 'success'},
            'step5': {'status': 'success'},
            'step6': {'status': 'success'},
            'step7': {'status': 'success'},
            'step8': {'status': 'success'}
        }

        # Mock the analysis steps
        with patch.object(analyzer, '_step1_ai_analysis'), \
             patch.object(analyzer, '_step2_disassembly'), \
             patch.object(analyzer, '_step3_ai_inspection'), \
             patch.object(analyzer, '_step4_specifications'), \
             patch.object(analyzer, '_step5_human_readable'), \
             patch.object(analyzer, '_step6_deobfuscation'), \
             patch.object(analyzer, '_step7_implementation'), \
             patch.object(analyzer, '_step8_validation'), \
             patch.object(analyzer, '_generate_final_report') as mock_generate_report:

            result = analyzer.analyze_binary()

            assert result is True

            # Verify final report generation was called
            mock_generate_report.assert_called_once()

    @pytest.mark.integration
    def test_pipeline_with_timeout(self, mock_binary_file):
        """Test pipeline with timeout handling."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock step1 to timeout
        with patch.object(analyzer, '_step1_ai_analysis') as mock_step1:
            mock_step1.side_effect = Exception("Timeout")

            result = analyzer.analyze_binary()

            assert result is False

    @pytest.mark.integration
    def test_pipeline_memory_usage(self, mock_binary_file, performance_benchmark):
        """Test pipeline memory usage."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        # Mock the analysis steps
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

    @pytest.mark.integration
    def test_pipeline_concurrent_analysis(self, mock_binary_file, mock_java_jar):
        """Test pipeline with concurrent analysis."""
        # Create two analyzers
        analyzer1 = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        analyzer2 = REVENGAnalyzer(
            binary_path=str(mock_java_jar),
            check_ollama=False
        )

        # Mock the analysis steps for both
        with patch.object(analyzer1, '_step1_ai_analysis'), \
             patch.object(analyzer1, '_step2_disassembly'), \
             patch.object(analyzer1, '_step3_ai_inspection'), \
             patch.object(analyzer1, '_step4_specifications'), \
             patch.object(analyzer1, '_step5_human_readable'), \
             patch.object(analyzer1, '_step6_deobfuscation'), \
             patch.object(analyzer1, '_step7_implementation'), \
             patch.object(analyzer1, '_step8_validation'), \
             patch.object(analyzer2, '_step1_ai_analysis'), \
             patch.object(analyzer2, '_step2_disassembly'), \
             patch.object(analyzer2, '_step3_ai_inspection'), \
             patch.object(analyzer2, '_step4_specifications'), \
             patch.object(analyzer2, '_step5_human_readable'), \
             patch.object(analyzer2, '_step6_deobfuscation'), \
             patch.object(analyzer2, '_step7_implementation'), \
             patch.object(analyzer2, '_step8_validation'):

            # Run both analyses
            result1 = analyzer1.analyze_binary()
            result2 = analyzer2.analyze_binary()

            assert result1 is True
            assert result2 is True
