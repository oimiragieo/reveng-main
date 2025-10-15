"""
Unit Tests for REVENG Analyzer
=============================

Test the core analyzer functionality.

Author: REVENG Development Team
Version: 2.1.0
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile
import shutil

from src.reveng.analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures


class TestREVENGAnalyzer:
    """Test the REVENGAnalyzer class."""

    def test_analyzer_initialization(self, mock_binary_file, temp_analysis_dir):
        """Test analyzer initialization."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        assert analyzer.binary_path == str(mock_binary_file)
        assert analyzer.binary_name == "test_binary"
        assert analyzer.analysis_folder.name.startswith("analysis_test_binary")
        assert analyzer.results == {}
        assert analyzer.enhanced_results == {}
        assert analyzer.ollama_available is False

    def test_analyzer_with_enhanced_features(self, mock_binary_file, mock_enhanced_features):
        """Test analyzer with enhanced features."""
        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False,
            enhanced_features=mock_enhanced_features
        )

        assert analyzer.enhanced_features.enable_enhanced_analysis is True
        assert analyzer.enhanced_features.enable_corporate_exposure is True

    def test_find_binary_auto_detection(self, temp_analysis_dir):
        """Test automatic binary detection."""
        # Create a test binary
        test_binary = temp_analysis_dir / "test.exe"
        test_binary.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)

        # Change to temp directory
        original_cwd = Path.cwd()
        try:
            os.chdir(temp_analysis_dir)
            analyzer = REVENGAnalyzer(check_ollama=False)
            assert analyzer.binary_path == "test.exe"
        finally:
            os.chdir(original_cwd)

    def test_find_binary_no_files(self, temp_analysis_dir):
        """Test binary detection when no files exist."""
        original_cwd = Path.cwd()
        try:
            os.chdir(temp_analysis_dir)
            analyzer = REVENGAnalyzer(check_ollama=False)
            assert analyzer.binary_path == "target_binary"
        finally:
            os.chdir(original_cwd)

    @patch('src.reveng.analyzer.LanguageDetector')
    def test_detect_file_type(self, mock_detector_class, mock_binary_file):
        """Test file type detection."""
        # Mock the detector
        mock_detector = Mock()
        mock_detector.detect.return_value = Mock(
            language="java",
            format="jar",
            confidence=0.95
        )
        mock_detector.get_language_category.return_value = "bytecode"
        mock_detector_class.return_value = mock_detector

        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        assert analyzer.file_type.language == "java"
        assert analyzer.file_type.format == "jar"
        assert analyzer.file_type.confidence == 0.95

    @patch('src.reveng.analyzer.LanguageDetector')
    def test_detect_file_type_import_error(self, mock_detector_class, mock_binary_file):
        """Test file type detection with import error."""
        mock_detector_class.side_effect = ImportError("Language detector not available")

        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=False
        )

        assert analyzer.file_type is None

    @patch('src.reveng.analyzer.OllamaPreflightChecker')
    @patch('src.reveng.analyzer.get_config')
    def test_check_ollama_availability_success(self, mock_get_config, mock_checker_class, mock_binary_file):
        """Test successful Ollama availability check."""
        # Mock config
        mock_config = Mock()
        mock_ai_config = Mock()
        mock_ai_config.enable_ai = True
        mock_ai_config.provider = "ollama"
        mock_ai_config.ollama_host = "http://localhost:11434"
        mock_ai_config.ollama_model = "llama2"
        mock_config.get_ai_config.return_value = mock_ai_config
        mock_get_config.return_value = mock_config

        # Mock checker
        mock_checker = Mock()
        mock_checker.check_all.return_value = (True, {
            'models_available': ['llama2', 'codellama'],
            'errors': []
        })
        mock_checker_class.return_value = mock_checker

        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=True
        )

        assert analyzer.ollama_available is True

    @patch('src.reveng.analyzer.OllamaPreflightChecker')
    @patch('src.reveng.analyzer.get_config')
    def test_check_ollama_availability_failure(self, mock_get_config, mock_checker_class, mock_binary_file):
        """Test failed Ollama availability check."""
        # Mock config
        mock_config = Mock()
        mock_ai_config = Mock()
        mock_ai_config.enable_ai = True
        mock_ai_config.provider = "ollama"
        mock_ai_config.ollama_host = "http://localhost:11434"
        mock_ai_config.ollama_model = "llama2"
        mock_config.get_ai_config.return_value = mock_ai_config
        mock_get_config.return_value = mock_config

        # Mock checker
        mock_checker = Mock()
        mock_checker.check_all.return_value = (False, {
            'models_available': [],
            'errors': ['Ollama not running']
        })
        mock_checker_class.return_value = mock_checker

        analyzer = REVENGAnalyzer(
            binary_path=str(mock_binary_file),
            check_ollama=True
        )

        assert analyzer.ollama_available is False

    def test_count_enabled_modules(self, mock_enhanced_features):
        """Test counting enabled enhanced modules."""
        analyzer = REVENGAnalyzer(
            binary_path="test.exe",
            check_ollama=False,
            enhanced_features=mock_enhanced_features
        )

        count = analyzer._count_enabled_modules()
        assert count == 5  # All modules enabled

    def test_count_enabled_modules_none(self):
        """Test counting when no modules are enabled."""
        features = EnhancedAnalysisFeatures()
        features.enable_enhanced_analysis = False

        analyzer = REVENGAnalyzer(
            binary_path="test.exe",
            check_ollama=False,
            enhanced_features=features
        )

        count = analyzer._count_enabled_modules()
        assert count == 0

    @patch('src.reveng.analyzer.subprocess.run')
    def test_step1_ai_analysis_success(self, mock_subprocess, mock_analyzer):
        """Test successful AI analysis step."""
        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout="AI analysis completed",
            stderr=""
        )

        mock_analyzer._step1_ai_analysis()

        assert mock_analyzer.results['step1']['status'] == 'success'
        assert mock_analyzer.results['step1']['output'] == "AI analysis completed"

    @patch('src.reveng.analyzer.subprocess.run')
    def test_step1_ai_analysis_failure(self, mock_subprocess, mock_analyzer):
        """Test failed AI analysis step."""
        mock_subprocess.return_value = Mock(
            returncode=1,
            stdout="Partial output",
            stderr="Error occurred"
        )

        mock_analyzer._step1_ai_analysis()

        assert mock_analyzer.results['step1']['status'] == 'warning'
        assert mock_analyzer.results['step1']['error'] == "Error occurred"

    @patch('src.reveng.analyzer.subprocess.run')
    def test_step1_ai_analysis_timeout(self, mock_subprocess, mock_analyzer):
        """Test AI analysis step timeout."""
        mock_subprocess.side_effect = subprocess.TimeoutExpired("python", 300)

        mock_analyzer._step1_ai_analysis()

        assert mock_analyzer.results['step1']['status'] == 'timeout'

    def test_step4_specifications_exists(self, mock_analyzer, temp_analysis_dir):
        """Test specifications step when SPECS folder exists."""
        # Create SPECS folder
        specs_folder = temp_analysis_dir / "SPECS"
        specs_folder.mkdir()

        with patch('src.reveng.analyzer.Path') as mock_path:
            mock_path.return_value = specs_folder
            mock_analyzer._step4_specifications()

        assert mock_analyzer.results['step4']['status'] == 'success'
        assert 'SPECS folder already exists' in mock_analyzer.results['step4']['message']

    def test_step4_specifications_not_exists(self, mock_analyzer):
        """Test specifications step when SPECS folder doesn't exist."""
        with patch('src.reveng.analyzer.Path') as mock_path:
            mock_specs = Mock()
            mock_specs.exists.return_value = False
            mock_path.return_value = mock_specs
            mock_analyzer._step4_specifications()

        assert mock_analyzer.results['step4']['status'] == 'warning'
        assert 'SPECS folder not found' in mock_analyzer.results['step4']['message']

    def test_generate_final_report(self, mock_analyzer):
        """Test final report generation."""
        # Set up some results
        mock_analyzer.results = {
            'step1': {'status': 'success'},
            'step2': {'status': 'success'}
        }
        mock_analyzer.enhanced_results = {
            'step9': {'status': 'success'}
        }

        with patch('builtins.open', mock_open()) as mock_file:
            mock_analyzer._generate_final_report()

        # Check that report was written
        mock_file.assert_called_once()
        assert mock_analyzer.analysis_folder / "universal_analysis_report.json" in str(mock_file.call_args[0])


class TestEnhancedAnalysisFeatures:
    """Test the EnhancedAnalysisFeatures class."""

    def test_enhanced_features_default(self):
        """Test default enhanced features configuration."""
        features = EnhancedAnalysisFeatures()

        assert features.enable_enhanced_analysis is True
        assert features.enable_corporate_exposure is True
        assert features.enable_vulnerability_discovery is True
        assert features.enable_threat_intelligence is True
        assert features.enable_enhanced_reconstruction is True
        assert features.enable_demonstration_generation is True

    def test_enhanced_features_from_config(self):
        """Test loading features from configuration."""
        features = EnhancedAnalysisFeatures()
        config = {
            'enable_enhanced_analysis': False,
            'enable_corporate_exposure': False,
            'enable_vulnerability_discovery': True
        }

        features.from_config(config)

        assert features.enable_enhanced_analysis is False
        assert features.enable_corporate_exposure is False
        assert features.enable_vulnerability_discovery is True

    def test_is_any_enhanced_enabled_true(self):
        """Test when any enhanced features are enabled."""
        features = EnhancedAnalysisFeatures()
        features.enable_enhanced_analysis = True
        features.enable_corporate_exposure = True

        assert features.is_any_enhanced_enabled() is True

    def test_is_any_enhanced_enabled_false(self):
        """Test when no enhanced features are enabled."""
        features = EnhancedAnalysisFeatures()
        features.enable_enhanced_analysis = False

        assert features.is_any_enhanced_enabled() is False

    def test_is_any_enhanced_enabled_partial(self):
        """Test when some enhanced features are enabled."""
        features = EnhancedAnalysisFeatures()
        features.enable_enhanced_analysis = True
        features.enable_corporate_exposure = False
        features.enable_vulnerability_discovery = True

        assert features.is_any_enhanced_enabled() is True


# Import required modules for tests
import subprocess
from unittest.mock import mock_open
