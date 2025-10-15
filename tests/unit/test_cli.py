"""
Unit Tests for REVENG CLI
========================

Test the command-line interface functionality.

Author: REVENG Development Team
Version: 2.1.0
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from click.testing import CliRunner
import sys
from pathlib import Path

from src.reveng.cli import main, create_parser, handle_analyze_command, handle_serve_command


class TestCLIParser:
    """Test the CLI argument parser."""

    def test_create_parser(self):
        """Test parser creation."""
        parser = create_parser()

        assert parser.prog == 'reveng'
        assert 'REVENG - Universal Reverse Engineering Platform' in parser.description

    def test_parser_help(self):
        """Test parser help output."""
        parser = create_parser()
        help_text = parser.format_help()

        assert 'REVENG - Universal Reverse Engineering Platform' in help_text
        assert 'analyze' in help_text
        assert 'serve' in help_text
        assert '--version' in help_text

    def test_parser_analyze_command(self):
        """Test analyze command parsing."""
        parser = create_parser()
        args = parser.parse_args(['analyze', 'test.exe'])

        assert args.command == 'analyze'
        assert args.binary_path == 'test.exe'

    def test_parser_serve_command(self):
        """Test serve command parsing."""
        parser = create_parser()
        args = parser.parse_args(['serve', '--host', '0.0.0.0', '--port', '3001'])

        assert args.command == 'serve'
        assert args.host == '0.0.0.0'
        assert args.port == 3001

    def test_parser_enhanced_options(self):
        """Test enhanced analysis options."""
        parser = create_parser()
        args = parser.parse_args([
            'analyze', 'test.exe',
            '--no-enhanced',
            '--no-corporate',
            '--no-vuln'
        ])

        assert args.no_enhanced is True
        assert args.no_corporate is True
        assert args.no_vuln is True

    def test_parser_config_option(self):
        """Test configuration file option."""
        parser = create_parser()
        args = parser.parse_args(['analyze', 'test.exe', '--config', 'config.yaml'])

        assert args.config == 'config.yaml'

    def test_parser_logging_options(self):
        """Test logging options."""
        parser = create_parser()
        args = parser.parse_args([
            'analyze', 'test.exe',
            '--verbose',
            '--log-file', 'test.log'
        ])

        assert args.verbose is True
        assert args.log_file == 'test.log'


class TestCLIHandlers:
    """Test CLI command handlers."""

    @patch('src.reveng.cli.REVENGAnalyzer')
    def test_handle_analyze_command_success(self, mock_analyzer_class, mock_binary_file):
        """Test successful analyze command."""
        # Mock analyzer
        mock_analyzer = Mock()
        mock_analyzer.analyze_binary.return_value = True
        mock_analyzer._count_enabled_modules.return_value = 3
        mock_analyzer_class.return_value = mock_analyzer

        # Mock args
        args = Mock()
        args.binary_path = str(mock_binary_file)
        args.no_ollama_check = False
        args.config = None
        args.no_enhanced = False
        args.no_corporate = False
        args.no_vuln = False
        args.no_threat = False
        args.no_reconstruction = False
        args.no_demo = False

        result = handle_analyze_command(args)

        assert result == 0
        mock_analyzer_class.assert_called_once()
        mock_analyzer.analyze_binary.assert_called_once()

    @patch('src.reveng.cli.REVENGAnalyzer')
    def test_handle_analyze_command_binary_not_found(self, mock_analyzer_class):
        """Test analyze command when binary not found."""
        # Mock analyzer
        mock_analyzer = Mock()
        mock_analyzer.binary_path = "nonexistent.exe"
        mock_analyzer_class.return_value = mock_analyzer

        # Mock Path.exists to return False
        with patch('src.reveng.cli.Path') as mock_path:
            mock_path.return_value.exists.return_value = False

            args = Mock()
            args.binary_path = "nonexistent.exe"
            args.no_ollama_check = False
            args.config = None
            args.no_enhanced = False
            args.no_corporate = False
            args.no_vuln = False
            args.no_threat = False
            args.no_reconstruction = False
            args.no_demo = False

            result = handle_analyze_command(args)

            assert result == 1

    @patch('src.reveng.cli.REVENGAnalyzer')
    def test_handle_analyze_command_failure(self, mock_analyzer_class, mock_binary_file):
        """Test analyze command failure."""
        # Mock analyzer
        mock_analyzer = Mock()
        mock_analyzer.analyze_binary.return_value = False
        mock_analyzer_class.return_value = mock_analyzer

        args = Mock()
        args.binary_path = str(mock_binary_file)
        args.no_ollama_check = False
        args.config = None
        args.no_enhanced = False
        args.no_corporate = False
        args.no_vuln = False
        args.no_threat = False
        args.no_reconstruction = False
        args.no_demo = False

        result = handle_analyze_command(args)

        assert result == 1

    @patch('src.reveng.cli.start_server')
    def test_handle_serve_command_success(self, mock_start_server):
        """Test successful serve command."""
        args = Mock()
        args.host = 'localhost'
        args.port = 3000
        args.reload = False

        result = handle_serve_command(args)

        assert result == 0
        mock_start_server.assert_called_once_with(
            host='localhost',
            port=3000,
            reload=False
        )

    @patch('src.reveng.cli.start_server')
    def test_handle_serve_command_import_error(self, mock_start_server):
        """Test serve command with import error."""
        mock_start_server.side_effect = ImportError("Web interface not available")

        args = Mock()
        args.host = 'localhost'
        args.port = 3000
        args.reload = False

        result = handle_serve_command(args)

        assert result == 1

    @patch('src.reveng.cli.start_server')
    def test_handle_serve_command_exception(self, mock_start_server):
        """Test serve command with exception."""
        mock_start_server.side_effect = Exception("Server error")

        args = Mock()
        args.host = 'localhost'
        args.port = 3000
        args.reload = False

        result = handle_serve_command(args)

        assert result == 1


class TestCLIMain:
    """Test the main CLI function."""

    @patch('src.reveng.cli.handle_analyze_command')
    def test_main_analyze_command(self, mock_handle_analyze):
        """Test main function with analyze command."""
        mock_handle_analyze.return_value = 0

        result = main()

        assert result == 0
        mock_handle_analyze.assert_called_once()

    @patch('src.reveng.cli.handle_serve_command')
    def test_main_serve_command(self, mock_handle_serve):
        """Test main function with serve command."""
        mock_handle_serve.return_value = 0

        result = main()

        assert result == 0
        mock_handle_serve.assert_called_once()

    def test_main_no_command(self):
        """Test main function with no command."""
        with patch('sys.argv', ['reveng']):
            result = main()

        assert result == 1

    def test_main_unknown_command(self):
        """Test main function with unknown command."""
        with patch('sys.argv', ['reveng', 'unknown']):
            result = main()

        assert result == 1


class TestCLIIntegration:
    """Test CLI integration scenarios."""

    @patch('src.reveng.cli.REVENGAnalyzer')
    def test_analyze_with_config_file(self, mock_analyzer_class, mock_binary_file, temp_analysis_dir):
        """Test analyze command with configuration file."""
        # Create config file
        config_file = temp_analysis_dir / "test_config.json"
        config_file.write_text('{"enhanced_analysis": {"enable_corporate_exposure": false}}')

        mock_analyzer = Mock()
        mock_analyzer.analyze_binary.return_value = True
        mock_analyzer._count_enabled_modules.return_value = 2
        mock_analyzer_class.return_value = mock_analyzer

        args = Mock()
        args.binary_path = str(mock_binary_file)
        args.no_ollama_check = False
        args.config = str(config_file)
        args.no_enhanced = False
        args.no_corporate = False
        args.no_vuln = False
        args.no_threat = False
        args.no_reconstruction = False
        args.no_demo = False

        result = handle_analyze_command(args)

        assert result == 0
        mock_analyzer_class.assert_called_once()

    @patch('src.reveng.cli.REVENGAnalyzer')
    def test_analyze_with_invalid_config(self, mock_analyzer_class, mock_binary_file, temp_analysis_dir):
        """Test analyze command with invalid configuration file."""
        # Create invalid config file
        config_file = temp_analysis_dir / "invalid_config.json"
        config_file.write_text('invalid json')

        mock_analyzer = Mock()
        mock_analyzer.analyze_binary.return_value = True
        mock_analyzer._count_enabled_modules.return_value = 5
        mock_analyzer_class.return_value = mock_analyzer

        args = Mock()
        args.binary_path = str(mock_binary_file)
        args.no_ollama_check = False
        args.config = str(config_file)
        args.no_enhanced = False
        args.no_corporate = False
        args.no_vuln = False
        args.no_threat = False
        args.no_reconstruction = False
        args.no_demo = False

        result = handle_analyze_command(args)

        assert result == 0  # Should continue despite config error
        mock_analyzer_class.assert_called_once()

    def test_enhanced_features_creation(self):
        """Test enhanced features creation from CLI args."""
        from src.reveng.cli import create_enhanced_features

        args = Mock()
        args.no_enhanced = False
        args.no_corporate = True
        args.no_vuln = False
        args.no_threat = True
        args.no_reconstruction = False
        args.no_demo = False
        args.config = None

        features = create_enhanced_features(args)

        assert features.enable_enhanced_analysis is True
        assert features.enable_corporate_exposure is False
        assert features.enable_vulnerability_discovery is True
        assert features.enable_threat_intelligence is False
        assert features.enable_enhanced_reconstruction is True
        assert features.enable_demonstration_generation is True

    def test_enhanced_features_all_disabled(self):
        """Test enhanced features when all are disabled."""
        from src.reveng.cli import create_enhanced_features

        args = Mock()
        args.no_enhanced = True
        args.no_corporate = False
        args.no_vuln = False
        args.no_threat = False
        args.no_reconstruction = False
        args.no_demo = False
        args.config = None

        features = create_enhanced_features(args)

        assert features.enable_enhanced_analysis is False
        assert features.is_any_enhanced_enabled() is False
