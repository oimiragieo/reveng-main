"""
Unit tests for Unified CLI
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys
import io

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from reveng.cli import main, create_parser, create_ml_parser


class TestUnifiedCLI:
    """Test cases for Unified CLI"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.original_argv = sys.argv
        self.original_stdout = sys.stdout
        self.original_stderr = sys.stderr

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        sys.argv = self.original_argv
        sys.stdout = self.original_stdout
        sys.stderr = self.original_stderr

    def test_create_parser_success(self):
        """Test creating parser successfully"""
        parser = create_parser()

        assert parser is not None
        assert hasattr(parser, 'parse_args')
        assert hasattr(parser, 'add_subparsers')

        # Test that parser has expected subcommands
        args = parser.parse_args(['--help'])
        assert args is not None

    def test_create_ml_parser_success(self):
        """Test creating ML parser successfully"""
        import argparse
        subparsers = Mock()
        subparsers.add_parser.return_value = Mock()

        # Create ML parser
        create_ml_parser(subparsers)

        # Verify that subparsers.add_parser was called
        assert subparsers.add_parser.called

    def test_main_with_help(self):
        """Test main function with help argument"""
        sys.argv = ['reveng', '--help']

        # Capture stdout
        captured_output = io.StringIO()
        sys.stdout = captured_output

        try:
            main()
        except SystemExit:
            pass

        output = captured_output.getvalue()
        assert 'usage:' in output
        assert 'reveng' in output

    def test_main_with_analyze_command(self):
        """Test main function with analyze command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'analyze', str(test_binary)]

        # Mock the analyzer
        with patch('reveng.cli.REVENGAnalyzer') as mock_analyzer:
            mock_instance = Mock()
            mock_analyzer.return_value = mock_instance
            mock_instance.analyze.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify analyzer was called
            mock_instance.analyze.assert_called_once()

    def test_main_with_hex_command(self):
        """Test main function with hex command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'hex', str(test_binary)]

        # Mock the hex editor
        with patch('reveng.cli.HexEditor') as mock_hex_editor:
            mock_instance = Mock()
            mock_hex_editor.return_value = mock_instance
            mock_instance.open_binary.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify hex editor was called
            mock_instance.open_binary.assert_called_once()

    def test_main_with_pe_command(self):
        """Test main function with PE command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'pe', str(test_binary)]

        # Mock the PE analyzer
        with patch('reveng.cli.PEAnalyzer') as mock_pe_analyzer:
            mock_instance = Mock()
            mock_pe_analyzer.return_value = mock_instance
            mock_instance.analyze.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify PE analyzer was called
            mock_instance.analyze.assert_called_once()

    def test_main_with_ghidra_command(self):
        """Test main function with Ghidra command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'ghidra', str(test_binary)]

        # Mock the Ghidra analyzer
        with patch('reveng.cli.GhidraAnalyzer') as mock_ghidra_analyzer:
            mock_instance = Mock()
            mock_ghidra_analyzer.return_value = mock_instance
            mock_instance.analyze.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify Ghidra analyzer was called
            mock_instance.analyze.assert_called_once()

    def test_main_with_pipeline_command(self):
        """Test main function with pipeline command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'pipeline', str(test_binary)]

        # Mock the pipeline engine
        with patch('reveng.cli.AnalysisPipeline') as mock_pipeline:
            mock_instance = Mock()
            mock_pipeline.return_value = mock_instance
            mock_instance.execute_pipeline.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify pipeline was called
            mock_instance.execute_pipeline.assert_called_once()

    def test_main_with_malware_command(self):
        """Test main function with malware command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'malware', str(test_binary)]

        # Mock the malware analyzer
        with patch('reveng.cli.MalwareAnalyzer') as mock_malware_analyzer:
            mock_instance = Mock()
            mock_malware_analyzer.return_value = mock_instance
            mock_instance.analyze.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify malware analyzer was called
            mock_instance.analyze.assert_called_once()

    def test_main_with_serve_command(self):
        """Test main function with serve command"""
        sys.argv = ['reveng', 'serve', '--port', '8080']

        # Mock the web server
        with patch('reveng.cli.start_web_server') as mock_server:
            mock_server.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify server was called
            mock_server.assert_called_once()

    def test_main_with_plugin_command(self):
        """Test main function with plugin command"""
        sys.argv = ['reveng', 'plugin', 'list']

        # Mock the plugin manager
        with patch('reveng.cli.PluginManager') as mock_plugin_manager:
            mock_instance = Mock()
            mock_plugin_manager.return_value = mock_instance
            mock_instance.list_plugins.return_value = []

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify plugin manager was called
            mock_instance.list_plugins.assert_called_once()

    def test_main_with_setup_command(self):
        """Test main function with setup command"""
        sys.argv = ['reveng', 'setup']

        # Mock the setup
        with patch('reveng.cli.setup_environment') as mock_setup:
            mock_setup.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify setup was called
            mock_setup.assert_called_once()

    def test_main_with_config_command(self):
        """Test main function with config command"""
        sys.argv = ['reveng', 'config', 'show']

        # Mock the config manager
        with patch('reveng.cli.ConfigManager') as mock_config_manager:
            mock_instance = Mock()
            mock_config_manager.return_value = mock_instance
            mock_instance.show_config.return_value = {}

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify config manager was called
            mock_instance.show_config.assert_called_once()

    def test_main_with_ml_analyze_command(self):
        """Test main function with ML analyze command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'ml', 'analyze', str(test_binary)]

        # Mock the ML integration
        with patch('reveng.cli.MLIntegration') as mock_ml_integration:
            mock_instance = Mock()
            mock_ml_integration.return_value = mock_instance
            mock_instance.analyze_binary.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify ML integration was called
            mock_instance.analyze_binary.assert_called_once()

    def test_main_with_ml_reconstruct_command(self):
        """Test main function with ML reconstruct command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'ml', 'reconstruct', str(test_binary)]

        # Mock the ML integration
        with patch('reveng.cli.MLIntegration') as mock_ml_integration:
            mock_instance = Mock()
            mock_ml_integration.return_value = mock_instance
            mock_instance.reconstruct_code.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify ML integration was called
            mock_instance.reconstruct_code.assert_called_once()

    def test_main_with_ml_anomaly_command(self):
        """Test main function with ML anomaly command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'ml', 'anomaly', str(test_binary)]

        # Mock the ML integration
        with patch('reveng.cli.MLIntegration') as mock_ml_integration:
            mock_instance = Mock()
            mock_ml_integration.return_value = mock_instance
            mock_instance.detect_anomalies.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify ML integration was called
            mock_instance.detect_anomalies.assert_called_once()

    def test_main_with_ml_threat_command(self):
        """Test main function with ML threat command"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        sys.argv = ['reveng', 'ml', 'threat', str(test_binary)]

        # Mock the ML integration
        with patch('reveng.cli.MLIntegration') as mock_ml_integration:
            mock_instance = Mock()
            mock_ml_integration.return_value = mock_instance
            mock_instance.analyze_threats.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify ML integration was called
            mock_instance.analyze_threats.assert_called_once()

    def test_main_with_ml_status_command(self):
        """Test main function with ML status command"""
        sys.argv = ['reveng', 'ml', 'status']

        # Mock the ML integration
        with patch('reveng.cli.MLIntegration') as mock_ml_integration:
            mock_instance = Mock()
            mock_ml_integration.return_value = mock_instance
            mock_instance.get_model_status.return_value = {}

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify ML integration was called
            mock_instance.get_model_status.assert_called_once()

    def test_main_with_invalid_command(self):
        """Test main function with invalid command"""
        sys.argv = ['reveng', 'invalid_command']

        # Capture stderr
        captured_output = io.StringIO()
        sys.stderr = captured_output

        try:
            main()
        except SystemExit:
            pass

        output = captured_output.getvalue()
        assert 'error:' in output or 'usage:' in output

    def test_main_with_missing_binary(self):
        """Test main function with missing binary file"""
        sys.argv = ['reveng', 'analyze', 'nonexistent.exe']

        # Capture stderr
        captured_output = io.StringIO()
        sys.stderr = captured_output

        try:
            main()
        except SystemExit:
            pass

        output = captured_output.getvalue()
        assert 'error:' in output or 'FileNotFoundError' in output

    def test_main_with_large_binary(self):
        """Test main function with large binary file"""
        # Create large test binary
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        sys.argv = ['reveng', 'analyze', str(test_binary)]

        # Mock the analyzer
        with patch('reveng.cli.REVENGAnalyzer') as mock_analyzer:
            mock_instance = Mock()
            mock_analyzer.return_value = mock_instance
            mock_instance.analyze.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify analyzer was called
            mock_instance.analyze.assert_called_once()

    def test_main_with_multiple_commands(self):
        """Test main function with multiple commands"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        commands = [
            ['reveng', 'analyze', str(test_binary)],
            ['reveng', 'hex', str(test_binary)],
            ['reveng', 'pe', str(test_binary)],
            ['reveng', 'ghidra', str(test_binary)],
            ['reveng', 'pipeline', str(test_binary)],
            ['reveng', 'malware', str(test_binary)]
        ]

        for cmd in commands:
            sys.argv = cmd

            # Mock the appropriate analyzer
            with patch('reveng.cli.REVENGAnalyzer') as mock_analyzer, \
                 patch('reveng.cli.HexEditor') as mock_hex_editor, \
                 patch('reveng.cli.PEAnalyzer') as mock_pe_analyzer, \
                 patch('reveng.cli.GhidraAnalyzer') as mock_ghidra_analyzer, \
                 patch('reveng.cli.AnalysisPipeline') as mock_pipeline, \
                 patch('reveng.cli.MalwareAnalyzer') as mock_malware_analyzer:

                # Setup mocks
                mock_analyzer.return_value = Mock()
                mock_hex_editor.return_value = Mock()
                mock_pe_analyzer.return_value = Mock()
                mock_ghidra_analyzer.return_value = Mock()
                mock_pipeline.return_value = Mock()
                mock_malware_analyzer.return_value = Mock()

                # Capture stdout
                captured_output = io.StringIO()
                sys.stdout = captured_output

                try:
                    main()
                except SystemExit:
                    pass

                # Verify command was processed
                output = captured_output.getvalue()
                assert output is not None
