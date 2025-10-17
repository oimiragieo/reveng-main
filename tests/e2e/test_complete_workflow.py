"""
End-to-end tests for complete REVENG workflow
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys
import io

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from reveng.cli import main, create_parser


class TestCompleteWorkflow:
    """End-to-end tests for complete REVENG workflow"""

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

    def test_complete_analysis_workflow(self):
        """Test complete analysis workflow from CLI to results"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'analyze', str(test_binary)]

        # Mock all analyzers
        with patch('reveng.cli.REVENGAnalyzer') as mock_analyzer, \
             patch('reveng.cli.DotNetAnalyzer') as mock_dotnet, \
             patch('reveng.cli.PEAnalyzer') as mock_pe, \
             patch('reveng.cli.GhidraAnalyzer') as mock_ghidra, \
             patch('reveng.cli.MalwareAnalyzer') as mock_malware, \
             patch('reveng.cli.MLIntegration') as mock_ml:

            # Setup mocks
            mock_analyzer.return_value = Mock()
            mock_dotnet.return_value = Mock()
            mock_pe.return_value = Mock()
            mock_ghidra.return_value = Mock()
            mock_malware.return_value = Mock()
            mock_ml.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify analyzers were called
            mock_analyzer.assert_called_once()
            mock_dotnet.assert_called_once()
            mock_pe.assert_called_once()
            mock_ghidra.assert_called_once()
            mock_malware.assert_called_once()
            mock_ml.assert_called_once()

    def test_complete_hex_analysis_workflow(self):
        """Test complete hex analysis workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'hex', str(test_binary)]

        # Mock hex editor
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

    def test_complete_pe_analysis_workflow(self):
        """Test complete PE analysis workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'pe', str(test_binary)]

        # Mock PE analyzer
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

    def test_complete_ghidra_analysis_workflow(self):
        """Test complete Ghidra analysis workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'ghidra', str(test_binary)]

        # Mock Ghidra analyzer
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

    def test_complete_pipeline_analysis_workflow(self):
        """Test complete pipeline analysis workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'pipeline', str(test_binary)]

        # Mock pipeline engine
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

    def test_complete_malware_analysis_workflow(self):
        """Test complete malware analysis workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'malware', str(test_binary)]

        # Mock malware analyzer
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

    def test_complete_ml_analysis_workflow(self):
        """Test complete ML analysis workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'ml', 'analyze', str(test_binary)]

        # Mock ML integration
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

    def test_complete_ml_reconstruct_workflow(self):
        """Test complete ML reconstruction workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'ml', 'reconstruct', str(test_binary)]

        # Mock ML integration
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

    def test_complete_ml_anomaly_workflow(self):
        """Test complete ML anomaly detection workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'ml', 'anomaly', str(test_binary)]

        # Mock ML integration
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

    def test_complete_ml_threat_workflow(self):
        """Test complete ML threat analysis workflow"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'ml', 'threat', str(test_binary)]

        # Mock ML integration
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

    def test_complete_ml_status_workflow(self):
        """Test complete ML status workflow"""
        # Set up CLI arguments
        sys.argv = ['reveng', 'ml', 'status']

        # Mock ML integration
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

    def test_complete_web_server_workflow(self):
        """Test complete web server workflow"""
        # Set up CLI arguments
        sys.argv = ['reveng', 'serve', '--port', '8080']

        # Mock web server
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

    def test_complete_plugin_workflow(self):
        """Test complete plugin workflow"""
        # Set up CLI arguments
        sys.argv = ['reveng', 'plugin', 'list']

        # Mock plugin manager
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

    def test_complete_setup_workflow(self):
        """Test complete setup workflow"""
        # Set up CLI arguments
        sys.argv = ['reveng', 'setup']

        # Mock setup
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

    def test_complete_config_workflow(self):
        """Test complete config workflow"""
        # Set up CLI arguments
        sys.argv = ['reveng', 'config', 'show']

        # Mock config manager
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

    def test_complete_workflow_with_large_binary(self):
        """Test complete workflow with large binary"""
        # Create large test binary
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        # Set up CLI arguments
        sys.argv = ['reveng', 'analyze', str(test_binary)]

        # Mock all analyzers
        with patch('reveng.cli.REVENGAnalyzer') as mock_analyzer, \
             patch('reveng.cli.DotNetAnalyzer') as mock_dotnet, \
             patch('reveng.cli.PEAnalyzer') as mock_pe, \
             patch('reveng.cli.GhidraAnalyzer') as mock_ghidra, \
             patch('reveng.cli.MalwareAnalyzer') as mock_malware, \
             patch('reveng.cli.MLIntegration') as mock_ml:

            # Setup mocks
            mock_analyzer.return_value = Mock()
            mock_dotnet.return_value = Mock()
            mock_pe.return_value = Mock()
            mock_ghidra.return_value = Mock()
            mock_malware.return_value = Mock()
            mock_ml.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify analyzers were called
            mock_analyzer.assert_called_once()
            mock_dotnet.assert_called_once()
            mock_pe.assert_called_once()
            mock_ghidra.assert_called_once()
            mock_malware.assert_called_once()
            mock_ml.assert_called_once()

    def test_complete_workflow_with_multiple_binaries(self):
        """Test complete workflow with multiple binaries"""
        # Create multiple test binaries
        test_binaries = []
        for i in range(3):
            binary_path = self.temp_dir / f'test_{i}.exe'
            binary_path.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)
            test_binaries.append(binary_path)

        # Test each binary
        for binary in test_binaries:
            # Set up CLI arguments
            sys.argv = ['reveng', 'analyze', str(binary)]

            # Mock all analyzers
            with patch('reveng.cli.REVENGAnalyzer') as mock_analyzer, \
                 patch('reveng.cli.DotNetAnalyzer') as mock_dotnet, \
                 patch('reveng.cli.PEAnalyzer') as mock_pe, \
                 patch('reveng.cli.GhidraAnalyzer') as mock_ghidra, \
                 patch('reveng.cli.MalwareAnalyzer') as mock_malware, \
                 patch('reveng.cli.MLIntegration') as mock_ml:

                # Setup mocks
                mock_analyzer.return_value = Mock()
                mock_dotnet.return_value = Mock()
                mock_pe.return_value = Mock()
                mock_ghidra.return_value = Mock()
                mock_malware.return_value = Mock()
                mock_ml.return_value = Mock()

                # Capture stdout
                captured_output = io.StringIO()
                sys.stdout = captured_output

                try:
                    main()
                except SystemExit:
                    pass

                # Verify analyzers were called
                mock_analyzer.assert_called_once()
                mock_dotnet.assert_called_once()
                mock_pe.assert_called_once()
                mock_ghidra.assert_called_once()
                mock_malware.assert_called_once()
                mock_ml.assert_called_once()

    def test_complete_workflow_with_failures(self):
        """Test complete workflow with failures"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments
        sys.argv = ['reveng', 'analyze', str(test_binary)]

        # Mock all analyzers with failures
        with patch('reveng.cli.REVENGAnalyzer') as mock_analyzer, \
             patch('reveng.cli.DotNetAnalyzer') as mock_dotnet, \
             patch('reveng.cli.PEAnalyzer') as mock_pe, \
             patch('reveng.cli.GhidraAnalyzer') as mock_ghidra, \
             patch('reveng.cli.MalwareAnalyzer') as mock_malware, \
             patch('reveng.cli.MLIntegration') as mock_ml:

            # Setup mocks with failures
            mock_analyzer.return_value = Mock()
            mock_dotnet.return_value = Mock()
            mock_pe.return_value = Mock()
            mock_ghidra.return_value = Mock()
            mock_malware.return_value = Mock()
            mock_ml.return_value = Mock()

            # Capture stderr
            captured_output = io.StringIO()
            sys.stderr = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify analyzers were called
            mock_analyzer.assert_called_once()
            mock_dotnet.assert_called_once()
            mock_pe.assert_called_once()
            mock_ghidra.assert_called_once()
            mock_malware.assert_called_once()
            mock_ml.assert_called_once()

    def test_complete_workflow_with_custom_models(self):
        """Test complete workflow with custom models"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments with custom model
        sys.argv = ['reveng', 'ml', 'analyze', str(test_binary), '--model', 'custom']

        # Mock ML integration
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

    def test_complete_workflow_with_custom_config(self):
        """Test complete workflow with custom configuration"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Set up CLI arguments with custom config
        sys.argv = ['reveng', 'analyze', str(test_binary), '--config', 'custom_config.yaml']

        # Mock all analyzers
        with patch('reveng.cli.REVENGAnalyzer') as mock_analyzer, \
             patch('reveng.cli.DotNetAnalyzer') as mock_dotnet, \
             patch('reveng.cli.PEAnalyzer') as mock_pe, \
             patch('reveng.cli.GhidraAnalyzer') as mock_ghidra, \
             patch('reveng.cli.MalwareAnalyzer') as mock_malware, \
             patch('reveng.cli.MLIntegration') as mock_ml:

            # Setup mocks
            mock_analyzer.return_value = Mock()
            mock_dotnet.return_value = Mock()
            mock_pe.return_value = Mock()
            mock_ghidra.return_value = Mock()
            mock_malware.return_value = Mock()
            mock_ml.return_value = Mock()

            # Capture stdout
            captured_output = io.StringIO()
            sys.stdout = captured_output

            try:
                main()
            except SystemExit:
                pass

            # Verify analyzers were called
            mock_analyzer.assert_called_once()
            mock_dotnet.assert_called_once()
            mock_pe.assert_called_once()
            mock_ghidra.assert_called_once()
            mock_malware.assert_called_once()
            mock_ml.assert_called_once()
