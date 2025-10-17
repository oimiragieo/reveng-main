"""
End-to-end tests for REVENG CLI workflows

Tests complete CLI workflows from command execution to result generation.
"""

import pytest
import tempfile
import subprocess
import sys
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

class TestCLIWorkflows:
    """Test cases for CLI workflows"""

    def test_analyze_command_basic(self, sample_binaries_dir):
        """Test basic analyze command"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the analyze command
        with patch('reveng.cli.commands.analyze.cmd_analyze') as mock_analyze:
            mock_analyze.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "analyze", str(binary_path)
            ], capture_output=True, text=True)

            # Should not raise exception
            assert result.returncode == 0

    def test_analyze_command_with_output(self, sample_binaries_dir, temp_dir):
        """Test analyze command with output directory"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"
        output_dir = temp_dir / "analysis_output"

        # Mock the analyze command
        with patch('reveng.cli.commands.analyze.cmd_analyze') as mock_analyze:
            mock_analyze.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "analyze", str(binary_path), "--output", str(output_dir)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_analyze_command_with_format(self, sample_binaries_dir):
        """Test analyze command with output format"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the analyze command
        with patch('reveng.cli.commands.analyze.cmd_analyze') as mock_analyze:
            mock_analyze.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "analyze", str(binary_path), "--format", "json"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_hex_command_basic(self, sample_binaries_dir):
        """Test basic hex command"""
        binary_path = sample_binaries_dir / "native_app.exe"

        # Mock the hex command
        with patch('reveng.cli.commands.hex.cmd_hex') as mock_hex:
            mock_hex.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "hex", str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_hex_command_with_offset(self, sample_binaries_dir):
        """Test hex command with offset"""
        binary_path = sample_binaries_dir / "native_app.exe"

        # Mock the hex command
        with patch('reveng.cli.commands.hex.cmd_hex') as mock_hex:
            mock_hex.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "hex", str(binary_path), "--offset", "0x1000"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_hex_command_with_search(self, sample_binaries_dir):
        """Test hex command with pattern search"""
        binary_path = sample_binaries_dir / "native_app.exe"

        # Mock the hex command
        with patch('reveng.cli.commands.hex.cmd_hex') as mock_hex:
            mock_hex.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "hex", str(binary_path), "--search", "4D5A"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_pe_command_resources(self, sample_binaries_dir):
        """Test PE resources command"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the PE command
        with patch('reveng.cli.commands.pe.cmd_pe') as mock_pe:
            mock_pe.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "pe", str(binary_path), "--extract-resources"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_pe_command_imports(self, sample_binaries_dir):
        """Test PE imports command"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the PE command
        with patch('reveng.cli.commands.pe.cmd_pe') as mock_pe:
            mock_pe.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "pe", str(binary_path), "--analyze-imports"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_ghidra_command_analyze(self, sample_binaries_dir):
        """Test Ghidra analyze command"""
        binary_path = sample_binaries_dir / "native_app.exe"

        # Mock the Ghidra command
        with patch('reveng.cli.commands.ghidra.cmd_ghidra') as mock_ghidra:
            mock_ghidra.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "ghidra", "analyze", str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_ghidra_command_script(self, sample_binaries_dir, test_scripts_dir):
        """Test Ghidra script command"""
        binary_path = sample_binaries_dir / "native_app.exe"
        script_path = test_scripts_dir["test_script"]

        # Mock the Ghidra command
        with patch('reveng.cli.commands.ghidra.cmd_ghidra') as mock_ghidra:
            mock_ghidra.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "ghidra", "analyze", str(binary_path), "--script", str(script_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_pipeline_command_create(self):
        """Test pipeline create command"""
        # Mock the pipeline command
        with patch('reveng.cli.commands.pipeline.cmd_pipeline') as mock_pipeline:
            mock_pipeline.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "pipeline", "create", "test_pipeline"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_pipeline_command_run(self, sample_binaries_dir, temp_dir):
        """Test pipeline run command"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"
        pipeline_file = temp_dir / "test_pipeline.yaml"

        # Create mock pipeline file
        with open(pipeline_file, 'w') as f:
            f.write("""
steps:
  - name: dotnet_analysis
    function: analyze_assembly
    args:
      binary_path: test.exe
""")

        # Mock the pipeline command
        with patch('reveng.cli.commands.pipeline.cmd_pipeline') as mock_pipeline:
            mock_pipeline.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "pipeline", "run", str(pipeline_file), str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_malware_command_analyze(self, sample_binaries_dir):
        """Test malware analyze command"""
        binary_path = sample_binaries_dir / "malware_sample.exe"

        # Mock the malware command
        with patch('reveng.cli.commands.malware.cmd_malware') as mock_malware:
            mock_malware.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "malware", "analyze", str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_malware_command_behavioral(self, sample_binaries_dir):
        """Test malware behavioral command"""
        binary_path = sample_binaries_dir / "malware_sample.exe"

        # Mock the malware command
        with patch('reveng.cli.commands.malware.cmd_malware') as mock_malware:
            mock_malware.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "malware", "behavioral", str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_malware_command_memory(self):
        """Test malware memory command"""
        # Mock the malware command
        with patch('reveng.cli.commands.malware.cmd_malware') as mock_malware:
            mock_malware.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "malware", "memory", "1234"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_ml_command_analyze(self, sample_binaries_dir):
        """Test ML analyze command"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the ML command
        with patch('reveng.cli.commands.ml.cmd_ml_analyze') as mock_ml:
            mock_ml.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "ml", "analyze", str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_ml_command_reconstruct(self, sample_binaries_dir):
        """Test ML reconstruct command"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the ML command
        with patch('reveng.cli.commands.ml.cmd_ml_reconstruct') as mock_ml:
            mock_ml.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "ml", "reconstruct", str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_ml_command_anomaly(self, sample_binaries_dir):
        """Test ML anomaly command"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the ML command
        with patch('reveng.cli.commands.ml.cmd_ml_anomaly') as mock_ml:
            mock_ml.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "ml", "anomaly", str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_ml_command_threat(self, sample_binaries_dir):
        """Test ML threat command"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the ML command
        with patch('reveng.cli.commands.ml.cmd_ml_threat') as mock_ml:
            mock_ml.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "ml", "threat", str(binary_path)
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_ml_command_status(self):
        """Test ML status command"""
        # Mock the ML command
        with patch('reveng.cli.commands.ml.cmd_ml_status') as mock_ml:
            mock_ml.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "ml", "status"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_plugin_command_list(self):
        """Test plugin list command"""
        # Mock the plugin command
        with patch('reveng.cli.commands.plugin.cmd_plugin') as mock_plugin:
            mock_plugin.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "plugin", "list"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_plugin_command_install(self):
        """Test plugin install command"""
        # Mock the plugin command
        with patch('reveng.cli.commands.plugin.cmd_plugin') as mock_plugin:
            mock_plugin.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "plugin", "install", "test_plugin"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_setup_command_verify(self):
        """Test setup verify command"""
        # Mock the setup command
        with patch('reveng.cli.commands.setup.cmd_setup') as mock_setup:
            mock_setup.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "setup", "verify"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_setup_command_install_deps(self):
        """Test setup install-deps command"""
        # Mock the setup command
        with patch('reveng.cli.commands.setup.cmd_setup') as mock_setup:
            mock_setup.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "setup", "install-deps"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_config_command_show(self):
        """Test config show command"""
        # Mock the config command
        with patch('reveng.cli.commands.config.cmd_config') as mock_config:
            mock_config.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "config", "show"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_config_command_set(self):
        """Test config set command"""
        # Mock the config command
        with patch('reveng.cli.commands.config.cmd_config') as mock_config:
            mock_config.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "config", "set", "test.key", "test.value"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_serve_command(self):
        """Test serve command"""
        # Mock the serve command
        with patch('reveng.cli.commands.serve.cmd_serve') as mock_serve:
            mock_serve.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "serve", "--port", "3000"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_help_command(self):
        """Test help command"""
        # Simulate CLI execution
        result = subprocess.run([
            sys.executable, "reveng.py", "--help"
        ], capture_output=True, text=True)

        assert result.returncode == 0
        assert "REVENG Universal Reverse Engineering Platform" in result.stdout

    def test_version_command(self):
        """Test version command"""
        # Simulate CLI execution
        result = subprocess.run([
            sys.executable, "reveng.py", "--version"
        ], capture_output=True, text=True)

        assert result.returncode == 0
        assert "REVENG 2.1.0" in result.stdout

    def test_invalid_command(self):
        """Test invalid command"""
        # Simulate CLI execution
        result = subprocess.run([
            sys.executable, "reveng.py", "invalid_command"
        ], capture_output=True, text=True)

        assert result.returncode != 0

    def test_missing_required_argument(self):
        """Test missing required argument"""
        # Simulate CLI execution
        result = subprocess.run([
            sys.executable, "reveng.py", "analyze"
        ], capture_output=True, text=True)

        assert result.returncode != 0

    def test_verbose_output(self, sample_binaries_dir):
        """Test verbose output option"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the analyze command
        with patch('reveng.cli.commands.analyze.cmd_analyze') as mock_analyze:
            mock_analyze.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "analyze", str(binary_path), "--verbose"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_log_level_debug(self, sample_binaries_dir):
        """Test debug log level"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"

        # Mock the analyze command
        with patch('reveng.cli.commands.analyze.cmd_analyze') as mock_analyze:
            mock_analyze.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "analyze", str(binary_path), "--log-level", "DEBUG"
            ], capture_output=True, text=True)

            assert result.returncode == 0

    def test_config_file_option(self, sample_binaries_dir, temp_dir):
        """Test config file option"""
        binary_path = sample_binaries_dir / "dotnet_app.exe"
        config_file = temp_dir / "config.yaml"

        # Create mock config file
        with open(config_file, 'w') as f:
            f.write("""
log_level: DEBUG
output_format: json
""")

        # Mock the analyze command
        with patch('reveng.cli.commands.analyze.cmd_analyze') as mock_analyze:
            mock_analyze.return_value = None

            # Simulate CLI execution
            result = subprocess.run([
                sys.executable, "reveng.py", "analyze", str(binary_path), "--config", str(config_file)
            ], capture_output=True, text=True)

            assert result.returncode == 0
