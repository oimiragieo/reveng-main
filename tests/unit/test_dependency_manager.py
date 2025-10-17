"""
Unit tests for DependencyManager
"""

import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.core.dependency_manager import DependencyManager, ToolInfo, InstallationResult


class TestDependencyManager:
    """Test cases for DependencyManager"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.dm = DependencyManager()

    def teardown_method(self):
        """Cleanup test environment"""
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test DependencyManager initialization"""
        assert self.dm is not None
        assert hasattr(self.dm, 'tools')
        assert hasattr(self.dm, 'fallback_analyzers')

    def test_check_all_dependencies(self):
        """Test checking all dependencies"""
        with patch.object(self.dm, 'tools', {
            'ghidra': Mock(check_installed=Mock(return_value=True)),
            'ilspy': Mock(check_installed=Mock(return_value=False)),
            'cfr': None
        }):
            results = self.dm.check_all_dependencies()

            assert results['ghidra'] is True
            assert results['ilspy'] is False
            assert results['cfr'] is False

    def test_install_missing_tools(self):
        """Test installing missing tools"""
        with patch.object(self.dm, 'tools', {
            'ghidra': Mock(
                check_installed=Mock(return_value=False),
                install=Mock(return_value=InstallationResult(True, 'ghidra', '/path'))
            ),
            'ilspy': Mock(
                check_installed=Mock(return_value=True),
                install=Mock(return_value=InstallationResult(True, 'ilspy', '/path'))
            )
        }):
            results = self.dm.install_missing_tools(['ghidra', 'ilspy'], auto_install=True)

            assert 'ghidra' in results
            assert 'ilspy' in results
            assert results['ghidra'].success is True
            assert results['ilspy'].success is True

    def test_install_missing_tools_no_auto_install(self):
        """Test installing missing tools with auto-install disabled"""
        with patch.object(self.dm, 'tools', {
            'ghidra': Mock(check_installed=Mock(return_value=False))
        }):
            results = self.dm.install_missing_tools(['ghidra'], auto_install=False)

            assert 'ghidra' in results
            assert results['ghidra'].success is False
            assert "Auto-installation disabled" in results['ghidra'].error_message

    def test_get_fallback_analyzer(self):
        """Test getting fallback analyzer"""
        fallback = self.dm.get_fallback_analyzer('ghidra')
        assert fallback == 'basic_pe_analyzer'

        fallback = self.dm.get_fallback_analyzer('nonexistent')
        assert fallback is None

    def test_get_tool_path(self):
        """Test getting tool path"""
        with patch.object(self.dm, 'tools', {
            'ghidra': Mock(
                check_installed=Mock(return_value=True),
                get_executable_path=Mock(return_value='/path/to/ghidra')
            )
        }):
            path = self.dm.get_tool_path('ghidra')
            assert path == '/path/to/ghidra'

        with patch.object(self.dm, 'tools', {
            'ghidra': Mock(check_installed=Mock(return_value=False))
        }):
            path = self.dm.get_tool_path('ghidra')
            assert path is None

    def test_get_installation_status(self):
        """Test getting installation status"""
        with patch.object(self.dm, 'tools', {
            'ghidra': Mock(
                check_installed=Mock(return_value=True),
                tool_version='11.0',
                get_executable_path=Mock(return_value='/path/to/ghidra'),
                get_executable_name=Mock(return_value='ghidraRun.bat')
            ),
            'nonexistent': None
        }):
            status = self.dm.get_installation_status()

            assert 'ghidra' in status
            assert status['ghidra'].is_installed is True
            assert status['ghidra'].version == '11.0'
            assert status['ghidra'].path == '/path/to/ghidra'

            assert 'nonexistent' in status
            assert status['nonexistent'].is_installed is False

    def test_cleanup_failed_installations(self):
        """Test cleaning up failed installations"""
        with patch.object(self.dm, 'tools', {
            'ghidra': Mock(
                install_dir=Path('/nonexistent'),
                check_installed=Mock(return_value=False)
            )
        }):
            with patch('shutil.rmtree') as mock_rmtree:
                cleaned = self.dm.cleanup_failed_installations()
                assert cleaned == 1
                mock_rmtree.assert_called_once()

    def test_export_configuration(self):
        """Test exporting configuration"""
        with patch.object(self.dm, 'tools', {
            'ghidra': Mock(
                tool_version='11.0',
                install_dir=Path('/path/to/ghidra'),
                get_executable_name=Mock(return_value='ghidraRun.bat')
            )
        }):
            config_path = self.temp_dir / 'config.json'
            success = self.dm.export_configuration(str(config_path))

            assert success is True
            assert config_path.exists()

            # Verify config content
            import json
            with open(config_path) as f:
                config = json.load(f)

            assert 'tools' in config
            assert 'ghidra' in config['tools']
            assert config['tools']['ghidra']['version'] == '11.0'

    def test_import_configuration(self):
        """Test importing configuration"""
        config_data = {
            'fallback_analyzers': {
                'ghidra': 'basic_pe_analyzer',
                'ilspy': 'basic_dotnet_analyzer'
            }
        }

        config_path = self.temp_dir / 'config.json'
        import json
        with open(config_path, 'w') as f:
            json.dump(config_data, f)

        success = self.dm.import_configuration(str(config_path))
        assert success is True
        assert 'ghidra' in self.dm.fallback_analyzers
        assert self.dm.fallback_analyzers['ghidra'] == 'basic_pe_analyzer'

    def test_import_configuration_invalid_file(self):
        """Test importing configuration from invalid file"""
        config_path = self.temp_dir / 'nonexistent.json'
        success = self.dm.import_configuration(str(config_path))
        assert success is False

    def test_import_configuration_invalid_json(self):
        """Test importing configuration from invalid JSON"""
        config_path = self.temp_dir / 'invalid.json'
        with open(config_path, 'w') as f:
            f.write('invalid json')

        success = self.dm.import_configuration(str(config_path))
        assert success is False
