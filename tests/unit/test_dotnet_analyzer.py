"""
Unit tests for DotNetAnalyzer
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.analyzers.dotnet_analyzer import (
    DotNetAnalyzer, DotNetAnalysisResult, ApplicationDomain, GUIFramework
)


class TestDotNetAnalyzer:
    """Test cases for DotNetAnalyzer"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.analyzer = DotNetAnalyzer()

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test DotNetAnalyzer initialization"""
        assert self.analyzer is not None
        assert hasattr(self.analyzer, 'logger')
        assert hasattr(self.analyzer, 'temp_dir')

    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._get_assembly_info')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._detect_framework_version')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._detect_runtime_version')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._detect_gui_framework')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._extract_dependencies')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._extract_embedded_resources')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._find_entry_points')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._extract_business_logic')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._detect_packing')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._analyze_obfuscation')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._extract_api_calls')
    @patch('src.reveng.analyzers.dotnet_analyzer.DotNetAnalyzer._analyze_pe_sections')
    def test_analyze_assembly_success(self, mock_pe_sections, mock_api_calls,
                                    mock_obfuscation, mock_packing, mock_business_logic,
                                    mock_entry_points, mock_resources, mock_dependencies,
                                    mock_gui, mock_runtime, mock_framework, mock_assembly):
        """Test successful assembly analysis"""
        # Setup mocks
        mock_assembly.return_value = Mock(name='TestApp', version='1.0.0', culture='',
                                         public_key_token='', processor_architecture='')
        mock_framework.return_value = '4.8'
        mock_runtime.return_value = '4.8.0'
        mock_gui.return_value = 'Windows Forms'
        mock_dependencies.return_value = ['System.Windows.Forms', 'System.Drawing']
        mock_resources.return_value = {'icons': [], 'strings': []}
        mock_entry_points.return_value = ['Main']
        mock_business_logic.return_value = {'application_domain': 'security'}
        mock_packing.return_value = False
        mock_obfuscation.return_value = 'None'
        mock_api_calls.return_value = ['CreateFile', 'ReadFile']
        mock_pe_sections.return_value = {'text': {}, 'data': {}}

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Run analysis
        result = self.analyzer.analyze_assembly(str(test_binary))

        # Verify result
        assert isinstance(result, DotNetAnalysisResult)
        assert result.framework_version == '4.8'
        assert result.runtime_version == '4.8.0'
        assert result.gui_framework == 'Windows Forms'
        assert result.assembly_name == 'TestApp'
        assert result.assembly_version == '1.0.0'
        assert result.dependencies == ['System.Windows.Forms', 'System.Drawing']
        assert result.is_packed is False
        assert result.obfuscation_level == 'None'
        assert result.api_calls == ['CreateFile', 'ReadFile']

    def test_analyze_assembly_failure(self):
        """Test assembly analysis failure"""
        # Create non-existent binary
        test_binary = self.temp_dir / 'nonexistent.exe'

        with pytest.raises(Exception):
            self.analyzer.analyze_assembly(str(test_binary))

    def test_detect_gui_framework_winforms(self):
        """Test Windows Forms detection"""
        strings = [
            'System.Windows.Forms',
            'Form',
            'Button',
            'TextBox',
            'MessageBox'
        ]

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._detect_gui_framework('test.exe')
            assert result == 'Windows Forms'

    def test_detect_gui_framework_wpf(self):
        """Test WPF detection"""
        strings = [
            'System.Windows',
            'XAML',
            'WPF',
            'PresentationFramework'
        ]

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._detect_gui_framework('test.exe')
            assert result == 'Windows Presentation Foundation'

    def test_detect_gui_framework_console(self):
        """Test console application detection"""
        strings = [
            'Console.WriteLine',
            'Console.Read',
            'System.Console'
        ]

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._detect_gui_framework('test.exe')
            assert result == 'Console Application'

    def test_detect_gui_framework_unknown(self):
        """Test unknown GUI framework"""
        strings = ['SomeOtherString']

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._detect_gui_framework('test.exe')
            assert result == 'Unknown'

    def test_extract_business_logic_security(self):
        """Test security domain business logic extraction"""
        strings = [
            'vulnerability',
            'security',
            'scan',
            'audit',
            'malware',
            'firewall'
        ]

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._extract_business_logic('test.exe')
            assert result['application_domain'] == 'security'

    def test_extract_business_logic_reporting(self):
        """Test reporting domain business logic extraction"""
        strings = [
            'report',
            'export',
            'generate',
            'template',
            'excel',
            'pdf'
        ]

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._extract_business_logic('test.exe')
            assert result['application_domain'] == 'reporting'

    def test_extract_business_logic_database(self):
        """Test database domain business logic extraction"""
        strings = [
            'database',
            'sql',
            'query',
            'table',
            'select',
            'insert'
        ]

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._extract_business_logic('test.exe')
            assert result['application_domain'] == 'database'

    def test_detect_packing_high_entropy(self):
        """Test packing detection with high entropy"""
        with patch.object(self.analyzer, '_analyze_entropy_for_packing', return_value=True):
            result = self.analyzer._detect_packing('test.exe')
            assert result is True

    def test_detect_packing_low_entropy(self):
        """Test packing detection with low entropy"""
        with patch.object(self.analyzer, '_analyze_entropy_for_packing', return_value=False):
            result = self.analyzer._detect_packing('test.exe')
            assert result is False

    def test_analyze_obfuscation_high(self):
        """Test high obfuscation detection"""
        strings = ['obfuscated', 'encrypted', 'packed']

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._analyze_obfuscation('test.exe')
            assert result == 'High'

    def test_analyze_obfuscation_medium(self):
        """Test medium obfuscation detection"""
        strings = ['xor', 'base64', 'encoded']

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._analyze_obfuscation('test.exe')
            assert result == 'Medium'

    def test_analyze_obfuscation_none(self):
        """Test no obfuscation detection"""
        strings = ['normal', 'string', 'content']

        with patch.object(self.analyzer, '_extract_strings', return_value=strings):
            result = self.analyzer._analyze_obfuscation('test.exe')
            assert result == 'None'

    def test_calculate_analysis_confidence(self):
        """Test analysis confidence calculation"""
        confidence = self.analyzer._calculate_analysis_confidence(
            framework_version='4.8',
            gui_framework='Windows Forms',
            business_logic={'application_domain': 'security', 'data_flows': [], 'file_operations': []}
        )

        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.5  # Should be high with good data

    def test_calculate_analysis_confidence_unknown(self):
        """Test analysis confidence calculation with unknown data"""
        confidence = self.analyzer._calculate_analysis_confidence(
            framework_version='Unknown',
            gui_framework='Unknown',
            business_logic={'application_domain': 'Unknown'}
        )

        assert 0.0 <= confidence <= 1.0
        assert confidence < 0.5  # Should be low with unknown data
