"""
Unit tests for ImportAnalyzer
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.pe.import_analyzer import (
    ImportAnalyzer, ImportAnalysis, APIInfo, APICategory, SuspiciousLevel
)


class TestImportAnalyzer:
    """Test cases for ImportAnalyzer"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.analyzer = ImportAnalyzer()

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test ImportAnalyzer initialization"""
        assert self.analyzer is not None
        assert hasattr(self.analyzer, 'logger')
        assert hasattr(self.analyzer, 'api_database')
        assert hasattr(self.analyzer, 'suspicious_patterns')
        assert hasattr(self.analyzer, 'behavioral_indicators')

    @patch('src.reveng.pe.import_analyzer.ImportAnalyzer._parse_import_table')
    @patch('src.reveng.pe.import_analyzer.ImportAnalyzer._extract_dlls')
    @patch('src.reveng.pe.import_analyzer.ImportAnalyzer._extract_api_calls')
    @patch('src.reveng.pe.import_analyzer.ImportAnalyzer._categorize_apis')
    @patch('src.reveng.pe.import_analyzer.ImportAnalyzer._detect_suspicious_apis')
    @patch('src.reveng.pe.import_analyzer.ImportAnalyzer._analyze_behavioral_indicators')
    def test_analyze_imports_success(self, mock_behavioral, mock_suspicious, mock_categorize,
                                    mock_api_calls, mock_dlls, mock_import_table):
        """Test successful import analysis"""
        # Setup mocks
        mock_import_table.return_value = {'pe_header': {}, 'import_table': {}, 'import_descriptors': []}
        mock_dlls.return_value = ['kernel32.dll', 'user32.dll']
        mock_api_calls.return_value = [
            APIInfo(name='CreateFile', dll='kernel32.dll', category=APICategory.FILE_IO,
                   suspicious_level=SuspiciousLevel.SAFE, description='Create file'),
            APIInfo(name='MessageBox', dll='user32.dll', category=APICategory.GUI,
                   suspicious_level=SuspiciousLevel.SAFE, description='Show message box')
        ]
        mock_categorize.return_value = {
            APICategory.FILE_IO: [APIInfo(name='CreateFile', dll='kernel32.dll', category=APICategory.FILE_IO,
                                        suspicious_level=SuspiciousLevel.SAFE, description='Create file')],
            APICategory.GUI: [APIInfo(name='MessageBox', dll='user32.dll', category=APICategory.GUI,
                                    suspicious_level=SuspiciousLevel.SAFE, description='Show message box')]
        }
        mock_suspicious.return_value = []
        mock_behavioral.return_value = {
            'file_operations': ['CreateFile'],
            'gui_operations': ['MessageBox']
        }

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Run analysis
        result = self.analyzer.analyze_imports(str(test_binary))

        # Verify result
        assert isinstance(result, ImportAnalysis)
        assert result.dlls == ['kernel32.dll', 'user32.dll']
        assert len(result.api_calls) == 2
        assert len(result.suspicious_apis) == 0
        assert APICategory.FILE_IO in result.api_categories
        assert APICategory.GUI in result.api_categories
        assert result.risk_score >= 0.0
        assert result.analysis_confidence >= 0.0

    def test_analyze_imports_failure(self):
        """Test import analysis failure"""
        # Create non-existent binary
        test_binary = self.temp_dir / 'nonexistent.exe'

        with pytest.raises(Exception):
            self.analyzer.analyze_imports(str(test_binary))

    def test_create_api_info_known(self):
        """Test creating API info for known API"""
        with patch.object(self.analyzer, 'api_database', {
            'kernel32.dll.CreateFile': {
                'category': 'file_io',
                'suspicious_level': 'safe',
                'description': 'Create file',
                'usage_context': 'File operations'
            }
        }):
            result = self.analyzer._create_api_info('CreateFile', 'kernel32.dll')

            assert result is not None
            assert result.name == 'CreateFile'
            assert result.dll == 'kernel32.dll'
            assert result.category == APICategory.FILE_IO
            assert result.suspicious_level == SuspiciousLevel.SAFE
            assert result.description == 'Create file'

    def test_create_api_info_unknown(self):
        """Test creating API info for unknown API"""
        with patch.object(self.analyzer, 'api_database', {}):
            result = self.analyzer._create_api_info('UnknownAPI', 'unknown.dll')

            assert result is not None
            assert result.name == 'UnknownAPI'
            assert result.dll == 'unknown.dll'
            assert result.category == APICategory.UNKNOWN
            assert result.suspicious_level == SuspiciousLevel.SAFE
            assert result.description == 'Unknown API'

    def test_determine_api_category_file_io(self):
        """Test API category determination for file I/O"""
        api = APIInfo(name='CreateFile', dll='kernel32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.FILE_IO

    def test_determine_api_category_network(self):
        """Test API category determination for network"""
        api = APIInfo(name='socket', dll='ws2_32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.NETWORK

    def test_determine_api_category_process(self):
        """Test API category determination for process"""
        api = APIInfo(name='CreateProcess', dll='kernel32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.PROCESS

    def test_determine_api_category_registry(self):
        """Test API category determination for registry"""
        api = APIInfo(name='RegOpenKey', dll='advapi32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.REGISTRY

    def test_determine_api_category_crypto(self):
        """Test API category determination for crypto"""
        api = APIInfo(name='CryptEncrypt', dll='advapi32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.CRYPTO

    def test_determine_api_category_gui(self):
        """Test API category determination for GUI"""
        api = APIInfo(name='CreateWindow', dll='user32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.GUI

    def test_determine_api_category_memory(self):
        """Test API category determination for memory"""
        api = APIInfo(name='VirtualAlloc', dll='kernel32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.MEMORY

    def test_determine_api_category_system(self):
        """Test API category determination for system"""
        api = APIInfo(name='GetSystemInfo', dll='kernel32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.SYSTEM

    def test_determine_api_category_unknown(self):
        """Test API category determination for unknown"""
        api = APIInfo(name='UnknownAPI', dll='unknown.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._determine_api_category(api)
        assert result == APICategory.UNKNOWN

    def test_assess_api_suspiciousness_critical(self):
        """Test API suspiciousness assessment for critical"""
        api = APIInfo(name='inject', dll='malware.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._assess_api_suspiciousness(api)
        assert result == SuspiciousLevel.CRITICAL

    def test_assess_api_suspiciousness_high(self):
        """Test API suspiciousness assessment for high"""
        api = APIInfo(name='bypass', dll='malware.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._assess_api_suspiciousness(api)
        assert result == SuspiciousLevel.HIGH

    def test_assess_api_suspiciousness_medium(self):
        """Test API suspiciousness assessment for medium"""
        api = APIInfo(name='keylog', dll='malware.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._assess_api_suspiciousness(api)
        assert result == SuspiciousLevel.MEDIUM

    def test_assess_api_suspiciousness_low(self):
        """Test API suspiciousness assessment for low"""
        api = APIInfo(name='socket', dll='ws2_32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._assess_api_suspiciousness(api)
        assert result == SuspiciousLevel.LOW

    def test_assess_api_suspiciousness_safe(self):
        """Test API suspiciousness assessment for safe"""
        api = APIInfo(name='GetSystemInfo', dll='kernel32.dll', category=APICategory.UNKNOWN,
                     suspicious_level=SuspiciousLevel.SAFE, description='')

        result = self.analyzer._assess_api_suspiciousness(api)
        assert result == SuspiciousLevel.SAFE

    def test_calculate_risk_score(self):
        """Test risk score calculation"""
        suspicious_apis = [
            APIInfo(name='inject', dll='malware.dll', category=APICategory.UNKNOWN,
                   suspicious_level=SuspiciousLevel.CRITICAL, description=''),
            APIInfo(name='bypass', dll='malware.dll', category=APICategory.UNKNOWN,
                   suspicious_level=SuspiciousLevel.HIGH, description='')
        ]

        behavioral_indicators = {
            'malware': ['inject', 'bypass'],
            'network': ['socket']
        }

        risk_score = self.analyzer._calculate_risk_score(suspicious_apis, behavioral_indicators)
        assert 0.0 <= risk_score <= 1.0
        assert risk_score > 0.5  # Should be high with critical and high suspicious APIs

    def test_calculate_risk_score_safe(self):
        """Test risk score calculation for safe APIs"""
        suspicious_apis = [
            APIInfo(name='CreateFile', dll='kernel32.dll', category=APICategory.FILE_IO,
                   suspicious_level=SuspiciousLevel.SAFE, description='')
        ]

        behavioral_indicators = {
            'file_operations': ['CreateFile']
        }

        risk_score = self.analyzer._calculate_risk_score(suspicious_apis, behavioral_indicators)
        assert 0.0 <= risk_score <= 1.0
        assert risk_score < 0.5  # Should be low with safe APIs

    def test_calculate_analysis_confidence(self):
        """Test analysis confidence calculation"""
        api_calls = [
            APIInfo(name='CreateFile', dll='kernel32.dll', category=APICategory.FILE_IO,
                   suspicious_level=SuspiciousLevel.SAFE, description=''),
            APIInfo(name='MessageBox', dll='user32.dll', category=APICategory.GUI,
                   suspicious_level=SuspiciousLevel.SAFE, description='')
        ]

        categorized_apis = {
            APICategory.FILE_IO: [api_calls[0]],
            APICategory.GUI: [api_calls[1]]
        }

        confidence = self.analyzer._calculate_analysis_confidence(api_calls, categorized_apis)
        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.5  # Should be high with good data

    def test_calculate_analysis_confidence_empty(self):
        """Test analysis confidence calculation with empty data"""
        api_calls = []
        categorized_apis = {}

        confidence = self.analyzer._calculate_analysis_confidence(api_calls, categorized_apis)
        assert 0.0 <= confidence <= 1.0
        assert confidence < 0.5  # Should be low with empty data

    def test_parse_pe_header_valid(self):
        """Test parsing valid PE header"""
        pe_data = b'MZ\x90\x00' + b'\x00' * 60 + b'PE\x00\x00' + b'\x00' * 1000

        result = self.analyzer._parse_pe_header(pe_data)
        assert result is not None
        assert 'pe_offset' in result
        assert 'coff_header' in result
        assert 'optional_header' in result

    def test_parse_pe_header_invalid(self):
        """Test parsing invalid PE header"""
        pe_data = b'INVALID' + b'\x00' * 1000

        result = self.analyzer._parse_pe_header(pe_data)
        assert result is None

    def test_find_import_table(self):
        """Test finding import table"""
        pe_header = {
            'pe_offset': 100,
            'coff_header': (0, 0, 0, 0, 0, 0),
            'optional_header': b'\x00' * 100
        }

        pe_data = b'MZ\x90\x00' + b'\x00' * 1000

        result = self.analyzer._find_import_table(pe_data, pe_header)
        assert result is not None
        assert 'rva' in result
        assert 'size' in result

    def test_parse_import_descriptors(self):
        """Test parsing import descriptors"""
        import_table = {'rva': 100, 'size': 200}
        pe_data = b'MZ\x90\x00' + b'\x00' * 1000

        result = self.analyzer._parse_import_descriptors(pe_data, import_table)
        assert isinstance(result, list)

    def test_load_api_database(self):
        """Test loading API database"""
        database = self.analyzer._load_api_database()
        assert isinstance(database, dict)
        assert 'kernel32.dll.CreateFile' in database
        assert 'user32.dll.MessageBox' in database
        assert 'ws2_32.dll.socket' in database

    def test_load_suspicious_patterns(self):
        """Test loading suspicious patterns"""
        patterns = self.analyzer._load_suspicious_patterns()
        assert isinstance(patterns, dict)
        assert 'malware' in patterns
        assert 'network' in patterns
        assert 'file_operations' in patterns

    def test_load_behavioral_indicators(self):
        """Test loading behavioral indicators"""
        indicators = self.analyzer._load_behavioral_indicators()
        assert isinstance(indicators, list)
        assert len(indicators) > 0
        assert all(hasattr(indicator, 'category') for indicator in indicators)
        assert all(hasattr(indicator, 'apis') for indicator in indicators)
