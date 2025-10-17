"""
Unit tests for BusinessLogicExtractor
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.analyzers.business_logic_extractor import (
    BusinessLogicExtractor, BusinessLogicAnalysis, ApplicationDomain, DataFlowType
)


class TestBusinessLogicExtractor:
    """Test cases for BusinessLogicExtractor"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.extractor = BusinessLogicExtractor()

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test BusinessLogicExtractor initialization"""
        assert self.extractor is not None
        assert hasattr(self.extractor, 'logger')
        assert hasattr(self.extractor, 'domain_indicators')
        assert hasattr(self.extractor, 'data_flow_patterns')
        assert hasattr(self.extractor, 'file_operation_patterns')
        assert hasattr(self.extractor, 'report_indicators')

    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._extract_strings')
    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._classify_application_domain')
    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._extract_data_flows')
    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._extract_file_operations')
    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._detect_report_generation')
    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._extract_network_operations')
    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._extract_database_operations')
    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._extract_security_features')
    @patch('src.reveng.analyzers.business_logic_extractor.BusinessLogicExtractor._analyze_behavioral_patterns')
    def test_analyze_application_domain_success(self, mock_behavioral, mock_security, mock_database,
                                             mock_network, mock_report, mock_file_ops, mock_data_flows,
                                             mock_domain, mock_strings):
        """Test successful application domain analysis"""
        # Setup mocks
        mock_strings.return_value = ['vulnerability', 'security', 'scan', 'report', 'excel']
        mock_domain.return_value = 'security'
        mock_data_flows.return_value = [
            Mock(source='Nessus XML', destination='Excel Report', flow_type=DataFlowType.PROCESSING,
                data_format='XML to XLSX', description='Nessus to Excel', confidence=0.9)
        ]
        mock_file_ops.return_value = [
            Mock(operation_type='read', file_extension='.nessus', file_path_pattern='*.nessus',
                description='Read Nessus files', frequency=1)
        ]
        mock_report.return_value = Mock(
            report_type='Excel Report',
            output_format='XLSX',
            template_indicators=['template', 'format'],
            data_sources=['nessus', 'vulnerability'],
            confidence=0.9
        )
        mock_network.return_value = ['https://example.com', '192.168.1.1']
        mock_database.return_value = ['sql', 'select', 'query']
        mock_security.return_value = ['encrypt', 'ssl', 'authentication']
        mock_behavioral.return_value = {
            'file_operations': ['CreateFile', 'ReadFile'],
            'network_operations': ['socket', 'connect'],
            'registry_operations': ['RegOpenKey'],
            'process_operations': ['CreateProcess'],
            'gui_operations': ['CreateWindow']
        }

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Run analysis
        result = self.extractor.analyze_application_domain(str(test_binary))

        # Verify result
        assert isinstance(result, BusinessLogicAnalysis)
        assert result.application_domain == 'security'
        assert len(result.data_flows) == 1
        assert len(result.file_operations) == 1
        assert result.report_generation is not None
        assert len(result.network_operations) == 2
        assert len(result.database_operations) == 3
        assert len(result.security_features) == 3
        assert len(result.behavioral_patterns) == 5
        assert result.confidence_score >= 0.0

    def test_analyze_application_domain_failure(self):
        """Test application domain analysis failure"""
        # Create non-existent binary
        test_binary = self.temp_dir / 'nonexistent.exe'

        with pytest.raises(Exception):
            self.extractor.analyze_application_domain(str(test_binary))

    def test_extract_strings(self):
        """Test string extraction from binary"""
        # Create test binary with strings
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'vulnerability\x00' + b'security\x00' + b'scan\x00' + b'\x00' * 1000)

        strings = self.extractor._extract_strings(str(test_binary))
        assert 'vulnerability' in strings
        assert 'security' in strings
        assert 'scan' in strings

    def test_classify_application_domain_security(self):
        """Test application domain classification for security"""
        strings = ['vulnerability', 'security', 'scan', 'audit', 'malware', 'firewall']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'security'

    def test_classify_application_domain_reporting(self):
        """Test application domain classification for reporting"""
        strings = ['report', 'export', 'generate', 'template', 'excel', 'pdf']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'reporting'

    def test_classify_application_domain_database(self):
        """Test application domain classification for database"""
        strings = ['database', 'sql', 'query', 'table', 'select', 'insert']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'database'

    def test_classify_application_domain_web_service(self):
        """Test application domain classification for web service"""
        strings = ['http', 'https', 'api', 'rest', 'web', 'server']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'web_service'

    def test_classify_application_domain_malware(self):
        """Test application domain classification for malware"""
        strings = ['inject', 'hook', 'steal', 'persist', 'hide', 'bypass']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'malware'

    def test_classify_application_domain_utility(self):
        """Test application domain classification for utility"""
        strings = ['utility', 'tool', 'helper', 'converter', 'formatter']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'utility'

    def test_classify_application_domain_game(self):
        """Test application domain classification for game"""
        strings = ['game', 'player', 'score', 'level', 'character', 'graphics']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'game'

    def test_classify_application_domain_media(self):
        """Test application domain classification for media"""
        strings = ['media', 'video', 'audio', 'image', 'player', 'editor']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'media'

    def test_classify_application_domain_unknown(self):
        """Test application domain classification for unknown"""
        strings = ['random', 'unknown', 'miscellaneous']

        result = self.extractor._classify_application_domain(strings)
        assert result == 'unknown'

    def test_extract_data_flows(self):
        """Test data flow extraction"""
        strings = ['nessus', 'xlsx', 'xml', 'pdf', 'csv', 'json']

        result = self.extractor._extract_data_flows(strings)
        assert len(result) > 0
        assert all(hasattr(flow, 'source') for flow in result)
        assert all(hasattr(flow, 'destination') for flow in result)
        assert all(hasattr(flow, 'flow_type') for flow in result)

    def test_extract_file_operations(self):
        """Test file operation extraction"""
        strings = ['nessus', 'xlsx', 'pdf', 'csv', 'json']

        result = self.extractor._extract_file_operations(strings)
        assert len(result) > 0
        assert all(hasattr(op, 'operation_type') for op in result)
        assert all(hasattr(op, 'file_extension') for op in result)
        assert all(hasattr(op, 'file_path_pattern') for op in result)

    def test_detect_report_generation_excel(self):
        """Test report generation detection for Excel"""
        strings = ['excel', 'report', 'template', 'format']

        result = self.extractor._detect_report_generation(strings)
        assert result is not None
        assert result.report_type == 'Excel Report'
        assert result.output_format == 'XLSX'
        assert result.confidence > 0.0

    def test_detect_report_generation_pdf(self):
        """Test report generation detection for PDF"""
        strings = ['pdf', 'report', 'template', 'format']

        result = self.extractor._detect_report_generation(strings)
        assert result is not None
        assert result.report_type == 'PDF Report'
        assert result.output_format == 'PDF'
        assert result.confidence > 0.0

    def test_detect_report_generation_html(self):
        """Test report generation detection for HTML"""
        strings = ['html', 'report', 'template', 'format']

        result = self.extractor._detect_report_generation(strings)
        assert result is not None
        assert result.report_type == 'HTML Report'
        assert result.output_format == 'HTML'
        assert result.confidence > 0.0

    def test_detect_report_generation_none(self):
        """Test report generation detection when none found"""
        strings = ['random', 'unknown', 'miscellaneous']

        result = self.extractor._detect_report_generation(strings)
        assert result is None

    def test_extract_network_operations(self):
        """Test network operations extraction"""
        strings = ['https://example.com', 'ftp://server.com', '192.168.1.1', 'domain.com', 'user@email.com']

        result = self.extractor._extract_network_operations(strings)
        assert len(result) > 0
        assert 'https://example.com' in result
        assert 'ftp://server.com' in result
        assert '192.168.1.1' in result
        assert 'domain.com' in result
        assert 'user@email.com' in result

    def test_extract_database_operations(self):
        """Test database operations extraction"""
        strings = ['sql', 'select', 'insert', 'update', 'delete', 'database', 'table', 'query']

        result = self.extractor._extract_database_operations(strings)
        assert len(result) > 0
        assert 'sql' in result
        assert 'select' in result
        assert 'insert' in result
        assert 'update' in result
        assert 'delete' in result
        assert 'database' in result
        assert 'table' in result
        assert 'query' in result

    def test_extract_security_features(self):
        """Test security features extraction"""
        strings = ['encrypt', 'decrypt', 'hash', 'signature', 'certificate', 'ssl', 'tls', 'authentication']

        result = self.extractor._extract_security_features(strings)
        assert len(result) > 0
        assert 'encrypt' in result
        assert 'decrypt' in result
        assert 'hash' in result
        assert 'signature' in result
        assert 'certificate' in result
        assert 'ssl' in result
        assert 'tls' in result
        assert 'authentication' in result

    def test_analyze_behavioral_patterns(self):
        """Test behavioral patterns analysis"""
        strings = ['CreateFile', 'ReadFile', 'socket', 'connect', 'RegOpenKey', 'CreateProcess', 'CreateWindow']

        result = self.extractor._analyze_behavioral_patterns(strings)
        assert isinstance(result, dict)
        assert 'file_operations' in result
        assert 'network_operations' in result
        assert 'registry_operations' in result
        assert 'process_operations' in result
        assert 'gui_operations' in result

        assert 'CreateFile' in result['file_operations']
        assert 'ReadFile' in result['file_operations']
        assert 'socket' in result['network_operations']
        assert 'connect' in result['network_operations']
        assert 'RegOpenKey' in result['registry_operations']
        assert 'CreateProcess' in result['process_operations']
        assert 'CreateWindow' in result['gui_operations']

    def test_calculate_confidence_score_high(self):
        """Test confidence score calculation with high confidence"""
        domain = 'security'
        data_flows = [Mock()]
        file_operations = [Mock()]
        report_generation = Mock()

        confidence = self.extractor._calculate_confidence_score(
            domain, data_flows, file_operations, report_generation
        )

        assert 0.0 <= confidence <= 1.0
        assert confidence > 0.5  # Should be high with good data

    def test_calculate_confidence_score_low(self):
        """Test confidence score calculation with low confidence"""
        domain = 'unknown'
        data_flows = []
        file_operations = []
        report_generation = None

        confidence = self.extractor._calculate_confidence_score(
            domain, data_flows, file_operations, report_generation
        )

        assert 0.0 <= confidence <= 1.0
        assert confidence < 0.5  # Should be low with poor data

    def test_load_domain_indicators(self):
        """Test loading domain indicators"""
        indicators = self.extractor._load_domain_indicators()
        assert isinstance(indicators, dict)
        assert 'security' in indicators
        assert 'reporting' in indicators
        assert 'database' in indicators
        assert 'web_service' in indicators
        assert 'malware' in indicators
        assert 'utility' in indicators
        assert 'game' in indicators
        assert 'media' in indicators

        # Check that each domain has indicators
        for domain, domain_indicators in indicators.items():
            assert isinstance(domain_indicators, list)
            assert len(domain_indicators) > 0

    def test_load_data_flow_patterns(self):
        """Test loading data flow patterns"""
        patterns = self.extractor._load_data_flow_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 0

        for pattern in patterns:
            assert 'regex' in pattern
            assert 'source' in pattern
            assert 'destination' in pattern
            assert 'flow_type' in pattern
            assert 'data_format' in pattern
            assert 'description' in pattern
            assert 'confidence' in pattern

    def test_load_file_operation_patterns(self):
        """Test loading file operation patterns"""
        patterns = self.extractor._load_file_operation_patterns()
        assert isinstance(patterns, list)
        assert len(patterns) > 0

        for pattern in patterns:
            assert 'regex' in pattern
            assert 'operation_type' in pattern
            assert 'file_extension' in pattern
            assert 'file_path_pattern' in pattern
            assert 'description' in pattern

    def test_load_report_indicators(self):
        """Test loading report indicators"""
        indicators = self.extractor._load_report_indicators()
        assert isinstance(indicators, list)
        assert len(indicators) > 0

        for indicator in indicators:
            assert 'pattern' in indicator
            assert 'report_type' in indicator
            assert 'output_format' in indicator
            assert 'template_indicators' in indicator
            assert 'data_sources' in indicator
            assert 'confidence' in indicator
