"""
Unit tests for PEResourceExtractor
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.pe.resource_extractor import (
    PEResourceExtractor, ResourceCollection, IconResource, StringResource,
    ManifestResource, VersionResource, CustomResource
)


class TestPEResourceExtractor:
    """Test cases for PEResourceExtractor"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.extractor = PEResourceExtractor()

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test PEResourceExtractor initialization"""
        assert self.extractor is not None
        assert hasattr(self.extractor, 'logger')
        assert hasattr(self.extractor, 'temp_dir')

    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor.extract_icons')
    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor.extract_bitmaps')
    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor.extract_string_table')
    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor.extract_manifests')
    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor.extract_version_info')
    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor.extract_custom_resources')
    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor.detect_embedded_files')
    def test_extract_all_resources_success(self, mock_embedded, mock_custom, mock_version,
                                          mock_manifests, mock_strings, mock_bitmaps, mock_icons):
        """Test successful resource extraction"""
        # Setup mocks
        mock_icons.return_value = [
            IconResource(id='1', size=(16, 16), format='ICO', data=b'icon_data', file_path='icon.ico')
        ]
        mock_bitmaps.return_value = [
            IconResource(id='2', size=(32, 32), format='BMP', data=b'bitmap_data', file_path='bitmap.bmp')
        ]
        mock_strings.return_value = [
            StringResource(id='1', language='en', value='Test String', encoding='utf-8')
        ]
        mock_manifests.return_value = [
            ManifestResource(id='1', content='<manifest>', version='1.0', dependencies=[], capabilities=[])
        ]
        mock_version.return_value = VersionResource(
            file_version='1.0.0.0',
            product_version='1.0.0.0',
            company_name='Test Company',
            product_name='Test Product',
            file_description='Test Description',
            legal_copyright='Copyright Test',
            legal_trademarks='Trademark Test'
        )
        mock_custom.return_value = [
            CustomResource(id='1', type='CUSTOM', data=b'custom_data', size=100, file_path='custom.bin')
        ]
        mock_embedded.return_value = [
            CustomResource(id='2', type='EMBEDDED', data=b'embedded_data', size=200, file_path='embedded.exe')
        ]

        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Run extraction
        result = self.extractor.extract_all_resources(str(test_binary))

        # Verify result
        assert isinstance(result, ResourceCollection)
        assert len(result.icons) == 1
        assert len(result.bitmaps) == 1
        assert len(result.strings) == 1
        assert len(result.manifests) == 1
        assert result.version_info is not None
        assert len(result.custom_resources) == 1
        assert len(result.embedded_files) == 1

    def test_extract_all_resources_failure(self):
        """Test resource extraction failure"""
        # Create non-existent binary
        test_binary = self.temp_dir / 'nonexistent.exe'

        with pytest.raises(Exception):
            self.extractor.extract_all_resources(str(test_binary))

    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor._get_resource_hacker_path')
    def test_extract_icons_with_rh(self, mock_rh_path):
        """Test icon extraction with Resource Hacker"""
        mock_rh_path.return_value = '/path/to/ResourceHacker.exe'

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout='Success')

            with patch.object(self.extractor, '_parse_extracted_icons') as mock_parse:
                mock_parse.return_value = [
                    IconResource(id='1', size=(16, 16), format='ICO', data=b'icon_data')
                ]

                result = self.extractor.extract_icons('test.exe')
                assert len(result) == 1
                assert result[0].id == '1'

    def test_extract_icons_manual(self):
        """Test manual icon extraction"""
        with patch.object(self.extractor, '_get_resource_hacker_path', return_value=None):
            with patch.object(self.extractor, '_extract_icons_manual') as mock_manual:
                mock_manual.return_value = [
                    IconResource(id='1', size=(16, 16), format='ICO', data=b'icon_data')
                ]

                result = self.extractor.extract_icons('test.exe')
                assert len(result) == 1
                assert result[0].id == '1'

    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor._get_resource_hacker_path')
    def test_extract_strings_with_rh(self, mock_rh_path):
        """Test string extraction with Resource Hacker"""
        mock_rh_path.return_value = '/path/to/ResourceHacker.exe'

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout='Success')

            with patch.object(self.extractor, '_parse_extracted_strings') as mock_parse:
                mock_parse.return_value = [
                    StringResource(id='1', language='en', value='Test String')
                ]

                result = self.extractor.extract_string_table('test.exe')
                assert len(result) == 1
                assert result[0].value == 'Test String'

    def test_extract_strings_manual(self):
        """Test manual string extraction"""
        with patch.object(self.extractor, '_get_resource_hacker_path', return_value=None):
            with patch.object(self.extractor, '_extract_strings_manual') as mock_manual:
                mock_manual.return_value = [
                    StringResource(id='1', language='en', value='Test String')
                ]

                result = self.extractor.extract_string_table('test.exe')
                assert len(result) == 1
                assert result[0].value == 'Test String'

    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor._get_resource_hacker_path')
    def test_extract_manifests_with_rh(self, mock_rh_path):
        """Test manifest extraction with Resource Hacker"""
        mock_rh_path.return_value = '/path/to/ResourceHacker.exe'

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout='Success')

            with patch.object(self.extractor, '_parse_extracted_manifests') as mock_parse:
                mock_parse.return_value = [
                    ManifestResource(id='1', content='<manifest>', version='1.0', dependencies=[], capabilities=[])
                ]

                result = self.extractor.extract_manifests('test.exe')
                assert len(result) == 1
                assert result[0].content == '<manifest>'

    def test_extract_manifests_manual(self):
        """Test manual manifest extraction"""
        with patch.object(self.extractor, '_get_resource_hacker_path', return_value=None):
            with patch.object(self.extractor, '_extract_manifests_manual') as mock_manual:
                mock_manual.return_value = [
                    ManifestResource(id='1', content='<manifest>', version='1.0', dependencies=[], capabilities=[])
                ]

                result = self.extractor.extract_manifests('test.exe')
                assert len(result) == 1
                assert result[0].content == '<manifest>'

    @patch('src.reveng.pe.resource_extractor.PEResourceExtractor._get_resource_hacker_path')
    def test_extract_version_info_with_rh(self, mock_rh_path):
        """Test version info extraction with Resource Hacker"""
        mock_rh_path.return_value = '/path/to/ResourceHacker.exe'

        with patch('subprocess.run') as mock_run:
            mock_run.return_value = Mock(returncode=0, stdout='Success')

            with patch.object(self.extractor, '_parse_extracted_version') as mock_parse:
                mock_parse.return_value = VersionResource(
                    file_version='1.0.0.0',
                    product_version='1.0.0.0',
                    company_name='Test Company',
                    product_name='Test Product',
                    file_description='Test Description',
                    legal_copyright='Copyright Test',
                    legal_trademarks='Trademark Test'
                )

                result = self.extractor.extract_version_info('test.exe')
                assert result is not None
                assert result.file_version == '1.0.0.0'
                assert result.company_name == 'Test Company'

    def test_extract_version_info_manual(self):
        """Test manual version info extraction"""
        with patch.object(self.extractor, '_get_resource_hacker_path', return_value=None):
            with patch.object(self.extractor, '_extract_version_manual') as mock_manual:
                mock_manual.return_value = VersionResource(
                    file_version='1.0.0.0',
                    product_version='1.0.0.0',
                    company_name='Test Company',
                    product_name='Test Product',
                    file_description='Test Description',
                    legal_copyright='Copyright Test',
                    legal_trademarks='Trademark Test'
                )

                result = self.extractor.extract_version_info('test.exe')
                assert result is not None
                assert result.file_version == '1.0.0.0'
                assert result.company_name == 'Test Company'

    def test_detect_embedded_files(self):
        """Test embedded file detection"""
        with patch.object(self.extractor, '_analyze_resources_for_embedded_files') as mock_analyze:
            mock_analyze.return_value = [
                CustomResource(id='1', type='EMBEDDED', data=b'embedded_data', size=100, file_path='embedded.exe')
            ]

            result = self.extractor.detect_embedded_files('test.exe')
            assert len(result) == 1
            assert result[0].type == 'EMBEDDED'
            assert result[0].file_path == 'embedded.exe'

    def test_find_resource_section(self):
        """Test finding resource section in PE file"""
        # Create test PE data
        pe_data = b'MZ\x90\x00' + b'\x00' * 100 + b'.rsrc' + b'\x00' * 1000

        with patch('builtins.open', mock_open(read_data=pe_data)):
            result = self.extractor._find_resource_section(pe_data)
            assert result is not None
            assert result[0] > 0
            assert result[1] > 0

    def test_find_resource_section_not_found(self):
        """Test finding resource section when not found"""
        # Create test PE data without resource section
        pe_data = b'MZ\x90\x00' + b'\x00' * 1000

        result = self.extractor._find_resource_section(pe_data)
        assert result is None

    def test_parse_icon_resources(self):
        """Test parsing icon resources from resource section"""
        pe_data = b'MZ\x90\x00' + b'\x00' * 1000
        resource_section = (100, 500)

        with patch.object(self.extractor, '_parse_icon_resources') as mock_parse:
            mock_parse.return_value = [
                IconResource(id='1', size=(16, 16), format='ICO', data=b'icon_data')
            ]

            result = self.extractor._parse_icon_resources(pe_data, resource_section)
            assert len(result) == 1
            assert result[0].id == '1'

    def test_parse_string_resources(self):
        """Test parsing string resources from resource section"""
        pe_data = b'MZ\x90\x00' + b'\x00' * 1000
        resource_section = (100, 500)

        with patch.object(self.extractor, '_parse_string_resources') as mock_parse:
            mock_parse.return_value = [
                StringResource(id='1', language='en', value='Test String')
            ]

            result = self.extractor._parse_string_resources(pe_data, resource_section)
            assert len(result) == 1
            assert result[0].value == 'Test String'

    def test_parse_manifest_resources(self):
        """Test parsing manifest resources from resource section"""
        pe_data = b'MZ\x90\x00' + b'\x00' * 1000
        resource_section = (100, 500)

        with patch.object(self.extractor, '_parse_manifest_resources') as mock_parse:
            mock_parse.return_value = [
                ManifestResource(id='1', content='<manifest>', version='1.0', dependencies=[], capabilities=[])
            ]

            result = self.extractor._parse_manifest_resources(pe_data, resource_section)
            assert len(result) == 1
            assert result[0].content == '<manifest>'

    def test_parse_version_resources(self):
        """Test parsing version resources from resource section"""
        pe_data = b'MZ\x90\x00' + b'\x00' * 1000
        resource_section = (100, 500)

        with patch.object(self.extractor, '_parse_version_resources') as mock_parse:
            mock_parse.return_value = VersionResource(
                file_version='1.0.0.0',
                product_version='1.0.0.0',
                company_name='Test Company',
                product_name='Test Product',
                file_description='Test Description',
                legal_copyright='Copyright Test',
                legal_trademarks='Trademark Test'
            )

            result = self.extractor._parse_version_resources(pe_data, resource_section)
            assert result is not None
            assert result.file_version == '1.0.0.0'
            assert result.company_name == 'Test Company'

    def test_parse_custom_resources(self):
        """Test parsing custom resources from resource section"""
        pe_data = b'MZ\x90\x00' + b'\x00' * 1000
        resource_section = (100, 500)

        with patch.object(self.extractor, '_parse_custom_resources') as mock_parse:
            mock_parse.return_value = [
                CustomResource(id='1', type='CUSTOM', data=b'custom_data', size=100)
            ]

            result = self.extractor._parse_custom_resources(pe_data, resource_section)
            assert len(result) == 1
            assert result[0].type == 'CUSTOM'
            assert result[0].data == b'custom_data'
