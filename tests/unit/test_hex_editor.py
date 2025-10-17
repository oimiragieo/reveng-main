"""
Unit tests for HexEditor
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.reveng.tools.hex_editor import (
    HexEditor, HexView, EntropyRegion, EmbeddedBinary, HexSearchResult
)


class TestHexEditor:
    """Test cases for HexEditor"""

    def setup_method(self):
        """Setup test environment"""
        self.temp_dir = Path(tempfile.mkdtemp())
        self.hex_editor = HexEditor()

    def teardown_method(self):
        """Cleanup test environment"""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_init(self):
        """Test HexEditor initialization"""
        assert self.hex_editor is not None
        assert hasattr(self.hex_editor, 'logger')
        assert hasattr(self.hex_editor, 'viewer')
        assert hasattr(self.hex_editor, 'searcher')
        assert hasattr(self.hex_editor, 'analyzer')

    def test_open_binary_success(self):
        """Test opening binary file successfully"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Open binary
        hex_view = self.hex_editor.open_binary(test_binary)

        assert isinstance(hex_view, HexView)
        assert hex_view.binary_path == test_binary
        assert len(hex_view.content) > 0
        assert hex_view.content.startswith(b'MZ')

    def test_open_binary_failure(self):
        """Test opening non-existent binary file"""
        test_binary = self.temp_dir / 'nonexistent.exe'

        with pytest.raises(FileNotFoundError):
            self.hex_editor.open_binary(test_binary)

    def test_search_pattern_success(self):
        """Test searching for pattern in binary"""
        # Create test binary with pattern
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'pattern\x00' + b'\x00' * 1000)

        # Search for pattern
        results = self.hex_editor.search_pattern(test_binary, b'pattern')

        assert isinstance(results, list)
        assert len(results) > 0
        assert all(isinstance(result, HexSearchResult) for result in results)
        assert all(result.pattern == b'pattern' for result in results)
        assert all(result.offset >= 0 for result in results)
        assert all(result.length == len(b'pattern') for result in results)

    def test_search_pattern_not_found(self):
        """Test searching for pattern that doesn't exist"""
        # Create test binary without pattern
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Search for non-existent pattern
        results = self.hex_editor.search_pattern(test_binary, b'nonexistent')

        assert isinstance(results, list)
        assert len(results) == 0

    def test_search_pattern_multiple_occurrences(self):
        """Test searching for pattern with multiple occurrences"""
        # Create test binary with multiple patterns
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'pattern\x00' + b'\x00' * 100 + b'pattern\x00' + b'\x00' * 1000)

        # Search for pattern
        results = self.hex_editor.search_pattern(test_binary, b'pattern')

        assert isinstance(results, list)
        assert len(results) == 2
        assert all(isinstance(result, HexSearchResult) for result in results)
        assert all(result.pattern == b'pattern' for result in results)
        assert all(result.offset >= 0 for result in results)
        assert all(result.length == len(b'pattern') for result in results)

    def test_extract_region_success(self):
        """Test extracting region from binary"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'data' + b'\x00' * 1000)

        # Extract region
        region_data = self.hex_editor.extract_region(test_binary, 4, 4)

        assert isinstance(region_data, bytes)
        assert region_data == b'data'

    def test_extract_region_out_of_bounds(self):
        """Test extracting region beyond file bounds"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Extract region beyond bounds
        region_data = self.hex_editor.extract_region(test_binary, 10000, 1000)

        assert isinstance(region_data, bytes)
        assert len(region_data) == 0

    def test_analyze_entropy_regions(self):
        """Test entropy analysis of regions"""
        # Create test binary with different entropy regions
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000 + b'random_data' * 100)

        # Analyze entropy
        entropy_regions = self.hex_editor.analyze_entropy_regions(test_binary)

        assert isinstance(entropy_regions, list)
        assert len(entropy_regions) > 0
        assert all(isinstance(region, EntropyRegion) for region in entropy_regions)
        assert all(region.offset >= 0 for region in entropy_regions)
        assert all(region.length > 0 for region in entropy_regions)
        assert all(0.0 <= region.entropy <= 1.0 for region in entropy_regions)

    def test_find_embedded_executables(self):
        """Test finding embedded executables"""
        # Create test binary with embedded PE
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000 + b'MZ\x90\x00' + b'\x00' * 1000)

        # Find embedded executables
        embedded_binaries = self.hex_editor.find_embedded_executables(test_binary)

        assert isinstance(embedded_binaries, list)
        assert len(embedded_binaries) > 0
        assert all(isinstance(binary, EmbeddedBinary) for binary in embedded_binaries)
        assert all(binary.offset >= 0 for binary in embedded_binaries)
        assert all(binary.size > 0 for binary in embedded_binaries)
        assert all(binary.file_type in ['PE', 'ELF', 'Mach-O'] for binary in embedded_binaries)

    def test_find_embedded_executables_none(self):
        """Test finding embedded executables when none exist"""
        # Create test binary without embedded executables
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Find embedded executables
        embedded_binaries = self.hex_editor.find_embedded_executables(test_binary)

        assert isinstance(embedded_binaries, list)
        assert len(embedded_binaries) == 0

    def test_extract_strings_advanced(self):
        """Test advanced string extraction"""
        # Create test binary with strings
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'string1\x00' + b'string2\x00' + b'\x00' * 1000)

        # Extract strings
        strings = self.hex_editor.extract_strings_advanced(test_binary)

        assert isinstance(strings, list)
        assert len(strings) > 0
        assert 'string1' in strings
        assert 'string2' in strings

    def test_extract_strings_advanced_min_length(self):
        """Test advanced string extraction with minimum length"""
        # Create test binary with strings
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'str\x00' + b'string\x00' + b'\x00' * 1000)

        # Extract strings with minimum length
        strings = self.hex_editor.extract_strings_advanced(test_binary, min_length=4)

        assert isinstance(strings, list)
        assert 'string' in strings
        assert 'str' not in strings  # Should be filtered out by min_length

    def test_hex_view_str_representation(self):
        """Test hex view string representation"""
        # Create test binary
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000)

        # Open binary and get string representation
        hex_view = self.hex_editor.open_binary(test_binary)
        hex_str = str(hex_view)

        assert isinstance(hex_str, str)
        assert 'MZ' in hex_str
        assert '00000000:' in hex_str  # Should have hex offset
        assert '4D 5A' in hex_str  # MZ in hex

    def test_entropy_region_properties(self):
        """Test EntropyRegion properties"""
        region = EntropyRegion(offset=100, length=50, entropy=0.8)

        assert region.offset == 100
        assert region.length == 50
        assert region.entropy == 0.8

    def test_embedded_binary_properties(self):
        """Test EmbeddedBinary properties"""
        binary = EmbeddedBinary(offset=200, size=1000, file_type='PE')

        assert binary.offset == 200
        assert binary.size == 1000
        assert binary.file_type == 'PE'

    def test_hex_search_result_properties(self):
        """Test HexSearchResult properties"""
        result = HexSearchResult(pattern=b'test', offset=100, length=4, context=b'context')

        assert result.pattern == b'test'
        assert result.offset == 100
        assert result.length == 4
        assert result.context == b'context'

    def test_hex_editor_with_large_file(self):
        """Test hex editor with large file"""
        # Create large test binary
        test_binary = self.temp_dir / 'large.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'\x00' * 1000000)  # 1MB file

        # Open binary
        hex_view = self.hex_editor.open_binary(test_binary)

        assert isinstance(hex_view, HexView)
        assert hex_view.binary_path == test_binary
        assert len(hex_view.content) == 1000004  # MZ + 1MB

    def test_hex_editor_with_binary_data(self):
        """Test hex editor with binary data"""
        # Create test binary with binary data
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + bytes(range(256)) + b'\x00' * 1000)

        # Open binary
        hex_view = self.hex_editor.open_binary(test_binary)

        assert isinstance(hex_view, HexView)
        assert hex_view.binary_path == test_binary
        assert len(hex_view.content) > 0

    def test_hex_editor_with_unicode_strings(self):
        """Test hex editor with unicode strings"""
        # Create test binary with unicode strings
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + 'unicode_string'.encode('utf-8') + b'\x00' * 1000)

        # Open binary
        hex_view = self.hex_editor.open_binary(test_binary)

        assert isinstance(hex_view, HexView)
        assert hex_view.binary_path == test_binary
        assert len(hex_view.content) > 0

    def test_hex_editor_with_mixed_encoding(self):
        """Test hex editor with mixed encoding"""
        # Create test binary with mixed encoding
        test_binary = self.temp_dir / 'test.exe'
        test_binary.write_bytes(b'MZ\x90\x00' + b'ascii_string\x00' + 'unicode_string'.encode('utf-8') + b'\x00' * 1000)

        # Open binary
        hex_view = self.hex_editor.open_binary(test_binary)

        assert isinstance(hex_view, HexView)
        assert hex_view.binary_path == test_binary
        assert len(hex_view.content) > 0
