"""
REVENG Hex Editor Integration

Low-level binary inspection with pattern matching, entropy analysis,
and embedded file detection.
"""

import os
import sys
import struct
import math
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass
from enum import Enum
import logging
import json
import tempfile

from ..core.errors import AnalysisFailureError, create_error_context
from ..core.logger import get_logger

class EntropyLevel(Enum):
    """Entropy levels"""
    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"

class PatternType(Enum):
    """Pattern types"""
    MAGIC_BYTES = "magic_bytes"
    CRYPTO_CONSTANTS = "crypto_constants"
    NETWORK_INDICATORS = "network_indicators"
    STRING_PATTERNS = "string_patterns"
    CODE_PATTERNS = "code_patterns"

@dataclass
class HexView:
    """Hex view representation"""
    data: bytes
    offset: int
    length: int
    encoding: str = "utf-8"

@dataclass
class EntropyRegion:
    """Entropy region information"""
    start_offset: int
    end_offset: int
    entropy: float
    level: EntropyLevel
    description: str

@dataclass
class PatternMatch:
    """Pattern match information"""
    pattern_type: PatternType
    pattern_name: str
    offset: int
    data: bytes
    description: str
    confidence: float

@dataclass
class EmbeddedBinary:
    """Embedded binary information"""
    offset: int
    size: int
    file_type: str
    magic_bytes: bytes
    description: str
    confidence: float

@dataclass
class HexAnalysis:
    """Hex analysis result"""
    entropy_regions: List[EntropyRegion]
    pattern_matches: List[PatternMatch]
    embedded_binaries: List[EmbeddedBinary]
    strings: List[str]
    analysis_confidence: float

class HexEditor:
    """Integrated hex editor functionality"""

    def __init__(self):
        self.logger = get_logger("hex_editor")
        self.magic_bytes_db = self._load_magic_bytes_database()
        self.crypto_constants_db = self._load_crypto_constants_database()
        self.network_patterns = self._load_network_patterns()
        self.temp_dir = Path(tempfile.gettempdir()) / "reveng_hex"
        self.temp_dir.mkdir(exist_ok=True)

    def open_binary(self, binary_path: str) -> HexView:
        """Open binary in hex view"""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            return HexView(
                data=data,
                offset=0,
                length=len(data),
                encoding="utf-8"
            )

        except Exception as e:
            context = create_error_context(
                "hex_editor",
                "open_binary",
                binary_path=binary_path
            )
            raise AnalysisFailureError(
                "hex_editor_open",
                binary_path,
                context=context,
                original_exception=e
            )

    def search_pattern(self, pattern: bytes, hex_view: HexView) -> List[int]:
        """Search for byte patterns in hex view"""
        try:
            matches = []
            data = hex_view.data
            pattern_len = len(pattern)

            for i in range(len(data) - pattern_len + 1):
                if data[i:i+pattern_len] == pattern:
                    matches.append(i)

            return matches

        except Exception as e:
            self.logger.warning(f"Failed to search pattern: {e}")
            return []

    def extract_region(self, offset: int, length: int, hex_view: HexView) -> bytes:
        """Extract specific byte region"""
        try:
            start = max(0, offset)
            end = min(len(hex_view.data), offset + length)
            return hex_view.data[start:end]

        except Exception as e:
            self.logger.warning(f"Failed to extract region: {e}")
            return b""

    def analyze_entropy_regions(self, hex_view: HexView) -> List[EntropyRegion]:
        """Identify high/low entropy regions"""
        try:
            entropy_regions = []
            data = hex_view.data
            window_size = 1024  # 1KB windows
            step_size = 512     # 512 byte steps

            for i in range(0, len(data) - window_size, step_size):
                window_data = data[i:i + window_size]
                entropy = self._calculate_shannon_entropy(window_data)
                level = self._classify_entropy_level(entropy)

                if level in [EntropyLevel.VERY_LOW, EntropyLevel.VERY_HIGH]:
                    region = EntropyRegion(
                        start_offset=i,
                        end_offset=i + window_size,
                        entropy=entropy,
                        level=level,
                        description=self._describe_entropy_region(entropy, level)
                    )
                    entropy_regions.append(region)

            return entropy_regions

        except Exception as e:
            self.logger.warning(f"Failed to analyze entropy regions: {e}")
            return []

    def find_embedded_executables(self, hex_view: HexView) -> List[EmbeddedBinary]:
        """Find embedded PE/ELF files using magic bytes"""
        try:
            embedded_binaries = []
            data = hex_view.data

            # Search for PE files
            pe_magic = b'MZ'
            pe_matches = self.search_pattern(pe_magic, hex_view)

            for offset in pe_matches:
                # Check if it's a valid PE
                if self._is_valid_pe(data, offset):
                    embedded_binary = EmbeddedBinary(
                        offset=offset,
                        size=self._get_pe_size(data, offset),
                        file_type="PE",
                        magic_bytes=pe_magic,
                        description="Embedded PE executable",
                        confidence=0.9
                    )
                    embedded_binaries.append(embedded_binary)

            # Search for ELF files
            elf_magic = b'\x7fELF'
            elf_matches = self.search_pattern(elf_magic, hex_view)

            for offset in elf_matches:
                if self._is_valid_elf(data, offset):
                    embedded_binary = EmbeddedBinary(
                        offset=offset,
                        size=self._get_elf_size(data, offset),
                        file_type="ELF",
                        magic_bytes=elf_magic,
                        description="Embedded ELF executable",
                        confidence=0.9
                    )
                    embedded_binaries.append(embedded_binary)

            return embedded_binaries

        except Exception as e:
            self.logger.warning(f"Failed to find embedded executables: {e}")
            return []

    def extract_strings_advanced(self, hex_view: HexView, min_length: int = 4) -> List[str]:
        """Advanced string extraction with encoding detection"""
        try:
            strings = []
            data = hex_view.data

            # Extract ASCII strings
            ascii_strings = self._extract_ascii_strings(data, min_length)
            strings.extend(ascii_strings)

            # Extract Unicode strings
            unicode_strings = self._extract_unicode_strings(data, min_length)
            strings.extend(unicode_strings)

            # Extract UTF-8 strings
            utf8_strings = self._extract_utf8_strings(data, min_length)
            strings.extend(utf8_strings)

            return list(set(strings))  # Remove duplicates

        except Exception as e:
            self.logger.warning(f"Failed to extract strings: {e}")
            return []

    def find_magic_bytes(self, hex_view: HexView) -> List[PatternMatch]:
        """Find known file format signatures"""
        try:
            pattern_matches = []
            data = hex_view.data

            for magic_name, magic_bytes in self.magic_bytes_db.items():
                matches = self.search_pattern(magic_bytes, hex_view)
                for offset in matches:
                    pattern_match = PatternMatch(
                        pattern_type=PatternType.MAGIC_BYTES,
                        pattern_name=magic_name,
                        offset=offset,
                        data=magic_bytes,
                        description=f"Found {magic_name} signature",
                        confidence=0.9
                    )
                    pattern_matches.append(pattern_match)

            return pattern_matches

        except Exception as e:
            self.logger.warning(f"Failed to find magic bytes: {e}")
            return []

    def find_crypto_constants(self, hex_view: HexView) -> List[PatternMatch]:
        """Identify cryptographic constants (S-boxes, etc.)"""
        try:
            pattern_matches = []
            data = hex_view.data

            for const_name, const_bytes in self.crypto_constants_db.items():
                matches = self.search_pattern(const_bytes, hex_view)
                for offset in matches:
                    pattern_match = PatternMatch(
                        pattern_type=PatternType.CRYPTO_CONSTANTS,
                        pattern_name=const_name,
                        offset=offset,
                        data=const_bytes,
                        description=f"Found {const_name} cryptographic constant",
                        confidence=0.8
                    )
                    pattern_matches.append(pattern_match)

            return pattern_matches

        except Exception as e:
            self.logger.warning(f"Failed to find crypto constants: {e}")
            return []

    def find_network_indicators(self, hex_view: HexView) -> List[PatternMatch]:
        """Find URLs, IPs, domains in binary"""
        try:
            pattern_matches = []
            data = hex_view.data

            for pattern_name, pattern_regex in self.network_patterns.items():
                import re
                matches = re.finditer(pattern_regex, data)
                for match in matches:
                    pattern_match = PatternMatch(
                        pattern_type=PatternType.NETWORK_INDICATORS,
                        pattern_name=pattern_name,
                        offset=match.start(),
                        data=match.group(),
                        description=f"Found {pattern_name} network indicator",
                        confidence=0.7
                    )
                    pattern_matches.append(pattern_match)

            return pattern_matches

        except Exception as e:
            self.logger.warning(f"Failed to find network indicators: {e}")
            return []

    def analyze_binary(self, binary_path: str) -> HexAnalysis:
        """Comprehensive hex analysis of binary"""
        try:
            self.logger.info(f"Starting hex analysis of {binary_path}")

            # Open binary
            hex_view = self.open_binary(binary_path)

            # Analyze entropy regions
            entropy_regions = self.analyze_entropy_regions(hex_view)

            # Find pattern matches
            magic_bytes = self.find_magic_bytes(hex_view)
            crypto_constants = self.find_crypto_constants(hex_view)
            network_indicators = self.find_network_indicators(hex_view)

            all_patterns = magic_bytes + crypto_constants + network_indicators

            # Find embedded binaries
            embedded_binaries = self.find_embedded_executables(hex_view)

            # Extract strings
            strings = self.extract_strings_advanced(hex_view)

            # Calculate analysis confidence
            confidence = self._calculate_analysis_confidence(
                entropy_regions, all_patterns, embedded_binaries, strings
            )

            result = HexAnalysis(
                entropy_regions=entropy_regions,
                pattern_matches=all_patterns,
                embedded_binaries=embedded_binaries,
                strings=strings,
                analysis_confidence=confidence
            )

            self.logger.info(f"Completed hex analysis with {confidence:.2f} confidence")
            return result

        except Exception as e:
            context = create_error_context(
                "hex_editor",
                "analyze_binary",
                binary_path=binary_path
            )
            raise AnalysisFailureError(
                "hex_analysis",
                binary_path,
                context=context,
                original_exception=e
            )

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        try:
            if not data:
                return 0.0

            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in data:
                byte_counts[byte] += 1

            # Calculate entropy
            entropy = 0.0
            data_len = len(data)
            for count in byte_counts:
                if count > 0:
                    probability = count / data_len
                    entropy -= probability * math.log2(probability)

            return entropy

        except Exception as e:
            self.logger.warning(f"Failed to calculate entropy: {e}")
            return 0.0

    def _classify_entropy_level(self, entropy: float) -> EntropyLevel:
        """Classify entropy level"""
        if entropy < 2.0:
            return EntropyLevel.VERY_LOW
        elif entropy < 4.0:
            return EntropyLevel.LOW
        elif entropy < 6.0:
            return EntropyLevel.MEDIUM
        elif entropy < 7.5:
            return EntropyLevel.HIGH
        else:
            return EntropyLevel.VERY_HIGH

    def _describe_entropy_region(self, entropy: float, level: EntropyLevel) -> str:
        """Describe entropy region"""
        descriptions = {
            EntropyLevel.VERY_LOW: "Very low entropy - likely packed/encrypted data",
            EntropyLevel.LOW: "Low entropy - structured data or text",
            EntropyLevel.MEDIUM: "Medium entropy - mixed data",
            EntropyLevel.HIGH: "High entropy - compressed or random data",
            EntropyLevel.VERY_HIGH: "Very high entropy - encrypted or compressed data"
        }
        return descriptions.get(level, "Unknown entropy level")

    def _is_valid_pe(self, data: bytes, offset: int) -> bool:
        """Check if data at offset is a valid PE file"""
        try:
            # Check DOS header
            if data[offset:offset+2] != b'MZ':
                return False

            # Get PE header offset
            pe_offset = struct.unpack('<L', data[offset+60:offset+64])[0]
            if offset + pe_offset >= len(data):
                return False

            # Check PE signature
            if data[offset+pe_offset:offset+pe_offset+4] != b'PE\x00\x00':
                return False

            return True

        except Exception:
            return False

    def _get_pe_size(self, data: bytes, offset: int) -> int:
        """Get PE file size"""
        try:
            # This is a simplified implementation
            # In practice, you would parse the PE header to get the actual size
            return 1024  # Placeholder

        except Exception:
            return 0

    def _is_valid_elf(self, data: bytes, offset: int) -> bool:
        """Check if data at offset is a valid ELF file"""
        try:
            # Check ELF magic
            if data[offset:offset+4] != b'\x7fELF':
                return False

            # Check ELF class (32-bit or 64-bit)
            if data[offset+4] not in [1, 2]:  # 1 = 32-bit, 2 = 64-bit
                return False

            return True

        except Exception:
            return False

    def _get_elf_size(self, data: bytes, offset: int) -> int:
        """Get ELF file size"""
        try:
            # This is a simplified implementation
            # In practice, you would parse the ELF header to get the actual size
            return 1024  # Placeholder

        except Exception:
            return 0

    def _extract_ascii_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract ASCII strings"""
        try:
            strings = []
            current_string = ""

            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= min_length:
                        strings.append(current_string)
                    current_string = ""

            if len(current_string) >= min_length:
                strings.append(current_string)

            return strings

        except Exception as e:
            self.logger.warning(f"Failed to extract ASCII strings: {e}")
            return []

    def _extract_unicode_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract Unicode strings"""
        try:
            strings = []
            # This is a simplified implementation
            # In practice, you would need to handle different Unicode encodings

            return strings

        except Exception as e:
            self.logger.warning(f"Failed to extract Unicode strings: {e}")
            return []

    def _extract_utf8_strings(self, data: bytes, min_length: int) -> List[str]:
        """Extract UTF-8 strings"""
        try:
            strings = []
            # This is a simplified implementation
            # In practice, you would need to handle UTF-8 encoding properly

            return strings

        except Exception as e:
            self.logger.warning(f"Failed to extract UTF-8 strings: {e}")
            return []

    def _calculate_analysis_confidence(
        self,
        entropy_regions: List[EntropyRegion],
        pattern_matches: List[PatternMatch],
        embedded_binaries: List[EmbeddedBinary],
        strings: List[str]
    ) -> float:
        """Calculate analysis confidence"""
        try:
            confidence = 0.0

            # Base confidence from entropy analysis
            if entropy_regions:
                confidence += 0.3

            # Confidence from pattern matches
            if pattern_matches:
                confidence += 0.3

            # Confidence from embedded binaries
            if embedded_binaries:
                confidence += 0.2

            # Confidence from string extraction
            if strings:
                confidence += 0.2

            return min(confidence, 1.0)

        except Exception as e:
            self.logger.warning(f"Failed to calculate analysis confidence: {e}")
            return 0.0

    # Database loading methods
    def _load_magic_bytes_database(self) -> Dict[str, bytes]:
        """Load magic bytes database"""
        try:
            return {
                'PE': b'MZ',
                'ELF': b'\x7fELF',
                'PDF': b'%PDF',
                'ZIP': b'PK\x03\x04',
                'JPEG': b'\xff\xd8\xff',
                'PNG': b'\x89PNG\r\n\x1a\n',
                'GIF': b'GIF87a',
                'BMP': b'BM',
                'TIFF': b'II*\x00',
                'ICO': b'\x00\x00\x01\x00'
            }

        except Exception as e:
            self.logger.warning(f"Failed to load magic bytes database: {e}")
            return {}

    def _load_crypto_constants_database(self) -> Dict[str, bytes]:
        """Load cryptographic constants database"""
        try:
            return {
                'AES_SBOX': b'\x63\x7c\x77\x7b',  # First 4 bytes of AES S-box
                'DES_SBOX1': b'\x04\x00\x0f\x0a',  # First 4 bytes of DES S-box 1
                'MD5_INIT': b'\x01\x23\x45\x67',   # MD5 initial values
                'SHA1_INIT': b'\x67\x45\x23\x01',  # SHA-1 initial values
                'RC4_SBOX': b'\x01\x02\x03\x04'    # RC4 S-box pattern
            }

        except Exception as e:
            self.logger.warning(f"Failed to load crypto constants database: {e}")
            return {}

    def _load_network_patterns(self) -> Dict[str, bytes]:
        """Load network patterns"""
        try:
            return {
                'HTTP_URL': rb'https?://[^\s]+',
                'FTP_URL': rb'ftp://[^\s]+',
                'IP_ADDRESS': rb'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                'DOMAIN': rb'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
                'EMAIL': rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            }

        except Exception as e:
            self.logger.warning(f"Failed to load network patterns: {e}")
            return {}
