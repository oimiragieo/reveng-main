"""
Firmware Analyzer

Comprehensive firmware extraction, unpacking, and analysis for IoT and
embedded devices.

Based on "The Modern Hacker's Playbook" - Part 4.1: Hardware & Embedded Systems
"""

import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum


class FirmwareType(Enum):
    """Types of firmware"""
    RAW_BINARY = "raw_binary"
    UBI_IMAGE = "ubi"
    SQUASHFS = "squashfs"
    CRAMFS = "cramfs"
    JFFS2 = "jffs2"
    UBOOT = "uboot"
    UNKNOWN = "unknown"


class Architecture(Enum):
    """Supported architectures"""
    ARM = "arm"
    MIPS = "mips"
    X86 = "x86"
    X86_64 = "x86_64"
    XTENSA = "xtensa"
    UNKNOWN = "unknown"


@dataclass
class FirmwareMetadata:
    """Firmware metadata"""
    file_path: str
    file_size: int
    firmware_type: FirmwareType
    architecture: Architecture
    endianness: str  # little, big
    base_address: Optional[int] = None
    entry_point: Optional[int] = None
    version: Optional[str] = None
    vendor: Optional[str] = None


@dataclass
class ExtractedFilesystem:
    """Extracted filesystem information"""
    extraction_path: str
    file_count: int
    directory_count: int
    interesting_files: List[str]
    embedded_keys: List[str]
    hardcoded_credentials: List[Tuple[str, str]]


class FirmwareAnalyzer:
    """
    Advanced firmware analysis engine.

    Capabilities:
    - Firmware type detection
    - Architecture identification
    - Filesystem extraction (squashfs, cramfs, jffs2, etc.)
    - Binary extraction and analysis
    - Credential and key discovery
    - Vulnerability scanning

    Example:
        >>> analyzer = FirmwareAnalyzer()
        >>> metadata = analyzer.analyze("firmware.bin")
        >>> filesystem = analyzer.extract_filesystem("firmware.bin")
        >>> vulns = analyzer.scan_for_vulnerabilities(filesystem)
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

        # Check for required tools
        self.tools = {
            'binwalk': self._check_tool('binwalk'),
            'strings': self._check_tool('strings'),
            'file': self._check_tool('file'),
        }

    def _check_tool(self, tool_name: str) -> bool:
        """Check if a tool is available"""
        try:
            result = subprocess.run(
                ['which', tool_name],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except:
            return False

    def analyze(self, firmware_path: str) -> FirmwareMetadata:
        """
        Analyze firmware file.

        Args:
            firmware_path: Path to firmware file

        Returns:
            FirmwareMetadata
        """
        self.logger.info(f"Analyzing firmware: {firmware_path}")

        if not os.path.exists(firmware_path):
            raise FileNotFoundError(f"Firmware not found: {firmware_path}")

        # Get file size
        file_size = os.path.getsize(firmware_path)

        # Detect firmware type
        fw_type = self._detect_firmware_type(firmware_path)

        # Detect architecture
        arch = self._detect_architecture(firmware_path)

        # Detect endianness
        endianness = self._detect_endianness(firmware_path)

        metadata = FirmwareMetadata(
            file_path=firmware_path,
            file_size=file_size,
            firmware_type=fw_type,
            architecture=arch,
            endianness=endianness
        )

        self.logger.info(f"Type: {fw_type.value}, Arch: {arch.value}, Endian: {endianness}")

        return metadata

    def _detect_firmware_type(self, firmware_path: str) -> FirmwareType:
        """Detect firmware type"""
        try:
            # Read magic bytes
            with open(firmware_path, 'rb') as f:
                magic = f.read(16)

            # Check magic signatures
            if magic.startswith(b'hsqs') or magic.startswith(b'sqsh'):
                return FirmwareType.SQUASHFS
            elif magic.startswith(b'\x45\x3d\xcd\x28'):
                return FirmwareType.CRAMFS
            elif b'UBI#' in magic:
                return FirmwareType.UBI_IMAGE
            elif magic.startswith(b'\x27\x05\x19\x56'):
                return FirmwareType.UBOOT
            elif magic.startswith(b'\x85\x19'):
                return FirmwareType.JFFS2

        except Exception as e:
            self.logger.error(f"Type detection error: {e}")

        return FirmwareType.UNKNOWN

    def _detect_architecture(self, firmware_path: str) -> Architecture:
        """Detect CPU architecture"""
        if not self.tools['strings']:
            return Architecture.UNKNOWN

        try:
            # Use strings to find architecture indicators
            result = subprocess.run(
                ['strings', firmware_path],
                capture_output=True,
                text=True,
                timeout=30
            )

            output = result.stdout.lower()

            # Check for arch-specific strings
            if 'arm' in output or 'cortex' in output:
                return Architecture.ARM
            elif 'mips' in output:
                return Architecture.MIPS
            elif 'xtensa' in output:
                return Architecture.XTENSA
            elif 'x86_64' in output or 'amd64' in output:
                return Architecture.X86_64
            elif 'i386' in output or 'i686' in output:
                return Architecture.X86

        except Exception as e:
            self.logger.error(f"Architecture detection error: {e}")

        return Architecture.UNKNOWN

    def _detect_endianness(self, firmware_path: str) -> str:
        """Detect byte order (endianness)"""
        # Default to little-endian (most common)
        return "little"

    def extract_filesystem(self, firmware_path: str,
                          output_dir: Optional[str] = None) -> Optional[ExtractedFilesystem]:
        """
        Extract filesystem from firmware.

        Args:
            firmware_path: Path to firmware
            output_dir: Output directory (default: temp)

        Returns:
            ExtractedFilesystem or None
        """
        if not self.tools['binwalk']:
            self.logger.error("binwalk not available. Install: sudo apt install binwalk")
            return None

        self.logger.info("Extracting filesystem...")

        if not output_dir:
            output_dir = tempfile.mkdtemp(prefix='firmware_')

        try:
            # Run binwalk to extract
            result = subprocess.run(
                ['binwalk', '-e', '-C', output_dir, firmware_path],
                capture_output=True,
                text=True,
                timeout=300
            )

            if result.returncode != 0:
                self.logger.error(f"Extraction failed: {result.stderr}")
                return None

            # Count extracted files
            file_count = 0
            dir_count = 0

            for root, dirs, files in os.walk(output_dir):
                file_count += len(files)
                dir_count += len(dirs)

            # Find interesting files
            interesting = self._find_interesting_files(output_dir)

            # Search for credentials
            credentials = self._find_credentials(output_dir)

            # Search for crypto keys
            keys = self._find_crypto_keys(output_dir)

            extracted = ExtractedFilesystem(
                extraction_path=output_dir,
                file_count=file_count,
                directory_count=dir_count,
                interesting_files=interesting,
                embedded_keys=keys,
                hardcoded_credentials=credentials
            )

            self.logger.info(f"Extracted {file_count} files to {output_dir}")

            return extracted

        except Exception as e:
            self.logger.error(f"Extraction error: {e}")
            return None

    def _find_interesting_files(self, root_dir: str) -> List[str]:
        """Find interesting files in extracted filesystem"""
        interesting = []

        patterns = [
            '*password*', '*passwd*', '*.key', '*.pem',
            '*credential*', '*secret*', '*.conf', '*.cfg',
            'shadow', 'sshd_config', '.env'
        ]

        for root, dirs, files in os.walk(root_dir):
            for file in files:
                for pattern in patterns:
                    if pattern.strip('*') in file.lower():
                        interesting.append(os.path.join(root, file))
                        break

        return interesting

    def _find_credentials(self, root_dir: str) -> List[Tuple[str, str]]:
        """Search for hardcoded credentials"""
        credentials = []

        # Patterns for credentials
        cred_patterns = [
            (r'username.*=.*[\'"](.*)[\'"]', r'password.*=.*[\'"](.*)[\'"]'),
            (r'user:\s*(\w+)', r'pass:\s*(\w+)'),
        ]

        # Search config files
        for root, dirs, files in os.walk(root_dir):
            for file in files:
                if file.endswith(('.conf', '.cfg', '.ini', '.env')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', errors='ignore') as f:
                            content = f.read()

                            # Simple check for "password" keyword
                            if 'password' in content.lower():
                                # Extract line
                                for line in content.split('\n'):
                                    if 'password' in line.lower():
                                        credentials.append((file_path, line.strip()))

                    except:
                        pass

        return credentials

    def _find_crypto_keys(self, root_dir: str) -> List[str]:
        """Find cryptographic keys"""
        keys = []

        for root, dirs, files in os.walk(root_dir):
            for file in files:
                if file.endswith(('.key', '.pem', '.crt', '.pub')):
                    keys.append(os.path.join(root, file))

        return keys

    def scan_for_vulnerabilities(self, extracted: ExtractedFilesystem) -> List[Dict[str, Any]]:
        """
        Scan extracted firmware for common vulnerabilities.

        Args:
            extracted: Extracted filesystem

        Returns:
            List of found vulnerabilities
        """
        vulns = []

        # Check for hardcoded credentials
        if extracted.hardcoded_credentials:
            vulns.append({
                'type': 'Hardcoded Credentials',
                'severity': 'HIGH',
                'count': len(extracted.hardcoded_credentials),
                'details': extracted.hardcoded_credentials[:5]  # First 5
            })

        # Check for weak crypto keys
        if extracted.embedded_keys:
            vulns.append({
                'type': 'Embedded Crypto Keys',
                'severity': 'MEDIUM',
                'count': len(extracted.embedded_keys),
                'details': extracted.embedded_keys
            })

        # Check for outdated libraries (simplified)
        # Real implementation would use CVE databases

        return vulns
