"""
Packer Detection for REVENG

Detects if a binary is packed/compressed and identifies the packer type.
"""

import hashlib
import logging
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PackerInfo:
    """Information about detected packer"""
    packed: bool
    packer_name: Optional[str]
    confidence: float  # 0.0 to 1.0
    entropy: float
    indicators: List[str]
    unpacking_method: str  # 'specialized', 'generic', 'manual'


class PackerDetector:
    """
    Detects packing/compression in binaries.

    Identifies common packers (UPX, Themida, VMProtect, etc.) and
    estimates if binary is packed based on entropy and other indicators.
    """

    # Known packer signatures
    PACKER_SIGNATURES = {
        'UPX': [
            b'UPX!',
            b'UPX0',
            b'UPX1',
            b'UPX2',
        ],
        'Themida': [
            b'Themida',
            b'WinLicense',
        ],
        'VMProtect': [
            b'VMProtect',
            b'.vmp0',
            b'.vmp1',
        ],
        'ASPack': [
            b'ASPack',
            b'.aspack',
        ],
        'Enigma': [
            b'Enigma',
        ],
        'PECompact': [
            b'PECompact',
            b'pec1',
            b'pec2',
        ],
        'FSG': [
            b'FSG!',
        ],
        'MPRESS': [
            b'MPRESS',
            b'.MPRESS',
        ],
    }

    def __init__(self):
        """Initialize packer detector"""
        logger.info("Packer detector initialized")

    def detect(self, file_path: str) -> PackerInfo:
        """
        Detect if binary is packed.

        Args:
            file_path: Path to binary file

        Returns:
            PackerInfo with detection results
        """
        logger.info(f"Detecting packer in {file_path}")

        indicators = []
        packer_name = None
        confidence = 0.0

        try:
            with open(file_path, 'rb') as f:
                data = f.read()

            # 1. Calculate entropy
            entropy = self._calculate_entropy(data)

            # High entropy suggests packing/encryption
            if entropy > 7.5:
                indicators.append(f"Very high entropy ({entropy:.2f}) - likely packed")
                confidence += 0.4
            elif entropy > 7.0:
                indicators.append(f"High entropy ({entropy:.2f}) - possibly packed")
                confidence += 0.2

            # 2. Check for known packer signatures
            detected_packer = self._check_signatures(data)
            if detected_packer:
                packer_name = detected_packer
                indicators.append(f"Signature match: {packer_name}")
                confidence += 0.5

            # 3. Check PE characteristics (if PE file)
            if data[:2] == b'MZ':
                pe_indicators = self._check_pe_indicators(data)
                indicators.extend(pe_indicators)
                if pe_indicators:
                    confidence += 0.1 * len(pe_indicators)

            # 4. Check for suspicious section names
            section_indicators = self._check_section_names(data)
            if section_indicators:
                indicators.extend(section_indicators)
                confidence += 0.2

            # Determine if packed
            packed = confidence > 0.3 or entropy > 7.2

            # Determine unpacking method
            if packer_name in ['UPX', 'MPRESS']:
                unpacking_method = 'specialized'
            elif packed:
                unpacking_method = 'generic'
            else:
                unpacking_method = 'none'

            result = PackerInfo(
                packed=packed,
                packer_name=packer_name,
                confidence=min(confidence, 1.0),
                entropy=entropy,
                indicators=indicators,
                unpacking_method=unpacking_method
            )

            logger.info(
                f"Packer detection: {'PACKED' if packed else 'NOT PACKED'} "
                f"({packer_name or 'unknown'}, confidence: {result.confidence:.1%})"
            )

            return result

        except Exception as e:
            logger.error(f"Packer detection failed: {e}")
            return PackerInfo(
                packed=False,
                packer_name=None,
                confidence=0.0,
                entropy=0.0,
                indicators=[f"Detection failed: {e}"],
                unpacking_method='none'
            )

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        import math

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)

        for count in byte_counts:
            if count > 0:
                prob = count / data_len
                entropy -= prob * math.log2(prob)

        return entropy

    def _check_signatures(self, data: bytes) -> Optional[str]:
        """Check for known packer signatures"""
        for packer, signatures in self.PACKER_SIGNATURES.items():
            for sig in signatures:
                if sig in data:
                    return packer
        return None

    def _check_pe_indicators(self, data: bytes) -> List[str]:
        """Check PE-specific packing indicators"""
        indicators = []

        try:
            # Read PE header offset
            if len(data) < 0x3C + 4:
                return indicators

            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]

            if pe_offset + 24 > len(data):
                return indicators

            # Check PE signature
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return indicators

            # Read number of sections
            num_sections_offset = pe_offset + 6
            num_sections = struct.unpack('<H', data[num_sections_offset:num_sections_offset+2])[0]

            # Very few sections can indicate packing
            if num_sections <= 2:
                indicators.append(f"Suspicious: only {num_sections} sections")

            # Read entry point RVA
            entrypoint_offset = pe_offset + 40
            entry_rva = struct.unpack('<I', data[entrypoint_offset:entrypoint_offset+4])[0]

            # Check if entry point is in unusual section
            # (Would need full section parsing for accurate check)

        except Exception as e:
            logger.error(f"PE indicator check failed: {e}")

        return indicators

    def _check_section_names(self, data: bytes) -> List[str]:
        """Check for suspicious PE section names"""
        indicators = []

        # Common packer section names
        suspicious_sections = [
            b'UPX0', b'UPX1', b'UPX2',
            b'.vmp', b'.themida',
            b'.aspack', b'.adata',
            b'pec1', b'pec2',
            b'.perplex', b'.nsp',
            b'.boom', b'.yP',
        ]

        for section in suspicious_sections:
            if section in data:
                indicators.append(f"Suspicious section: {section.decode('ascii', errors='ignore')}")

        return indicators


# Convenience function
def quick_detect(file_path: str) -> PackerInfo:
    """Quick packer detection"""
    detector = PackerDetector()
    return detector.detect(file_path)
