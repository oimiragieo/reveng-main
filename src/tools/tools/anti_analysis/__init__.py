"""
Anti-Analysis Detection and Unpacking Module

Detects and bypasses anti-analysis techniques including:
- Packing detection and unpacking
- Anti-debugging detection
- Anti-VM/sandbox detection
- Obfuscation detection
"""

from .packer_detector import PackerDetector, PackerInfo
from .universal_unpacker import UniversalUnpacker, UnpackResult

__all__ = [
    'PackerDetector',
    'PackerInfo',
    'UniversalUnpacker',
    'UnpackResult',
]
