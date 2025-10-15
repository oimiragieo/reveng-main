"""
REVENG Universal Reverse Engineering Platform
============================================

Enterprise-grade, AI-powered reverse engineering platform with complete
binary reconstruction capabilities.

Author: REVENG Development Team
Version: 2.1.0
License: MIT
"""

__version__ = "2.1.0"
__author__ = "REVENG Development Team"
__email__ = "contact@reveng-project.org"
__license__ = "MIT"
__url__ = "https://github.com/oimiragieo/reveng-main"

# Core imports
from .analyzer import REVENGAnalyzer
from .cli import main
from .version import get_version, get_version_info

# Public API
__all__ = [
    "REVENGAnalyzer",
    "main",
    "get_version",
    "get_version_info",
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__url__",
]

# Package metadata
__title__ = "reveng-toolkit"
__description__ = "Universal reverse engineering platform with AI-powered analysis"
__keywords__ = [
    "reverse-engineering",
    "binary-analysis",
    "decompiler",
    "disassembler",
    "ai-powered",
    "malware-analysis",
    "vulnerability-detection",
    "binary-reconstruction",
    "ghidra",
    "security",
]

# Development status
__status__ = "Production/Stable"
__python_requires__ = ">=3.11"
__supported_python_versions__ = ["3.11", "3.12"]
