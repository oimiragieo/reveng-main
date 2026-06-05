"""
REVENG Universal Reverse Engineering Platform
============================================

Enterprise-grade, AI-powered reverse engineering platform with complete
binary reconstruction capabilities.

Author: REVENG Development Team
Version: 4.0.0
License: MIT
"""

import importlib
from typing import Any

__version__ = "4.0.0"
__author__ = "REVENG Development Team"
__email__ = "contact@reveng-project.org"
__license__ = "MIT"
__url__ = "https://github.com/oimiragieo/reveng-main"

# Public API
__all__ = [
    "REVENGAnalyzer",
    "main",
    "get_version",
    "get_version_info",
    "MLIntegration",
    "MLIntegrationConfig",
    "REVENGAPI",
    "analyze_binary",
    "detect_malware",
    "reconstruct_binary",
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    "__url__",
]

_LAZY_IMPORTS = {
    "REVENGAnalyzer": ("reveng.analysis.analyzer", "REVENGAnalyzer"),
    "main": ("reveng.cli", "main"),
    "get_version": ("reveng.version", "get_version"),
    "get_version_info": ("reveng.version", "get_version_info"),
    "MLIntegration": ("reveng.ml", "MLIntegration"),
    "MLIntegrationConfig": ("reveng.ml", "MLIntegrationConfig"),
    "REVENGAPI": ("reveng.api", "REVENGAPI"),
    "analyze_binary": ("reveng.api", "analyze_binary"),
    "detect_malware": ("reveng.api", "detect_malware"),
    "reconstruct_binary": ("reveng.api", "reconstruct_binary"),
}


def __getattr__(name: str) -> Any:
    """Lazily import top-level exports to avoid eager optional-dependency loading."""
    try:
        module_name, attribute_name = _LAZY_IMPORTS[name]
    except KeyError as exc:
        raise AttributeError(f"module '{__name__}' has no attribute '{name}'") from exc

    module = importlib.import_module(module_name)
    value = getattr(module, attribute_name)
    globals()[name] = value
    return value


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
__python_requires__ = ">=3.9"
__supported_python_versions__ = ["3.9", "3.10", "3.11", "3.12"]
