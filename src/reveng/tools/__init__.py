"""
REVENG Tools Package

Comprehensive collection of analysis tools organized by category:
- core: Core analysis tools
- languages: Language-specific analyzers
- ai: AI/ML tools and integrations
- security: Security analysis tools
- quality: Code quality tools
- binary: Binary processing tools
- visualization: Visualization tools
- enterprise: Enterprise features
- config: Configuration management
- utils: Utility functions
- threat_intel: Threat intelligence tools
- diffing: Binary comparison tools
- anti_analysis: Anti-analysis detection
- translation: Code translation tools
- decompilers: Decompiler integrations
"""

__version__ = "2.1.0"
__author__ = "REVENG Development Team"

# AI/ML tools
from .ai import *

# Anti-analysis tools
from .anti_analysis import *

# Binary tools
from .binary import *

# Configuration tools
from .config import *

# Core tools
from .core import *

# Decompiler tools
from .decompilers import *

# Diffing tools
from .diffing import *

# Enterprise tools
from .enterprise import *

# Language analyzers
from .languages import *

# Quality tools
from .quality import *

# Security tools
from .security import *

# Threat intelligence
from .threat_intel import *

# Translation tools
from .translation import *

# Utility tools
from .utils import *

# Visualization tools
from .visualization import *

__all__ = [
    # Core tools
    "ai_recompiler_converter",
    "optimal_binary_analysis",
    "ai_source_inspector",
    "binary_reassembler_v2",
    "binary_validator",
    "deobfuscation_tool",
    "human_readable_converter_fixed",
    "implementation_tool",
    # Language analyzers
    "java_bytecode_analyzer",
    "csharp_il_analyzer",
    "python_bytecode_analyzer",
    "language_detector",
    # AI tools
    "ai_analyzer_enhanced",
    "ollama_analyzer",
    "ml_malware_classifier",
    # Security tools
    "vulnerability_discovery_engine",
    "threat_intelligence_correlator",
    "corporate_exposure_detector",
    # Quality tools
    "code_formatter",
    "c_type_parser",
    "type_inference_engine",
    # Binary tools
    "binary_diff",
    "validation_config",
    # Visualization tools
    "code_visualizer",
    "executive_reporting_engine",
    # Enterprise tools
    "audit_trail",
    "plugin_system",
    "gpu_accelerator",
    # Configuration tools
    "config_manager",
    "ghidra_mcp_connector",
    # Utility tools
    "demonstration_generator",
    "progress_reporter",
    # Threat intelligence
    "virustotal_connector",
    "yara_generator",
    "yara_scanner",
    # Diffing tools
    "binary_differ",
    "patch_analyzer",
    # Anti-analysis tools
    "packer_detector",
    "universal_unpacker",
    # Translation tools
    "api_mappings",
    "hint_generator",
    # Decompiler tools
    "download_decompilers",
]
