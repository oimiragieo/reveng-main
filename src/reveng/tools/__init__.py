"""Unified tool namespace with lazy loading and optional dependency handling."""

import importlib
import logging
from typing import Any

__version__ = "2.1.0"
__author__ = "REVENG Development Team"

LOGGER = logging.getLogger(__name__)

__all__ = [
    "ai_recompiler_converter",
    "optimal_binary_analysis",
    "ai_source_inspector",
    "binary_reassembler_v2",
    "binary_validator",
    "deobfuscation_tool",
    "human_readable_converter_fixed",
    "implementation_tool",
    "java_bytecode_analyzer",
    "csharp_il_analyzer",
    "python_bytecode_analyzer",
    "language_detector",
    "ai_analyzer_enhanced",
    "ollama_analyzer",
    "ml_malware_classifier",
    "vulnerability_discovery_engine",
    "threat_intelligence_correlator",
    "corporate_exposure_detector",
    "code_formatter",
    "c_type_parser",
    "type_inference_engine",
    "binary_diff",
    "validation_config",
    "code_visualizer",
    "executive_reporting_engine",
    "audit_trail",
    "plugin_system",
    "gpu_accelerator",
    "config_manager",
    "ghidra_mcp_connector",
    "demonstration_generator",
    "progress_reporter",
    "virustotal_connector",
    "yara_generator",
    "yara_scanner",
    "binary_differ",
    "patch_analyzer",
    "packer_detector",
    "universal_unpacker",
    "api_mappings",
    "hint_generator",
    "download_decompilers",
]

_MODULE_MAP = {
    "ai_recompiler_converter": "reveng.tools.core.ai_recompiler_converter",
    "optimal_binary_analysis": "reveng.tools.core.optimal_binary_analysis",
    "ai_source_inspector": "reveng.tools.core.ai_source_inspector",
    "binary_reassembler_v2": "reveng.tools.core.binary_reassembler_v2",
    "binary_validator": "reveng.tools.core.binary_validator",
    "deobfuscation_tool": "reveng.tools.core.deobfuscation_tool",
    "human_readable_converter_fixed": "reveng.tools.core.human_readable_converter_fixed",
    "implementation_tool": "reveng.tools.core.implementation_tool",
    "java_bytecode_analyzer": "reveng.tools.languages.java_bytecode_analyzer",
    "csharp_il_analyzer": "reveng.tools.languages.csharp_il_analyzer",
    "python_bytecode_analyzer": "reveng.tools.languages.python_bytecode_analyzer",
    "language_detector": "reveng.tools.languages.language_detector",
    "ai_analyzer_enhanced": "reveng.agents.ai.ai_analyzer_enhanced",
    "ollama_analyzer": "reveng.agents.ai.ollama_analyzer",
    "ml_malware_classifier": "reveng.security.ml_malware_classifier",
    "vulnerability_discovery_engine": "reveng.security.vulnerability_discovery_engine",
    "threat_intelligence_correlator": "reveng.security.threat_intelligence_correlator",
    "corporate_exposure_detector": "reveng.security.corporate_exposure_detector",
    "code_formatter": "reveng.tools.quality.code_formatter",
    "c_type_parser": "reveng.tools.quality.c_type_parser",
    "type_inference_engine": "reveng.tools.quality.type_inference_engine",
    "binary_diff": "reveng.tools.diffing.binary_diff",
    "validation_config": "reveng.tools.binary.validation_config",
    "code_visualizer": "reveng.reporting.visualization.code_visualizer",
    "executive_reporting_engine": "reveng.reporting.visualization.executive_reporting_engine",
    "audit_trail": "reveng.tools.enterprise.audit_trail",
    "plugin_system": "reveng.tools.enterprise.plugin_system",
    "gpu_accelerator": "reveng.tools.enterprise.gpu_accelerator",
    "config_manager": "reveng.tools.config.config_manager",
    "ghidra_mcp_connector": "reveng.tools.config.ghidra_mcp_connector",
    "demonstration_generator": "reveng.tools.utils.demonstration_generator",
    "progress_reporter": "reveng.tools.utils.progress_reporter",
    "virustotal_connector": "reveng.tools.threat_intel.virustotal_connector",
    "yara_generator": "reveng.tools.threat_intel.yara_generator",
    "yara_scanner": "reveng.tools.threat_intel.yara_scanner",
    "binary_differ": "reveng.tools.diffing.binary_differ",
    "patch_analyzer": "reveng.tools.diffing.patch_analyzer",
    "packer_detector": "reveng.tools.anti_analysis.packer_detector",
    "universal_unpacker": "reveng.tools.anti_analysis.universal_unpacker",
    "api_mappings": "reveng.tools.translation.api_mappings",
    "hint_generator": "reveng.tools.translation.hint_generator",
    "download_decompilers": "reveng.tools.decompilers.download_decompilers",
}


def __getattr__(name: str) -> Any:
    if name in _MODULE_MAP:
        try:
            return importlib.import_module(_MODULE_MAP[name])
        except ImportError as exc:
            LOGGER.warning("Tool module '%s' unavailable: %s", name, exc)

            class _UnavailableModule:
                def __getattr__(self, attr):
                    raise ImportError(
                        f"Optional dependency for '{name}' is missing; module cannot be used"
                    ) from exc

            return _UnavailableModule()
    raise AttributeError(f"module '{__name__}' has no attribute '{name}'")
