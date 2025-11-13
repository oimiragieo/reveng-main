"""
REVENG-specific tools for agent SDK.

These tools integrate existing REVENG capabilities with the agent framework:
- Binary analysis
- JavaScript deobfuscation
- Malware detection
- Ghidra integration
"""

from .binary_analysis_tool import BinaryAnalysisTool
from .js_deobfuscation_tool import JSDeobfuscationTool

# Auto-register tools
_binary_tool = BinaryAnalysisTool()
_js_tool = JSDeobfuscationTool()

__all__ = [
    "BinaryAnalysisTool",
    "JSDeobfuscationTool",
]
