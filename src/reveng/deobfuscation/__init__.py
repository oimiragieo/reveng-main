"""
REVENG v5.0 - LLM-Powered Advanced Deobfuscation

Use large language models for sophisticated deobfuscation:
- GPT-4/Claude for code understanding
- Control flow unflattening
- String deobfuscation
- Dead code elimination guided by LLM
- Pattern recognition for obfuscation techniques
"""

from .llm_deobfuscator import (
    LLMDeobfuscator,
    DeobfuscationResult,
    ObfuscationTechnique,
    LLMProvider,
)

__all__ = [
    "LLMDeobfuscator",
    "DeobfuscationResult",
    "ObfuscationTechnique",
    "LLMProvider",
]
