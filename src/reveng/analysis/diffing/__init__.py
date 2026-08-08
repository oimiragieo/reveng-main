"""
REVENG v4.0 - Semantic Binary Diffing

Advanced patch analysis and malware variant detection:
- Graph-based semantic similarity
- LLM-powered patch summarization
- Vulnerability verification
- Security impact analysis
"""

from .semantic_differ import DiffResult, GraphAlignment, SecurityImpact, SemanticBinaryDiffer

__all__ = [
    "SemanticBinaryDiffer",
    "DiffResult",
    "GraphAlignment",
    "SecurityImpact",
]
