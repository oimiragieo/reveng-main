"""
Binary Diffing and Comparison Module

Provides binary comparison, patch analysis, and variant detection capabilities.
"""

from .binary_differ import BinaryDiffer, DiffResult, FunctionMatch
from .patch_analyzer import PatchAnalyzer, Vulnerability

__all__ = [
    'BinaryDiffer',
    'DiffResult',
    'FunctionMatch',
    'PatchAnalyzer',
    'Vulnerability',
]
