"""
Translation hints module for AI-assisted C-to-Python code translation.

This module provides tools to help AI agents translate decompiled C code
into Python by:
1. Mapping Windows APIs to Python equivalents
2. Detecting API usage patterns in C code
3. Generating inline translation hints and examples
"""

from .api_mappings import API_MAPPINGS, get_api_mapping
from .pattern_matcher import detect_api_calls, APICallMatch
from .hint_generator import generate_translation_hints, TranslationHint

__all__ = [
    "API_MAPPINGS",
    "get_api_mapping",
    "detect_api_calls",
    "APICallMatch",
    "generate_translation_hints",
    "TranslationHint",
]
