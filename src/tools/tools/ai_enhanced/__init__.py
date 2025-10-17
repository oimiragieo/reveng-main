"""
AI-Enhanced Analysis Module

Advanced AI capabilities for REVENG including natural language queries,
code quality enhancement, and intelligent automation.
"""

from .nl_interface import NaturalLanguageInterface, QueryIntent
from .code_quality_enhancer import AICodeQualityEnhancer
from .instant_triage import InstantTriageEngine

__all__ = [
    'NaturalLanguageInterface',
    'QueryIntent',
    'AICodeQualityEnhancer',
    'InstantTriageEngine',
]
