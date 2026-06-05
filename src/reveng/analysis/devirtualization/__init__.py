"""
Advanced Devirtualization Module

Implements cutting-edge techniques for defeating commercial code virtualizers
like VMProtect and Themida.

Based on "The Modern Hacker's Playbook" - Part 3: Deobfuscation
"""

from .devirtualization_engine import DevirtualizationEngine, VMType
from .llvm_flattener import LLVMFlattener
from .symbolic_devirtualizer import SymbolicDevirtualizer
from .vm_analyzer import VMAnalyzer

__all__ = [
    "DevirtualizationEngine",
    "VMType",
    "LLVMFlattener",
    "SymbolicDevirtualizer",
    "VMAnalyzer",
]
