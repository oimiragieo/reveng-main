"""
Dynamic Instrumentation Module

This module provides runtime instrumentation capabilities for analyzing and
manipulating running processes, similar to Frida and other DBI frameworks.
"""

from .dynamic_instrumentation_engine import DynamicInstrumentationEngine
from .hook_manager import HookManager, HookType
from .memory_scanner import MemoryScanner
from .function_hooker import FunctionHooker

__all__ = [
    'DynamicInstrumentationEngine',
    'HookManager',
    'HookType',
    'MemoryScanner',
    'FunctionHooker',
]
