"""
REVENG v4.0 - Advanced Compilation Module

This module provides world-class compilation capabilities including:
- Incremental compilation with intelligent caching
- Smart compilation with AI-powered error recovery
- LLVM optimization pipeline for maximum accuracy
- Distributed compilation support
"""

from .incremental_compiler import IncrementalCompiler, BuildManifest, DependencyGraph
from .smart_compiler import SmartCompiler, CompileError, CompileResult
from .llvm_optimizer import LLVMOptimizationPipeline, PGOCompiler

__all__ = [
    "IncrementalCompiler",
    "BuildManifest",
    "DependencyGraph",
    "SmartCompiler",
    "CompileError",
    "CompileResult",
    "LLVMOptimizationPipeline",
    "PGOCompiler",
]
