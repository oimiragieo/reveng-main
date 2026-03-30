"""
REVENG v4.0 - Advanced Compilation Module

This module provides world-class compilation capabilities including:
- Incremental compilation with intelligent caching
- Smart compilation with AI-powered error recovery
- LLVM optimization pipeline for maximum accuracy
- Distributed compilation support
"""

from .incremental_compiler import BuildManifest, DependencyGraph, IncrementalCompiler
from .llvm_optimizer import LLVMOptimizationPipeline, PGOCompiler
from .smart_compiler import CompileError, CompileResult, SmartCompiler

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
