"""
REVENG v4.0 - Symbolic Execution Module

Automatic vulnerability discovery through symbolic execution:
- angr framework integration
- Z3 SMT solver for constraint solving
- Automated exploit input generation
- Deobfuscation via SMT simplification
- Test case generation for coverage
"""

from .symbolic_execution_engine import (
    SymbolicExecutionEngine,
    SymbolicVulnerability,
    ExploitInput,
    PathExplorationResult,
)

__all__ = [
    "SymbolicExecutionEngine",
    "SymbolicVulnerability",
    "ExploitInput",
    "PathExplorationResult",
]
