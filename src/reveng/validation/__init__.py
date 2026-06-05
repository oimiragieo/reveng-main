"""
REVENG v5.0 - Binary Validation Module

Differential fuzzing and validation for behavioral equivalence testing:
- AFL++/LibFuzzer integration for coverage-guided fuzzing
- Differential execution testing between original and recompiled binaries
- Divergence analysis and minimization
- 95%+ behavioral equivalence validation
"""

from .differential_fuzzer import (
    CoverageTracker,
    DifferentialFuzzingEngine,
    Divergence,
    DivergenceAnalyzer,
    DivergenceType,
    ExecutionResult,
    ValidationResult,
)

__all__ = [
    "DifferentialFuzzingEngine",
    "ValidationResult",
    "ExecutionResult",
    "Divergence",
    "DivergenceType",
    "DivergenceAnalyzer",
    "CoverageTracker",
]
