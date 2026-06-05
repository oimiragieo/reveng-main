"""
Shared data models for the Verified Recompilation Loop verification oracles.

Phase 1 scaffold: defines VerificationVerdict, DivergenceReport, and
EquivalenceResult. ValidationGrade and EvidenceItem are imported from
reveng.validation when available, falling back to lightweight stubs so
this package can be imported without the full validation subsystem.
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Optional, Tuple

logger_name = __name__

#: Ordered ValidationGrade ladder (ascending priority).
#:
#: This is the canonical vocabulary recorded in
#: ``.reveng/benchmarks/corpus.yaml`` (see the file header comment).  Each
#: value's rank is its index in this tuple; lower ranks are weaker results.
VALIDATION_GRADE_LADDER: Tuple[str, ...] = (
    "unknown",  # -1: no information
    "analysis_only",  # 0: static analysis only, never executed
    "compile_only",  # 1: source compiles, behaviour unverified
    "structural_candidate",  # 2: plausible structure, not launched
    "launches_but_divergent",  # 3: runs but output diverges
    "partial_equivalence",  # 4: some inputs match
    "behavior_matched",  # 5: all sampled inputs match
    "source_reconstruction_match",  # 6: source-level match
    "evidence_backed",  # 7: match with corroborating evidence
)


def grade_rank(grade: Optional[str]) -> int:
    """
    Return the ladder rank of *grade*.

    ``unknown`` and any unrecognised / ``None`` value map to rank ``-1`` so the
    ladder is totally ordered and a missing grade always sorts lowest.
    """
    if grade is None:
        return -1
    try:
        return VALIDATION_GRADE_LADDER.index(grade) - 1
    except ValueError:
        return -1


try:
    from reveng.validation.differential_fuzzer import (  # noqa: F401
        ValidationResult as _ValidationResult,
    )

    # ValidationGrade and EvidenceItem are not yet defined in the validation
    # package (as of Phase 1 reconnaissance). Declare stubs below.
    raise ImportError("ValidationGrade not present in validation package")
except ImportError:
    # ValidationGrade is an ordered string vocabulary (the ladder above).
    # We type it as ``str`` so consumers can compare against ladder members
    # while still treating values as plain strings on disk / in YAML.
    ValidationGrade = str  # type: ignore[assignment, misc]

    @dataclass
    class EvidenceItem:  # type: ignore[no-redef]
        """Stub EvidenceItem used when reveng.validation is unavailable."""

        description: str
        data: Any = None

        def __repr__(self) -> str:
            return f"EvidenceItem(description={self.description!r})"


class VerificationVerdict(Enum):
    """High-level outcome of a verification run."""

    EQUIVALENT = "equivalent"
    DIVERGENT = "divergent"
    UNDETERMINED = "undetermined"
    TIMED_OUT = "timed_out"
    ERROR = "error"


@dataclass
class DivergenceReport:
    """
    Result from differential execution of an original vs recompiled binary.

    Produced by DifferentialOracle.verify() and DifferentialOracle.fuzz_until_divergence().
    """

    verdict: VerificationVerdict
    failing_inputs: List[bytes] = field(default_factory=list)
    diverging_outputs: List[Tuple[bytes, bytes]] = field(default_factory=list)
    iterations: int = 0
    elapsed_seconds: float = 0.0
    evidence: List[Any] = field(default_factory=list)
    grade: Optional[Any] = None  # ValidationGrade when available
    notes: str = ""

    def __repr__(self) -> str:
        return (
            f"DivergenceReport("
            f"verdict={self.verdict.value!r}, "
            f"iterations={self.iterations}, "
            f"divergences={len(self.failing_inputs)}, "
            f"elapsed={self.elapsed_seconds:.2f}s)"
        )

    def divergence_rate(self) -> float:
        """Return fraction of inputs that caused divergence (0.0 – 1.0)."""
        if self.iterations == 0:
            return 0.0
        return len(self.failing_inputs) / self.iterations


@dataclass
class EquivalenceResult:
    """
    Result from symbolic equivalence checking of a single function pair.

    Produced by SymbolicOracle.verify_function_equivalence().
    """

    verdict: VerificationVerdict
    function_name: str = "<unknown>"
    path_count: int = 0
    counterexample: Optional[bytes] = None
    elapsed_seconds: float = 0.0
    evidence: List[Any] = field(default_factory=list)
    notes: str = ""

    def __repr__(self) -> str:
        return (
            f"EquivalenceResult("
            f"verdict={self.verdict.value!r}, "
            f"function={self.function_name!r}, "
            f"paths={self.path_count}, "
            f"elapsed={self.elapsed_seconds:.2f}s)"
        )


def _grade_from_divergence_count(divergent: int, total: int) -> str:
    """
    Map divergence statistics to a grade string.

    Tries to use ValidationGrade enum values; falls back to plain strings
    so the package works without the validation subsystem.

    Grade mapping:
      0 divergences             -> "behavior_matched"
      < 10 % of inputs diverge  -> "partial_equivalence"
      >= 10 % diverge           -> "launches_but_divergent"
    """
    if total == 0 or divergent == 0:
        return "behavior_matched"
    rate = divergent / total
    if rate < 0.10:
        return "partial_equivalence"
    return "launches_but_divergent"
