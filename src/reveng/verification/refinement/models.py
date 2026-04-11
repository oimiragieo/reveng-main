"""
Data models for the Iterative LLM Refiner.

Defines RefinementBudget, RefinementRound, RefinementResult, and
RefinementStatus.  All types are Python 3.9-compatible (no match,
no PEP 695, no @override).
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from ..models import DivergenceReport, VerificationVerdict


class RefinementStatus(str, Enum):
    """Terminal state of an IterativeRefiner run."""

    CONVERGED = "converged"  # oracle reported EQUIVALENT
    BUDGET_EXHAUSTED = "budget_exhausted"  # hit max_iterations or wall clock
    NO_PROGRESS = "no_progress"  # LLM echoed identical source twice
    LLM_ERROR = "llm_error"  # provider raised an exception
    ABORTED = "aborted"  # caller cancelled (reserved for future use)
    TIMEOUT = "timeout"  # oracle.verify() raised TimeoutError
    ERROR = "error"  # oracle.verify() raised an unexpected exception


@dataclass(frozen=True)
class RefinementBudget:
    """
    Constraints that govern how long the refinement loop is allowed to run.

    Attributes:
        max_iterations:       Hard cap on the number of LLM round-trips.
        max_wall_seconds:     Wall-clock budget for the whole refine() call.
        max_tokens_per_round: Hint passed to the LLM about response length.
        abort_on_no_progress: When True, stop immediately if the LLM returns
                              source that is byte-identical to the previous
                              round's source.
    """

    max_iterations: int = 5
    max_wall_seconds: float = 600.0
    max_tokens_per_round: int = 8192
    abort_on_no_progress: bool = True


@dataclass
class RefinementRound:
    """
    Record of a single iteration in the refinement loop.

    Attributes:
        index:         1-based round number.
        prompt:        The text sent to the LLM.
        response:      The raw text returned by the LLM.
        source_before: Decompiled C source *before* this round's LLM edit.
        source_after:  Decompiled C source *after* this round's LLM edit
                       (extracted from the response).
        divergence:    DivergenceReport produced by verifying source_after,
                       or None when verification was not attempted.
        elapsed_seconds: Wall-clock time consumed by this round.
        tokens_used:   Number of tokens consumed (0 when the provider does
                       not report usage).
    """

    index: int
    prompt: str
    response: str
    source_before: str
    source_after: str
    divergence: Optional[DivergenceReport]
    elapsed_seconds: float
    tokens_used: int = 0

    @property
    def converged(self) -> bool:
        """True when the oracle declared EQUIVALENT after this round."""
        if self.divergence is None:
            return False
        return self.divergence.verdict == VerificationVerdict.EQUIVALENT


@dataclass
class RefinementResult:
    """
    Final outcome returned by IterativeRefiner.refine().

    Attributes:
        status:                Terminal status of the refinement run.
        rounds:                Ordered list of per-iteration records.
        final_source:          The best source found (converged, or last).
        final_divergence:      The DivergenceReport for final_source.
        total_elapsed_seconds: Wall-clock time for the entire refine() call.
        total_tokens:          Sum of tokens_used across all rounds.
        notes:                 Human-readable explanation of the outcome.
    """

    status: RefinementStatus
    rounds: List[RefinementRound] = field(default_factory=list)
    final_source: str = ""
    final_divergence: Optional[DivergenceReport] = None
    total_elapsed_seconds: float = 0.0
    total_tokens: int = 0
    notes: str = ""

    @property
    def converged(self) -> bool:
        """True when status is CONVERGED."""
        return self.status == RefinementStatus.CONVERGED

    @property
    def iterations(self) -> int:
        """Number of LLM round-trips that were actually executed."""
        return len(self.rounds)
