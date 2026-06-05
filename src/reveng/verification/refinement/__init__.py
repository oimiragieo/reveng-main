"""
reveng.verification.refinement — Iterative LLM Refiner
=======================================================

Provides the IterativeRefiner, which drives a structured feedback loop
between a differential oracle and an LLM provider to converge decompiled C
source toward behavioural equivalence with the original binary.

Public surface
--------------
    IterativeRefiner   — main loop engine (refiner.py)
    RefinementResult   — final outcome of a refine() call (models.py)
    RefinementBudget   — constraints (iterations, wall clock, tokens) (models.py)

Lower-level types also available:
    RefinementRound    — per-iteration record
    RefinementStatus   — terminal state enum
"""

from .models import RefinementBudget, RefinementResult, RefinementRound, RefinementStatus
from .refiner import IterativeRefiner

__all__ = [
    "IterativeRefiner",
    "RefinementBudget",
    "RefinementResult",
    "RefinementRound",
    "RefinementStatus",
]
