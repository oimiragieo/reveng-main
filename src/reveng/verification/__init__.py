"""
reveng.verification — Verified Recompilation Loop Oracle Package
================================================================

Phase 1 scaffold of the Verified Recompilation Loop (VRL), a pipeline that
confirms a recompiled binary is behaviourally and symbolically equivalent to
the original binary.

Two oracle strategies are provided:

* **DifferentialOracle** (``reveng.verification.differential``)
  Runs both binaries against a shared input corpus and flags any output
  divergence.  Backed by subprocess execution today; LibAFL fuzzing loop is
  planned for Phase 1.5.

* **SymbolicOracle** (``reveng.verification.symbolic``)
  Uses symbolic execution (angr) to prove per-function equivalence.  Phase 1
  returns UNDETERMINED while the angr integration is being designed.

Shared result types live in ``reveng.verification.models``:

* :class:`VerificationVerdict` — five-value enum (EQUIVALENT / DIVERGENT /
  UNDETERMINED / TIMED_OUT / ERROR)
* :class:`DivergenceReport` — differential oracle output
* :class:`EquivalenceResult` — symbolic oracle output

All imports are lazy where the underlying dependency (angr, LibAFL) may be
absent; this package is importable in environments where those libraries are
not installed.
"""

from reveng.verification.differential.oracle import DifferentialOracle
from reveng.verification.models import DivergenceReport, EquivalenceResult, VerificationVerdict
from reveng.verification.symbolic.oracle import SymbolicOracle

__all__ = [
    "DifferentialOracle",
    "SymbolicOracle",
    "DivergenceReport",
    "EquivalenceResult",
    "VerificationVerdict",
]
