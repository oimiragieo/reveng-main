"""
Differential execution oracle.

Compares an original binary against a recompiled binary by feeding both the
same input corpus and checking for output divergence (stdout + exit-code).

Phase 1 limitations
-------------------
* Only subprocess-based execution is implemented.
* LibAFL-backed fuzzing loop is planned for Phase 1.5.
* Grade values use plain strings; ValidationGrade enum integration is
  deferred until the validation package exposes it.

TODO(phase-1.5): wire LibAFL fuzzing loop in fuzz_until_divergence().
"""

import logging
import time
from pathlib import Path
from typing import Iterable, List, Optional

from reveng.verification.differential.harness import ExecutionHarness, HarnessError
from reveng.verification.models import (
    DivergenceReport,
    VerificationVerdict,
    _grade_from_divergence_count,
)

logger = logging.getLogger(__name__)

_MAX_STORED_DIVERGENCES = 50  # cap stored failures to avoid unbounded memory


class DifferentialOracle:
    """
    Differential execution oracle for the Verified Recompilation Loop.

    Instantiate with paths to the original and recompiled binaries, then
    call :meth:`verify` with an iterable of byte strings to compare
    behaviours across the entire corpus.

    Parameters
    ----------
    original:
        Path to the reference (original) binary.
    recompiled:
        Path to the candidate (recompiled) binary.
    timeout_seconds:
        Per-invocation wall-clock deadline (seconds).
    max_iterations:
        Maximum number of inputs processed before stopping.
    """

    def __init__(
        self,
        original: Path,
        recompiled: Path,
        timeout_seconds: float = 5.0,
        max_iterations: int = 1000,
    ) -> None:
        self._original = Path(original)
        self._recompiled = Path(recompiled)
        self._timeout = timeout_seconds
        self._max_iterations = max_iterations

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(
        self,
        inputs: Iterable[bytes],
        argv: Optional[List[str]] = None,
    ) -> DivergenceReport:
        """
        Run both binaries on each input in *inputs* and return a report.

        Comparison criteria: stdout bytes and exit code must match.
        Stderr divergence is noted but does not count as a failure.

        Parameters
        ----------
        inputs:
            Iterable of byte strings written to each binary's stdin.
        argv:
            Optional command-line arguments applied to *every* invocation of
            both binaries.  When ``None`` the binaries run with no extra args.
            This keeps argv (flags) distinct from stdin payloads so CLI tools
            that read their arguments from argv behave correctly.

        The verdict is:
        * ``EQUIVALENT``  — no divergences found on any input.
        * ``DIVERGENT``   — at least one input produced different output.
        * ``TIMED_OUT``   — both harnesses returned timed-out results for
                            the same input; this input is skipped.
        * ``ERROR``       — harness could not launch one of the binaries.
        """
        harness_orig = ExecutionHarness(self._original, timeout_seconds=self._timeout)
        harness_reco = ExecutionHarness(self._recompiled, timeout_seconds=self._timeout)

        failing_inputs: List[bytes] = []
        diverging_outputs = []
        t_start = time.monotonic()
        iteration = 0

        for inp in inputs:
            if iteration >= self._max_iterations:
                logger.debug(
                    "Reached max_iterations=%d, stopping verify loop.", self._max_iterations
                )
                break

            iteration += 1

            try:
                r_orig = harness_orig.run(argv=argv, input_bytes=inp)
                r_reco = harness_reco.run(argv=argv, input_bytes=inp)
            except HarnessError as exc:
                elapsed = time.monotonic() - t_start
                logger.error("Harness error on iteration %d: %s", iteration, exc)
                return DivergenceReport(
                    verdict=VerificationVerdict.ERROR,
                    failing_inputs=failing_inputs,
                    diverging_outputs=diverging_outputs,
                    iterations=iteration,
                    elapsed_seconds=elapsed,
                    grade="analysis_only",
                    notes=str(exc),
                )

            # Skip inputs where both sides timed out (uninformative)
            if r_orig.timed_out and r_reco.timed_out:
                logger.debug("Both binaries timed out on input #%d — skipping.", iteration)
                continue

            # Divergence: stdout or exit code differs
            if r_orig.stdout != r_reco.stdout or r_orig.exit_code != r_reco.exit_code:
                logger.info(
                    "Divergence on input #%d: orig_exit=%d reco_exit=%d "
                    "orig_stdout_len=%d reco_stdout_len=%d",
                    iteration,
                    r_orig.exit_code,
                    r_reco.exit_code,
                    len(r_orig.stdout),
                    len(r_reco.stdout),
                )
                if len(failing_inputs) < _MAX_STORED_DIVERGENCES:
                    failing_inputs.append(inp)
                    diverging_outputs.append((r_orig.stdout, r_reco.stdout))

        elapsed = time.monotonic() - t_start
        n_divergent = len(failing_inputs)
        verdict = (
            VerificationVerdict.EQUIVALENT if n_divergent == 0 else VerificationVerdict.DIVERGENT
        )
        grade_str = _grade_from_divergence_count(n_divergent, iteration)

        logger.info(
            "verify() complete: %d/%d inputs diverged in %.2fs — %s",
            n_divergent,
            iteration,
            elapsed,
            verdict.value,
        )

        return DivergenceReport(
            verdict=verdict,
            failing_inputs=failing_inputs,
            diverging_outputs=diverging_outputs,
            iterations=iteration,
            elapsed_seconds=elapsed,
            grade=grade_str,
            notes=f"Phase 1 differential oracle; grade={grade_str}",
        )

    def fuzz_until_divergence(
        self,
        seed_inputs: List[bytes],
        budget_seconds: float = 60.0,
    ) -> DivergenceReport:
        """
        Run a coverage-guided fuzzing loop until a divergence is found.

        .. note::
            **Phase 1 stub.**  LibAFL integration is scheduled for Phase 1.5.
            This method raises :class:`NotImplementedError` in Phase 1.

        Parameters
        ----------
        seed_inputs:
            Initial seed corpus for the fuzzer.
        budget_seconds:
            Wall-clock time budget for the fuzzing campaign.

        TODO(phase-1.5): wire LibAFL fuzzing loop here.
        """
        raise NotImplementedError(
            "LibAFL integration scheduled for Phase 1.5. "
            "Use DifferentialOracle.verify(inputs) with a handcrafted corpus for Phase 1."
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _classify_verdict(
        self,
        n_divergent: int,
        n_total: int,
        any_timeout: bool,
    ) -> VerificationVerdict:
        """Map raw counts to a VerificationVerdict."""
        if n_total == 0:
            return VerificationVerdict.UNDETERMINED
        if n_divergent > 0:
            return VerificationVerdict.DIVERGENT
        if any_timeout:
            return VerificationVerdict.TIMED_OUT
        return VerificationVerdict.EQUIVALENT
