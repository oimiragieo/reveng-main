"""
Iterative LLM-guided recompilation refinement loop.

The IterativeRefiner drives a structured feedback loop:

  1. Ask the oracle to verify the current source's compiled binary.
  2. If EQUIVALENT: return CONVERGED immediately.
  3. If DIVERGENT: build a structured prompt from the divergence and send
     it to the LLM.
  4. Extract revised C source from the LLM response.
  5. Compile the revised source via the caller-supplied compile_fn.
  6. Re-verify with a new oracle instance (from oracle_factory).
  7. Repeat until convergence, budget exhaustion, or no-progress.

The three injectable callables (analyzer, compile_fn, oracle_factory) keep
this module free of hard dependencies on any specific compiler, oracle
implementation, or LLM provider.
"""

import logging
import time
from pathlib import Path
from typing import Callable, Iterable, Optional

from ..models import DivergenceReport, VerificationVerdict
from .models import RefinementBudget, RefinementResult, RefinementRound, RefinementStatus
from .prompts import build_refinement_prompt

logger = logging.getLogger(__name__)


class IterativeRefiner:
    """
    Iterative LLM-guided recompilation refinement loop.

    Given an initial decompiled source and a verification oracle factory,
    this loop attempts to converge on a source that compiles to a binary
    behaviourally equivalent to the original binary.

    Args:
        analyzer:
            Any object with an ``analyze(prompt: str)`` method that returns
            an object with a ``.content`` attribute containing the LLM
            response text.  Compatible with AnthropicAnalyzer and
            OpenAIAnalyzer from ``reveng.agents.ai``, or any mock thereof.
        compile_fn:
            ``Callable[[str], Path]`` — accepts a C source string and returns
            the path to the compiled binary.  Raises on compilation failure.
        oracle_factory:
            ``Callable[[Path], DifferentialOracle]`` — accepts a recompiled
            binary path and returns a fresh oracle instance ready for
            ``verify(seed_inputs)``.
        budget:
            Controls iteration / time / token limits.  Defaults to
            ``RefinementBudget()`` (5 rounds, 600 s wall clock).
        logger:
            Optional pre-configured logger.  Defaults to the module logger.
    """

    def __init__(
        self,
        analyzer,
        compile_fn: Callable[[str], Path],
        oracle_factory: Callable[[Path], object],
        budget: Optional[RefinementBudget] = None,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.analyzer = analyzer
        self.compile_fn = compile_fn
        self.oracle_factory = oracle_factory
        self.budget = budget or RefinementBudget()
        self.logger = logger or logging.getLogger(__name__)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def refine(
        self,
        initial_source: str,
        seed_inputs: Iterable[bytes],
    ) -> RefinementResult:
        """
        Run the iterative refinement loop.

        Args:
            initial_source:
                Decompiled C source to start from.
            seed_inputs:
                Iterable of byte strings used as test inputs by the oracle.
                Will be fully materialised once at the start of the loop.

        Returns:
            A ``RefinementResult`` describing the terminal state.
        """
        wall_start = time.monotonic()
        seed_list = list(seed_inputs)
        rounds: list = []
        source = initial_source

        # ---- Initial verification ----------------------------------------
        try:
            initial_binary = self.compile_fn(source)
        except Exception as exc:
            self.logger.error("Initial compile failed: %s", exc)
            return RefinementResult(
                status=RefinementStatus.LLM_ERROR,
                final_source=source,
                total_elapsed_seconds=time.monotonic() - wall_start,
                notes=f"Initial compile_fn raised: {exc}",
            )

        initial_oracle = self.oracle_factory(initial_binary)
        try:
            initial_divergence = initial_oracle.verify(seed_list)
        except TimeoutError as exc:
            self.logger.error("Initial oracle.verify() timed out: %s", exc)
            return RefinementResult(
                status=RefinementStatus.TIMEOUT,
                final_source=source,
                total_elapsed_seconds=time.monotonic() - wall_start,
                notes=f"Initial oracle.verify() raised TimeoutError: {exc}",
            )
        except Exception as exc:
            self.logger.error("Initial oracle.verify() raised: %s", exc)
            return RefinementResult(
                status=RefinementStatus.ERROR,
                final_source=source,
                total_elapsed_seconds=time.monotonic() - wall_start,
                notes=f"Initial oracle.verify() raised: {exc}",
            )

        if initial_divergence.verdict == VerificationVerdict.EQUIVALENT:
            return RefinementResult(
                status=RefinementStatus.CONVERGED,
                final_source=source,
                final_divergence=initial_divergence,
                total_elapsed_seconds=time.monotonic() - wall_start,
                notes="Already equivalent before first LLM round.",
            )

        divergence = initial_divergence

        # ---- Main refinement loop ----------------------------------------
        for iteration in range(1, self.budget.max_iterations + 1):
            round_start = time.monotonic()

            # --- build prompt ---
            prompt = build_refinement_prompt(
                source=source,
                divergence=divergence,
                iteration=iteration,
                max_iterations=self.budget.max_iterations,
            )

            # --- call LLM ---
            try:
                llm_result = self.analyzer.analyze(prompt)
                response_text = llm_result.content
            except Exception as exc:
                self.logger.error("LLM provider raised on round %d: %s", iteration, exc)
                elapsed = time.monotonic() - round_start
                rounds.append(
                    RefinementRound(
                        index=iteration,
                        prompt=prompt,
                        response="",
                        source_before=source,
                        source_after=source,
                        divergence=divergence,
                        elapsed_seconds=elapsed,
                        tokens_used=0,
                    )
                )
                total_elapsed = time.monotonic() - wall_start
                return RefinementResult(
                    status=RefinementStatus.LLM_ERROR,
                    rounds=rounds,
                    final_source=source,
                    final_divergence=divergence,
                    total_elapsed_seconds=total_elapsed,
                    total_tokens=sum(r.tokens_used for r in rounds),
                    notes=f"LLM provider raised on round {iteration}: {exc}",
                )

            # --- extract code ---
            new_source = _extract_code_block(response_text)

            # --- detect no-progress ---
            if self.budget.abort_on_no_progress and new_source == source:
                elapsed = time.monotonic() - round_start
                rounds.append(
                    RefinementRound(
                        index=iteration,
                        prompt=prompt,
                        response=response_text,
                        source_before=source,
                        source_after=new_source,
                        divergence=divergence,
                        elapsed_seconds=elapsed,
                        tokens_used=_count_tokens(llm_result),
                    )
                )
                total_elapsed = time.monotonic() - wall_start
                return RefinementResult(
                    status=RefinementStatus.NO_PROGRESS,
                    rounds=rounds,
                    final_source=source,
                    final_divergence=divergence,
                    total_elapsed_seconds=total_elapsed,
                    total_tokens=sum(r.tokens_used for r in rounds),
                    notes=(
                        f"LLM returned byte-identical source on round {iteration}; "
                        "aborting (abort_on_no_progress=True)."
                    ),
                )

            # --- compile ---
            try:
                new_binary = self.compile_fn(new_source)
            except Exception as exc:
                self.logger.warning("compile_fn raised on round %d: %s", iteration, exc)
                # Treat as no-progress: keep old source, continue loop
                elapsed = time.monotonic() - round_start
                rounds.append(
                    RefinementRound(
                        index=iteration,
                        prompt=prompt,
                        response=response_text,
                        source_before=source,
                        source_after=new_source,
                        divergence=divergence,
                        elapsed_seconds=elapsed,
                        tokens_used=_count_tokens(llm_result),
                    )
                )
                # Check wall clock before continuing
                if time.monotonic() - wall_start >= self.budget.max_wall_seconds:
                    return RefinementResult(
                        status=RefinementStatus.BUDGET_EXHAUSTED,
                        rounds=rounds,
                        final_source=source,
                        final_divergence=divergence,
                        total_elapsed_seconds=time.monotonic() - wall_start,
                        total_tokens=sum(r.tokens_used for r in rounds),
                        notes=f"Wall-clock budget exhausted after compile failure on round {iteration}.",
                    )
                continue

            # --- verify ---
            oracle = self.oracle_factory(new_binary)
            try:
                new_divergence = oracle.verify(seed_list)
            except TimeoutError as exc:
                self.logger.warning("oracle.verify() timed out on round %d: %s", iteration, exc)
                elapsed = time.monotonic() - round_start
                rounds.append(
                    RefinementRound(
                        index=iteration,
                        prompt=prompt,
                        response=response_text,
                        source_before=source,
                        source_after=new_source,
                        divergence=None,
                        elapsed_seconds=elapsed,
                        tokens_used=_count_tokens(llm_result),
                    )
                )
                if time.monotonic() - wall_start >= self.budget.max_wall_seconds:
                    return RefinementResult(
                        status=RefinementStatus.BUDGET_EXHAUSTED,
                        rounds=rounds,
                        final_source=source,
                        final_divergence=divergence,
                        total_elapsed_seconds=time.monotonic() - wall_start,
                        total_tokens=sum(r.tokens_used for r in rounds),
                        notes=(
                            f"Wall-clock budget exhausted after oracle timeout "
                            f"on round {iteration}."
                        ),
                    )
                continue
            except Exception as exc:
                self.logger.error("oracle.verify() raised on round %d: %s", iteration, exc)
                elapsed = time.monotonic() - round_start
                rounds.append(
                    RefinementRound(
                        index=iteration,
                        prompt=prompt,
                        response=response_text,
                        source_before=source,
                        source_after=new_source,
                        divergence=None,
                        elapsed_seconds=elapsed,
                        tokens_used=_count_tokens(llm_result),
                    )
                )
                if time.monotonic() - wall_start >= self.budget.max_wall_seconds:
                    return RefinementResult(
                        status=RefinementStatus.BUDGET_EXHAUSTED,
                        rounds=rounds,
                        final_source=source,
                        final_divergence=divergence,
                        total_elapsed_seconds=time.monotonic() - wall_start,
                        total_tokens=sum(r.tokens_used for r in rounds),
                        notes=(
                            f"Wall-clock budget exhausted after oracle error "
                            f"on round {iteration}."
                        ),
                    )
                continue
            elapsed = time.monotonic() - round_start

            round_record = RefinementRound(
                index=iteration,
                prompt=prompt,
                response=response_text,
                source_before=source,
                source_after=new_source,
                divergence=new_divergence,
                elapsed_seconds=elapsed,
                tokens_used=_count_tokens(llm_result),
            )
            rounds.append(round_record)

            source = new_source
            divergence = new_divergence

            if new_divergence.verdict == VerificationVerdict.EQUIVALENT:
                total_elapsed = time.monotonic() - wall_start
                return RefinementResult(
                    status=RefinementStatus.CONVERGED,
                    rounds=rounds,
                    final_source=source,
                    final_divergence=divergence,
                    total_elapsed_seconds=total_elapsed,
                    total_tokens=sum(r.tokens_used for r in rounds),
                    notes=f"Converged on round {iteration}.",
                )

            # --- wall clock check ---
            if time.monotonic() - wall_start >= self.budget.max_wall_seconds:
                total_elapsed = time.monotonic() - wall_start
                return RefinementResult(
                    status=RefinementStatus.BUDGET_EXHAUSTED,
                    rounds=rounds,
                    final_source=source,
                    final_divergence=divergence,
                    total_elapsed_seconds=total_elapsed,
                    total_tokens=sum(r.tokens_used for r in rounds),
                    notes=(
                        f"Wall-clock budget of {self.budget.max_wall_seconds}s exhausted "
                        f"after round {iteration}."
                    ),
                )

        # Loop completed without converging
        total_elapsed = time.monotonic() - wall_start
        return RefinementResult(
            status=RefinementStatus.BUDGET_EXHAUSTED,
            rounds=rounds,
            final_source=source,
            final_divergence=divergence,
            total_elapsed_seconds=total_elapsed,
            total_tokens=sum(r.tokens_used for r in rounds),
            notes=f"Budget exhausted after {self.budget.max_iterations} iterations.",
        )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _extract_code_block(text: str) -> str:
    """
    Extract the first fenced code block from *text*.

    Mirrors the logic in ``reveng.agents.ai.anthropic_analyzer._extract_code_block``:
    splits on ``` boundaries and returns the contents of the first non-empty
    fence, stripping an optional language identifier line.  Returns the raw
    text (stripped) when no fence is found.
    """
    if "```" not in text:
        return text.strip()
    parts = text.split("```")
    for i in range(1, len(parts), 2):
        content = parts[i]
        newline_pos = content.find("\n")
        if newline_pos != -1:
            content = content[newline_pos + 1 :]
        stripped = content.strip()
        if stripped:
            return stripped
    return text.strip()


def _count_tokens(llm_result) -> int:
    """
    Best-effort extraction of token count from an LLM result object.

    Checks common attribute paths used by AnthropicAnalyzer and
    OpenAIAnalyzer result objects.  Returns 0 when usage is not reported.
    """
    # Anthropic AnalysisResult-style: result.usage.output_tokens
    usage = getattr(llm_result, "usage", None)
    if usage is not None:
        total = getattr(usage, "output_tokens", 0) + getattr(usage, "input_tokens", 0)
        if total:
            return total
    # Generic: result.tokens_used
    tokens = getattr(llm_result, "tokens_used", 0)
    if tokens:
        return tokens
    return 0
