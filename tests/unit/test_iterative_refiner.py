"""
Unit tests for reveng.verification.refinement.

All LLM provider calls, compile_fn invocations, and oracle interactions are
mocked — no real API calls, no real compilation, no real binary execution.
"""

import time
from pathlib import Path
from typing import List
from unittest.mock import MagicMock, patch

import pytest

from reveng.verification.models import DivergenceReport, VerificationVerdict
from reveng.verification.refinement import (
    IterativeRefiner,
    RefinementBudget,
    RefinementResult,
    RefinementStatus,
)
from reveng.verification.refinement.prompts import (
    REFINEMENT_PROMPT_TEMPLATE,
    build_refinement_prompt,
)
from reveng.verification.refinement.refiner import _extract_code_block

# ---------------------------------------------------------------------------
# Shared helpers / factories
# ---------------------------------------------------------------------------

_SEED_INPUTS: List[bytes] = [b"hello", b"\x00\x01\x02"]

_INITIAL_SOURCE = """\
#include <stdio.h>
int main(void) { return 0; }
"""

_REVISED_SOURCE = """\
#include <stdio.h>
int main(void) { printf("ok"); return 0; }
"""


def _equiv_report() -> DivergenceReport:
    return DivergenceReport(
        verdict=VerificationVerdict.EQUIVALENT,
        failing_inputs=[],
        diverging_outputs=[],
        iterations=10,
        elapsed_seconds=0.1,
    )


def _diverge_report() -> DivergenceReport:
    return DivergenceReport(
        verdict=VerificationVerdict.DIVERGENT,
        failing_inputs=[b"\xde\xad"],
        diverging_outputs=[(b"expected\n", b"actual\n")],
        iterations=10,
        elapsed_seconds=0.1,
    )


def _make_analyzer(content: str = _REVISED_SOURCE) -> MagicMock:
    """Return a mock analyzer whose analyze() returns an object with .content."""
    analyzer = MagicMock()
    result = MagicMock()
    result.content = content
    analyzer.analyze.return_value = result
    return analyzer


def _make_compile_fn(binary_path: Path = Path("/tmp/fake.bin")) -> MagicMock:
    """Return a mock compile_fn that returns a fixed Path."""
    compile_fn = MagicMock(return_value=binary_path)
    return compile_fn


def _make_oracle_factory(divergence: DivergenceReport) -> MagicMock:
    """Return a mock oracle_factory whose oracle.verify() returns *divergence*."""
    oracle = MagicMock()
    oracle.verify.return_value = divergence
    factory = MagicMock(return_value=oracle)
    return factory


def _make_refiner(
    analyzer=None,
    compile_fn=None,
    oracle_factory=None,
    budget: RefinementBudget = None,
) -> IterativeRefiner:
    return IterativeRefiner(
        analyzer=analyzer or _make_analyzer(),
        compile_fn=compile_fn or _make_compile_fn(),
        oracle_factory=oracle_factory or _make_oracle_factory(_equiv_report()),
        budget=budget or RefinementBudget(max_iterations=5),
    )


# ---------------------------------------------------------------------------
# Test 1: initial source already equivalent → CONVERGED immediately
# ---------------------------------------------------------------------------


def test_refiner_returns_converged_when_initial_source_already_equivalent():
    factory = _make_oracle_factory(_equiv_report())
    refiner = _make_refiner(oracle_factory=factory)

    result = refiner.refine(_INITIAL_SOURCE, _SEED_INPUTS)

    assert result.status == RefinementStatus.CONVERGED
    assert result.converged is True
    assert result.iterations == 0
    assert "Already equivalent" in result.notes
    # LLM should not have been called
    refiner.analyzer.analyze.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2: LLM called on divergence; revised source leads to convergence
# ---------------------------------------------------------------------------


def test_refiner_calls_llm_on_divergence_and_applies_response():
    diverge = _diverge_report()
    equiv = _equiv_report()

    # First oracle call (initial compile) → diverge; second (revised) → equiv
    oracle1 = MagicMock()
    oracle1.verify.return_value = diverge
    oracle2 = MagicMock()
    oracle2.verify.return_value = equiv
    factory = MagicMock(side_effect=[oracle1, oracle2])

    analyzer = _make_analyzer(content=f"```c\n{_REVISED_SOURCE}\n```")
    compile_fn = _make_compile_fn()

    refiner = IterativeRefiner(
        analyzer=analyzer,
        compile_fn=compile_fn,
        oracle_factory=factory,
        budget=RefinementBudget(max_iterations=5),
    )
    result = refiner.refine(_INITIAL_SOURCE, _SEED_INPUTS)

    assert result.status == RefinementStatus.CONVERGED
    assert result.iterations == 1
    analyzer.analyze.assert_called_once()
    # compile_fn: once for initial, once for revised
    assert compile_fn.call_count == 2
    # The source passed to the second compile call should be the revised source
    second_call_source = compile_fn.call_args_list[1][0][0]
    assert "printf" in second_call_source


# ---------------------------------------------------------------------------
# Test 3: LLM echoes the same source → NO_PROGRESS
# ---------------------------------------------------------------------------


def test_refiner_returns_no_progress_when_llm_echoes_source():
    # oracle always diverges; LLM always returns the same source
    factory = _make_oracle_factory(_diverge_report())
    # Wrap the initial source in a code fence — after extraction it equals
    # _INITIAL_SOURCE (stripped)
    echoed_content = f"```c\n{_INITIAL_SOURCE.strip()}\n```"
    analyzer = _make_analyzer(content=echoed_content)

    refiner = _make_refiner(
        analyzer=analyzer,
        oracle_factory=factory,
        budget=RefinementBudget(max_iterations=5, abort_on_no_progress=True),
    )
    result = refiner.refine(_INITIAL_SOURCE.strip(), _SEED_INPUTS)

    assert result.status == RefinementStatus.NO_PROGRESS
    assert result.converged is False
    assert "abort_on_no_progress" in result.notes or "identical" in result.notes.lower()


# ---------------------------------------------------------------------------
# Test 4: max_iterations reached without convergence → BUDGET_EXHAUSTED
# ---------------------------------------------------------------------------


def test_refiner_returns_budget_exhausted_when_max_iterations_hit():
    # Each oracle call diverges; LLM returns a different source each time
    factory = _make_oracle_factory(_diverge_report())
    # Return always-different source by appending iteration counter via side_effect
    call_count = [0]

    def make_result(*args, **kwargs):
        call_count[0] += 1
        r = MagicMock()
        r.content = f"```c\nint main(void) {{ return {call_count[0]}; }}\n```"
        return r

    analyzer = MagicMock()
    analyzer.analyze.side_effect = make_result

    budget = RefinementBudget(max_iterations=3, abort_on_no_progress=True)
    refiner = _make_refiner(
        analyzer=analyzer,
        oracle_factory=factory,
        budget=budget,
    )
    result = refiner.refine(_INITIAL_SOURCE, _SEED_INPUTS)

    assert result.status == RefinementStatus.BUDGET_EXHAUSTED
    assert result.iterations == 3
    assert not result.converged


# ---------------------------------------------------------------------------
# Test 5: each round is recorded with tokens and elapsed
# ---------------------------------------------------------------------------


def test_refiner_records_each_round_with_tokens_and_elapsed():
    diverge = _diverge_report()
    equiv = _equiv_report()

    oracle1 = MagicMock()
    oracle1.verify.return_value = diverge
    oracle2 = MagicMock()
    oracle2.verify.return_value = equiv
    factory = MagicMock(side_effect=[oracle1, oracle2])

    llm_result = MagicMock(spec=["content", "tokens_used"])
    llm_result.content = f"```c\n{_REVISED_SOURCE}\n```"
    llm_result.tokens_used = 42
    analyzer = MagicMock()
    analyzer.analyze.return_value = llm_result

    refiner = IterativeRefiner(
        analyzer=analyzer,
        compile_fn=_make_compile_fn(),
        oracle_factory=factory,
        budget=RefinementBudget(max_iterations=5),
    )
    result = refiner.refine(_INITIAL_SOURCE, _SEED_INPUTS)

    assert result.iterations == 1
    round0 = result.rounds[0]
    assert round0.index == 1
    assert round0.tokens_used == 42
    assert round0.elapsed_seconds >= 0.0
    assert result.total_tokens == 42
    assert result.total_elapsed_seconds >= 0.0


# ---------------------------------------------------------------------------
# Test 6: analyzer.analyze raises → LLM_ERROR
# ---------------------------------------------------------------------------


def test_refiner_returns_llm_error_when_analyzer_raises():
    factory = _make_oracle_factory(_diverge_report())
    analyzer = MagicMock()
    analyzer.analyze.side_effect = RuntimeError("connection refused")

    refiner = _make_refiner(analyzer=analyzer, oracle_factory=factory)
    result = refiner.refine(_INITIAL_SOURCE, _SEED_INPUTS)

    assert result.status == RefinementStatus.LLM_ERROR
    assert "connection refused" in result.notes


# ---------------------------------------------------------------------------
# Test 7: wall-clock budget is respected
# ---------------------------------------------------------------------------


def test_refiner_respects_wall_clock_budget():
    """
    Verify that the refiner stops with BUDGET_EXHAUSTED when the wall-clock
    budget is exceeded, even if max_iterations has not been reached.

    Strategy: set max_iterations=1, always-diverging oracle, LLM returns
    different source.  After the one iteration the loop finishes naturally
    as BUDGET_EXHAUSTED (not CONVERGED).  Then we use a tiny max_wall_seconds
    and a real-time sleep to force the clock path, OR we simply verify
    that with max_iterations=1 and no convergence we get BUDGET_EXHAUSTED.

    For determinism we patch time.monotonic so that after the first oracle
    verify the elapsed time exceeds max_wall_seconds.
    """
    diverge = _diverge_report()

    # Factory always returns diverging oracles (unlimited)
    factory = _make_oracle_factory(diverge)

    # LLM always returns a source different from _INITIAL_SOURCE
    analyzer = _make_analyzer(content=f"```c\n{_REVISED_SOURCE}\n```")
    compile_fn = _make_compile_fn()

    # Time sequence:
    #   call 0: wall_start
    #   call 1: round_start (iteration 1)
    #   call 2: time.monotonic() - wall_start for initial compile (not called; after verify)
    #   The wall-clock check fires after oracle verify; we need it to exceed 600 s.
    # Use a counter-based side_effect to return 0 for the first few calls and
    # 800.0 for all subsequent calls so the wall-clock check always triggers.
    call_counter = [0]

    def monotonic_side_effect():
        call_counter[0] += 1
        if call_counter[0] <= 2:
            return 0.0
        return 800.0

    budget = RefinementBudget(max_iterations=5, max_wall_seconds=600.0)
    refiner = IterativeRefiner(
        analyzer=analyzer,
        compile_fn=compile_fn,
        oracle_factory=factory,
        budget=budget,
    )

    with patch("reveng.verification.refinement.refiner.time") as mock_time:
        mock_time.monotonic.side_effect = monotonic_side_effect
        result = refiner.refine(_INITIAL_SOURCE, _SEED_INPUTS)

    assert result.status == RefinementStatus.BUDGET_EXHAUSTED
    assert (
        "Wall-clock" in result.notes
        or "wall" in result.notes.lower()
        or "budget" in result.notes.lower()
    )


# ---------------------------------------------------------------------------
# Test 8: build_refinement_prompt includes all required placeholders
# ---------------------------------------------------------------------------


def test_build_refinement_prompt_includes_all_placeholders():
    divergence = _diverge_report()
    prompt = build_refinement_prompt(
        source=_INITIAL_SOURCE,
        divergence=divergence,
        iteration=2,
        max_iterations=5,
    )

    # Iteration counters
    assert "2" in prompt
    assert "5" in prompt
    # Failing input hex
    assert divergence.failing_inputs[0].hex() in prompt
    # Expected / actual outputs
    assert "expected" in prompt
    assert "actual" in prompt
    # Source embedded
    assert _INITIAL_SOURCE.strip() in prompt
    # Contains the fence instruction
    assert "```c" in prompt


# ---------------------------------------------------------------------------
# Test 9: _extract_code_block handles a ```c fence
# ---------------------------------------------------------------------------


def test_extract_code_block_handles_c_fence():
    code = "int main(void) { return 0; }"
    text = f"Here is the fix:\n```c\n{code}\n```\nThat is all."
    result = _extract_code_block(text)
    assert result == code


# ---------------------------------------------------------------------------
# Test 10: _extract_code_block returns raw text when no fence present
# ---------------------------------------------------------------------------


def test_extract_code_block_returns_raw_when_no_fence_present():
    text = "int main(void) { return 0; }"
    result = _extract_code_block(text)
    assert result == text
