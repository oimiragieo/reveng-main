"""
Regression tests for ValidationGrade vs RefinementStatus handling (VRL Task 1.8).

Three bugs are covered:

1. ``run_vrl`` wrote ``result.status.value`` (a RefinementStatus like
   ``"llm_error"``) into the corpus ``current_grade`` field, which expects a
   ValidationGrade ladder value.  The grade must come from
   ``result.final_divergence.grade``.

2. ``result.final_divergence`` may be ``None`` on LLM_ERROR / timeout — the
   grade resolver must fall back to a valid ladder value (never None / null /
   AttributeError).

3. ``_update_corpus_grade`` matched the binary entry with a substring test
   (``binary_name in line``), so ``"hex"`` would wrongly match ``"hexyl"``.
   The match must be exact.
"""

import importlib.util
from pathlib import Path

# ---------------------------------------------------------------------------
# Import run_vrl.py as a module (it lives in scripts/, not on the package path)
# ---------------------------------------------------------------------------
_REPO_ROOT = Path(__file__).resolve().parents[2]
_RUN_VRL_PATH = _REPO_ROOT / "scripts" / "run_vrl.py"
_spec = importlib.util.spec_from_file_location("run_vrl_under_test", _RUN_VRL_PATH)
run_vrl = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_vrl)

from reveng.verification.models import (  # noqa: E402
    DivergenceReport,
    VerificationVerdict,
)
from reveng.verification.refinement.models import (  # noqa: E402
    RefinementResult,
    RefinementStatus,
)

# Valid ladder values (ascending) from .reveng/benchmarks/corpus.yaml.
_VALID_GRADES = {
    "unknown",
    "analysis_only",
    "compile_only",
    "structural_candidate",
    "launches_but_divergent",
    "partial_equivalence",
    "behavior_matched",
    "source_reconstruction_match",
    "evidence_backed",
}


def test_converged_result_yields_ladder_grade() -> None:
    """A CONVERGED result carries a DivergenceReport.grade ladder value."""
    report = DivergenceReport(
        verdict=VerificationVerdict.EQUIVALENT,
        iterations=3,
        grade="behavior_matched",
    )
    result = RefinementResult(
        status=RefinementStatus.CONVERGED,
        final_divergence=report,
    )
    grade = run_vrl._grade_for_result(result)
    assert grade == "behavior_matched"
    assert grade in _VALID_GRADES
    # never the RefinementStatus value
    assert grade != result.status.value


def test_llm_error_with_none_divergence_falls_back() -> None:
    """LLM_ERROR with final_divergence=None must yield a valid fallback grade."""
    result = RefinementResult(
        status=RefinementStatus.LLM_ERROR,
        final_divergence=None,
        notes="provider exploded",
    )
    grade = run_vrl._grade_for_result(result)
    # Must be a real ladder grade, never None / "llm_error" / a status value.
    assert grade is not None
    assert grade in _VALID_GRADES
    assert grade != "llm_error"


def test_update_corpus_grade_exact_name_not_substring(tmp_path: Path) -> None:
    """``hex`` must NOT match ``hexyl`` — entry matching is exact."""
    corpus = tmp_path / "corpus.yaml"
    corpus.write_text(
        "binaries:\n"
        "  - name: hexyl\n"
        "    current_grade: unknown\n"
        "  - name: hex\n"
        "    current_grade: unknown\n",
        encoding="utf-8",
    )

    run_vrl._update_corpus_grade(corpus, "hex", "behavior_matched")
    text = corpus.read_text(encoding="utf-8")

    # Only the 'hex' entry's grade changes; 'hexyl' stays untouched.
    lines = text.splitlines()
    hexyl_idx = next(i for i, ln in enumerate(lines) if "name: hexyl" in ln)
    hex_idx = next(i for i, ln in enumerate(lines) if ln.strip() == "- name: hex")

    assert "unknown" in lines[hexyl_idx + 1]  # hexyl unchanged
    assert "behavior_matched" in lines[hex_idx + 1]  # hex updated


def test_grade_for_result_never_writes_none() -> None:
    """No status path may produce None (would write 'null' into the corpus)."""
    for status in RefinementStatus:
        result = RefinementResult(status=status, final_divergence=None)
        grade = run_vrl._grade_for_result(result)
        assert grade is not None
        assert isinstance(grade, str)
        assert grade in _VALID_GRADES
