"""Phase 5 thin honesty CI workflow contract."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "wave-c-phase5-honesty.yml"

EXPECTED = (
    "scripts/verify_equivalence_honesty.py",
    "tests/unit/test_equivalence_honesty_gate.py",
    "reports/equivalence_honesty/latest.json",
)


def test_phase5_honesty_workflow_exists():
    assert WORKFLOW.is_file()


def test_phase5_honesty_workflow_fail_closed_and_python39():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'python-version: "3.9"' in text
    assert "verify_equivalence_honesty.py" in text
    assert "pytest --no-cov" in text
    # Must not flip native required or claim full nightly corpus.
    assert "required: true" not in text.lower()
    assert (
        "nightly corpus" in text.lower()
        or "M4 residual" in text
        or "corpus residual" in text.lower()
    )
    for needle in EXPECTED:
        assert needle in text, f"workflow missing {needle}"
