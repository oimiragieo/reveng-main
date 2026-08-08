"""Wave B honesty CI workflow contract — no hexyl binary required in CI."""

from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
WORKFLOW = REPO / ".github" / "workflows" / "wave-b-honesty.yml"

EXPECTED_TESTS = (
    "tests/unit/test_probe_native_analyze_timeout.py",
    "tests/unit/test_evidence_dir_hygiene.py",
    "tests/unit/test_git_status_scoped.py",
    "tests/unit/test_backlog_wave_a_invariants.py",
    "tests/unit/test_native_fixture_ci_visibility.py",
    "tests/unit/test_df5_process_completed_honesty.py",
)


def test_wave_b_honesty_workflow_exists():
    assert WORKFLOW.is_file()


def test_wave_b_honesty_workflow_uses_python_39_and_no_cov():
    text = WORKFLOW.read_text(encoding="utf-8")
    assert 'python-version: "3.9"' in text
    assert "pytest --no-cov" in text
    assert "hexyl" not in text.lower() or "no hexyl" in text.lower()
    # Must not apt-install or cargo-build hexyl in CI.
    assert "cargo install hexyl" not in text
    assert "apt-get install" not in text or "hexyl" not in text


def test_wave_b_honesty_workflow_lists_contract_tests():
    text = WORKFLOW.read_text(encoding="utf-8")
    for path in EXPECTED_TESTS:
        assert path in text, f"workflow missing {path}"
    assert "M4 residual" in text or "corpus" in text.lower()
