"""
Unit tests for scripts/run_vrl.py.

All external dependencies (get_analyzer, make_compile_fn, make_oracle_factory,
IterativeRefiner, yaml loading, filesystem writes) are mocked so tests run
fully offline with no real binaries, compilers, or AI providers.
"""

from __future__ import annotations

import importlib
import json
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, call, patch

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helpers to import run_vrl from scripts/ (not on sys.path by default)
# ---------------------------------------------------------------------------

_SCRIPTS_DIR = Path(__file__).resolve().parent.parent.parent / "scripts"


def _import_run_vrl():
    """Return the run_vrl module, inserting scripts/ onto sys.path if needed."""
    if str(_SCRIPTS_DIR) not in sys.path:
        sys.path.insert(0, str(_SCRIPTS_DIR))
    import importlib

    if "run_vrl" in sys.modules:
        return sys.modules["run_vrl"]
    return importlib.import_module("run_vrl")


run_vrl = _import_run_vrl()

# ---------------------------------------------------------------------------
# Shared corpus YAML fixture
# ---------------------------------------------------------------------------

_MINIMAL_CORPUS = {
    "schema_version": 1,
    "binaries": [
        {
            "name": "hexyl",
            "current_grade": "compile_only",
            "target_grade": "behavior_matched",
            "category": "rust-cli-utility",
        },
        {
            "name": "fd",
            "current_grade": "unknown",
            "target_grade": "behavior_matched",
            "category": "rust-cli-utility",
        },
    ],
}

_CORPUS_YAML_TEXT = yaml.dump(_MINIMAL_CORPUS)


def _make_mock_result(status_value: str = "budget_exhausted", iterations: int = 2) -> MagicMock:
    """Build a fake RefinementResult-like object."""
    from reveng.verification.refinement.models import RefinementResult, RefinementStatus

    result = MagicMock(spec=RefinementResult)
    result.status = RefinementStatus(status_value)
    result.iterations = iterations
    result.total_elapsed_seconds = 4.2
    result.total_tokens = 1024
    result.notes = f"Ran {iterations} iterations."
    # No verified divergence report by default → grade resolver uses the
    # status-based fallback (a real ValidationGrade ladder value, never the
    # RefinementStatus string).
    result.final_divergence = None
    return result


# ---------------------------------------------------------------------------
# Test 1 — full happy path: mocked run produces a JSON log
# ---------------------------------------------------------------------------


def test_main_happy_path_produces_json_log(tmp_path: Path) -> None:
    """
    When all components are mocked and refiner.refine() returns a result,
    main() should write a JSON log file under .reveng/vrl-runs/.
    """
    corpus_file = tmp_path / "corpus.yaml"
    corpus_file.write_text(_CORPUS_YAML_TEXT, encoding="utf-8")

    original_binary = tmp_path / "hexyl.exe"
    original_binary.write_bytes(b"\x4d\x5a")  # dummy PE magic

    runs_dir = tmp_path / "runs"
    workspace_base = tmp_path / "workspaces"

    mock_result = _make_mock_result("budget_exhausted", iterations=2)

    with (
        patch.object(run_vrl, "_CORPUS_YAML", corpus_file),
        patch.object(run_vrl, "_RUNS_DIR", runs_dir),
        patch.object(run_vrl, "_WORKSPACE_BASE", workspace_base),
        patch.object(run_vrl, "_load_initial_source", return_value="/* stub */"),
        patch.object(run_vrl, "_resolve_binary_path", return_value=original_binary),
        patch("reveng.agents.ai.ai_analyzer_enhanced.get_analyzer") as mock_get_analyzer,
        patch("reveng.verification.refinement.compile_adapter.make_compile_fn") as mock_compile,
        patch("reveng.verification.refinement.oracle_adapter.make_oracle_factory") as mock_oracle,
        patch("reveng.verification.refinement.refiner.IterativeRefiner") as mock_refiner_cls,
    ):
        mock_get_analyzer.return_value = MagicMock()
        mock_compile.return_value = MagicMock()
        mock_oracle.return_value = MagicMock()
        mock_instance = MagicMock()
        mock_instance.refine.return_value = mock_result
        mock_refiner_cls.return_value = mock_instance

        rc = run_vrl.main(
            ["--binary", "hexyl", "--max-iterations", "2", "--workspace", str(workspace_base)]
        )

    assert rc == 0
    log_files = list(runs_dir.glob("hexyl-*.json"))
    assert len(log_files) == 1, f"Expected one JSON log, found: {log_files}"

    log_data = json.loads(log_files[0].read_text(encoding="utf-8"))
    assert log_data["binary_name"] == "hexyl"
    assert log_data["iterations"] == 2
    assert "final_grade" in log_data
    assert "date" in log_data


# ---------------------------------------------------------------------------
# Test 2 — --binary arg selects the correct corpus entry
# ---------------------------------------------------------------------------


def test_binary_arg_selects_correct_corpus_entry(tmp_path: Path) -> None:
    """
    Passing --binary fd should resolve the fd entry, not hexyl.
    """
    corpus_file = tmp_path / "corpus.yaml"
    corpus_file.write_text(_CORPUS_YAML_TEXT, encoding="utf-8")

    original_binary = tmp_path / "fd.exe"
    original_binary.write_bytes(b"\x4d\x5a")

    runs_dir = tmp_path / "runs"
    workspace_base = tmp_path / "workspaces"

    mock_result = _make_mock_result("budget_exhausted", iterations=1)

    with (
        patch.object(run_vrl, "_CORPUS_YAML", corpus_file),
        patch.object(run_vrl, "_RUNS_DIR", runs_dir),
        patch.object(run_vrl, "_WORKSPACE_BASE", workspace_base),
        patch.object(run_vrl, "_load_initial_source", return_value="/* stub */"),
        patch.object(run_vrl, "_resolve_binary_path", return_value=original_binary),
        patch("reveng.agents.ai.ai_analyzer_enhanced.get_analyzer", return_value=MagicMock()),
        patch(
            "reveng.verification.refinement.compile_adapter.make_compile_fn",
            return_value=MagicMock(),
        ),
        patch(
            "reveng.verification.refinement.oracle_adapter.make_oracle_factory",
            return_value=MagicMock(),
        ),
        patch("reveng.verification.refinement.refiner.IterativeRefiner") as mock_refiner_cls,
    ):
        mock_instance = MagicMock()
        mock_instance.refine.return_value = mock_result
        mock_refiner_cls.return_value = mock_instance

        rc = run_vrl.main(
            ["--binary", "fd", "--max-iterations", "1", "--workspace", str(workspace_base)]
        )

    assert rc == 0
    log_files = list(runs_dir.glob("fd-*.json"))
    assert len(log_files) == 1
    log_data = json.loads(log_files[0].read_text(encoding="utf-8"))
    assert log_data["binary_name"] == "fd"


# ---------------------------------------------------------------------------
# Test 3 — corpus.yaml not found → clear error, exit code 1
# ---------------------------------------------------------------------------


def test_missing_corpus_yaml_returns_error(tmp_path: Path) -> None:
    """When corpus.yaml does not exist, main() should return 1."""
    missing_corpus = tmp_path / "nonexistent" / "corpus.yaml"

    with patch.object(run_vrl, "_CORPUS_YAML", missing_corpus):
        rc = run_vrl.main(["--binary", "hexyl"])

    assert rc == 1


# ---------------------------------------------------------------------------
# Test 4 — binary not in corpus → clear error, exit code 1
# ---------------------------------------------------------------------------


def test_binary_not_in_corpus_returns_error(tmp_path: Path) -> None:
    """When the requested binary is absent from corpus.yaml, return 1."""
    corpus_file = tmp_path / "corpus.yaml"
    corpus_file.write_text(_CORPUS_YAML_TEXT, encoding="utf-8")

    with patch.object(run_vrl, "_CORPUS_YAML", corpus_file):
        rc = run_vrl.main(["--binary", "nonexistent_binary_xyz"])

    assert rc == 1


# ---------------------------------------------------------------------------
# Test 5 — result grade is recorded in the corpus update call
# ---------------------------------------------------------------------------


def test_result_grade_recorded_in_corpus_update(tmp_path: Path) -> None:
    """
    The final_grade from refiner.refine() should be passed to
    _update_corpus_grade().
    """
    corpus_file = tmp_path / "corpus.yaml"
    corpus_file.write_text(_CORPUS_YAML_TEXT, encoding="utf-8")

    original_binary = tmp_path / "hexyl.exe"
    original_binary.write_bytes(b"\x4d\x5a")

    runs_dir = tmp_path / "runs"
    workspace_base = tmp_path / "workspaces"

    # converged status → grade should be "converged"
    mock_result = _make_mock_result("converged", iterations=1)

    with (
        patch.object(run_vrl, "_CORPUS_YAML", corpus_file),
        patch.object(run_vrl, "_RUNS_DIR", runs_dir),
        patch.object(run_vrl, "_WORKSPACE_BASE", workspace_base),
        patch.object(run_vrl, "_load_initial_source", return_value="/* stub */"),
        patch.object(run_vrl, "_resolve_binary_path", return_value=original_binary),
        patch.object(run_vrl, "_update_corpus_grade") as mock_update,
        patch("reveng.agents.ai.ai_analyzer_enhanced.get_analyzer", return_value=MagicMock()),
        patch(
            "reveng.verification.refinement.compile_adapter.make_compile_fn",
            return_value=MagicMock(),
        ),
        patch(
            "reveng.verification.refinement.oracle_adapter.make_oracle_factory",
            return_value=MagicMock(),
        ),
        patch("reveng.verification.refinement.refiner.IterativeRefiner") as mock_refiner_cls,
    ):
        mock_instance = MagicMock()
        mock_instance.refine.return_value = mock_result
        mock_refiner_cls.return_value = mock_instance

        rc = run_vrl.main(
            ["--binary", "hexyl", "--max-iterations", "1", "--workspace", str(workspace_base)]
        )

    assert rc == 0
    mock_update.assert_called_once()
    _path, _name, grade = mock_update.call_args[0]
    # Grade is a ValidationGrade ladder value, NOT the RefinementStatus string.
    # CONVERGED (with no divergence report) maps to behavior_matched.
    assert grade == "behavior_matched", f"Expected grade='behavior_matched', got {grade!r}"


# ---------------------------------------------------------------------------
# Test 6 — JSON log contains required fields with correct values
# ---------------------------------------------------------------------------


def test_json_log_fields_are_correct(tmp_path: Path) -> None:
    """
    The written JSON log must contain binary_name, date, final_grade,
    iterations, and status with values that match the run result.
    """
    corpus_file = tmp_path / "corpus.yaml"
    corpus_file.write_text(_CORPUS_YAML_TEXT, encoding="utf-8")

    original_binary = tmp_path / "hexyl.exe"
    original_binary.write_bytes(b"\x4d\x5a")

    runs_dir = tmp_path / "runs"
    workspace_base = tmp_path / "workspaces"

    mock_result = _make_mock_result("no_progress", iterations=3)

    with (
        patch.object(run_vrl, "_CORPUS_YAML", corpus_file),
        patch.object(run_vrl, "_RUNS_DIR", runs_dir),
        patch.object(run_vrl, "_WORKSPACE_BASE", workspace_base),
        patch.object(run_vrl, "_load_initial_source", return_value="/* stub */"),
        patch.object(run_vrl, "_resolve_binary_path", return_value=original_binary),
        patch("reveng.agents.ai.ai_analyzer_enhanced.get_analyzer", return_value=MagicMock()),
        patch(
            "reveng.verification.refinement.compile_adapter.make_compile_fn",
            return_value=MagicMock(),
        ),
        patch(
            "reveng.verification.refinement.oracle_adapter.make_oracle_factory",
            return_value=MagicMock(),
        ),
        patch("reveng.verification.refinement.refiner.IterativeRefiner") as mock_refiner_cls,
    ):
        mock_instance = MagicMock()
        mock_instance.refine.return_value = mock_result
        mock_refiner_cls.return_value = mock_instance

        rc = run_vrl.main(
            ["--binary", "hexyl", "--max-iterations", "3", "--workspace", str(workspace_base)]
        )

    assert rc == 0

    log_files = list(runs_dir.glob("hexyl-*.json"))
    assert len(log_files) == 1
    log_data = json.loads(log_files[0].read_text(encoding="utf-8"))

    # Required fields
    assert log_data["binary_name"] == "hexyl"
    assert log_data["iterations"] == 3
    assert log_data["status"] == "no_progress"
    # final_grade is now a ValidationGrade ladder value (not the status string).
    # NO_PROGRESS with no divergence report falls back to analysis_only.
    assert log_data["final_grade"] == "analysis_only"
    # Date must be a valid ISO date string
    from datetime import date

    parsed_date = date.fromisoformat(log_data["date"])
    assert parsed_date is not None
