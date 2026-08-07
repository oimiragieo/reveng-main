"""Phase 5 equivalence honesty gate — bidirectional empty/valid evidence.

Fail-first shape:
* missing evidence file / empty object / empty grade must fail
* valid ValidationGrade ladder + measured status must pass
* emit path writes a real grade into a report path (not unit-only)
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "verify_equivalence_honesty.py"
_TRACKED = _REPO_ROOT / "reports" / "equivalence_honesty" / "latest.json"


def _load_gate():
    spec = importlib.util.spec_from_file_location("verify_equivalence_honesty", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def gate():
    assert _SCRIPT.is_file(), "scripts/verify_equivalence_honesty.py must exist"
    return _load_gate()


def _valid(**overrides):
    payload = {
        "schema_version": 1,
        "runtime_status": "measured",
        "validation_grade": "partial_equivalence",
        "subject_id": "equiv_honesty_micro",
        "seed_results": [
            {"seed_id": "help", "matched": True, "argv": ["--help"]},
            {"seed_id": "sample", "matched": True, "argv": ["sample"]},
        ],
        "policy": {
            "empty_evidence_fails": True,
            "native_required_true_forbidden": True,
            "source": "docs/architecture/decision-phase-05-thin-honesty-auth.md",
        },
    }
    payload.update(overrides)
    return payload


def test_valid_measured_passes(gate):
    v = gate.evaluate_evidence(_valid())
    assert v.exit_code == 0
    assert v.runtime_status == "measured"
    assert v.validation_grade == "partial_equivalence"


def test_empty_object_fails(gate):
    v = gate.evaluate_evidence({})
    assert v.exit_code == 1
    assert "evidence_empty" in v.reasons or "grade_missing" in v.reasons


def test_missing_grade_fails(gate):
    payload = _valid()
    del payload["validation_grade"]
    v = gate.evaluate_evidence(payload)
    assert v.exit_code == 1
    assert "grade_missing" in v.reasons


def test_empty_string_grade_fails(gate):
    v = gate.evaluate_evidence(_valid(validation_grade=""))
    assert v.exit_code == 1
    assert "grade_missing" in v.reasons or "invalid_grade" in "".join(v.reasons)


def test_invalid_grade_fails(gate):
    v = gate.evaluate_evidence(_valid(validation_grade="totally_equivalent_ship_it"))
    assert v.exit_code == 1
    assert any("invalid_grade" in r for r in v.reasons)


def test_missing_file_exits_nonzero(gate, tmp_path):
    missing = tmp_path / "absent.json"
    code = gate.main(["--evidence", str(missing)])
    assert code != 0


def test_empty_json_object_file_fails(gate, tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("{}\n", encoding="utf-8")
    code = gate.main(["--evidence", str(path)])
    assert code == 1


def test_emit_report_writes_nonzero_grade(gate, tmp_path):
    out = tmp_path / "latest.json"
    code = gate.main(["--emit-report", "--evidence", str(out)])
    assert code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data.get("runtime_status") == "measured"
    assert data.get("validation_grade") in gate.VALIDATION_GRADE_LADDER
    assert data.get("validation_grade") not in ("", None, "unknown")
    assert isinstance(data.get("seed_results"), list) and data["seed_results"]


def test_tracked_report_exists_and_passes_gate(gate):
    """Committed customer evidence must be present and fail-closed green."""
    assert _TRACKED.is_file(), "reports/equivalence_honesty/latest.json must be tracked"
    text = _TRACKED.read_text(encoding="utf-8").strip()
    assert text, "tracked equivalence report must not be empty"
    data = json.loads(text)
    assert data, "tracked equivalence report must not be {}"
    v = gate.evaluate_evidence(data)
    assert v.exit_code == 0
    code = gate.main(["--evidence", str(_TRACKED)])
    assert code == 0
