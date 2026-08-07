"""
Phase 4 / VRL-LLM-1 honesty gate — bidirectional + policy predicates.

Fail-first shape:
* claiming measured with <3 seeds must fail
* missing ValidationGrade must never pass
* no-LLM control that *passes* must fail the gate (hollow)
* measured requires ollama_actually_ran
* could_not_measure exits 2 (not a green pass)
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO_ROOT / "scripts" / "verify_vrl_llm_honesty.py"


def _load_gate():
    import sys

    spec = importlib.util.spec_from_file_location("verify_vrl_llm_honesty", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    # Python 3.9 dataclasses need the module present in sys.modules during exec.
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load_gate()


def _base(**overrides):
    payload = {
        "provider": "ollama",
        "min_seeds": 3,
        "runtime_status": "measured",
        "ollama_reachable": True,
        "ollama_actually_ran": True,
        "grades": ["analysis_only", "compile_only", "launches_but_divergent"],
        "control_arm": {"llm_enabled": False, "passed": False},
    }
    payload.update(overrides)
    return payload


def test_measured_happy_path_passes():
    v = gate.evaluate_evidence(_base())
    assert v.exit_code == 0
    assert v.runtime_status == "measured"
    assert v.provider == "ollama"
    assert v.min_seeds == 3


def test_min_seeds_below_policy_cannot_claim_measured():
    v = gate.evaluate_evidence(_base(min_seeds=2))
    assert v.exit_code == 1
    assert any("min_seeds_below_policy" in r for r in v.reasons)


def test_missing_grades_never_pass():
    v = gate.evaluate_evidence(_base(grades=[]))
    assert v.exit_code == 1
    assert "grades_missing" in v.reasons


def test_invalid_grade_never_pass():
    v = gate.evaluate_evidence(_base(grades=["llm_error"]))  # RefinementStatus leak
    assert v.exit_code == 1
    assert any("invalid_grade" in r for r in v.reasons)


def test_no_llm_control_passing_fails_gate_bidirectional():
    """Control arm that passes without LLM ⇒ hollow gate ⇒ fail."""
    v = gate.evaluate_evidence(
        _base(control_arm={"llm_enabled": False, "passed": True})
    )
    assert v.exit_code == 1
    assert "no_llm_control_passed" in v.reasons


def test_no_llm_control_failing_allows_measurement_path():
    v = gate.evaluate_evidence(
        _base(control_arm={"llm_enabled": False, "passed": False})
    )
    assert v.exit_code == 0


def test_measured_requires_ollama_actually_ran():
    v = gate.evaluate_evidence(_base(ollama_actually_ran=False))
    assert v.exit_code == 1
    assert "ollama_did_not_run" in v.reasons


def test_provider_identity_required_when_measured():
    v = gate.evaluate_evidence(_base(provider=""))
    assert v.exit_code == 1
    assert "provider_missing" in v.reasons


def test_could_not_measure_exits_two():
    v = gate.evaluate_evidence(
        _base(
            runtime_status="could_not_measure",
            ollama_reachable=False,
            ollama_actually_ran=False,
            grades=[],
            reason="ollama_unreachable: connection refused on 127.0.0.1:11434",
        )
    )
    assert v.exit_code == 2
    assert v.runtime_status == "could_not_measure"
    assert v.ok is False


def test_write_cnm_evidence_roundtrip(tmp_path: Path):
    out = tmp_path / "latest.json"
    payload = gate.write_could_not_measure_evidence(
        out,
        reason="ollama_unreachable: connection refused on 127.0.0.1:11434",
        ollama_reachable=False,
    )
    assert out.is_file()
    assert payload["runtime_status"] == "could_not_measure"
    assert payload["control_arm"]["passed"] is False
    assert payload["control_arm"]["llm_enabled"] is False
    loaded = json.loads(out.read_text(encoding="utf-8"))
    v = gate.evaluate_evidence(loaded)
    assert v.exit_code == 2


def test_cli_evaluates_cnm_evidence(tmp_path: Path):
    out = tmp_path / "latest.json"
    gate.write_could_not_measure_evidence(
        out,
        reason="ollama_unreachable: connection refused on 127.0.0.1:11434",
    )
    rc = gate.main(["--evidence", str(out)])
    assert rc == 2


def test_cli_rejects_hollow_measured_evidence(tmp_path: Path):
    out = tmp_path / "hollow.json"
    out.write_text(
        json.dumps(
            _base(
                min_seeds=1,
                control_arm={"llm_enabled": False, "passed": True},
            )
        ),
        encoding="utf-8",
    )
    rc = gate.main(["--evidence", str(out)])
    assert rc == 1


def test_is_valid_grade_ladder():
    assert gate.is_valid_grade("behavior_matched")
    assert not gate.is_valid_grade("llm_error")
    assert not gate.is_valid_grade(None)
    assert not gate.is_valid_grade("")


def test_invalid_runtime_status_rejected():
    v = gate.evaluate_evidence(_base(runtime_status="passed"))
    assert v.exit_code == 1
    assert "invalid_runtime_status" in v.reasons
