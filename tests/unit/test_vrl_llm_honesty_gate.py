"""
Phase 4 / VRL-LLM-1 honesty gate — bidirectional + policy predicates.

Fail-first shape:
* claiming measured with <3 seeds must fail
* missing ValidationGrade must never pass
* no-LLM control that *passes* must fail the gate (hollow)
* measured requires ollama_actually_ran
* measured requires seed_runs (≥3 distinct executed seed_ids); legacy grades alone never unlock exit 0
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


def _seed_runs(*grades, executed=True):
    """Build gate-consumable seed_runs rows (one per grade)."""
    rows = []
    for idx, grade in enumerate(grades):
        rows.append(
            {
                "seed_id": f"seed_{idx}",
                "grade": grade,
                "argv": [f"--seed={idx}"],
                "executed": executed,
            }
        )
    return rows


def _base(**overrides):
    payload = {
        "provider": "ollama",
        "min_seeds": 3,
        "runtime_status": "measured",
        "ollama_reachable": True,
        "ollama_actually_ran": True,
        "grades": ["analysis_only", "compile_only", "launches_but_divergent"],
        "seed_runs": _seed_runs(
            "analysis_only", "compile_only", "launches_but_divergent"
        ),
        "control_arm": {
            "llm_enabled": False,
            "passed": False,
            "executed": True,
        },
    }
    payload.update(overrides)
    return payload


def test_measured_happy_path_passes():
    v = gate.evaluate_evidence(_base())
    assert v.exit_code == 0
    assert v.runtime_status == "measured"
    assert v.provider == "ollama"
    assert v.min_seeds == 3


def test_measured_legacy_grades_only_fails():
    """Bare grades list alone must never unlock measured exit 0 (Sol Round-3)."""
    payload = _base(
        grades=["analysis_only", "compile_only", "launches_but_divergent"]
    )
    del payload["seed_runs"]
    v = gate.evaluate_evidence(payload)
    assert v.exit_code == 1
    assert any("seed_runs_required" in r for r in v.reasons)


def test_min_seeds_below_policy_cannot_claim_measured():
    v = gate.evaluate_evidence(_base(min_seeds=2))
    assert v.exit_code == 1
    assert any("min_seeds_below_policy" in r for r in v.reasons)


def test_missing_grades_never_pass():
    v = gate.evaluate_evidence(
        _base(
            grades=[],
            seed_runs=[
                {"seed_id": "a", "argv": ["x"], "executed": True},
                {"seed_id": "b", "argv": ["y"], "executed": True},
                {"seed_id": "c", "argv": ["z"], "executed": True},
            ],
        )
    )
    assert v.exit_code == 1
    assert "grades_missing" in v.reasons


def test_measured_with_min_seeds_field_but_one_grade_fails():
    """Declaring min_seeds: 3 with a single grade must FAIL (Sol HIGH 1)."""
    v = gate.evaluate_evidence(
        _base(
            min_seeds=3,
            grades=["analysis_only"],
            seed_runs=_seed_runs("analysis_only"),
        )
    )
    assert v.exit_code == 1
    assert any("grades_below_min_seeds" in r for r in v.reasons)


def test_invalid_grade_never_pass():
    v = gate.evaluate_evidence(
        _base(grades=["llm_error"], seed_runs=_seed_runs("llm_error"))
    )  # RefinementStatus leak
    assert v.exit_code == 1
    assert any("invalid_grade" in r for r in v.reasons)


def test_seed_runs_derive_grades_and_require_three_executed():
    """When seed_runs present, gate derives grades from executed runs (Sol HIGH 2)."""
    seed_runs = _seed_runs(
        "analysis_only", "compile_only", "launches_but_divergent"
    )
    v = gate.evaluate_evidence(_base(grades=[], seed_runs=seed_runs))
    assert v.exit_code == 0
    assert v.runtime_status == "measured"


def test_measured_three_duplicate_seed_ids_fails():
    """Three executed rows with the same seed_id must FAIL (Sol Round-2 CRITICAL)."""
    seed_runs = [
        {
            "seed_id": "hexyl:same",
            "grade": "analysis_only",
            "argv": ["--help"],
            "executed": True,
        },
        {
            "seed_id": "hexyl:same",
            "grade": "compile_only",
            "argv": ["--version"],
            "executed": True,
        },
        {
            "seed_id": "hexyl:same",
            "grade": "launches_but_divergent",
            "argv": ["sample.bin"],
            "executed": True,
        },
    ]
    v = gate.evaluate_evidence(_base(grades=[], seed_runs=seed_runs))
    assert v.exit_code == 1
    assert any("seed_ids_not_distinct" in r for r in v.reasons)


def test_measured_three_distinct_seed_ids_passes():
    """≥3 executed rows with unique seed_ids + valid grades may claim measured."""
    seed_runs = _seed_runs(
        "analysis_only", "compile_only", "launches_but_divergent"
    )
    assert len({r["seed_id"] for r in seed_runs}) == 3
    v = gate.evaluate_evidence(_base(grades=[], seed_runs=seed_runs))
    assert v.exit_code == 0
    assert v.runtime_status == "measured"
    assert not any("seed_ids_not_distinct" in r for r in v.reasons)


def test_seed_runs_with_fewer_than_three_executed_fails():
    seed_runs = _seed_runs("analysis_only", "compile_only")
    v = gate.evaluate_evidence(_base(grades=[], seed_runs=seed_runs))
    assert v.exit_code == 1
    assert any(
        "grades_below_min_seeds" in r
        or "seed_runs_below" in r
        or "seed_ids_not_distinct" in r
        for r in v.reasons
    )


def test_seed_runs_unexecuted_rows_do_not_count():
    seed_runs = _seed_runs(
        "analysis_only", "compile_only", "launches_but_divergent", executed=False
    )
    v = gate.evaluate_evidence(_base(grades=[], seed_runs=seed_runs))
    assert v.exit_code == 1


def test_legacy_grades_still_require_three_for_measured():
    """Legacy grades without seed_runs never unlock measured (informational only)."""
    payload = _base(grades=["analysis_only", "compile_only"])
    del payload["seed_runs"]
    v = gate.evaluate_evidence(payload)
    assert v.exit_code == 1
    assert any("seed_runs_required" in r for r in v.reasons)


def test_no_llm_control_passing_fails_gate_bidirectional():
    """Control arm that passes without LLM ⇒ hollow gate ⇒ fail."""
    v = gate.evaluate_evidence(
        _base(
            control_arm={
                "llm_enabled": False,
                "passed": True,
                "executed": True,
            }
        )
    )
    assert v.exit_code == 1
    assert "no_llm_control_passed" in v.reasons


def test_no_llm_control_failing_allows_measurement_path():
    v = gate.evaluate_evidence(
        _base(
            control_arm={
                "llm_enabled": False,
                "passed": False,
                "executed": True,
            }
        )
    )
    assert v.exit_code == 0


def test_unexecuted_control_cannot_claim_passed_false_as_executed_fail():
    """Phantom control fail (executed:false + passed:false) must not unlock measured."""
    v = gate.evaluate_evidence(
        _base(
            control_arm={
                "llm_enabled": False,
                "passed": False,
                "executed": False,
            }
        )
    )
    assert v.exit_code == 1
    assert "control_arm_not_executed" in v.reasons


def test_cnm_with_unexecuted_control_omits_phantom_fail():
    """CNM may stamp executed:false without claiming a failed control that never ran."""
    v = gate.evaluate_evidence(
        _base(
            runtime_status="could_not_measure",
            ollama_reachable=False,
            ollama_actually_ran=False,
            grades=[],
            control_arm={"llm_enabled": False, "executed": False},
            reason="ollama_unreachable: connection refused on 127.0.0.1:11434",
        )
    )
    assert v.exit_code == 2
    assert "control_arm_passed_not_bool_false" not in v.reasons
    assert "control_arm_not_executed" not in v.reasons


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
            control_arm={"llm_enabled": False, "executed": False},
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
    assert payload["control_arm"]["executed"] is False
    assert payload["control_arm"].get("passed") is None
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
                control_arm={
                    "llm_enabled": False,
                    "passed": True,
                    "executed": True,
                },
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


def test_resolve_ollama_tags_url_default():
    assert (
        gate.resolve_ollama_tags_url(environ={})
        == "http://127.0.0.1:11434/api/tags"
    )


def test_resolve_ollama_tags_url_from_ollama_host(monkeypatch):
    monkeypatch.delenv("REVENG_OLLAMA_HOST", raising=False)
    monkeypatch.setenv("OLLAMA_HOST", "http://172.28.160.1:11434")
    assert (
        gate.resolve_ollama_tags_url()
        == "http://172.28.160.1:11434/api/tags"
    )


def test_resolve_ollama_tags_url_bare_host_and_reveng_override():
    assert (
        gate.resolve_ollama_tags_url(
            environ={"OLLAMA_HOST": "10.0.0.1:11434"}
        )
        == "http://10.0.0.1:11434/api/tags"
    )
    assert (
        gate.resolve_ollama_tags_url(
            environ={
                "OLLAMA_HOST": "http://ignored:1",
                "REVENG_OLLAMA_HOST": "http://override:11434",
            }
        )
        == "http://override:11434/api/tags"
    )


def test_probe_ollama_uses_resolved_host(monkeypatch):
    """--probe-ollama / probe_ollama must hit OLLAMA_HOST, not hardcoded localhost."""
    seen = {}

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def _fake_urlopen(url, timeout=None):
        seen["url"] = url
        seen["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr(gate.urllib.request, "urlopen", _fake_urlopen)
    ok = gate.probe_ollama(environ={"OLLAMA_HOST": "http://172.28.160.1:11434"})
    assert ok is True
    assert seen["url"] == "http://172.28.160.1:11434/api/tags"


def test_cli_probe_ollama_prints_resolved_url(monkeypatch, capsys):
    monkeypatch.setenv("OLLAMA_HOST", "http://172.28.160.1:11434")
    monkeypatch.delenv("REVENG_OLLAMA_HOST", raising=False)

    class _Resp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        gate.urllib.request, "urlopen", lambda url, timeout=None: _Resp()
    )
    rc = gate.main(["--probe-ollama"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ollama_reachable"] is True
    assert payload["url"] == "http://172.28.160.1:11434/api/tags"


def test_write_cnm_reason_includes_resolved_url(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://172.28.160.1:11434")
    out = tmp_path / "latest.json"
    tags = gate.resolve_ollama_tags_url()
    payload = gate.write_could_not_measure_evidence(
        out,
        reason=f"ollama_unreachable: connection refused at {tags}",
        ollama_reachable=False,
        ollama_tags_url=tags,
    )
    assert "172.28.160.1:11434" in payload["reason"]
    assert payload["ollama_tags_url"] == tags


def test_build_seed_run_log_schema_helper():
    """run_vrl helper emits gate-consumable seed_runs without inventing measured grades."""
    import importlib.util
    import sys

    run_vrl_path = _REPO_ROOT / "scripts" / "run_vrl.py"
    spec = importlib.util.spec_from_file_location("run_vrl_honesty_schema", run_vrl_path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    rows = mod.build_seed_runs_for_log(
        [
            {"seed_id": "a", "argv": ["--help"], "grade": "analysis_only", "executed": True},
            {"seed_id": "b", "argv": ["x"], "grade": "compile_only", "executed": True},
            {
                "seed_id": "c",
                "argv": ["y"],
                "grade": "launches_but_divergent",
                "executed": True,
            },
        ]
    )
    assert len(rows) == 3
    assert rows[0]["seed_id"] == "a"
    assert rows[0]["executed"] is True
    assert "grade" in rows[0]
    assert "argv" in rows[0]

    # Empty / not-yet-run path: writer exists, does not fake grades.
    empty = mod.build_seed_runs_for_log([])
    assert empty == []

    # Declared corpus seeds → one row per seed; unrun stay executed=false.
    declared = ["--help", "--version", "tests/fixtures/hexyl/sample.bin"]
    first_id = mod._seed_identity("hexyl", 0, "--help")
    expanded = mod.build_seed_runs_for_log(
        declared_seeds=declared,
        binary_name="hexyl",
        executed_seed_ids=[first_id],
        grade_by_seed_id={first_id: "analysis_only"},
    )
    assert len(expanded) == 3
    assert len({r["seed_id"] for r in expanded}) == 3
    assert expanded[0]["executed"] is True
    assert expanded[0]["grade"] == "analysis_only"
    assert expanded[1]["executed"] is False
    assert expanded[1]["grade"] is None
    assert expanded[2]["executed"] is False
    assert sum(1 for r in expanded if r["executed"]) == 1
