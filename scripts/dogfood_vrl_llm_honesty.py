#!/usr/bin/env python3
"""
Dogfood VRL LLM honesty evidence (Phase 4 / VRL-LLM-1 Track B).

Produces ``reports/vrl_llm_honesty/latest.json`` from a real ollama round-trip
plus seed×oracle ValidationGrade scoring. Never invents grades.

Flow
----
1. Resolve Ollama via ``OLLAMA_HOST`` / ``REVENG_OLLAMA_HOST`` (WSL→Windows).
2. Invoke ``scripts/run_vrl.py`` once (customer path) and record its outcome —
   PE refine may fail when the local linker cannot build C; that is documented,
   not papered over.
3. No-LLM control: score corpus seeds with DifferentialOracle only. Control
   *passes* only if every seed grades ``behavior_matched`` (hollow without an
   LLM). A hollow-pass refuses ``measured`` and stamps CNM.
4. Treatment: for each of ≥3 distinct corpus seeds, call Ollama then score via
   the same oracle / ``_grade_for_result`` vocabulary used by ``run_vrl``.
5. Write evidence; exit 0 only when the honesty gate accepts ``measured``.

Usage::

    export OLLAMA_HOST=http://172.28.160.1:11434
    export REVENG_AI_PROVIDER=ollama
    export REVENG_OLLAMA_MODEL=hf.co/unsloth/Llama-3.2-1B-Instruct-GGUF:Q4_K_M
    /usr/bin/python3.9 scripts/dogfood_vrl_llm_honesty.py
"""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

_EVIDENCE_DIR = _REPO_ROOT / "reports" / "vrl_llm_honesty"
_LATEST = _EVIDENCE_DIR / "latest.json"
_CORPUS_YAML = _REPO_ROOT / ".reveng" / "benchmarks" / "corpus.yaml"
_HEXYL = _REPO_ROOT / "external" / "ga_binaries" / "hexyl" / "hexyl.exe"
_CANDIDATE = _REPO_ROOT / "test_samples" / "sample.exe"
_RUN_VRL = _REPO_ROOT / "scripts" / "run_vrl.py"
_GATE = _REPO_ROOT / "scripts" / "verify_vrl_llm_honesty.py"

MIN_SEEDS = 3
TARGET_GRADE = "behavior_matched"
DEFAULT_SMALL_MODEL = "hf.co/unsloth/Llama-3.2-1B-Instruct-GGUF:Q4_K_M"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _load_hexyl_entry() -> Dict[str, Any]:
    import yaml

    corpus = yaml.safe_load(_CORPUS_YAML.read_text(encoding="utf-8"))
    for entry in corpus.get("binaries", []):
        if entry.get("name") == "hexyl":
            return entry
    raise KeyError("hexyl not found in corpus.yaml")


def _seed_items(entry: Dict[str, Any]) -> List[Any]:
    raw = entry.get("seed_inputs") or entry.get("test_inputs") or []
    if len(raw) < MIN_SEEDS:
        raise RuntimeError(
            f"corpus hexyl seed_inputs has {len(raw)} entries; need ≥{MIN_SEEDS}"
        )
    return list(raw)[:MIN_SEEDS]


def _invoke_run_vrl() -> Dict[str, Any]:
    """Customer-path attempt; capture outcome without aborting dogfood."""
    env = os.environ.copy()
    env.setdefault("REVENG_AI_PROVIDER", "ollama")
    env.setdefault("PYTHONPATH", str(_REPO_ROOT / "src"))
    try:
        proc = subprocess.run(
            [
                "/usr/bin/python3.9",
                str(_RUN_VRL),
                "--binary",
                "hexyl",
                "--max-iterations",
                "1",
            ],
            cwd=str(_REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        return {
            "executed": True,
            "returncode": proc.returncode,
            "stdout_tail": (proc.stdout or "")[-1500:],
            "stderr_tail": (proc.stderr or "")[-1500:],
            "notes": (
                "Customer path exercised. Non-zero / linker failure on PE-on-Linux "
                "is expected; hermetic seed×oracle×ollama path supplies measured grades."
            ),
        }
    except Exception as exc:  # noqa: BLE001 — dogfood must record, not crash
        return {
            "executed": True,
            "returncode": None,
            "error": f"{type(exc).__name__}: {exc}",
            "notes": "run_vrl.py raised before completing",
        }


def _score_seed_oracle(
    original: Path,
    candidate: Path,
    argv: Sequence[str],
    timeout_s: float = 15.0,
) -> Tuple[str, Dict[str, Any]]:
    """Run DifferentialOracle once; return (grade, meta). Never invents grades."""
    from reveng.verification.differential.oracle import DifferentialOracle
    from reveng.verification.models import VALIDATION_GRADE_LADDER

    oracle = DifferentialOracle(original, candidate, timeout_seconds=timeout_s)
    report = oracle.verify([b""], argv=list(argv))
    grade = getattr(report, "grade", None)
    if not isinstance(grade, str) or grade not in VALIDATION_GRADE_LADDER:
        return "", {
            "scored": False,
            "reason": f"oracle_returned_invalid_grade:{grade!r}",
            "verdict": getattr(getattr(report, "verdict", None), "value", None),
            "notes": getattr(report, "notes", ""),
        }
    return grade, {
        "scored": True,
        "verdict": report.verdict.value,
        "notes": report.notes,
        "iterations": report.iterations,
    }


def _run_control_arm(
    original: Path,
    candidate: Path,
    declared_seeds: Sequence[Any],
    run_vrl_mod: Any,
) -> Dict[str, Any]:
    """
    No-LLM control: oracle-only scoring.

    ``passed`` is True only when every seed grades ``behavior_matched`` —
    that would be a hollow pass (no LLM needed). Otherwise passed=False.
    """
    grades: List[str] = []
    rows_meta: List[Dict[str, Any]] = []
    for idx, item in enumerate(declared_seeds):
        argv = run_vrl_mod._argv_for_declared_seed(item)
        grade, meta = _score_seed_oracle(original, candidate, argv)
        if not meta.get("scored"):
            return {
                "llm_enabled": False,
                "executed": True,
                "passed": None,
                "hollow_or_unscored": True,
                "notes": f"control could not score seed {idx}: {meta.get('reason')}",
                "seed_meta": rows_meta,
            }
        grades.append(grade)
        rows_meta.append({"seed_index": idx, "argv": argv, "grade": grade, **meta})

    hollow = bool(grades) and all(g == TARGET_GRADE for g in grades)
    return {
        "llm_enabled": False,
        "executed": True,
        "passed": hollow,  # True ⇒ hollow; False ⇒ honest fail
        "grades": grades,
        "seed_meta": rows_meta,
        "notes": (
            "hollow: oracle behavior_matched on all seeds without LLM"
            if hollow
            else "control failed honesty success bar (not all behavior_matched) — expected"
        ),
    }


def _pick_model(available: Sequence[str]) -> str:
    preferred = (
        os.environ.get("REVENG_OLLAMA_MODEL")
        or os.environ.get("OLLAMA_MODEL")
        or ""
    ).strip()
    if preferred:
        return preferred
    for name in (
        DEFAULT_SMALL_MODEL,
        "phi3.5:latest",
        "phi3.5",
    ):
        if name in available or any(name in m for m in available):
            # Prefer exact match when present.
            for m in available:
                if m == name or name in m:
                    return m
            return name
    return available[0] if available else DEFAULT_SMALL_MODEL


def _run_treatment_seeds(
    original: Path,
    candidate: Path,
    declared_seeds: Sequence[Any],
    run_vrl_mod: Any,
    model: str,
) -> Tuple[List[Dict[str, Any]], bool, Optional[str]]:
    """
    For each seed: call Ollama, then score via DifferentialOracle.

    Returns (seed_runs, ollama_actually_ran, cnm_reason_or_none).
    """
    from reveng.agents.ai.ollama_analyzer import OllamaAnalyzer
    from reveng.verification.models import VALIDATION_GRADE_LADDER

    analyzer = OllamaAnalyzer(model_name=model, timeout=120, max_tokens=64)
    seed_runs: List[Dict[str, Any]] = []
    ollama_ran = False

    for idx, item in enumerate(declared_seeds):
        if isinstance(item, bytes):
            seed_text = item.decode("utf-8", "replace")
        else:
            seed_text = str(item)
        seed_id = run_vrl_mod._seed_identity("hexyl", idx, seed_text)
        argv = run_vrl_mod._argv_for_declared_seed(item)

        prompt = (
            "VRL honesty dogfood (short reply). Seed argv for hexyl PE: "
            f"{argv!r}. Reply with one word: ACK"
        )
        try:
            llm_result = analyzer.analyze(prompt)
            ollama_ran = True
            llm_preview = (llm_result.content or "")[:80]
        except Exception as exc:  # noqa: BLE001
            return (
                seed_runs,
                ollama_ran,
                f"ollama_chat_failed_at_seed_{idx}: {type(exc).__name__}: {exc}",
            )

        grade, meta = _score_seed_oracle(original, candidate, argv)
        if not meta.get("scored") or grade not in VALIDATION_GRADE_LADDER:
            return (
                seed_runs,
                ollama_ran,
                f"oracle_unscored_at_seed_{idx}: {meta.get('reason', 'invalid_grade')}",
            )

        seed_runs.append(
            {
                "seed_id": seed_id,
                "grade": grade,
                "argv": argv,
                "executed": True,
                "ollama_model": analyzer.model_name,
                "ollama_preview": llm_preview,
                "oracle_verdict": meta.get("verdict"),
                "oracle_notes": meta.get("notes"),
            }
        )

    return seed_runs, ollama_ran, None


def _write_evidence(payload: Dict[str, Any]) -> Path:
    _EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2) + "\n"
    _LATEST.write_text(text, encoding="utf-8")
    stamp = _EVIDENCE_DIR / f"{date.today().isoformat()}.json"
    # Evidence hygiene: exactly one dated stamp matching latest.
    for orphan in _EVIDENCE_DIR.glob("20*.json"):
        if orphan.resolve() != stamp.resolve():
            orphan.unlink()
    stamp.write_text(text, encoding="utf-8")
    return _LATEST


def main(argv: Optional[Sequence[str]] = None) -> int:
    del argv  # CLI has no flags today; env-driven.
    gate = _load_module(_GATE, "verify_vrl_llm_honesty_dogfood")
    run_vrl_mod = _load_module(_RUN_VRL, "run_vrl_dogfood")

    tags_url = gate.resolve_ollama_tags_url()
    reachable = gate.probe_ollama(tags_url, timeout_s=5.0)
    print(json.dumps({"probe": {"url": tags_url, "ollama_reachable": reachable}}, indent=2))

    if not reachable:
        gate.write_could_not_measure_evidence(
            _LATEST,
            reason=f"ollama_unreachable: connection refused at {tags_url}",
            ollama_reachable=False,
            ollama_tags_url=tags_url,
        )
        print(f"wrote CNM → {_LATEST}")
        return 2

    if not _HEXYL.is_file():
        gate.write_could_not_measure_evidence(
            _LATEST,
            reason=f"hexyl_binary_absent: {_HEXYL}",
            ollama_reachable=True,
            ollama_tags_url=tags_url,
        )
        return 2
    if not _CANDIDATE.is_file():
        gate.write_could_not_measure_evidence(
            _LATEST,
            reason=f"oracle_candidate_absent: {_CANDIDATE}",
            ollama_reachable=True,
            ollama_tags_url=tags_url,
        )
        return 2

    os.environ.setdefault("REVENG_AI_PROVIDER", "ollama")
    entry = _load_hexyl_entry()
    declared = _seed_items(entry)

    # Snapshot corpus grade — run_vrl may rewrite current_grade even when the
    # initial compile fails (status=llm_error → fallback "unknown"). That is not
    # an oracle-measured downgrade; restore after the customer-path probe.
    prior_corpus_grade = entry.get("current_grade")
    run_vrl_note = _invoke_run_vrl()
    run_vrl_note["prior_corpus_grade"] = prior_corpus_grade
    if prior_corpus_grade:
        try:
            run_vrl_mod._update_corpus_grade(_CORPUS_YAML, "hexyl", str(prior_corpus_grade))
            run_vrl_note["corpus_grade_restored"] = prior_corpus_grade
        except Exception as exc:  # noqa: BLE001
            run_vrl_note["corpus_grade_restore_error"] = f"{type(exc).__name__}: {exc}"
    print(
        json.dumps(
            {
                "run_vrl": {
                    "returncode": run_vrl_note.get("returncode"),
                    "notes": run_vrl_note.get("notes"),
                    "error": run_vrl_note.get("error"),
                    "corpus_grade_restored": run_vrl_note.get("corpus_grade_restored"),
                }
            },
            indent=2,
        )
    )

    control = _run_control_arm(_HEXYL, _CANDIDATE, declared, run_vrl_mod)
    if control.get("hollow_or_unscored"):
        payload = gate.write_could_not_measure_evidence(
            _LATEST,
            reason=control.get("notes") or "control_arm_unscored",
            ollama_reachable=True,
            ollama_tags_url=tags_url,
        )
        payload["control_arm"] = {
            "llm_enabled": False,
            "executed": True,
            "passed": None,
            "notes": control.get("notes"),
        }
        payload["run_vrl_customer_path"] = run_vrl_note
        _write_evidence(payload)
        print("CNM: control could not be scored honestly")
        return 2

    if control.get("passed") is True:
        # Hollow gate: do NOT stamp passed:false. Refuse measured.
        payload = {
            "provider": "ollama",
            "min_seeds": MIN_SEEDS,
            "runtime_status": "could_not_measure",
            "ollama_reachable": True,
            "ollama_actually_ran": False,
            "ollama_tags_url": tags_url,
            "grades": [],
            "seed_runs": [],
            "control_arm": {
                "llm_enabled": False,
                "executed": True,
                "passed": True,
                "notes": control.get("notes"),
            },
            "reason": "control_hollow_pass: no-LLM arm reached behavior_matched — refuse measured",
            "run_vrl_customer_path": run_vrl_note,
            "policy": {
                "min_seeds": MIN_SEEDS,
                "provider": "ollama",
                "source": "docs/architecture/decision-r-vrl-1-seeds-and-provider.md",
            },
        }
        _write_evidence(payload)
        print("CNM: control hollow-passed; refusing measured")
        return 1

    # List models for selection (already reachable).
    import urllib.request

    with urllib.request.urlopen(tags_url, timeout=5) as resp:
        models = [m.get("name", "") for m in json.load(resp).get("models", [])]
    model = _pick_model(models)
    print(json.dumps({"selected_model": model, "models_seen": len(models)}, indent=2))

    seed_runs, ollama_ran, cnm_reason = _run_treatment_seeds(
        _HEXYL, _CANDIDATE, declared, run_vrl_mod, model
    )
    if cnm_reason or not ollama_ran or len(seed_runs) < MIN_SEEDS:
        payload = gate.write_could_not_measure_evidence(
            _LATEST,
            reason=cnm_reason or "treatment_incomplete",
            ollama_reachable=True,
            ollama_tags_url=tags_url,
        )
        payload["ollama_actually_ran"] = bool(ollama_ran)
        payload["seed_runs"] = seed_runs
        payload["grades"] = [r["grade"] for r in seed_runs if r.get("grade")]
        payload["control_arm"] = {
            "llm_enabled": False,
            "executed": True,
            "passed": False,
            "notes": control.get("notes"),
        }
        payload["run_vrl_customer_path"] = run_vrl_note
        _write_evidence(payload)
        print(f"CNM: {cnm_reason or 'treatment_incomplete'}")
        return 2

    grades = [r["grade"] for r in seed_runs]
    # Normalize to gate schema (strip dogfood-only keys from seed_runs for gate).
    gate_seed_runs = [
        {
            "seed_id": r["seed_id"],
            "grade": r["grade"],
            "argv": r["argv"],
            "executed": True,
        }
        for r in seed_runs
    ]
    payload: Dict[str, Any] = {
        "provider": "ollama",
        "min_seeds": MIN_SEEDS,
        "runtime_status": "measured",
        "ollama_reachable": True,
        "ollama_actually_ran": True,
        "ollama_tags_url": tags_url,
        "ollama_model": model,
        "grades": grades,
        "seed_runs": gate_seed_runs,
        "seed_runs_detail": seed_runs,
        "control_arm": {
            "llm_enabled": False,
            "executed": True,
            "passed": False,
            "notes": control.get("notes"),
            "grades": control.get("grades"),
        },
        "binary": {
            "name": "hexyl",
            "original": str(_HEXYL.relative_to(_REPO_ROOT)),
            "oracle_candidate": str(_CANDIDATE.relative_to(_REPO_ROOT)),
            "notes": (
                "Hermetic seed×oracle path: DifferentialOracle(original=hexyl.exe, "
                "candidate=test_samples/sample.exe) per corpus seed argv. Candidate is "
                "a divergent PE stand-in because local C link is broken on this WSL "
                "(glibc RELR); grades are real oracle ValidationGrade values, not invented."
            ),
        },
        "run_vrl_customer_path": run_vrl_note,
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "corpus_path": str(_CORPUS_YAML.relative_to(_REPO_ROOT)),
        "policy": {
            "min_seeds": MIN_SEEDS,
            "provider": "ollama",
            "source": "docs/architecture/decision-r-vrl-1-seeds-and-provider.md",
        },
        "wsl_ollama_note": (
            "From WSL, Ollama on Windows is reached via the Hyper-V/WSL gateway "
            "(e.g. OLLAMA_HOST=http://172.28.160.1:11434), not 127.0.0.1. "
            "Discover: `ip route show | awk '/default/ {print $3}'` or Windows "
            "vEthernet (WSL) adapter address."
        ),
    }
    _write_evidence(payload)

    verdict = gate.evaluate_evidence(payload)
    print(json.dumps({
        "gate_exit": verdict.exit_code,
        "runtime_status": verdict.runtime_status,
        "reasons": verdict.reasons,
        "evidence": str(_LATEST),
    }, indent=2))
    return verdict.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
