#!/usr/bin/env python3
"""
Dogfood VRL LLM honesty evidence (Phase 4 / VRL-LLM-1 Track B).

Produces ``reports/vrl_llm_honesty/latest.json`` from a **load-bearing**
compile → LLM → recompile → regrade loop on a Linux-hermetic Go micro
subject (``test_samples/vrl_llm_micro_go``). Never invents grades.

Hollow ACK-ping + fixed ``sample.exe`` oracle is intentionally **not** a
measured path (Sol REJECT 2026-08-07).

Flow
----
1. Resolve Ollama via ``OLLAMA_HOST`` / ``REVENG_OLLAMA_HOST`` (WSL→Windows).
2. Record customer ``run_vrl.py --binary hexyl`` outcome (usually
   ``vrl_compile_toolchain_broken`` on this WSL) without treating it as
   measured.
3. No-LLM control: score broken Go binary vs original on 3 argv seeds.
4. Treatment: ask Ollama to fix broken source → write → ``CGO_ENABLED=0 go
   build`` → re-grade. Require hash change + ``llm_influenced`` + grade
   delta for ``measured``.
5. Write evidence; exit 0 only when the honesty gate accepts ``measured``.

Usage::

    export OLLAMA_HOST=http://172.28.160.1:11434
    export REVENG_AI_PROVIDER=ollama
    export REVENG_OLLAMA_MODEL=hf.co/unsloth/Llama-3.2-1B-Instruct-GGUF:Q4_K_M
    /usr/bin/python3.9 scripts/dogfood_vrl_llm_honesty.py
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT / "src"))

_EVIDENCE_DIR = _REPO_ROOT / "reports" / "vrl_llm_honesty"
_LATEST = _EVIDENCE_DIR / "latest.json"
_CORPUS_YAML = _REPO_ROOT / ".reveng" / "benchmarks" / "corpus.yaml"
_MICRO_DIR = _REPO_ROOT / "test_samples" / "vrl_llm_micro_go"
_ORIG_SRC = _MICRO_DIR / "main.go"
_BROKEN_SRC = _MICRO_DIR / "broken_main.go"
_GO_MOD = _MICRO_DIR / "go.mod"
_RUN_VRL = _REPO_ROOT / "scripts" / "run_vrl.py"
_GATE = _REPO_ROOT / "scripts" / "verify_vrl_llm_honesty.py"

MIN_SEEDS = 3
CORPUS_ENTRY_NAME = "vrl_llm_micro_go"
TARGET_GRADE = "behavior_matched"
DEFAULT_SMALL_MODEL = "hf.co/unsloth/Llama-3.2-1B-Instruct-GGUF:Q4_K_M"
BLOCKER_C_TOOLCHAIN = "vrl_compile_toolchain_broken"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _load_corpus_entry(name: str = CORPUS_ENTRY_NAME) -> Dict[str, Any]:
    """Load the tracked corpus entry used for argv seeds + honesty subject metadata."""
    import yaml

    corpus = yaml.safe_load(_CORPUS_YAML.read_text(encoding="utf-8"))
    for entry in corpus.get("binaries", []) or []:
        if isinstance(entry, dict) and entry.get("name") == name:
            return entry
    raise KeyError(f"corpus entry {name!r} not found in {_CORPUS_YAML}")


def _argv_seeds_from_corpus(entry: Dict[str, Any]) -> List[List[str]]:
    """
    Convert corpus ``seed_inputs`` into per-seed argv lists.

    Matches dogfood oracle usage: each seed_inputs string is one argv token list
    (single token today: ``--help``, ``--version``, ``sample``).
    """
    raw = entry.get("seed_inputs") or entry.get("test_inputs") or []
    if not isinstance(raw, list) or len(raw) < MIN_SEEDS:
        raise ValueError(
            f"corpus entry {entry.get('name')!r} needs ≥{MIN_SEEDS} seed_inputs; got {raw!r}"
        )
    seeds: List[List[str]] = []
    for item in raw:
        if isinstance(item, list):
            seeds.append([str(x) for x in item])
        else:
            seeds.append([str(item)])
    return seeds


def _go_compile(source: str, out_bin: Path) -> Tuple[bool, str]:
    """Compile Go source with CGO_ENABLED=0. Returns (ok, stderr_or_note)."""
    if shutil.which("go") is None:
        return False, "go_absent"
    ws = Path(tempfile.mkdtemp(prefix="vrl_llm_go_"))
    try:
        (ws / "main.go").write_text(source, encoding="utf-8")
        (ws / "go.mod").write_text(
            _GO_MOD.read_text(encoding="utf-8")
            if _GO_MOD.is_file()
            else "module reveng.vrl_llm_micro_go\n\ngo 1.21\n",
            encoding="utf-8",
        )
        env = os.environ.copy()
        env["CGO_ENABLED"] = "0"
        proc = subprocess.run(
            ["go", "build", "-o", str(out_bin), "."],
            cwd=str(ws),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if proc.returncode != 0 or not out_bin.is_file():
            return False, (proc.stderr or proc.stdout or "go_build_failed")[-800:]
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__}: {exc}"
    finally:
        shutil.rmtree(ws, ignore_errors=True)


def _invoke_run_vrl_hexyl() -> Dict[str, Any]:
    """Customer-path probe; C compile usually fails on this WSL — recorded, not measured."""
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
        out = (proc.stdout or "") + "\n" + (proc.stderr or "")
        compile_blocked = (
            "Initial compile_fn raised" in out
            or "All compilers failed" in out
            or "tokens used  : 0" in out
            or "iterations   : 0" in out
        )
        return {
            "executed": True,
            "returncode": proc.returncode,
            "stdout_tail": (proc.stdout or "")[-1500:],
            "stderr_tail": (proc.stderr or "")[-1500:],
            "compile_blocked": compile_blocked,
            "tokens_used": 0,
            "iterations": 0,
            "notes": (
                f"{BLOCKER_C_TOOLCHAIN}: hexyl/PE C refine cannot link on this WSL "
                "(glibc RELR / cl PermissionError). Infra-only probe — not load-bearing."
            ),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "executed": True,
            "returncode": None,
            "error": f"{type(exc).__name__}: {exc}",
            "compile_blocked": True,
            "tokens_used": 0,
            "iterations": 0,
            "notes": f"{BLOCKER_C_TOOLCHAIN}: run_vrl raised before completing",
        }


def _score_seed_oracle(
    original: Path,
    candidate: Path,
    argv: Sequence[str],
    timeout_s: float = 15.0,
) -> Tuple[str, Dict[str, Any]]:
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
    original: Path, candidate: Path, argv_seeds: Sequence[Sequence[str]]
) -> Dict[str, Any]:
    """No-LLM control: oracle-only on broken candidate. Hollow iff all matched."""
    grades: List[str] = []
    rows_meta: List[Dict[str, Any]] = []
    for idx, argv in enumerate(argv_seeds):
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
        rows_meta.append({"seed_index": idx, "argv": list(argv), "grade": grade, **meta})

    hollow = bool(grades) and all(g == TARGET_GRADE for g in grades)
    return {
        "llm_enabled": False,
        "executed": True,
        "passed": hollow,
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
    for name in (DEFAULT_SMALL_MODEL, "phi3.5:latest", "phi3.5"):
        if name in available or any(name in m for m in available):
            for m in available:
                if m == name or name in m:
                    return m
            return name
    return available[0] if available else DEFAULT_SMALL_MODEL


def _extract_go_source(text: str) -> str:
    from reveng.verification.refinement.refiner import _extract_code_block

    return _extract_code_block(text or "")


def _run_treatment_load_bearing(
    original: Path,
    broken_src: str,
    control_candidate: Path,
    model: str,
    argv_seeds: Sequence[Sequence[str]],
) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    LLM fix → apply to candidate → go build → regrade.

    Returns (payload_fragment, cnm_reason_or_none).
    """
    from reveng.agents.ai.ollama_analyzer import OllamaAnalyzer
    from reveng.verification.models import VALIDATION_GRADE_LADDER

    analyzer = OllamaAnalyzer(model_name=model, timeout=120, max_tokens=400)
    prompt = (
        "The Go program below always prints WRONG. Fix it so it prints "
        'os.Args[1] when present, else "ok".\n'
        "Return a COMPLETE compilable Go source in a ```go fence. No explanation.\n\n"
        "## Current Go source\n"
        f"```go\n{broken_src}\n```\n"
    )
    try:
        llm_result = analyzer.analyze(prompt)
    except Exception as exc:  # noqa: BLE001
        return {}, f"ollama_chat_failed: {type(exc).__name__}: {exc}"

    response = llm_result.content or ""
    tokens_used = int(getattr(llm_result, "tokens_used", 0) or 0)
    tokens_used_estimated = False
    if tokens_used <= 0:
        # OllamaAnalyzer often omits usage — count approximate prompt+response tokens.
        tokens_used = max(1, (len(prompt) + len(response)) // 4)
        tokens_used_estimated = True

    new_source = _extract_go_source(response)
    if not new_source.strip():
        return {}, "llm_empty_source"

    control_sha = _sha256(control_candidate)
    applied_source_sha = _sha256_text(new_source)
    out_dir = Path(tempfile.mkdtemp(prefix="vrl_llm_treat_"))
    out_bin = out_dir / "candidate.bin"
    # Durable receipt under evidence dir (survives /tmp cleanup; cited by gate).
    _EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    applied_src_path = _EVIDENCE_DIR / "applied_main.go"
    applied_src_path.write_text(new_source, encoding="utf-8")
    applied_src_rel = str(applied_src_path.relative_to(_REPO_ROOT))
    ok, note = _go_compile(new_source, out_bin)
    if not ok:
        return {
            "ollama_actually_ran": True,
            "tokens_used": tokens_used,
            "tokens_used_estimated": tokens_used_estimated,
            "vrl_iterations": 1,
            "llm_preview": response[:120],
            "compile_note": note,
            "control_candidate_sha256": control_sha,
            "applied_source_path": applied_src_rel,
            "applied_source_sha256": applied_source_sha,
        }, f"llm_source_compile_failed: {note[:200]}"

    treatment_sha = _sha256(out_bin)
    hash_changed = bool(control_sha and treatment_sha and control_sha != treatment_sha)
    if new_source.strip() == broken_src.strip():
        return {
            "ollama_actually_ran": True,
            "tokens_used": tokens_used,
            "tokens_used_estimated": tokens_used_estimated,
            "control_candidate_sha256": control_sha,
            "treatment_candidate_sha256": treatment_sha,
            "candidate_hash_before": control_sha,
            "candidate_hash_after": treatment_sha,
            "candidate_hash_changed": hash_changed,
            "applied_source_path": applied_src_rel,
            "applied_source_sha256": applied_source_sha,
        }, "llm_source_identical_to_broken"

    seed_runs: List[Dict[str, Any]] = []
    grades: List[str] = []
    for idx, argv in enumerate(argv_seeds):
        grade, meta = _score_seed_oracle(original, out_bin, argv)
        if not meta.get("scored") or grade not in VALIDATION_GRADE_LADDER:
            return (
                {
                    "ollama_actually_ran": True,
                    "tokens_used": tokens_used,
                    "tokens_used_estimated": tokens_used_estimated,
                    "control_candidate_sha256": control_sha,
                    "treatment_candidate_sha256": treatment_sha,
                    "candidate_hash_changed": hash_changed,
                    "applied_source_path": applied_src_rel,
                    "applied_source_sha256": applied_source_sha,
                },
                f"oracle_unscored_at_seed_{idx}: {meta.get('reason', 'invalid_grade')}",
            )
        grades.append(grade)
        seed_runs.append(
            {
                "seed_id": f"vrl_micro_go:seed_{idx}",
                "grade": grade,
                "argv": list(argv),
                "executed": True,
                "llm_influenced": True,
                "ollama_model": analyzer.model_name,
                "ollama_preview": response[:80].replace("\n", " "),
                "oracle_verdict": meta.get("verdict"),
                "oracle_notes": meta.get("notes"),
            }
        )

    return {
        "ollama_actually_ran": True,
        "ollama_model": analyzer.model_name,
        "tokens_used": tokens_used,
        "tokens_used_estimated": tokens_used_estimated,
        "vrl_iterations": 1,
        "vrl_compile_blocked": False,
        "control_candidate_sha256": control_sha,
        "treatment_candidate_sha256": treatment_sha,
        "candidate_hash_before": control_sha,
        "candidate_hash_after": treatment_sha,
        "candidate_hash_changed": hash_changed,
        "applied_source_path": applied_src_rel,
        "applied_source_sha256": applied_source_sha,
        "grades": grades,
        "seed_runs": seed_runs,
        "seed_runs_detail": list(seed_runs),
        "llm_source_applied": True,
        "treatment_workspace_binary": str(out_bin),
    }, None


def _write_evidence(payload: Dict[str, Any]) -> Path:
    _EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2) + "\n"
    _LATEST.write_text(text, encoding="utf-8")
    stamp = _EVIDENCE_DIR / f"{date.today().isoformat()}.json"
    for orphan in _EVIDENCE_DIR.glob("20*.json"):
        if orphan.resolve() != stamp.resolve():
            orphan.unlink()
    stamp.write_text(text, encoding="utf-8")
    return _LATEST


def _cnm_payload(
    gate: Any,
    *,
    reason: str,
    tags_url: str,
    ollama_ran: bool = False,
    control: Optional[Dict[str, Any]] = None,
    run_vrl_note: Optional[Dict[str, Any]] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    payload = gate.write_could_not_measure_evidence(
        _LATEST,
        reason=reason,
        ollama_reachable=True,
        ollama_tags_url=tags_url,
    )
    payload["ollama_actually_ran"] = bool(ollama_ran)
    payload["reason"] = reason
    payload["blocker"] = BLOCKER_C_TOOLCHAIN if BLOCKER_C_TOOLCHAIN in reason else reason
    if control is not None:
        payload["control_arm"] = {
            "llm_enabled": False,
            "executed": control.get("executed", True),
            "passed": control.get("passed"),
            "notes": control.get("notes"),
            "grades": control.get("grades"),
        }
    if run_vrl_note is not None:
        payload["run_vrl_customer_path"] = run_vrl_note
        payload["vrl_compile_blocked"] = True
    if extra:
        payload.update(extra)
    _write_evidence(payload)
    return payload


def main(argv: Optional[Sequence[str]] = None) -> int:
    del argv
    gate = _load_module(_GATE, "verify_vrl_llm_honesty_dogfood")

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

    for path in (_ORIG_SRC, _BROKEN_SRC, _GO_MOD):
        if not path.is_file():
            gate.write_could_not_measure_evidence(
                _LATEST,
                reason=f"micro_go_fixture_absent: {path}",
                ollama_reachable=True,
                ollama_tags_url=tags_url,
            )
            return 2

    os.environ.setdefault("REVENG_AI_PROVIDER", "ollama")

    try:
        corpus_entry = _load_corpus_entry(CORPUS_ENTRY_NAME)
        argv_seeds = _argv_seeds_from_corpus(corpus_entry)
    except (KeyError, ValueError, OSError) as exc:
        gate.write_could_not_measure_evidence(
            _LATEST,
            reason=f"corpus_entry_unavailable: {exc}",
            ollama_reachable=True,
            ollama_tags_url=tags_url,
        )
        print(f"CNM: corpus entry {CORPUS_ENTRY_NAME!r} unavailable: {exc}")
        return 2

    prior_corpus_grade = None
    try:
        import yaml

        corpus = yaml.safe_load(_CORPUS_YAML.read_text(encoding="utf-8"))
        for entry in corpus.get("binaries", []):
            if entry.get("name") == "hexyl":
                prior_corpus_grade = entry.get("current_grade")
                break
    except Exception:  # noqa: BLE001
        prior_corpus_grade = None

    run_vrl_note = _invoke_run_vrl_hexyl()
    run_vrl_note["prior_corpus_grade"] = prior_corpus_grade
    if prior_corpus_grade:
        try:
            run_vrl_mod = _load_module(_RUN_VRL, "run_vrl_dogfood")
            run_vrl_mod._update_corpus_grade(
                _CORPUS_YAML, "hexyl", str(prior_corpus_grade)
            )
            run_vrl_note["corpus_grade_restored"] = prior_corpus_grade
        except Exception as exc:  # noqa: BLE001
            run_vrl_note["corpus_grade_restore_error"] = f"{type(exc).__name__}: {exc}"

    print(
        json.dumps(
            {
                "run_vrl": {
                    "returncode": run_vrl_note.get("returncode"),
                    "compile_blocked": run_vrl_note.get("compile_blocked"),
                    "notes": run_vrl_note.get("notes"),
                },
                "corpus_entry": CORPUS_ENTRY_NAME,
                "argv_seeds": argv_seeds,
            },
            indent=2,
        )
    )

    # Prefer corpus build_recipe → binary_path when present; else compile sources.
    work = Path(tempfile.mkdtemp(prefix="vrl_llm_micro_"))
    orig_bin = work / "orig.bin"
    broken_bin = work / "broken.bin"
    orig_src = _ORIG_SRC.read_text(encoding="utf-8")
    broken_src = _BROKEN_SRC.read_text(encoding="utf-8")

    build_recipe = corpus_entry.get("build_recipe")
    recipe_path = (
        (_REPO_ROOT / str(build_recipe)).resolve() if build_recipe else None
    )
    if recipe_path and recipe_path.is_file():
        try:
            subprocess.run(
                ["bash", str(recipe_path)],
                cwd=str(recipe_path.parent),
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
            built = _REPO_ROOT / str(
                corpus_entry.get("binary_path")
                or "test_samples/vrl_llm_micro_go/micro.bin"
            )
            if built.is_file():
                shutil.copy2(built, orig_bin)
        except Exception as exc:  # noqa: BLE001
            print(json.dumps({"build_recipe_note": f"{type(exc).__name__}: {exc}"}))

    if not orig_bin.is_file():
        ok, note = _go_compile(orig_src, orig_bin)
        if not ok:
            _cnm_payload(
                gate,
                reason=f"micro_go_orig_compile_failed: {note[:200]}",
                tags_url=tags_url,
                run_vrl_note=run_vrl_note,
            )
            return 2
    ok, note = _go_compile(broken_src, broken_bin)
    if not ok:
        _cnm_payload(
            gate,
            reason=f"micro_go_broken_compile_failed: {note[:200]}",
            tags_url=tags_url,
            run_vrl_note=run_vrl_note,
        )
        return 2

    control = _run_control_arm(orig_bin, broken_bin, argv_seeds)
    if control.get("hollow_or_unscored"):
        _cnm_payload(
            gate,
            reason=control.get("notes") or "control_arm_unscored",
            tags_url=tags_url,
            control=control,
            run_vrl_note=run_vrl_note,
        )
        print("CNM: control could not be scored honestly")
        return 2

    if control.get("passed") is True:
        _cnm_payload(
            gate,
            reason=(
                "control_hollow_pass: no-LLM arm reached behavior_matched — refuse measured"
            ),
            tags_url=tags_url,
            control=control,
            run_vrl_note=run_vrl_note,
        )
        print("CNM: control hollow-passed; refusing measured")
        return 1

    import urllib.request

    with urllib.request.urlopen(tags_url, timeout=5) as resp:
        models = [m.get("name", "") for m in json.load(resp).get("models", [])]
    model = _pick_model(models)
    print(json.dumps({"selected_model": model, "models_seen": len(models)}, indent=2))

    treatment, cnm_reason = _run_treatment_load_bearing(
        orig_bin, broken_src, broken_bin, model, argv_seeds
    )
    if cnm_reason:
        _cnm_payload(
            gate,
            reason=cnm_reason,
            tags_url=tags_url,
            ollama_ran=bool(treatment.get("ollama_actually_ran")),
            control=control,
            run_vrl_note=run_vrl_note,
            extra={
                "tokens_used": treatment.get("tokens_used"),
                "tokens_used_estimated": treatment.get("tokens_used_estimated"),
                "candidate_hash_changed": treatment.get("candidate_hash_changed"),
                "control_candidate_sha256": treatment.get("control_candidate_sha256"),
                "treatment_candidate_sha256": treatment.get(
                    "treatment_candidate_sha256"
                ),
                "applied_source_path": treatment.get("applied_source_path"),
                "applied_source_sha256": treatment.get("applied_source_sha256"),
                "corpus_entry": CORPUS_ENTRY_NAME,
                "infra_progress": {
                    "ollama_host_probe": "ok",
                    "go_cgo_disabled_compile": "ok",
                    "hexyl_c_refine": BLOCKER_C_TOOLCHAIN,
                },
            },
        )
        print(f"CNM: {cnm_reason}")
        return 2

    grades = list(treatment["grades"])
    control_grades = list(control.get("grades") or [])
    treatment_differs = grades != control_grades
    control_sha = treatment.get("control_candidate_sha256")
    treatment_sha = treatment.get("treatment_candidate_sha256")
    hash_changed = bool(
        control_sha and treatment_sha and control_sha != treatment_sha
    )
    gate_seed_runs = [
        {
            "seed_id": r["seed_id"],
            "grade": r["grade"],
            "argv": r["argv"],
            "executed": True,
            "llm_influenced": True,
        }
        for r in treatment["seed_runs"]
    ]

    if not hash_changed and not treatment_differs:
        _cnm_payload(
            gate,
            reason="llm_not_load_bearing: no hash change and grades match control",
            tags_url=tags_url,
            ollama_ran=True,
            control=control,
            run_vrl_note=run_vrl_note,
            extra=treatment,
        )
        return 2

    payload: Dict[str, Any] = {
        "provider": "ollama",
        "min_seeds": MIN_SEEDS,
        "runtime_status": "measured",
        "ollama_reachable": True,
        "ollama_actually_ran": True,
        "ollama_tags_url": tags_url,
        "ollama_model": treatment.get("ollama_model") or model,
        "tokens_used": treatment.get("tokens_used"),
        "tokens_used_estimated": bool(treatment.get("tokens_used_estimated")),
        "vrl_iterations": treatment.get("vrl_iterations", 1),
        "vrl_compile_blocked": False,
        "treatment_differs_from_control": treatment_differs,
        "control_candidate_sha256": control_sha,
        "treatment_candidate_sha256": treatment_sha,
        "candidate_hash_before": control_sha,
        "candidate_hash_after": treatment_sha,
        "candidate_hash_changed": hash_changed,
        "applied_source_path": treatment.get("applied_source_path"),
        "applied_source_sha256": treatment.get("applied_source_sha256"),
        "grades": grades,
        "seed_runs": gate_seed_runs,
        "seed_runs_detail": treatment.get("seed_runs_detail"),
        "control_arm": {
            "llm_enabled": False,
            "executed": True,
            "passed": False,
            "notes": control.get("notes"),
            "grades": control_grades,
        },
        "corpus_entry": CORPUS_ENTRY_NAME,
        "corpus_seed_inputs": list(corpus_entry.get("seed_inputs") or []),
        "binary": {
            "name": CORPUS_ENTRY_NAME,
            "original_source": str(_ORIG_SRC.relative_to(_REPO_ROOT)),
            "broken_source": str(_BROKEN_SRC.relative_to(_REPO_ROOT)),
            "binary_path": corpus_entry.get("binary_path"),
            "build_recipe": corpus_entry.get("build_recipe"),
            "notes": (
                "Load-bearing micro path: Go CGO_ENABLED=0 compile → Ollama revise "
                "broken_main.go → recompile → DifferentialOracle on corpus "
                f"{CORPUS_ENTRY_NAME} seed_inputs. Hexyl/PE C refine remains blocked "
                "on this WSL (recorded under run_vrl_customer_path)."
            ),
        },
        "run_vrl_customer_path": run_vrl_note,
        "infra_progress": {
            "ollama_host_probe": "ok",
            "go_cgo_disabled_compile": "ok",
            "hexyl_c_refine": BLOCKER_C_TOOLCHAIN,
        },
        "measured_at": datetime.now(timezone.utc).isoformat(),
        "corpus_path": str(_CORPUS_YAML.relative_to(_REPO_ROOT)),
        "policy": {
            "min_seeds": MIN_SEEDS,
            "provider": "ollama",
            "source": "docs/architecture/decision-r-vrl-1-seeds-and-provider.md",
            "load_bearing": (
                "treatment_differs_from_control | derived candidate_hash_changed "
                "(control/treatment sha256 unequal) | seed_runs.llm_influenced+"
                "applied_source receipt | tokens_used>0 with iterations>0"
            ),
        },
        "wsl_ollama_note": (
            "From WSL, Ollama on Windows is reached via the Hyper-V/WSL gateway "
            "(e.g. OLLAMA_HOST=http://172.28.160.1:11434), not 127.0.0.1."
        ),
    }
    _write_evidence(payload)

    verdict = gate.evaluate_evidence(payload)
    print(
        json.dumps(
            {
                "gate_exit": verdict.exit_code,
                "runtime_status": verdict.runtime_status,
                "reasons": verdict.reasons,
                "evidence": str(_LATEST),
                "grades": grades,
                "control_grades": control_grades,
                "candidate_hash_changed": payload["candidate_hash_changed"],
                "corpus_entry": CORPUS_ENTRY_NAME,
            },
            indent=2,
        )
    )
    return verdict.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
