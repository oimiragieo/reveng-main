#!/usr/bin/env python3
"""
VRL LLM honesty gate (Phase 4 / VRL-LLM-1).

Evaluates a tracked evidence JSON against R-VRL-1 policy:

* ``min_seeds >= 3`` whenever ``runtime_status`` claims ``measured``
* measured **requires** non-empty ``seed_runs`` with ≥3 executed rows carrying
  **distinct** non-empty ``seed_id`` + valid ValidationGrade — missing/empty
  ``seed_runs`` ⇒ ``seed_runs_required`` (legacy bare ``grades`` alone never
  unlocks exit 0; may remain informational)
* declaring ``min_seeds: 3`` with fewer than three executed graded seed runs
  must FAIL (``grades_below_min_seeds`` / ``seed_ids_not_distinct``)
* three identical ``seed_id`` values must FAIL
* every scored run records a real ValidationGrade (ladder value) — missing grade
  ⇒ fail measured / never a pass
* no-LLM control arm must be *executed* and FAIL for measured
  (``executed: true``, ``passed: false``, ``llm_enabled: false``)
* unexecuted control (``executed: false``) is a CNM contribution — never a
  phantom ``passed: false`` that unlocks measured
* provider identity recorded; ``runtime_status: measured`` only when ollama
  actually ran
* **LLM must be load-bearing** for ``measured`` (Sol REJECT 2026-08-07): at
  least one of (a) ``treatment_differs_from_control`` with different grade
  lists, (b) **derived** ``candidate_hash_changed`` (control/treatment SHA256
  present and unequal — never trust a lone boolean), (c) any
  ``seed_runs[].llm_influenced: true`` **with** ``applied_source_path`` or
  ``applied_source_sha256`` receipt, (d) refine ``tokens_used > 0`` with
  ``vrl_iterations > 0`` and not compile-blocked. Hollow ACK-ping + identical
  control/treatment grades ⇒ ``hollow_ack_ping_identical_grades`` / fail.
  Self-asserted ``candidate_hash_changed: true`` with missing/equal hashes ⇒ fail.

Exit codes
----------
0 — gate pass (measured + honest controls)
1 — gate fail (hollow evidence / policy breach / control passed)
2 — could_not_measure (ollama unreachable / incomplete evidence) — not a fake pass

Usage::

    /usr/bin/python3.9 scripts/verify_vrl_llm_honesty.py \\
        --evidence reports/vrl_llm_honesty/latest.json

    /usr/bin/python3.9 scripts/verify_vrl_llm_honesty.py --probe-ollama
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_EVIDENCE = _REPO_ROOT / "reports" / "vrl_llm_honesty" / "latest.json"
_CORPUS_YAML = _REPO_ROOT / ".reveng" / "benchmarks" / "corpus.yaml"

MIN_SEEDS = 3
REQUIRED_PROVIDER = "ollama"
_DEFAULT_OLLAMA_BASE = "http://127.0.0.1:11434"
OLLAMA_TAGS_URL = f"{_DEFAULT_OLLAMA_BASE}/api/tags"


def resolve_ollama_tags_url(
    host_override: Optional[str] = None,
    *,
    environ: Optional[Dict[str, str]] = None,
) -> str:
    """
    Resolve the Ollama ``/api/tags`` URL from env (or an explicit override).

    Precedence:
      1. *host_override* argument
      2. ``REVENG_OLLAMA_HOST``
      3. ``OLLAMA_HOST`` (standard Ollama env — may be ``http://host:11434``
         or bare ``host:11434``)
      4. Default ``http://127.0.0.1:11434``

    Appends ``/api/tags`` when the resolved base does not already end with it.
    """
    env = environ if environ is not None else os.environ
    raw = (host_override or "").strip()
    if not raw:
        raw = (env.get("REVENG_OLLAMA_HOST") or env.get("OLLAMA_HOST") or "").strip()
    if not raw:
        raw = _DEFAULT_OLLAMA_BASE

    # Bare host:port → assume http://
    if "://" not in raw:
        raw = f"http://{raw}"

    raw = raw.rstrip("/")
    if raw.endswith("/api/tags"):
        return raw
    return f"{raw}/api/tags"

VALIDATION_GRADE_LADDER = (
    "unknown",
    "analysis_only",
    "compile_only",
    "structural_candidate",
    "launches_but_divergent",
    "partial_equivalence",
    "behavior_matched",
    "source_reconstruction_match",
    "evidence_backed",
)


@dataclass
class GateVerdict:
    """Result of evaluating one evidence document."""

    exit_code: int
    runtime_status: str
    reasons: List[str] = field(default_factory=list)
    provider: Optional[str] = None
    min_seeds: Optional[int] = None
    ollama_reachable: Optional[bool] = None

    @property
    def ok(self) -> bool:
        return self.exit_code == 0


def probe_ollama(
    url: Optional[str] = None,
    timeout_s: float = 2.0,
    *,
    environ: Optional[Dict[str, str]] = None,
) -> bool:
    """Return True when Ollama answers ``/api/tags`` at the resolved URL."""
    resolved = url or resolve_ollama_tags_url(environ=environ)
    try:
        with urllib.request.urlopen(resolved, timeout=timeout_s) as resp:
            return 200 <= int(getattr(resp, "status", 200)) < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def is_valid_grade(grade: Any) -> bool:
    """True when *grade* is a non-empty ValidationGrade ladder value."""
    if not isinstance(grade, str):
        return False
    return grade.strip() in VALIDATION_GRADE_LADDER


def _treatment_grades_list(evidence: Dict[str, Any]) -> List[Any]:
    """Prefer top-level grades; else executed seed_runs grades (order preserved)."""
    grades = evidence.get("grades")
    if isinstance(grades, list) and grades:
        return list(grades)
    derived: List[Any] = []
    for row in evidence.get("seed_runs") or []:
        if not isinstance(row, dict) or row.get("executed") is not True:
            continue
        g = row.get("grade")
        if is_valid_grade(g):
            derived.append(g)
    return derived


def _control_grades_list(evidence: Dict[str, Any]) -> Optional[List[Any]]:
    control = evidence.get("control_arm")
    if not isinstance(control, dict):
        return None
    grades = control.get("grades")
    if isinstance(grades, list):
        return list(grades)
    return None


def _ack_only_ping(evidence: Dict[str, Any]) -> bool:
    """
    True when every executed detail/seed row looks like an Ollama ACK ping
    with no ``llm_influenced`` application of model output to the candidate.
    """
    details = evidence.get("seed_runs_detail")
    rows: Sequence[Any]
    if isinstance(details, list) and details:
        rows = details
    else:
        seed_runs = evidence.get("seed_runs")
        if not isinstance(seed_runs, list) or not seed_runs:
            return False
        rows = seed_runs

    previews: List[str] = []
    any_influenced = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        if row.get("executed") is False:
            continue
        if row.get("llm_influenced") is True:
            any_influenced = True
        preview = str(row.get("ollama_preview") or "").strip().upper()
        previews.append(preview)

    if not previews:
        return False
    if any_influenced:
        return False
    # ACK ping (or empty preview with no influence) — hollow pattern.
    return all(p in ("ACK", "") for p in previews)


def _refine_tokens_load_bearing(evidence: Dict[str, Any]) -> bool:
    """True when refine/run_vrl recorded tokens with at least one iteration."""
    tokens = evidence.get("tokens_used")
    iterations = evidence.get("vrl_iterations")
    run_vrl = evidence.get("run_vrl_customer_path")
    if not isinstance(run_vrl, dict):
        run_vrl = {}
    if not isinstance(tokens, int):
        tokens = run_vrl.get("tokens_used")
    if not isinstance(iterations, int):
        iterations = run_vrl.get("iterations")
    if evidence.get("vrl_compile_blocked") is True:
        return False
    if run_vrl.get("compile_blocked") is True:
        return False
    return (
        isinstance(tokens, int)
        and tokens > 0
        and isinstance(iterations, int)
        and iterations > 0
    )


def _nonempty_sha256(value: Any) -> Optional[str]:
    """Return stripped sha256 hex digest (exactly 64 chars), or None."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if len(text) != 64:
        return None
    if any(c not in "0123456789abcdef" for c in text):
        return None
    return text


def candidate_sha256_pair(
    evidence: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    """
    Resolve control/treatment candidate digests.

    Prefer ``control_candidate_sha256`` / ``treatment_candidate_sha256``;
    accept legacy ``candidate_hash_before`` / ``candidate_hash_after``.
    """
    control = _nonempty_sha256(
        evidence.get("control_candidate_sha256")
        or evidence.get("candidate_hash_before")
    )
    treatment = _nonempty_sha256(
        evidence.get("treatment_candidate_sha256")
        or evidence.get("candidate_hash_after")
    )
    return control, treatment


def derive_candidate_hash_changed(evidence: Dict[str, Any]) -> bool:
    """
    True only when both SHA256 fields are present and unequal.

    Never trusts a lone ``candidate_hash_changed`` boolean.
    """
    control, treatment = candidate_sha256_pair(evidence)
    if control is None or treatment is None:
        return False
    return control != treatment


def _sha256_file(path: Path) -> str:
    import hashlib

    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _applied_source_receipt_present(evidence: Dict[str, Any]) -> bool:
    """True when evidence carries a valid applied-source digest receipt."""
    digest = _nonempty_sha256(evidence.get("applied_source_sha256"))
    if digest is None:
        return False
    path_raw = evidence.get("applied_source_path")
    if not isinstance(path_raw, str) or not path_raw.strip():
        # Digest alone is a receipt; path optional.
        return True
    path = Path(path_raw.strip())
    if not path.is_absolute():
        path = _REPO_ROOT / path
    if not path.is_file():
        # Path claimed but missing → not a verified receipt.
        return False
    return _sha256_file(path) == digest


def llm_load_bearing_reasons(evidence: Dict[str, Any]) -> List[str]:
    """
    Reasons why a ``measured`` claim fails the load-bearing LLM contract.

    Empty list ⇒ load-bearing predicates satisfied (or not claiming measured).
    """
    reasons: List[str] = []
    control_grades = _control_grades_list(evidence)
    treatment_grades = _treatment_grades_list(evidence)
    grades_identical = (
        isinstance(control_grades, list)
        and bool(control_grades)
        and list(control_grades) == list(treatment_grades)
    )

    if grades_identical and _ack_only_ping(evidence):
        reasons.append("hollow_ack_ping_identical_grades")

    treatment_differs_flag = evidence.get("treatment_differs_from_control") is True
    grades_differ = (
        isinstance(control_grades, list)
        and bool(control_grades)
        and list(control_grades) != list(treatment_grades)
    )

    control_sha, treatment_sha = candidate_sha256_pair(evidence)
    hash_changed = derive_candidate_hash_changed(evidence)
    claimed_hash_changed = evidence.get("candidate_hash_changed") is True

    # Forgeable boolean: self-asserted true with missing or equal hashes.
    if claimed_hash_changed and not hash_changed:
        if control_sha is None or treatment_sha is None:
            reasons.append("candidate_hash_changed_unverified_missing_sha256")
        else:
            reasons.append("candidate_hash_changed_unverified_equal_sha256")

    # Measured honesty requires the SHA pair present (not merely a boolean).
    if control_sha is None or treatment_sha is None:
        reasons.append("candidate_sha256_pair_required")

    llm_influenced_any = any(
        isinstance(row, dict) and row.get("llm_influenced") is True
        for row in (evidence.get("seed_runs") or [])
    )
    if llm_influenced_any and not _applied_source_receipt_present(evidence):
        reasons.append("llm_influenced_missing_applied_source_receipt")

    load_bearing = (
        (treatment_differs_flag and grades_differ)
        or hash_changed
        or (llm_influenced_any and _applied_source_receipt_present(evidence))
        or _refine_tokens_load_bearing(evidence)
    )
    if not load_bearing:
        reasons.append("llm_not_load_bearing")

    if treatment_differs_flag and not grades_differ and not hash_changed:
        # Claimed divergence without grade delta or artifact change.
        reasons.append("treatment_differs_claim_without_evidence")

    return reasons


def derive_grades_from_evidence(evidence: Dict[str, Any]) -> Tuple[List[Any], List[str]]:
    """
    Resolve the grade list the gate will score.

    Prefer ``seed_runs`` when present: only ``executed: true`` rows with a valid
    ValidationGrade count. Those rows must also carry distinct non-empty
    ``seed_id`` values (duplicate ids cannot pad ``min_seeds``). Legacy
    ``grades`` alone is informational — measured exit 0 still requires
    ``seed_runs`` (enforced by ``evaluate_evidence``).
    Returns ``(grades, reasons)`` where *reasons* are schema problems found while
    deriving (caller still enforces length / validity for measured).
    """
    reasons: List[str] = []
    seed_runs = evidence.get("seed_runs")
    if seed_runs is not None:
        if not isinstance(seed_runs, list):
            reasons.append("seed_runs_not_list")
            return [], reasons
        derived: List[Any] = []
        seed_ids: List[str] = []
        for idx, row in enumerate(seed_runs):
            if not isinstance(row, dict):
                reasons.append(f"seed_run_not_object_at_{idx}")
                continue
            if row.get("executed") is not True:
                continue
            grade = row.get("grade")
            if not is_valid_grade(grade):
                reasons.append(f"invalid_grade_at_{idx}:{grade!r}")
                continue
            seed_id = str(row.get("seed_id") or "").strip()
            if not seed_id:
                reasons.append(f"seed_id_missing_at_{idx}")
                continue
            derived.append(grade)
            seed_ids.append(seed_id)
        unique_ids = set(seed_ids)
        if seed_ids and len(unique_ids) < MIN_SEEDS:
            reasons.append(
                f"seed_ids_not_distinct:{len(unique_ids)}<{MIN_SEEDS}"
            )
        return derived, reasons

    grades = evidence.get("grades")
    if grades is None:
        return [], reasons
    if not isinstance(grades, list):
        reasons.append("grades_not_list")
        return [], reasons
    return list(grades), reasons


def evaluate_evidence(evidence: Dict[str, Any]) -> GateVerdict:
    """
    Evaluate a VRL LLM honesty evidence document.

    Expected evidence shape (all keys optional except where noted by rules)::

        {
          "provider": "ollama",
          "min_seeds": 3,
          "runtime_status": "measured" | "could_not_measure",
          "ollama_reachable": true | false,
          "ollama_actually_ran": true | false,
          "grades": ["analysis_only", ...],   # legacy: one per scored run
          "seed_runs": [                      # preferred run-log schema
            {"seed_id": "...", "grade": "...", "argv": ["..."], "executed": true},
            ...
          ],
          "control_arm": {
            "llm_enabled": false,
            "executed": true | false,
            "passed": false | null            # null/omit when executed is false
          },
          "reason": "optional free-text when could_not_measure"
        }
    """
    reasons: List[str] = []
    provider = evidence.get("provider")
    min_seeds_raw = evidence.get("min_seeds")
    try:
        min_seeds = int(min_seeds_raw) if min_seeds_raw is not None else None
    except (TypeError, ValueError):
        min_seeds = None
        reasons.append("min_seeds_not_int")

    runtime_status = evidence.get("runtime_status")
    if runtime_status not in ("measured", "could_not_measure"):
        return GateVerdict(
            exit_code=1,
            runtime_status=str(runtime_status),
            reasons=["invalid_runtime_status"],
            provider=provider if isinstance(provider, str) else None,
            min_seeds=min_seeds,
            ollama_reachable=evidence.get("ollama_reachable")
            if isinstance(evidence.get("ollama_reachable"), bool)
            else None,
        )

    ollama_reachable = evidence.get("ollama_reachable")
    ollama_actually_ran = evidence.get("ollama_actually_ran")
    control = evidence.get("control_arm") or {}

    # --- Control arm: executed flag + bidirectional no-LLM fail ------------
    control_executed: Optional[bool] = None
    if not isinstance(control, dict) or not control:
        reasons.append("control_arm_missing")
    else:
        executed_raw = control.get("executed")
        if executed_raw is not True and executed_raw is not False:
            reasons.append("control_arm_executed_missing")
        else:
            control_executed = bool(executed_raw)

        if control.get("llm_enabled") is not False:
            reasons.append("control_arm_must_disable_llm")

        if control_executed is True:
            if control.get("passed") is True:
                # Hollow gate: passes without an LLM — fail closed.
                reasons.append("no_llm_control_passed")
            elif control.get("passed") is not False:
                reasons.append("control_arm_passed_not_bool_false")
        # executed:false → CNM contribution; do not require passed:false
        # (that would invent a failed control that never ran).

    if "no_llm_control_passed" in reasons:
        return GateVerdict(
            exit_code=1,
            runtime_status=runtime_status,
            reasons=reasons,
            provider=provider if isinstance(provider, str) else None,
            min_seeds=min_seeds,
            ollama_reachable=ollama_reachable if isinstance(ollama_reachable, bool) else None,
        )

    # --- could_not_measure path (honest incomplete) ------------------------
    if runtime_status == "could_not_measure":
        # Drop measured-only control reasons that do not apply to CNM.
        reasons = [
            r
            for r in reasons
            if r
            not in (
                "control_arm_executed_missing",
                "control_arm_passed_not_bool_false",
            )
        ]
        if not reasons:
            reason = evidence.get("reason")
            if isinstance(reason, str) and reason.strip():
                reasons.append(reason.strip())
            else:
                reasons.append("could_not_measure")
        return GateVerdict(
            exit_code=2,
            runtime_status="could_not_measure",
            reasons=reasons,
            provider=provider if isinstance(provider, str) else None,
            min_seeds=min_seeds,
            ollama_reachable=ollama_reachable if isinstance(ollama_reachable, bool) else None,
        )

    # --- measured path -----------------------------------------------------
    if control_executed is not True:
        reasons.append("control_arm_not_executed")

    if not isinstance(provider, str) or not provider.strip():
        reasons.append("provider_missing")
    elif provider != REQUIRED_PROVIDER:
        reasons.append(f"provider_not_{REQUIRED_PROVIDER}:{provider}")

    if min_seeds is None:
        reasons.append("min_seeds_missing")
    elif min_seeds < MIN_SEEDS:
        reasons.append(f"min_seeds_below_policy:{min_seeds}<{MIN_SEEDS}")

    if ollama_actually_ran is not True:
        reasons.append("ollama_did_not_run")
    if ollama_reachable is False:
        reasons.append("ollama_unreachable_cannot_be_measured")

    # Measured exit 0 requires seed_runs; legacy bare grades never unlock it.
    seed_runs_raw = evidence.get("seed_runs")
    if seed_runs_raw is None or seed_runs_raw == []:
        reasons.append("seed_runs_required")

    grades, derive_reasons = derive_grades_from_evidence(evidence)
    reasons.extend(derive_reasons)

    if not grades:
        reasons.append("grades_missing")
    else:
        for idx, grade in enumerate(grades):
            if not is_valid_grade(grade):
                reasons.append(f"invalid_grade_at_{idx}:{grade!r}")
        if len(grades) < MIN_SEEDS:
            reasons.append(f"grades_below_min_seeds:{len(grades)}<{MIN_SEEDS}")

    # LLM must be load-bearing — ACK ping + identical grades never unlock measured.
    reasons.extend(llm_load_bearing_reasons(evidence))

    if reasons:
        # Claiming measured with broken evidence is a hard fail (not CNM).
        return GateVerdict(
            exit_code=1,
            runtime_status="measured",
            reasons=reasons,
            provider=provider if isinstance(provider, str) else None,
            min_seeds=min_seeds,
            ollama_reachable=ollama_reachable if isinstance(ollama_reachable, bool) else None,
        )

    return GateVerdict(
        exit_code=0,
        runtime_status="measured",
        reasons=[],
        provider=provider,
        min_seeds=min_seeds,
        ollama_reachable=True if ollama_reachable is True else ollama_reachable,
    )


def load_evidence(path: Path) -> Dict[str, Any]:
    """Load evidence JSON; raise FileNotFoundError / ValueError on bad input."""
    if not path.is_file():
        raise FileNotFoundError(f"evidence not found: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("evidence root must be a JSON object")
    return data


def write_could_not_measure_evidence(
    out_path: Path,
    *,
    reason: str,
    provider: str = REQUIRED_PROVIDER,
    min_seeds: int = MIN_SEEDS,
    ollama_reachable: bool = False,
    ollama_tags_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Write an honest could_not_measure evidence stamp.

    Control arm is recorded as ``executed: false`` with ``passed: null`` —
    do not claim a failed control that never ran.
    """
    tags_url = ollama_tags_url or resolve_ollama_tags_url()
    payload: Dict[str, Any] = {
        "provider": provider,
        "min_seeds": min_seeds,
        "runtime_status": "could_not_measure",
        "ollama_reachable": ollama_reachable,
        "ollama_actually_ran": False,
        "ollama_tags_url": tags_url,
        "grades": [],
        "seed_runs": [],
        "control_arm": {
            "llm_enabled": False,
            "executed": False,
            "passed": None,
            "notes": "control not executed; CNM — do not invent a failed control",
        },
        "reason": reason,
        "corpus_path": str(_CORPUS_YAML.relative_to(_REPO_ROOT)),
        "policy": {
            "min_seeds": MIN_SEEDS,
            "provider": REQUIRED_PROVIDER,
            "source": "docs/architecture/decision-r-vrl-1-seeds-and-provider.md",
        },
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="VRL LLM honesty gate (R-VRL-1 / Phase 4)")
    parser.add_argument(
        "--evidence",
        type=Path,
        default=_DEFAULT_EVIDENCE,
        help="Path to evidence JSON (default: reports/vrl_llm_honesty/latest.json)",
    )
    parser.add_argument(
        "--probe-ollama",
        action="store_true",
        help="Probe Ollama (OLLAMA_HOST / REVENG_OLLAMA_HOST) and print reachability; "
        "exit 0 if up, 2 if down",
    )
    parser.add_argument(
        "--write-cnm",
        action="store_true",
        help="Write could_not_measure evidence at --evidence when Ollama is down",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    tags_url = resolve_ollama_tags_url()
    reachable = probe_ollama(tags_url)

    if args.probe_ollama and not args.write_cnm and args.evidence == _DEFAULT_EVIDENCE:
        # Probe-only mode (no evaluate) unless write-cnm requested.
        print(json.dumps({"ollama_reachable": reachable, "url": tags_url}, indent=2))
        return 0 if reachable else 2

    if args.write_cnm:
        if reachable:
            print("Ollama reachable — refusing to write could_not_measure evidence", file=sys.stderr)
            return 1
        write_could_not_measure_evidence(
            args.evidence,
            reason=f"ollama_unreachable: connection refused at {tags_url}",
            ollama_reachable=False,
            ollama_tags_url=tags_url,
        )
        print(f"wrote could_not_measure evidence → {args.evidence}")

    try:
        evidence = load_evidence(args.evidence)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (ValueError, json.JSONDecodeError) as exc:
        print(f"error: invalid evidence: {exc}", file=sys.stderr)
        return 1

    # Prefer live probe over stale evidence flag when evaluating.
    if "ollama_reachable" not in evidence:
        evidence = {**evidence, "ollama_reachable": reachable}

    verdict = evaluate_evidence(evidence)
    summary = {
        "exit_code": verdict.exit_code,
        "runtime_status": verdict.runtime_status,
        "provider": verdict.provider,
        "min_seeds": verdict.min_seeds,
        "ollama_reachable": verdict.ollama_reachable,
        "reasons": verdict.reasons,
        "evidence": str(args.evidence),
    }
    print(json.dumps(summary, indent=2))
    return verdict.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
