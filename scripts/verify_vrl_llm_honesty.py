#!/usr/bin/env python3
"""
VRL LLM honesty gate (Phase 4 / VRL-LLM-1).

Evaluates a tracked evidence JSON against R-VRL-1 policy:

* ``min_seeds >= 3`` whenever ``runtime_status`` claims ``measured``
* measured also requires ``len(grades) >= MIN_SEEDS`` (or ≥3 executed
  ``seed_runs`` with valid ValidationGrade) — declaring ``min_seeds: 3`` with
  one grade must FAIL
* every scored run records a real ValidationGrade (ladder value) — missing grade
  ⇒ ``could_not_measure``, never a pass
* no-LLM control arm must be *executed* and FAIL for measured
  (``executed: true``, ``passed: false``, ``llm_enabled: false``)
* unexecuted control (``executed: false``) is a CNM contribution — never a
  phantom ``passed: false`` that unlocks measured
* provider identity recorded; ``runtime_status: measured`` only when ollama
  actually ran

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
OLLAMA_TAGS_URL = "http://127.0.0.1:11434/api/tags"

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


def probe_ollama(url: str = OLLAMA_TAGS_URL, timeout_s: float = 2.0) -> bool:
    """Return True when local Ollama answers ``/api/tags``."""
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            return 200 <= int(getattr(resp, "status", 200)) < 300
    except (urllib.error.URLError, TimeoutError, OSError):
        return False


def is_valid_grade(grade: Any) -> bool:
    """True when *grade* is a non-empty ValidationGrade ladder value."""
    if not isinstance(grade, str):
        return False
    return grade.strip() in VALIDATION_GRADE_LADDER


def derive_grades_from_evidence(evidence: Dict[str, Any]) -> Tuple[List[Any], List[str]]:
    """
    Resolve the grade list the gate will score.

    Prefer ``seed_runs`` when present: only ``executed: true`` rows with a valid
    ValidationGrade count. Otherwise fall back to the legacy ``grades`` list.
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
            derived.append(grade)
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
) -> Dict[str, Any]:
    """
    Write an honest could_not_measure evidence stamp.

    Control arm is recorded as ``executed: false`` with ``passed: null`` —
    do not claim a failed control that never ran.
    """
    payload: Dict[str, Any] = {
        "provider": provider,
        "min_seeds": min_seeds,
        "runtime_status": "could_not_measure",
        "ollama_reachable": ollama_reachable,
        "ollama_actually_ran": False,
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
        help="Probe local Ollama and print reachability; exit 0 if up, 2 if down",
    )
    parser.add_argument(
        "--write-cnm",
        action="store_true",
        help="Write could_not_measure evidence at --evidence when Ollama is down",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    reachable = probe_ollama()

    if args.probe_ollama and not args.write_cnm and args.evidence == _DEFAULT_EVIDENCE:
        # Probe-only mode (no evaluate) unless write-cnm requested.
        print(json.dumps({"ollama_reachable": reachable, "url": OLLAMA_TAGS_URL}, indent=2))
        return 0 if reachable else 2

    if args.write_cnm:
        if reachable:
            print("Ollama reachable — refusing to write could_not_measure evidence", file=sys.stderr)
            return 1
        write_could_not_measure_evidence(
            args.evidence,
            reason="ollama_unreachable: connection refused on 127.0.0.1:11434",
            ollama_reachable=False,
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
