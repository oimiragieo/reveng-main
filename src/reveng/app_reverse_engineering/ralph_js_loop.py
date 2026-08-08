"""
Ralph-style outer loop for JavaScript oracle scoring (execute → measure → retry with variants).

Repeating the *same* toolchain configuration does not improve recall; this module rotates
optional post-processors (webcrack, restringer, etc.) so each attempt can differ.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import (
    Any,
    Awaitable,
    Callable,
    Dict,
    List,
    Mapping,
    MutableMapping,
    Optional,
    Sequence,
    Tuple,
)

# Keys passed through to AppReverseEngineeringFramework.reverse_engineer for JavaScript.
ALLOWED_JS_RALPH_VARIANT_KEYS = frozenset(
    {
        "label",
        "run_webcrack",
        "run_restringer",
        "run_deobfuscator",
        "run_wakaru",
        "run_js_deobfuscator",
        "max_snippets",
        "snippet_context",
    }
)


def load_js_ralph_variants_from_json(path: Path | str) -> List[Dict[str, Any]]:
    """
    Load variant profiles from a JSON array of objects.

    Each object may only contain keys in ``ALLOWED_JS_RALPH_VARIANT_KEYS``.
    """
    p = Path(path).expanduser().resolve()
    raw = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("variants JSON must be a top-level JSON array")
    if not raw:
        raise ValueError("variants JSON array must be non-empty")
    out: List[Dict[str, Any]] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            raise ValueError(f"variants[{i}] must be a JSON object")
        cleaned: Dict[str, Any] = {}
        for key, value in item.items():
            if key not in ALLOWED_JS_RALPH_VARIANT_KEYS:
                raise ValueError(
                    f"unknown variant key {key!r} in variants[{i}] "
                    f"(allowed: {sorted(ALLOWED_JS_RALPH_VARIANT_KEYS)})"
                )
            cleaned[key] = value
        out.append(cleaned)
    return out


def oracle_recall_precision(metadata: Mapping[str, Any]) -> Tuple[float, float]:
    """Read project_file_recall / project_file_precision from enriched analysis metadata."""
    sc = metadata.get("benchmark_scorecard")
    if not isinstance(sc, Mapping):
        return (0.0, 0.0)
    recall = float(sc.get("project_file_recall", 0.0) or 0.0)
    precision = float(sc.get("project_file_precision", 0.0) or 0.0)
    return (recall, precision)


def js_behavior_probe_tier(metadata: Mapping[str, Any]) -> int:
    """Return 0–2 from ``capability_report.dimensions.javascript_behavior_probe``."""
    cap = metadata.get("capability_report")
    if not isinstance(cap, Mapping):
        return 0
    dims = cap.get("dimensions")
    if not isinstance(dims, Mapping):
        return 0
    probe = dims.get("javascript_behavior_probe")
    if not isinstance(probe, Mapping) or probe.get("skipped", True):
        return 0
    tier = probe.get("tier", 0)
    try:
        t = int(tier)
    except (TypeError, ValueError):
        return 0
    return max(0, min(t, 2))


def ralph_score_key(
    recall: float,
    precision: float,
    metadata: Optional[Mapping[str, Any]] = None,
) -> Tuple[float, float, int, float]:
    """
    Lexicographic ranking: recall, precision, JS behavior-probe tier, then F1-like product.

    ``metadata`` should be enriched app analysis (includes ``capability_report``).
    """
    behavior = js_behavior_probe_tier(metadata or {})
    product = recall * precision if recall > 0 and precision > 0 else 0.0
    return (recall, precision, behavior, product)


def default_js_ralph_variants() -> List[Dict[str, Any]]:
    """
    Built-in attempt profiles. Each dict is merged into framework.reverse_engineer kwargs.

    Heavy tools are gated late so fast baselines run first.
    """
    return [
        {
            "label": "baseline",
            "run_webcrack": False,
            "run_restringer": False,
            "run_deobfuscator": False,
            "run_wakaru": False,
            "run_js_deobfuscator": False,
            "max_snippets": 12,
        },
        {
            "label": "webcrack",
            "run_webcrack": True,
            "run_restringer": False,
            "run_deobfuscator": False,
            "run_wakaru": False,
            "run_js_deobfuscator": False,
            "max_snippets": 12,
        },
        {
            "label": "webcrack_more_snippets",
            "run_webcrack": True,
            "run_restringer": False,
            "run_deobfuscator": False,
            "run_wakaru": False,
            "run_js_deobfuscator": False,
            "max_snippets": 24,
        },
        {
            "label": "webcrack_restringer",
            "run_webcrack": True,
            "run_restringer": True,
            "run_deobfuscator": False,
            "run_wakaru": False,
            "run_js_deobfuscator": False,
            "max_snippets": 16,
        },
        {
            "label": "deobfuscator_pass",
            "run_webcrack": True,
            "run_restringer": False,
            "run_deobfuscator": True,
            "run_wakaru": False,
            "run_js_deobfuscator": False,
            "max_snippets": 16,
        },
    ]


def heavy_js_ralph_variants(
    *,
    include_wakaru: bool = False,
    include_js_deobfuscator: bool = False,
) -> List[Dict[str, Any]]:
    """
    Optional slow / external-tool profiles appended after defaults.

    Requires those tools to be installed and discoverable by the JS adapter.
    """
    out: List[Dict[str, Any]] = []
    if include_wakaru:
        out.append(
            {
                "label": "webcrack_wakaru",
                "run_webcrack": True,
                "run_restringer": False,
                "run_deobfuscator": False,
                "run_wakaru": True,
                "run_js_deobfuscator": False,
                "max_snippets": 16,
            }
        )
    if include_js_deobfuscator:
        out.append(
            {
                "label": "webcrack_js_deobfuscator",
                "run_webcrack": True,
                "run_restringer": False,
                "run_deobfuscator": False,
                "run_wakaru": False,
                "run_js_deobfuscator": True,
                "max_snippets": 16,
            }
        )
    return out


def compose_ralph_variants(
    *,
    use_defaults: bool = True,
    extra_from_json: Optional[Sequence[Mapping[str, Any]]] = None,
    append_wakaru: bool = False,
    append_js_deobfuscator: bool = False,
) -> List[Dict[str, Any]]:
    """
    Build the variant list: optional defaults, optional JSON-loaded profiles, optional heavy tools.
    """
    variants: List[Dict[str, Any]] = []
    if use_defaults:
        variants.extend(default_js_ralph_variants())
    if extra_from_json:
        variants.extend(dict(x) for x in extra_from_json)
    variants.extend(
        heavy_js_ralph_variants(
            include_wakaru=append_wakaru,
            include_js_deobfuscator=append_js_deobfuscator,
        )
    )
    if not variants:
        raise ValueError(
            "composed variant list is empty (enable defaults, pass JSON variants, or use heavy flags)"
        )
    return variants


async def run_ralph_js_oracle_loop(
    *,
    input_path: str,
    oracle_dir: str,
    output_root: str,
    target_project_file_recall: float,
    max_attempts: int,
    plateau_attempts: int,
    variants: Sequence[Mapping[str, Any]],
    stop_on_plateau: bool = True,
    snippet_context: int = 2,
    run_js_syntax_check: bool = False,
    run_js_behavior_probe: bool = True,
    attempt_runner: Optional[
        Callable[[int, Mapping[str, Any], str], Awaitable[MutableMapping[str, Any]]]
    ] = None,
) -> Dict[str, Any]:
    """
    Run up to ``max_attempts`` attempts, cycling ``variants``, keeping the best oracle recall.

    Stops when ``project_file_recall`` >= ``target_project_file_recall``, when ``max_attempts``
    is exhausted, or (if ``stop_on_plateau``) after ``plateau_attempts`` **consecutive**
    non-improving tries (raised to at least ``len(variants)`` so one full variant rotation can run).

    Set ``stop_on_plateau=False`` for a **fixed iteration budget**: only the recall target or
    ``max_attempts`` ends the loop (e.g. ``max_attempts=100`` runs up to 100 attempts).
    If ``attempt_runner`` is provided, it must be an async callable::

        async def attempt_runner(attempt_num, variant, attempt_dir) -> dict:
            return {"metadata": {...}, "validation_grade": "...", "analysis_file": "..."}

    Otherwise the real framework is used.
    """
    if max_attempts < 1:
        raise ValueError("max_attempts must be >= 1")
    if stop_on_plateau and plateau_attempts < 1:
        raise ValueError("plateau_attempts must be >= 1 when stop_on_plateau is True")
    if not variants:
        raise ValueError("variants must be non-empty")

    from pathlib import Path

    root = Path(output_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)

    n_variants = len(variants)
    effective_plateau = max(plateau_attempts, n_variants) if stop_on_plateau else 0

    framework = None
    attempts_out: List[Dict[str, Any]] = []
    best_meta: Optional[Mapping[str, Any]] = None
    best_key: Optional[Tuple[float, float, int, float]] = None
    best_attempt = 0
    plateau_streak = 0
    completion_reason = "max_attempts_reached"

    for i in range(1, max_attempts + 1):
        raw_variant = dict(variants[(i - 1) % len(variants)])
        label = str(raw_variant.pop("label", f"variant_{i}"))

        attempt_dir = root / f"attempt_{i:03d}_{label}"
        attempt_dir.mkdir(parents=True, exist_ok=True)

        if attempt_runner is not None:
            payload = await attempt_runner(i, raw_variant, str(attempt_dir))
            metadata = payload.get("metadata") or {}
            validation_grade = str(payload.get("validation_grade", ""))
            analysis_file = str(payload.get("analysis_file", ""))
        else:
            if framework is None:
                from . import create_default_framework

                framework = create_default_framework()
            result = await framework.reverse_engineer(
                input_path,
                str(attempt_dir),
                language="javascript",
                oracle_dir=oracle_dir,
                snippet_context=snippet_context,
                run_js_syntax_check=run_js_syntax_check,
                run_js_behavior_probe=run_js_behavior_probe,
                **raw_variant,
            )
            metadata = result.metadata
            validation_grade = result.validation_grade
            analysis_file = str(result.analysis_file)

        recall, precision = oracle_recall_precision(metadata)
        behavior_tier = js_behavior_probe_tier(metadata)
        key = ralph_score_key(recall, precision, metadata)
        improved = best_key is None or key > best_key
        if improved:
            best_key = key
            best_meta = metadata
            best_attempt = i
            plateau_streak = 0
        else:
            plateau_streak += 1

        attempts_out.append(
            {
                "attempt": i,
                "label": label,
                "variant": raw_variant,
                "project_file_recall": recall,
                "project_file_precision": precision,
                "js_behavior_probe_tier": behavior_tier,
                "validation_grade": validation_grade,
                "analysis_file": analysis_file,
                "improved": improved,
                "ralph_knobs": (metadata or {}).get("ralph_knobs"),
            }
        )

        if recall >= target_project_file_recall:
            completion_reason = f"target_recall_reached:{i}"
            break
        if (
            stop_on_plateau
            and effective_plateau > 0
            and plateau_streak >= effective_plateau
            and i < max_attempts
        ):
            completion_reason = f"plateau_after:{i}"
            break

    assert best_key is not None
    br, bp = best_key[0], best_key[1]
    best_behavior = js_behavior_probe_tier(best_meta or {})
    return {
        "schema_version": "1.0",
        "result_type": "ralph_js_oracle_loop_report",
        "input_path": input_path,
        "oracle_dir": oracle_dir,
        "output_root": str(root),
        "target_project_file_recall": target_project_file_recall,
        "variant_count": n_variants,
        "stop_on_plateau": stop_on_plateau,
        "plateau_attempts_configured": plateau_attempts,
        "effective_plateau_attempts": effective_plateau if stop_on_plateau else None,
        "max_attempts_limit": max_attempts,
        "best_attempt": best_attempt,
        "best_project_file_recall": br,
        "best_project_file_precision": bp,
        "best_js_behavior_probe_tier": best_behavior,
        "completion_reason": completion_reason,
        "attempt_count": len(attempts_out),
        "attempts": attempts_out,
        "best_benchmark_scorecard": (best_meta or {}).get("benchmark_scorecard"),
    }
