"""Unit tests for Ralph-style JS oracle loop (pure logic + injected runner)."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping

import pytest

from reveng.app_reverse_engineering.ralph_js_loop import (
    compose_ralph_variants,
    default_js_ralph_variants,
    heavy_js_ralph_variants,
    js_behavior_probe_tier,
    load_js_ralph_variants_from_json,
    oracle_recall_precision,
    ralph_score_key,
    run_ralph_js_oracle_loop,
)

pytestmark = pytest.mark.ralph_js


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _ralph_cli_script() -> Path:
    return _repo_root() / "scripts" / "ralph_js_oracle_loop.py"


def test_ralph_cli_help_exits_zero() -> None:
    script = _ralph_cli_script()
    proc = subprocess.run(
        [sys.executable, str(script), "--help"],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 0
    out = proc.stdout or ""
    assert "--variants-json" in out
    assert "--no-plateau" in out


def test_ralph_cli_missing_input_exits_one(tmp_path: Path) -> None:
    script = _ralph_cli_script()
    oracle = tmp_path / "oracle"
    oracle.mkdir()
    missing = tmp_path / "missing.js"
    proc = subprocess.run(
        [sys.executable, str(script), "--input", str(missing), "--oracle", str(oracle)],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 1
    assert "Input not found" in proc.stderr


def test_ralph_cli_variants_json_only_without_json_exits_one(tmp_path: Path) -> None:
    script = _ralph_cli_script()
    inp = tmp_path / "in.js"
    inp.write_text("//\n", encoding="utf-8")
    oracle = tmp_path / "oracle"
    oracle.mkdir()
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--input",
            str(inp),
            "--oracle",
            str(oracle),
            "--variants-json-only",
        ],
        cwd=str(_repo_root()),
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 1
    assert "variants-json" in proc.stderr.lower()


def test_oracle_recall_precision_reads_scorecard() -> None:
    meta = {"benchmark_scorecard": {"project_file_recall": 0.25, "project_file_precision": 0.9}}
    assert oracle_recall_precision(meta) == (0.25, 0.9)


def test_oracle_recall_precision_missing() -> None:
    assert oracle_recall_precision({}) == (0.0, 0.0)


def test_ralph_score_key_orders_recall_first() -> None:
    assert ralph_score_key(0.5, 0.5, {}) > ralph_score_key(0.4, 1.0, {})


def test_js_behavior_probe_tier_reads_capability_report() -> None:
    meta = {
        "capability_report": {
            "dimensions": {
                "javascript_behavior_probe": {"skipped": False, "tier": 2},
            }
        }
    }
    assert js_behavior_probe_tier(meta) == 2


def test_ralph_score_key_behavior_tiebreak() -> None:
    low = {
        "capability_report": {
            "dimensions": {"javascript_behavior_probe": {"skipped": False, "tier": 1}}
        }
    }
    high = {
        "capability_report": {
            "dimensions": {"javascript_behavior_probe": {"skipped": False, "tier": 2}}
        }
    }
    assert ralph_score_key(0.5, 0.5, high) > ralph_score_key(0.5, 0.5, low)


def test_ralph_score_key_recall_dominates_behavior() -> None:
    m_high_beh = {
        "capability_report": {
            "dimensions": {"javascript_behavior_probe": {"skipped": False, "tier": 2}}
        }
    }
    assert ralph_score_key(0.6, 0.1, {}) > ralph_score_key(0.5, 1.0, m_high_beh)


def test_ralph_loop_stops_at_target_recall(tmp_path: Path) -> None:
    states: List[Dict[str, Any]] = [
        {"recall": 0.1, "precision": 0.5},
        {"recall": 0.85, "precision": 0.6},
    ]
    idx = {"n": 0}

    async def fake_runner(
        attempt: int, variant: Mapping[str, Any], attempt_dir: str
    ) -> MutableMapping[str, Any]:
        del variant, attempt_dir
        i = idx["n"]
        idx["n"] += 1
        st = states[min(i, len(states) - 1)]
        return {
            "metadata": {
                "benchmark_scorecard": {
                    "project_file_recall": st["recall"],
                    "project_file_precision": st["precision"],
                }
            },
            "validation_grade": "evidence_backed",
            "analysis_file": str(tmp_path / f"a{i}.json"),
        }

    report = asyncio.run(
        run_ralph_js_oracle_loop(
            input_path="/fake/in.js",
            oracle_dir="/fake/oracle",
            output_root=str(tmp_path / "out"),
            target_project_file_recall=0.8,
            max_attempts=10,
            plateau_attempts=3,
            variants=default_js_ralph_variants(),
            attempt_runner=fake_runner,
        )
    )
    assert report["completion_reason"].startswith("target_recall_reached")
    assert report["best_project_file_recall"] == 0.85
    assert report["attempt_count"] == 2


def test_ralph_loop_runs_max_attempts_when_plateau_disabled(tmp_path: Path) -> None:
    flat = {"recall": 0.1, "precision": 0.1}
    one_variant = [
        {
            "label": "only",
            "run_webcrack": False,
            "run_restringer": False,
            "run_deobfuscator": False,
            "run_wakaru": False,
            "run_js_deobfuscator": False,
            "max_snippets": 12,
        }
    ]

    async def fake_runner(
        attempt: int, variant: Mapping[str, Any], attempt_dir: str
    ) -> MutableMapping[str, Any]:
        del attempt, variant, attempt_dir
        return {
            "metadata": {
                "benchmark_scorecard": {
                    "project_file_recall": flat["recall"],
                    "project_file_precision": flat["precision"],
                }
            },
            "validation_grade": "evidence_backed",
            "analysis_file": str(tmp_path / "x.json"),
        }

    report = asyncio.run(
        run_ralph_js_oracle_loop(
            input_path="/fake/in.js",
            oracle_dir="/fake/oracle",
            output_root=str(tmp_path / "out"),
            target_project_file_recall=0.99,
            max_attempts=7,
            plateau_attempts=2,
            variants=one_variant,
            stop_on_plateau=False,
            attempt_runner=fake_runner,
        )
    )
    assert report["attempt_count"] == 7
    assert report["completion_reason"] == "max_attempts_reached"
    assert report["stop_on_plateau"] is False
    assert report["effective_plateau_attempts"] is None


def test_ralph_effective_plateau_at_least_variant_count(tmp_path: Path) -> None:
    flat = {"recall": 0.1, "precision": 0.2}
    variants = [
        {
            "label": f"v{i}",
            "run_webcrack": False,
            "run_restringer": False,
            "run_deobfuscator": False,
            "run_wakaru": False,
            "run_js_deobfuscator": False,
            "max_snippets": 12,
        }
        for i in range(4)
    ]

    async def fake_runner(
        attempt: int, variant: Mapping[str, Any], attempt_dir: str
    ) -> MutableMapping[str, Any]:
        del attempt, variant, attempt_dir
        return {
            "metadata": {
                "benchmark_scorecard": {
                    "project_file_recall": flat["recall"],
                    "project_file_precision": flat["precision"],
                }
            },
            "validation_grade": "evidence_backed",
            "analysis_file": str(tmp_path / "x.json"),
        }

    report = asyncio.run(
        run_ralph_js_oracle_loop(
            input_path="/fake/in.js",
            oracle_dir="/fake/oracle",
            output_root=str(tmp_path / "out"),
            target_project_file_recall=0.99,
            max_attempts=20,
            plateau_attempts=2,
            variants=variants,
            attempt_runner=fake_runner,
        )
    )
    assert report["effective_plateau_attempts"] == 4
    assert report["completion_reason"].startswith("plateau_after")
    assert report["attempt_count"] == 5


def test_ralph_loop_stops_on_plateau(tmp_path: Path) -> None:
    flat = {"recall": 0.2, "precision": 0.5}
    # Single variant so effective_plateau == plateau_attempts (multi-variant raises floor to len(variants)).
    one_variant = [
        {
            "label": "flat_only",
            "run_webcrack": False,
            "run_restringer": False,
            "run_deobfuscator": False,
            "run_wakaru": False,
            "run_js_deobfuscator": False,
            "max_snippets": 12,
        }
    ]

    async def fake_runner(
        attempt: int, variant: Mapping[str, Any], attempt_dir: str
    ) -> MutableMapping[str, Any]:
        del attempt, variant, attempt_dir
        return {
            "metadata": {
                "benchmark_scorecard": {
                    "project_file_recall": flat["recall"],
                    "project_file_precision": flat["precision"],
                }
            },
            "validation_grade": "evidence_backed",
            "analysis_file": str(tmp_path / "x.json"),
        }

    report = asyncio.run(
        run_ralph_js_oracle_loop(
            input_path="/fake/in.js",
            oracle_dir="/fake/oracle",
            output_root=str(tmp_path / "out"),
            target_project_file_recall=0.99,
            max_attempts=20,
            plateau_attempts=2,
            variants=one_variant,
            attempt_runner=fake_runner,
        )
    )
    assert report["completion_reason"].startswith("plateau_after")
    assert report["attempt_count"] == 3
    assert report["effective_plateau_attempts"] == 2


def test_default_variants_have_labels() -> None:
    v = default_js_ralph_variants()
    assert len(v) >= 3
    assert all("label" in item for item in v)


def test_load_js_ralph_variants_from_json(tmp_path: Path) -> None:
    p = tmp_path / "v.json"
    p.write_text(
        '[{"label": "x", "run_webcrack": true, "max_snippets": 5}]',
        encoding="utf-8",
    )
    loaded = load_js_ralph_variants_from_json(p)
    assert loaded == [{"label": "x", "run_webcrack": True, "max_snippets": 5}]


def test_load_js_ralph_variants_rejects_unknown_key(tmp_path: Path) -> None:
    p = tmp_path / "bad.json"
    p.write_text('[{"label": "x", "not_a_key": 1}]', encoding="utf-8")
    with pytest.raises(ValueError, match="unknown variant key"):
        load_js_ralph_variants_from_json(p)


def test_load_js_ralph_variants_requires_non_empty_array(tmp_path: Path) -> None:
    p = tmp_path / "empty.json"
    p.write_text("[]", encoding="utf-8")
    with pytest.raises(ValueError, match="non-empty"):
        load_js_ralph_variants_from_json(p)


def test_compose_merges_defaults_json_and_heavy() -> None:
    extra = [{"label": "from_json", "run_webcrack": False}]
    v = compose_ralph_variants(
        use_defaults=True,
        extra_from_json=extra,
        append_wakaru=True,
        append_js_deobfuscator=True,
    )
    assert v[0]["label"] == "baseline"
    assert any(x.get("label") == "from_json" for x in v)
    assert any(x.get("label") == "webcrack_wakaru" for x in v)
    assert any(x.get("label") == "webcrack_js_deobfuscator" for x in v)


def test_compose_no_defaults_wakaru_only() -> None:
    v = compose_ralph_variants(
        use_defaults=False,
        extra_from_json=None,
        append_wakaru=True,
        append_js_deobfuscator=False,
    )
    assert len(v) == 1
    assert v[0]["label"] == "webcrack_wakaru"


def test_compose_empty_raises() -> None:
    with pytest.raises(ValueError, match="empty"):
        compose_ralph_variants(
            use_defaults=False,
            extra_from_json=None,
            append_wakaru=False,
            append_js_deobfuscator=False,
        )


def test_heavy_js_ralph_variants_both_flags() -> None:
    h = heavy_js_ralph_variants(include_wakaru=True, include_js_deobfuscator=True)
    assert len(h) == 2
    assert {x["label"] for x in h} == {"webcrack_wakaru", "webcrack_js_deobfuscator"}
