"""Wave 9 — readable normalize + semantic digest + optional LLM chunk digest."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering.js_recovery_toolkit import run_recovery_toolkit
from reveng.app_reverse_engineering.js_recovery_toolkit.llm_digest import (
    heuristic_summarize_fn,
    tags_from_summary,
)
from reveng.app_reverse_engineering.js_recovery_toolkit.readable_normalize import readable_normalize
from reveng.app_reverse_engineering.js_recovery_toolkit.semantic_digest import (
    extract_semantic_features,
)

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "test_samples" / "js_recovery_toolkit"
MAP = FIX / "stale.map.json"
POS = FIX / "targets" / "positive_remix.js"


def test_readable_normalize_expands_minifier_idioms() -> None:
    src = "function a(){return void 0}if(!0){x=!1}"
    out = readable_normalize(src)
    assert "undefined" in out.text
    assert "true" in out.text
    assert "false" in out.text
    assert "\n" in out.text
    assert out.to_serializable()["decoded_exe_claim"] is False


def test_semantic_features_detect_api_anchors() -> None:
    body = "async function f(){ await fetch('/x'); localStorage.setItem('a',1); }"
    feats = extract_semantic_features(body)
    assert "api_fetch" in feats
    assert "api_local_storage" in feats


def test_heuristic_llm_digest_tags() -> None:
    summary = heuristic_summarize_fn(
        "src/auth.ts",
        "fetch('/login'); process.env.TOKEN; localStorage.setItem('t',1);",
    )
    tags = tags_from_summary(summary)
    assert tags
    assert any("api" in t or "fetch" in t or "auth" in t for t in tags)


def test_pipeline_readable_stage(tmp_path: Path) -> None:
    report = run_recovery_toolkit(
        output_dir=tmp_path / "out",
        bundle=POS,
        sourcemap=MAP,
        run_external=False,
        enable_llm_digest=True,
    )
    assert "readable_normalize" in report.stages
    assert report.stages["iterative_defrag"]["oracle_coverage"] == 1.0
    assert report.stages["llm_digest"]["module_count"] >= 1
    assert report.llm_used is True
    assert report.to_serializable()["decoded_exe_claim"] is False
