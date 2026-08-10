"""Wave 9b — provider summarize + tag boost + webcrack adapter."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from reveng.app_reverse_engineering.js_recovery_toolkit import run_recovery_toolkit
from reveng.app_reverse_engineering.js_recovery_toolkit.llm_digest import LlmModuleDigest
from reveng.app_reverse_engineering.js_recovery_toolkit.provider_summarize import (
    build_summarize_fn,
    probe_providers,
)
from reveng.app_reverse_engineering.js_recovery_toolkit.tag_boost import (
    run_tag_boost_defrag,
    unlock_by_llm_tags,
)

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "test_samples" / "js_recovery_toolkit"
MAP = FIX / "stale.map.json"
POS = FIX / "targets" / "positive_remix.js"


def test_probe_providers_shape() -> None:
    probe = probe_providers()
    assert "openai_compat" in probe
    assert "ollama" in probe
    assert "anthropic_key" in probe


def test_build_summarize_falls_back_heuristic() -> None:
    fn, notes = build_summarize_fn(prefer="anthropic", allow_heuristic_fallback=True)
    # No key → should fall through to heuristic without raising
    text = fn("src/x.ts", "fetch('/a'); localStorage.setItem('k',1); process.env.X;")
    assert "module" in text.lower() or "api" in text.lower() or "involves" in text.lower()
    assert notes


def test_unlock_by_llm_tags_precision() -> None:
    sources = {
        "src/a.ts": "export const a=1",
        "src/b.ts": "export const b=2",
    }
    digests = [
        LlmModuleDigest(
            path="src/a.ts",
            summary="auth login",
            tags=["unique_auth_login_w9", "bearer_token_flow_w9"],
        )
    ]
    bundle = "unique_auth_login_w9 and bearer_token_flow_w9 appear here"
    hits = unlock_by_llm_tags(
        sources=sources,
        bundle_text=bundle,
        attributed={},
        digests=digests,
        min_tags=2,
    )
    assert hits == {"src/a.ts": "llm_tag"}


def test_tag_boost_defrag_merges(tmp_path: Path) -> None:
    sources = {
        "src/core.ts": 'require("./neighbor"); const CORE_UNIQUE_FINGERPRINT_TOKEN_W7ABCDEF="CORE_UNIQUE_FINGERPRINT_TOKEN_W7ABCDEF";',
        "src/neighbor.ts": 'const NW8WEAK="NW8WEAK";',
        "src/extra.ts": "export const x=1",
    }
    bundle = (
        "CORE_UNIQUE_FINGERPRINT_TOKEN_W7ABCDEF NW8WEAK unique_topic_alpha_w9 unique_topic_beta_w9"
    )
    seed = {"src/core.ts": "ensemble"}
    digests = [
        LlmModuleDigest(
            path="src/extra.ts",
            summary="extra module",
            tags=["unique_topic_alpha_w9", "unique_topic_beta_w9"],
        )
    ]
    boost = run_tag_boost_defrag(
        sources=sources,
        bundle_text=bundle,
        seed_attributed=seed,
        digests=digests,
        max_rounds=3,
    )
    assert "src/extra.ts" in boost.defrag.attributed
    assert boost.defrag.survivor_coverage == 1.0
    assert boost.to_serializable()["decoded_exe_claim"] is False


def test_pipeline_llm_digest_with_mocked_provider(tmp_path: Path) -> None:
    def fake_build(prefer=None, allow_heuristic_fallback=True):
        def _fn(path, body):
            return f"module {path} handles toolkit recovery fetch storage tags: toolkit_recovery_panel toolkit_config_boot"

        return _fn, ["used:mock"]

    with patch(
        "reveng.app_reverse_engineering.js_recovery_toolkit.pipeline.build_summarize_fn",
        fake_build,
    ):
        report = run_recovery_toolkit(
            output_dir=tmp_path / "out",
            bundle=POS,
            sourcemap=MAP,
            enable_llm_digest=True,
            llm_max_modules=10,
            llm_tag_boost=True,
        )
    assert report.llm_used is True
    assert report.stages["llm_digest"]["module_count"] >= 1
    assert "llm_tag_boost" in report.stages
    assert report.stages["iterative_defrag"]["oracle_coverage"] == 1.0
    assert report.to_serializable()["decoded_exe_claim"] is False
