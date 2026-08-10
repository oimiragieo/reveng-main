"""Wave 8 — structural match, Bun SerializedSourceMap, coverage union."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering.js_recovery_toolkit import run_recovery_toolkit
from reveng.app_reverse_engineering.js_recovery_toolkit.bun_serialized_sourcemap import (
    build_serialized_sourcemap_fixture,
    materialize_serialized_sources,
    parse_serialized_sourcemap,
)
from reveng.app_reverse_engineering.js_recovery_toolkit.coverage_union import (
    singleton_literal_hits,
    union_coverage,
)
from reveng.app_reverse_engineering.js_recovery_toolkit.structural_match import (
    file_signature,
    jaccard_from_sigs,
    match_sources_to_bundle,
)

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "test_samples" / "js_recovery_toolkit"
MAP = FIX / "stale.map.json"
POS = FIX / "targets" / "positive_remix.js"
MIS = FIX / "targets" / "mismatch.js"


def test_serialized_sourcemap_roundtrip_100pct(tmp_path: Path) -> None:
    sources = {
        "src/a.ts": "export const A_UNIQUE_TOKEN_W8AAAA = 1;\n",
        "src/b.ts": "export const B_UNIQUE_TOKEN_W8BBBB = 2;\n",
    }
    blob = build_serialized_sourcemap_fixture(sources)
    parsed = parse_serialized_sourcemap(blob)
    assert parsed.decode_ok
    assert set(parsed.sources) == set(sources)
    assert parsed.sources["src/a.ts"] == sources["src/a.ts"]
    n = materialize_serialized_sources(parsed, tmp_path / "out")
    assert n == 2
    assert (tmp_path / "out" / "src" / "a.ts").read_text(encoding="utf-8") == sources["src/a.ts"]


def test_structural_match_prefers_similar_body() -> None:
    sources = {
        "src/keep.ts": "function keepAliveWidget(){const x=1;const y=2;return x+y;}\n" * 5,
        "src/other.ts": "class TotallyDifferentThing{run(){return null}}\n" * 5,
    }
    bundle = sources["src/keep.ts"] + "\n// filler\n"
    hits = match_sources_to_bundle(sources, bundle, threshold=0.4)
    paths = {h.source_path for h in hits}
    assert "src/keep.ts" in paths


def test_minhash_identical_is_one() -> None:
    body = "function fooBarBaz(){return 1+2+3;}\n" * 10
    a = file_signature(body)
    b = file_signature(body)
    assert jaccard_from_sigs(a, b) == 1.0


def test_pipeline_survivor_and_oracle_100pct(tmp_path: Path) -> None:
    report = run_recovery_toolkit(
        output_dir=tmp_path / "out",
        bundle=POS,
        sourcemap=MAP,
        run_external=False,
    )
    # Option C: final coverage after iterative defrag unlocks weak neighbors
    cov = report.stages.get("coverage_union_final") or report.stages["coverage_union"]
    assert cov["oracle_count"] >= 3
    assert report.stages["iterative_defrag"]["survivor_coverage"] == 1.0
    assert report.stages["iterative_defrag"]["oracle_coverage"] == 1.0
    assert report.to_serializable()["decoded_exe_claim"] is False


def test_pipeline_mismatch_coverage_stays_low(tmp_path: Path) -> None:
    report = run_recovery_toolkit(
        output_dir=tmp_path / "mis",
        bundle=MIS,
        sourcemap=MAP,
        run_external=False,
    )
    cov = report.stages["coverage_union"]
    assert cov["attributed_count"] == 0
    assert cov["oracle_coverage"] == 0.0


def test_singleton_and_union_helpers() -> None:
    sources = {
        "src/a.ts": 'const t = "SINGLETON_LITERAL_TOKEN_W8XXXX";\n',
        "src/b.ts": 'const t = "OTHER_UNIQUE_LITERAL_TOKEN_W8";\n',
    }
    bundle = 'x="SINGLETON_LITERAL_TOKEN_W8XXXX";'
    confirmed, survivors = singleton_literal_hits(sources, bundle)
    assert confirmed == {"src/a.ts"}
    assert survivors == {"src/a.ts"}
    cov = union_coverage(
        oracle_paths=set(sources),
        attributed={"src/a.ts": "singleton_literal"},
        survivor_paths=survivors,
    )
    assert cov.survivor_coverage == 1.0
    assert cov.oracle_coverage == 0.5
