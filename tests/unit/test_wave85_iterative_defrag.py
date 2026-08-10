"""Wave 8.5 — iterative defrag + TF-IDF word-map (option C)."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering.js_recovery_toolkit import run_recovery_toolkit
from reveng.app_reverse_engineering.js_recovery_toolkit.ensemble_index import (
    build_ensemble_index_from_sourcemap,
    scan_ensemble,
)
from reveng.app_reverse_engineering.js_recovery_toolkit.iterative_defrag import run_iterative_defrag
from reveng.app_reverse_engineering.js_recovery_toolkit.word_map import (
    best_unique_assignments,
    word_map_sources_to_bundle,
)

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "test_samples" / "js_recovery_toolkit"
MAP = FIX / "stale.map.json"
POS = FIX / "targets" / "positive_remix.js"
MIS = FIX / "targets" / "mismatch.js"


def test_neighbor_not_ensemble_confirmed() -> None:
    hits = scan_ensemble(build_ensemble_index_from_sourcemap(MAP), POS.read_text(encoding="utf-8"))
    paths = {h.source_path for h in hits}
    assert "src/neighbor.ts" not in paths


def test_defrag_unlocks_neighbor_to_100(tmp_path: Path) -> None:
    report = run_recovery_toolkit(
        output_dir=tmp_path / "out",
        bundle=POS,
        sourcemap=MAP,
        run_external=False,
    )
    defrag = report.stages["iterative_defrag"]
    assert defrag["decoded_exe_claim"] is False
    assert "src/neighbor.ts" in defrag["attributed"]
    assert defrag["survivor_coverage"] == 1.0
    assert defrag["oracle_coverage"] == 1.0
    assert "defrag_oracle_coverage_100pct" in report.notes


def test_mismatch_stays_zero(tmp_path: Path) -> None:
    report = run_recovery_toolkit(
        output_dir=tmp_path / "mis",
        bundle=MIS,
        sourcemap=MAP,
        run_external=False,
    )
    assert report.stages["iterative_defrag"]["attributed_count"] == 0
    assert report.stages["iterative_defrag"]["oracle_coverage"] == 0.0


def test_word_map_unique_assignment_helper() -> None:
    scores = {
        "src/a.ts": [(0, 0.9), (1, 0.4)],
        "src/b.ts": [(0, 0.8), (1, 0.7)],
    }
    assigned = best_unique_assignments(scores, threshold=0.35)
    assert assigned["src/a.ts"][0] == 0
    assert assigned["src/b.ts"][0] == 1


def test_word_map_bundle_prefers_matching_text() -> None:
    sources = {
        "src/alpha.ts": "function alphaWidgetFactory(){ return ALPHA_MARKER_TOKEN; }",
        "src/beta.ts": "function betaSomethingElse(){ return BETA_OTHER_TOKEN; }",
    }
    bundle = "zzzz " + sources["src/alpha.ts"] + " yyyy"
    result = word_map_sources_to_bundle(sources, bundle, threshold=0.2)
    assert "src/alpha.ts" in result.assignments
