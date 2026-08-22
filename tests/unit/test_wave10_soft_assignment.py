"""Wave 10 — soft bipartite assignment + tombstone metrics."""

from __future__ import annotations

from reveng.app_reverse_engineering.js_recovery_toolkit.soft_assignment import (
    hungarian_unique_assignments,
    soft_assign_sources_to_bundle,
)
from reveng.app_reverse_engineering.js_recovery_toolkit.tombstone import (
    classify_tombstones,
    recoverable_oracle_coverage,
)


def test_hungarian_beats_greedy_collision() -> None:
    """Classic assignment trap: greedy locks A onto B's only good chunk."""
    scores = {
        "src/a.ts": [(0, 0.60), (1, 0.55)],
        "src/b.ts": [(0, 0.59), (1, 0.10)],
    }
    greedy_style = {}
    used = set()
    for score, path, idx in sorted(
        ((s, p, i) for p, ranked in scores.items() for i, s in ranked),
        reverse=True,
    ):
        if path in greedy_style or idx in used or score < 0.35:
            continue
        greedy_style[path] = (idx, score)
        used.add(idx)
    assert "src/a.ts" in greedy_style and greedy_style["src/a.ts"][0] == 0
    assert "src/b.ts" not in greedy_style

    assigned = hungarian_unique_assignments(scores, threshold=0.35, min_margin=0.0)
    assert assigned["src/a.ts"][0] == 1
    assert assigned["src/b.ts"][0] == 0


def test_margin_rejects_ambiguous_pair() -> None:
    scores = {
        "src/a.ts": [(0, 0.50), (1, 0.49)],
    }
    assigned = hungarian_unique_assignments(scores, threshold=0.35, min_margin=0.05)
    assert assigned == {}


def test_soft_assign_prefers_matching_module() -> None:
    sources = {
        "src/alpha.ts": "export function AlphaUniqueFactoryTokenXYZ(){ return 1 }",
        "src/beta.ts": "export function BetaOtherWidgetQQQ(){ return 2 }",
    }
    bundle = sources["src/alpha.ts"] + "\n" + "noise noise noise"
    result = soft_assign_sources_to_bundle(sources, bundle, threshold=0.15, min_margin=0.01)
    assert "src/alpha.ts" in result.assignments
    assert result.decoded_exe_claim is False


def test_tombstone_marks_absent_source() -> None:
    sources = {
        "src/alive.ts": "ALIVE_UNIQUE_TOKEN_ABCDEFGHIJ more words here",
        "src/gone.ts": "DELETED_ONLY_IN_MAP_ZZZZZZZZ never shipped",
    }
    bundle = "prefix ALIVE_UNIQUE_TOKEN_ABCDEFGHIJ suffix"
    report = classify_tombstones(sources, bundle, min_hits=1)
    assert "src/gone.ts" in report.tombstones
    assert "src/alive.ts" in report.survivors
    cov = recoverable_oracle_coverage(
        oracle_paths=set(sources),
        attributed={"src/alive.ts": "seed"},
        tombstones=report.tombstones,
    )
    assert cov == 1.0


def test_tombstone_ignores_shared_boilerplate() -> None:
    sources = {
        "src/a.ts": "SHARED_BOILERPLATE_TOKEN and A_ONLY_TOKEN_XXXX",
        "src/b.ts": "SHARED_BOILERPLATE_TOKEN and B_ONLY_TOKEN_YYYY",
        "src/ghost.ts": "SHARED_BOILERPLATE_TOKEN only",
    }
    bundle = "SHARED_BOILERPLATE_TOKEN A_ONLY_TOKEN_XXXX"
    report = classify_tombstones(sources, bundle, min_hits=1, unique_tokens_only=True)
    assert "src/a.ts" in report.survivors
    assert "src/ghost.ts" in report.tombstones
    assert "src/b.ts" in report.tombstones
