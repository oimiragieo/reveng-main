"""Wave 7 JS recovery toolkit — hermetic unit tests."""

from __future__ import annotations

import json
from pathlib import Path

from reveng.app_reverse_engineering.js_recovery_toolkit import run_recovery_toolkit
from reveng.app_reverse_engineering.js_recovery_toolkit.behavior_probe import (
    behavior_token_overlap,
)
from reveng.app_reverse_engineering.js_recovery_toolkit.ensemble_index import (
    build_ensemble_index_from_sourcemap,
    scan_ensemble,
)
from reveng.app_reverse_engineering.js_recovery_toolkit.external_tools import probe_external_tools
from reveng.app_reverse_engineering.js_recovery_toolkit.graph_complete import (
    suggest_graph_completions,
)

REPO = Path(__file__).resolve().parents[2]
FIX = REPO / "test_samples" / "js_recovery_toolkit"
MAP = FIX / "stale.map.json"
POS = FIX / "targets" / "positive_remix.js"
MIS = FIX / "targets" / "mismatch.js"
ORACLE = FIX / "oracle"


def test_ensemble_positive_confirms_and_mismatch_zero() -> None:
    index = build_ensemble_index_from_sourcemap(MAP)
    assert index.to_serializable()["entry_count"] > 0
    blob = json.dumps(index.to_serializable())
    assert "CORE_UNIQUE_FINGERPRINT_TOKEN_W7ABCDEF" not in blob
    pos = scan_ensemble(index, POS.read_text(encoding="utf-8"))
    assert len(pos) >= 1
    mis = scan_ensemble(index, MIS.read_text(encoding="utf-8"))
    assert mis == []


def test_graph_completion_unique_subset() -> None:
    confirmed = {
        "src/cli.ts": "require('./core');\nrequire('./util');\n",
        "src/core.ts": "require('./util');\n",
    }
    anonymous = {
        "anon:x": "require('./core');\nrequire('./util');\n",
    }
    hints = suggest_graph_completions(
        confirmed_path_to_body=confirmed,
        anonymous_modules=anonymous,
        min_shared=2,
    )
    assert len(hints) == 1
    assert hints[0].inferred_path == "src/cli.ts"


def test_behavior_overlap_positive() -> None:
    ov = behavior_token_overlap(
        ORACLE.joinpath("src/cli.ts").read_text(encoding="utf-8"),
        POS.read_text(encoding="utf-8"),
    )
    assert ov.intersection >= 1
    assert ov.recall > 0


def test_pipeline_hermetic_end_to_end(tmp_path: Path) -> None:
    report = run_recovery_toolkit(
        output_dir=tmp_path / "out",
        bundle=POS,
        sourcemap=MAP,
        oracle_dir=ORACLE,
        run_external=False,
    )
    ser = report.to_serializable()
    assert ser["decoded_exe_claim"] is False
    assert ser["llm_used"] is False
    assert ser["stages"]["fingerprint_ensemble"]["confirmed"] >= 1
    assert ser["stages"]["fingerprint_v5"]["confirmed"] >= 1
    assert (tmp_path / "out" / "toolkit_report.json").is_file()
    assert probe_external_tools()["bun_extractor_in_tree"] is True


def test_pipeline_mismatch_stays_low(tmp_path: Path) -> None:
    report = run_recovery_toolkit(
        output_dir=tmp_path / "mis",
        bundle=MIS,
        sourcemap=MAP,
        run_external=False,
    )
    assert report.stages["fingerprint_ensemble"]["confirmed"] == 0
    assert report.stages["fingerprint_v5"]["confirmed"] == 0
