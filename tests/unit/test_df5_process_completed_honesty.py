"""DF-5: process completed ≠ native GA — reporting contract only.

Proves that completed probe results expose semantic keys and that backlog /
architecture language forbids treating process completion alone as native GA.
Does NOT assert that semantic keys prove analyze correctness or native GA.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
LATEST = REPO / "reports" / "native_analyze_probe" / "latest.json"
BACKLOG = REPO / "backlog.md"
LESSONS = REPO / "docs" / "architecture" / "lessons-learned-scope-c-2026-08.md"
PROBE_README = REPO / "reports" / "native_analyze_probe" / "README.md"

REQUIRED_SEMANTIC_KEYS = (
    "process_status",
    "analysis_report_present",
    "native_fallback_empty",
    "semantic_reason",
    "job_output_dir",
)


def _hello_go_completed():
    payload = json.loads(LATEST.read_text(encoding="utf-8"))
    # Evidence stamps may predate stream attribution (1.2); code contract is 1.3+.
    assert payload.get("probe_version") in ("1.2", "1.3")
    results = payload.get("results") or []
    matches = [
        r for r in results if r.get("id") == "hello_go_analyze" and r.get("status") == "completed"
    ]
    assert matches, "latest.json must include hello_go_analyze with status=completed"
    return matches[0]


def test_completed_hello_go_exposes_semantic_keys_and_identity():
    """Reporting contract: completed arms carry semantic + binary identity fields."""
    row = _hello_go_completed()
    sem = row.get("semantic")
    assert isinstance(sem, dict), "completed result must include semantic object"
    for key in REQUIRED_SEMANTIC_KEYS:
        assert key in sem, f"missing semantic key {key!r}"
    assert sem["process_status"] == "completed"
    # Identity pin (Sol nit): completed subject records sha256 + path.
    assert row.get("binary"), "completed result must record binary path"
    assert row.get("binary_sha256"), "completed result must record binary_sha256"
    assert re.fullmatch(r"[0-9a-f]{64}", row["binary_sha256"]), row["binary_sha256"]
    # Explicit non-claim: these fields do not equal native GA.
    assert row["status"] == "completed"
    # Semantic presence alone must not be treated as GA proof in this module —
    # see test_docs_forbid_native_ga_from_process_completed.


def test_docs_forbid_native_ga_from_process_completed():
    """Backlog + lessons + probe README must forbid completed → native GA leap."""
    backlog = BACKLOG.read_text(encoding="utf-8")
    lessons = LESSONS.read_text(encoding="utf-8")
    readme = PROBE_README.read_text(encoding="utf-8")

    # DF-5 closed as documented+tested honesty row.
    assert re.search(
        r"\|\s*DF-5\s*\|[^|]*\|\s*done\b",
        backlog,
    ), "DF-5 must be marked done in backlog after Wave B honesty contract"

    for text, label in (
        (backlog, "backlog.md"),
        (lessons, "lessons-learned"),
        (readme, "probe README"),
    ):
        assert re.search(
            r"(?i)(process\s+[`']?completed[`']?\s*.{0,80}native\s+GA|"
            r"completed.{0,40}≠.{0,40}native|"
            r"Process `completed` is not native GA|"
            r"process completed ≠ native)",
            text,
        ), f"{label} must state process completed ≠ native GA"

    # L22 section retained as the durable lesson id.
    assert re.search(r"L22.*[Pp]rocess.*completed", lessons)
    assert "Do not flip `required: true` from process green alone" in lessons


def test_completed_plus_semantic_is_not_native_ga_claim():
    """Control: having completed+semantic keys must not satisfy a GA assertion.

    This is the documentation/reporting half of DF-5 — if a future edit claimed
    native GA solely from process green, this guard (plus manifest required:false)
    is the intended fail surface alongside test_source_binary_benchmarks_manifest.
    """
    row = _hello_go_completed()
    # Positive control that the fixture really is completed with semantics.
    assert row["status"] == "completed"
    assert "semantic" in row
    # Negative control language must appear in the same evidence directory README.
    readme = PROBE_README.read_text(encoding="utf-8")
    assert "Process `completed` is not native GA success" in readme
    # Manifest native fixtures must remain required:false (no hollow GA flip).
    manifest = json.loads(
        (REPO / ".reveng" / "source_binary_benchmarks.ga.json").read_text(encoding="utf-8")
    )
    by_id = {e["id"]: e for e in manifest["benchmarks"]}
    for fid in ("native_hello_c", "native_hello_go"):
        assert by_id[fid]["required"] is False
