"""Wave A/B backlog honesty gates + architecture doc placeholder scans.

Wave A assertions cover research decisions + parked T3 + phases 4–13.
Wave B adds M0/M4/DF-5 closures and non-closure safeguards (RALPH-2, M2, …).
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKLOG = REPO_ROOT / "backlog.md"
MANIFEST = REPO_ROOT / ".reveng" / "source_binary_benchmarks.ga.json"
WAVE_C_EXIT = REPO_ROOT / "docs" / "architecture" / "wave-c-exit-criteria.md"

ARCH = REPO_ROOT / "docs" / "architecture"
RALPH_BASELINE = ARCH / "research-r-ralph-2-baseline.md"
DECISION_DOCS = (
    ARCH / "decision-r-pipe-1-pipeline-packages.md",
    ARCH / "decision-r-sec-1-sandbox-class.md",
    ARCH / "decision-r-vrl-1-seeds-and-provider.md",
)
WAVE_A_DOCS = (RALPH_BASELINE,) + DECISION_DOCS

# Angle-bracket template holes such as <path>, <candidate>, <n> — not comparisons.
_PLACEHOLDER_RE = re.compile(r"<[A-Za-z_][^>\n]*>")
_STATUS_TOKEN_RE = re.compile(
    r"\b(open|done|partial|parked|blocked|research|mitigated|in_progress|deferred|wontfix)\b",
    re.IGNORECASE,
)
_BOLD_STATUS_RE = re.compile(
    r"\*\*\s*(open|done|partial|parked|blocked|research|mitigated|in_progress|deferred|wontfix)\s*\*\*",
    re.IGNORECASE,
)


def _strip_cell(cell: str) -> str:
    return cell.strip().strip("`").strip()


def _parse_md_tables(text: str) -> List[Tuple[List[str], List[List[str]]]]:
    """Return list of (headers, rows) for GitHub-style markdown tables."""
    lines = text.splitlines()
    tables: List[Tuple[List[str], List[List[str]]]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.strip().startswith("|"):
            i += 1
            continue
        header_cells = [_strip_cell(c) for c in line.strip().strip("|").split("|")]
        if i + 1 >= len(lines) or not re.match(r"^\s*\|?\s*:?-{3,}", lines[i + 1]):
            i += 1
            continue
        i += 2
        rows: List[List[str]] = []
        while i < len(lines) and lines[i].strip().startswith("|"):
            cells = [_strip_cell(c) for c in lines[i].strip().strip("|").split("|")]
            rows.append(cells)
            i += 1
        tables.append((header_cells, rows))
    return tables


def _row_by_exact_id(
    tables: List[Tuple[List[str], List[List[str]]]], item_id: str
) -> Tuple[List[str], List[str]]:
    """Find a table row whose first cell equals item_id exactly (no substring).

    Section J may mirror ops-table ids; duplicates are allowed when every match
    yields the same status token (prefer the first / ops-table row).
    """
    matches: List[Tuple[List[str], List[str]]] = []
    for headers, rows in tables:
        for row in rows:
            if row and row[0] == item_id:
                matches.append((headers, row))
    assert matches, f"backlog row id {item_id!r} not found (exact match)"
    if len(matches) > 1:
        statuses = {_status_from_row(h, r) for h, r in matches}
        assert len(statuses) == 1, (
            f"duplicate backlog rows for exact id {item_id!r} disagree on status: "
            f"{sorted(statuses)}"
        )
    return matches[0]


def _status_from_row(headers: List[str], row: List[str]) -> str:
    lower_headers = [h.lower() for h in headers]
    if "status" in lower_headers:
        idx = lower_headers.index("status")
        assert idx < len(row), f"status column OOB for row {row!r}"
        cell = row[idx]
        bold = _BOLD_STATUS_RE.search(cell)
        if bold:
            return bold.group(1).lower()
        token = _STATUS_TOKEN_RE.search(cell)
        assert token, f"status column present but no status token in {cell!r}"
        return token.group(1).lower()
    # Research-queue style (no status column): require an explicit bold status
    # so free-text notes like "remains open under M2" cannot false-match.
    joined = " | ".join(row[1:])
    bold = _BOLD_STATUS_RE.search(joined)
    assert bold, (
        f"row {row[0]!r} has no status column and no bold status "
        f"(expected **open**|**done**|**blocked**|… for Task 9 reconcile); row={row!r}"
    )
    return bold.group(1).lower()


def _backlog_status(item_id: str) -> str:
    text = BACKLOG.read_text(encoding="utf-8")
    headers, row = _row_by_exact_id(_parse_md_tables(text), item_id)
    return _status_from_row(headers, row)


def _section_e_phase_status(phase: int) -> str:
    text = BACKLOG.read_text(encoding="utf-8")
    # Narrow to section E heading through next ## heading.
    m = re.search(r"^## E\..*?(?=^## |\Z)", text, flags=re.MULTILINE | re.DOTALL)
    assert m, "section E not found in backlog.md"
    tables = _parse_md_tables(m.group(0))
    headers, row = _row_by_exact_id(tables, str(phase))
    return _status_from_row(headers, row)


# ---------------------------------------------------------------------------
# Doc placeholder / honesty scans (should be GREEN once Task 5–6 docs exist)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", WAVE_A_DOCS, ids=lambda p: p.name)
def test_wave_a_architecture_docs_exist(path: Path):
    assert path.is_file(), f"missing Wave A architecture doc: {path}"


@pytest.mark.parametrize("path", WAVE_A_DOCS, ids=lambda p: p.name)
def test_wave_a_docs_have_no_angle_placeholders(path: Path):
    text = path.read_text(encoding="utf-8")
    hits = _PLACEHOLDER_RE.findall(text)
    assert not hits, f"{path.name} still has placeholder tokens: {hits}"


def test_ralph_baseline_could_not_measure_forbids_numeric_zero_recall():
    text = RALPH_BASELINE.read_text(encoding="utf-8")
    assert "could_not_measure" in text
    # Forbid presenting a lone 0 / 0.0 as the recall measurement under CNM.
    fake_zero = re.search(
        r"(?im)^(?:\|?\s*)?recall\s*[|:]\s*`?(?:0(?:\.0+)?|0\.0)`?\b",
        text,
    )
    assert (
        fake_zero is None
    ), "must not present numeric 0 / 0.0 as recall when status is could_not_measure"
    assert re.search(
        r"(?im)recall\s*[|:].*\bnull\b", text
    ), "could_not_measure baseline must label recall as null"


def test_vrl_decision_states_min_seeds_and_provider_policy():
    text = (ARCH / "decision-r-vrl-1-seeds-and-provider.md").read_text(encoding="utf-8")
    assert re.search(r"min_seeds\s*:\s*3\b", text)
    assert re.search(r"provider\s*:\s*`?ollama`?\b", text)
    assert re.search(r"runtime_status\s*:\s*`?(?:measured|could_not_measure)`?\b", text)


def test_pipe_decision_is_permanent_split_freeze():
    text = (ARCH / "decision-r-pipe-1-pipeline-packages.md").read_text(encoding="utf-8")
    assert re.search(r"permanent documented split", text, re.IGNORECASE)
    assert "test_pipeline_package_split" in text
    assert "reveng.pipeline" in text and "reveng.pipelines" in text


def test_sec_decision_docker_only_no_exploit_expansion():
    text = (ARCH / "decision-r-sec-1-sandbox-class.md").read_text(encoding="utf-8")
    assert re.search(r"Docker-only", text, re.IGNORECASE)
    assert re.search(r"no exploit expansion", text, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Backlog invariants — Wave A reconcile + Wave B non-closures
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "item_id",
    ["T3-KERNEL", "T3-PACKED", "T3-JIT", "T3-ANTI", "T3-GUI"],
)
def test_t3_rows_remain_parked(item_id: str):
    assert _backlog_status(item_id) == "parked"


@pytest.mark.parametrize("phase", list(range(5, 14)))
def test_section_e_phases_5_through_13_open(phase: int):
    status = _section_e_phase_status(phase)
    assert status == "open", f"section E phase {phase} status={status!r}, want open"


def test_section_e_phase_4_partial_until_both_exits():
    """Phase 4 may be partial when VRL half is could_not_measure; never hollow done."""
    status = _section_e_phase_status(4)
    assert status in ("open", "partial", "in_progress")
    # Done only when both Track A and measured VRL exits land — not while CNM.
    assert status != "done"


def test_m1_native_fam_remains_open_and_not_required():
    assert _backlog_status("M1-NATIVE-FAM") == "open"
    benches = json.loads(MANIFEST.read_text(encoding="utf-8"))["benchmarks"]
    by_id = {e["id"]: e for e in benches}
    for fid in ("native_hello_c", "native_hello_go"):
        assert by_id[fid]["required"] is not True
        assert by_id[fid]["required"] is False


def test_r_hex_1_matches_measured_hexyl_subject_json():
    """R-HEX-1 status must track the hexyl_subject probe arm (never hollow done)."""
    latest = json.loads(
        (REPO_ROOT / "reports" / "native_analyze_probe" / "latest.json").read_text(encoding="utf-8")
    )
    hexyl_subject = next(
        (r for r in latest.get("results") or [] if r.get("id") == "hexyl_subject"),
        None,
    )
    assert hexyl_subject is not None, "missing hexyl_subject arm in latest.json"
    analyze_cmd = hexyl_subject.get("analyze_cmd") or []
    assert any("python" in str(part).lower() for part in analyze_cmd), analyze_cmd
    assert "hexyl" in str(hexyl_subject.get("binary") or "")
    proc = hexyl_subject.get("status")
    backlog_status = _backlog_status("R-HEX-1")
    headers, row = _row_by_exact_id(
        _parse_md_tables(BACKLOG.read_text(encoding="utf-8")), "R-HEX-1"
    )
    row_text = " | ".join(row)
    del headers  # exact-id lookup only
    if proc == "timeout":
        # Plan: keep open/blocked if still timeout-only; never claim hollow done.
        assert backlog_status in ("open", "blocked")
        assert backlog_status != "done"
    elif proc == "completed":
        assert backlog_status == "done"
        assert "(measured)" in row_text
        # Live stamp sha must be non-empty; Phase 4 rebuild pin may differ from
        # the Wave B historical digest documented in research-r-hex-1.
        sha = hexyl_subject.get("binary_sha256") or ""
        assert len(sha) == 64
        assert sha == (
            "3d26048bbbaee5e87a4613b4e21e898185e15b43cf43bd4fe74cc5d2dbaa5dba"
        ) or sha == ("e2040b5deda5900a152ac28a7444ba565b2b0d46861a3efefafaf074f1a16dfc")
    else:
        # could_not_measure / other — not done.
        assert backlog_status != "done"


def test_r_ralph_2_baseline_done_exact_id():
    """Task 9 must add R-RALPH-2-BASELINE; exact id so BASELINE ≠ R-RALPH-2."""
    assert _backlog_status("R-RALPH-2-BASELINE") == "done"


def test_r_ralph_2_remains_open_exact_id():
    status = _backlog_status("R-RALPH-2")
    assert status == "open"
    # Guard against accidental substring collapse with BASELINE.
    text = BACKLOG.read_text(encoding="utf-8")
    tables = _parse_md_tables(text)
    headers, row = _row_by_exact_id(tables, "R-RALPH-2")
    assert row[0] == "R-RALPH-2"
    assert row[0] != "R-RALPH-2-BASELINE"
    assert _status_from_row(headers, row) == "open"


def test_research_decision_rows_done_after_reconcile():
    """Final desired research-queue statuses after Task 9."""
    assert _backlog_status("R-PIPE-1") == "done"
    assert _backlog_status("R-SEC-1") == "done"
    assert _backlog_status("R-VRL-1") == "done"


# ---------------------------------------------------------------------------
# Wave B closures + non-closures (executable Sol nits)
# ---------------------------------------------------------------------------


def test_wave_b_m0_done_m4_partial_df5_done():
    assert _backlog_status("M0") == "done"
    assert _backlog_status("M4") == "partial"
    assert _backlog_status("DF-5") == "done"
    m0_notes = " | ".join(
        _row_by_exact_id(_parse_md_tables(BACKLOG.read_text(encoding="utf-8")), "M0")[1]
    )
    assert re.search(r"M4\s+residual", m0_notes, re.IGNORECASE)


def test_wave_b_nonclosures_ralph2_m2_m1_native_phases_t3():
    assert _backlog_status("RALPH-2") == "open"
    # Phase 4 Track A = honesty attribution only; world-class M2 stays partial.
    assert _backlog_status("M2") == "partial"
    assert _backlog_status("M1-NATIVE-FAM") == "open"
    assert _section_e_phase_status(4) in ("open", "partial", "in_progress")
    assert _section_e_phase_status(4) != "done"
    for phase in range(5, 14):
        assert _section_e_phase_status(phase) == "open"
    for tid in ("T3-KERNEL", "T3-PACKED", "T3-JIT", "T3-ANTI", "T3-GUI"):
        assert _backlog_status(tid) == "parked"


def test_wave_c_exit_criteria_doc_lists_remaining_poles():
    assert WAVE_C_EXIT.is_file()
    text = WAVE_C_EXIT.read_text(encoding="utf-8")
    for needle in (
        "RALPH-2",
        "M1-NATIVE-FAM",
        "M2",
        "M4 corpus",
        "VRL",
        "phases 4",
        "P4-BUNDLER",
        "T3",
        "parked",
    ):
        assert needle in text, f"wave-c-exit-criteria missing {needle!r}"
    hits = _PLACEHOLDER_RE.findall(text)
    assert not hits, f"wave-c-exit-criteria still has placeholders: {hits}"
