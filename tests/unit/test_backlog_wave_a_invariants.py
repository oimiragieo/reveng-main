"""Wave A backlog honesty gates + architecture doc placeholder scans.

Assertions target the FINAL post-Task-9 backlog state. They are expected RED
against the current backlog until Task 9 reconciles rows.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Tuple

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKLOG = REPO_ROOT / "backlog.md"

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
    r"\b(open|done|partial|parked|blocked|research|mitigated|in_progress)\b",
    re.IGNORECASE,
)
_BOLD_STATUS_RE = re.compile(
    r"\*\*\s*(open|done|partial|parked|blocked|research|mitigated|in_progress)\s*\*\*",
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
        if i + 1 >= len(lines) or not re.match(
            r"^\s*\|?\s*:?-{3,}", lines[i + 1]
        ):
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
    """Find a table row whose first cell equals item_id exactly (no substring)."""
    matches: List[Tuple[List[str], List[str]]] = []
    for headers, rows in tables:
        for row in rows:
            if row and row[0] == item_id:
                matches.append((headers, row))
    assert matches, f"backlog row id {item_id!r} not found (exact match)"
    assert len(matches) == 1, f"duplicate backlog rows for exact id {item_id!r}"
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
    m = re.search(
        r"^## E\..*?(?=^## |\Z)", text, flags=re.MULTILINE | re.DOTALL
    )
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
    assert fake_zero is None, (
        "must not present numeric 0 / 0.0 as recall when status is could_not_measure"
    )
    assert re.search(r"(?im)recall\s*[|:].*\bnull\b", text), (
        "could_not_measure baseline must label recall as null"
    )


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
# Backlog invariants — FINAL Task-9 state (expected RED until reconcile)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "item_id",
    ["T3-KERNEL", "T3-PACKED", "T3-JIT", "T3-ANTI", "T3-GUI"],
)
def test_t3_rows_remain_parked(item_id: str):
    assert _backlog_status(item_id) == "parked"


@pytest.mark.parametrize("phase", list(range(4, 14)))
def test_section_e_phases_4_through_13_open(phase: int):
    status = _section_e_phase_status(phase)
    assert status == "open", f"section E phase {phase} status={status!r}, want open"


def test_m1_native_fam_remains_open():
    assert _backlog_status("M1-NATIVE-FAM") == "open"


def test_r_hex_1_is_blocked_not_done():
    """Final desired state after Task 9: R-HEX-1 blocked (never done without hexyl timed run)."""
    status = _backlog_status("R-HEX-1")
    assert status != "done"
    assert status == "blocked"


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
