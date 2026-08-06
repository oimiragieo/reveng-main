"""Wave A Task 4: R-HEX / hello_go diagnosis doc invariants."""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ARCH = REPO_ROOT / "docs" / "architecture"

R_HEX = ARCH / "research-r-hex-1-hexyl-availability-block.md"
DIAGNOSIS = ARCH / "diagnosis-hello-go-analyze-reconciliation.md"

PLACEHOLDER_TOKEN = "<placeholder>"


def test_r_hex_1_availability_block_doc_exists_and_says_blocked():
    assert R_HEX.is_file(), f"missing {R_HEX.relative_to(REPO_ROOT)}"
    text = R_HEX.read_text(encoding="utf-8")
    assert PLACEHOLDER_TOKEN not in text
    assert "blocked" in text
    assert "R-HEX-1" in text


def test_hello_go_diagnosis_doc_exists_without_placeholders():
    assert DIAGNOSIS.is_file(), f"missing {DIAGNOSIS.relative_to(REPO_ROOT)}"
    text = DIAGNOSIS.read_text(encoding="utf-8")
    assert PLACEHOLDER_TOKEN not in text
    assert "Observation A" in text
    assert "Observation B" in text
