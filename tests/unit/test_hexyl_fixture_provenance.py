"""Wave B Task 1: hexyl fixture provenance (loud skip when ELF absent)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
HEXYL_BIN = REPO_ROOT / "test_samples" / "native" / "hexyl" / "build" / "hexyl"
HEXYL_SHA = HEXYL_BIN.with_name("hexyl.sha256")
RESEARCH = REPO_ROOT / "docs" / "architecture" / "research-r-hex-1-hexyl-timed-run.md"
BUILD_SCRIPT = REPO_ROOT / "scripts" / "build_hexyl_fixture.sh"

# Phase 4 rebuild pin (research-r-hex-1-hexyl-timed-run.md). Wave B historical
# digest remains documented there; live ELF + tests track this rebuild.
EXPECTED_SHA256 = "3d26048bbbaee5e87a4613b4e21e898185e15b43cf43bd4fe74cc5d2dbaa5dba"
WAVE_B_HISTORICAL_SHA256 = "e2040b5deda5900a152ac28a7444ba565b2b0d46861a3efefafaf074f1a16dfc"
EXPECTED_VERSION = "0.17.0"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def test_build_hexyl_fixture_script_exists_and_is_executable():
    assert BUILD_SCRIPT.is_file(), f"missing {BUILD_SCRIPT.relative_to(REPO_ROOT)}"
    assert BUILD_SCRIPT.stat().st_mode & 0o111, f"{BUILD_SCRIPT.name} must be executable"


def test_research_doc_pins_version_sha_and_path():
    assert RESEARCH.is_file(), f"missing {RESEARCH.relative_to(REPO_ROOT)}"
    text = RESEARCH.read_text(encoding="utf-8")
    assert EXPECTED_VERSION in text
    assert EXPECTED_SHA256 in text
    assert WAVE_B_HISTORICAL_SHA256 in text
    assert "test_samples/native/hexyl/build/hexyl" in text
    assert "scripts/build_hexyl_fixture.sh" in text
    assert "<placeholder>" not in text


def test_hexyl_provenance_when_binary_present_or_loud_skip():
    """
    If the gitignored ELF is present: hexyl.sha256 must exist and match the
    binary + the digest pinned in the research doc.

    If absent: skip loudly with an actionable build recipe (not a silent pass).
    """
    if not HEXYL_BIN.is_file():
        reason = (
            "hexyl ELF absent at test_samples/native/hexyl/build/hexyl — "
            "run: scripts/build_hexyl_fixture.sh "
            "(requires external/hexyl-benchmark/hexyl + cargo)"
        )
        print(f"NATIVE_FIXTURE_SKIPPED: hexyl reason={reason}")
        pytest.skip(reason)

    assert HEXYL_SHA.is_file(), (
        f"{HEXYL_SHA.relative_to(REPO_ROOT)} missing beside present ELF — "
        "re-run scripts/build_hexyl_fixture.sh (script writes the checksum)"
    )
    digest = _sha256_file(HEXYL_BIN)
    assert digest == EXPECTED_SHA256, (
        f"binary sha256 {digest} != pinned {EXPECTED_SHA256}; "
        "rebuild with scripts/build_hexyl_fixture.sh and update the research doc"
    )
    sha_text = HEXYL_SHA.read_text(encoding="utf-8").strip()
    file_digest = sha_text.split()[0]
    assert file_digest == digest, (
        f"hexyl.sha256 records {file_digest} but binary hashes to {digest}"
    )
    # Research doc must stay aligned with the local provenance file.
    research = RESEARCH.read_text(encoding="utf-8")
    assert digest in research
    assert f"**Hexyl version:** `{EXPECTED_VERSION}`" in research
