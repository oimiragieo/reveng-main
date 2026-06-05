"""TDD: tracked JS bundle artifact integrity (manifest + SHA-256 proof)."""

from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from reveng.app_reverse_engineering.tracked_bundle_manifest import (
    TRACKED_BUNDLE_MANIFEST_SCHEMA,
    benchmark_tracked_js_bundle_row,
    load_tracked_js_bundle_manifest,
    verify_tracked_js_bundle_artifact,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
ARTIFACT_DIR = REPO_ROOT / "test_samples" / "js_tracked_bundle_artifact"
MANIFEST_PATH = ARTIFACT_DIR / "build_manifest.json"


def test_manifest_schema_constant() -> None:
    assert TRACKED_BUNDLE_MANIFEST_SCHEMA == "reveng.tracked_js_bundle/1"


def test_corpus_configs_reference_tracked_bundle_row() -> None:
    """Benchmarking contract: smoke + GA corpora include the portable tracked JS row."""
    for name in (
        ".reveng/app_reverse_engineering_corpus.json",
        ".reveng/app_reverse_engineering_corpus.ga.json",
    ):
        raw = json.loads((REPO_ROOT / name).read_text(encoding="utf-8"))
        entry_names = {e["name"] for e in raw["entries"]}
        assert "javascript-tracked-bundle" in entry_names


def test_committed_artifact_matches_manifest() -> None:
    """Proof gate: checked-in bundle.js / .map bytes match build_manifest.json."""
    assert (
        MANIFEST_PATH.is_file()
    ), f"Missing {MANIFEST_PATH} — run: python scripts/build_tracked_js_bundle.py"
    manifest = load_tracked_js_bundle_manifest(MANIFEST_PATH)
    result = verify_tracked_js_bundle_artifact(ARTIFACT_DIR, manifest)
    assert result.ok is True, f"Hash mismatch: {result.errors}"
    assert result.files_verified >= 1


def test_manifest_lists_required_outputs() -> None:
    manifest = load_tracked_js_bundle_manifest(MANIFEST_PATH)
    files = manifest.get("files", {})
    assert "bundle.js" in files
    assert "bundle.js.map" in files
    for key in ("bundle.js", "bundle.js.map"):
        assert "sha256" in files[key]
        assert len(files[key]["sha256"]) == 64


def test_verify_detects_tampering(tmp_path: Path) -> None:
    tiny = tmp_path / "artifact"
    tiny.mkdir()
    payload = b"//x\n"
    (tiny / "bundle.js").write_bytes(payload)
    h = hashlib.sha256(payload).hexdigest()
    manifest = {
        "schema": TRACKED_BUNDLE_MANIFEST_SCHEMA,
        "files": {"bundle.js": {"sha256": h}},
    }
    (tiny / "build_manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    loaded = load_tracked_js_bundle_manifest(tiny / "build_manifest.json")
    assert verify_tracked_js_bundle_artifact(tiny, loaded).ok is True
    (tiny / "bundle.js").write_bytes(b"//y\n")
    bad = verify_tracked_js_bundle_artifact(tiny, loaded)
    assert bad.ok is False
    assert any("bundle.js" in e for e in bad.errors)


@pytest.mark.tracked_bundle
@pytest.mark.slow
@pytest.mark.xfail(
    reason="benchmark_tracked_js_bundle_row expects oracle_dir/syntax-check/behavior-probe "
    "params + capability_report/benchmark_scorecard metadata not yet wired through the "
    "framework/JS adapter (tracking: oracle-scoring feature gap)",
    strict=False,
)
def test_tracked_bundle_corpus_benchmark_includes_capability(
    tmp_path: Path, performance_benchmark
) -> None:
    """Benchmark-style check: one RE row yields capability_report + scorecard keys."""
    bundle = ARTIFACT_DIR / "bundle.js"
    oracle = REPO_ROOT / "test_samples" / "js_tracked_bundle_source"
    if not bundle.is_file():
        pytest.skip("Tracked bundle artifact not present")
    performance_benchmark.start()
    summary = asyncio.run(
        benchmark_tracked_js_bundle_row(
            str(bundle),
            str(oracle),
            output_dir=str(tmp_path / "tracked_re_out"),
        )
    )
    wall_s = performance_benchmark.stop()
    assert wall_s < 180.0, f"tracked bundle RE took {wall_s:.1f}s (regression if unbounded)"

    assert summary["status"] in ("ok", "completed")
    assert summary["result_type"] == "app_reverse_engineering_result"
    assert "capability_report" in summary
    cap = summary["capability_report"]
    assert cap.get("schema_version") == "1.0"
    # Oracle-backed JS should surface alignment slice when scorecard exists
    oa = cap.get("dimensions", {}).get("oracle_alignment") or {}
    if oa.get("present"):
        assert "project_file_recall" in oa or "project_file_precision" in oa

    score = summary.get("benchmark_scorecard") or {}
    assert "overall_score" in score
    assert "token_signal_score" in score


def test_build_tracked_js_bundle_script_verify_only_exits_zero() -> None:
    """CLI proof: rebuild verifier must succeed on committed artifact (no npm)."""
    script = REPO_ROOT / "scripts" / "build_tracked_js_bundle.py"
    proc = subprocess.run(
        [sys.executable, str(script), "--verify-only"],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_benchmark_tracked_js_bundle_script_writes_combined_report(tmp_path: Path) -> None:
    """CLI proof: benchmark script emits schema-versioned JSON for CI artifacts."""
    script = REPO_ROOT / "scripts" / "benchmark_tracked_js_bundle.py"
    out = tmp_path / "bench.json"
    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--verify-only",
            "--output",
            str(out),
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["schema"] == "reveng.tracked_js_bundle_benchmark/1"
    assert data["manifest_verify"] is not None
    assert data["manifest_verify"]["ok"] is True
    assert data["reverse_engineer"] is None
