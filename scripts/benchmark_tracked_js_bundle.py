#!/usr/bin/env python3
"""
Benchmark + integrity gate for the tracked JS bundle corpus artifact.

1. Verifies SHA-256 proofs in test_samples/js_tracked_bundle_artifact/build_manifest.json
2. Runs one app reverse-engineering pass (bundle + oracle) and prints timing + scorecard JSON

Usage (from repo root, package installed editable or PYTHONPATH=src):

    python scripts/benchmark_tracked_js_bundle.py
    python scripts/benchmark_tracked_js_bundle.py --skip-verify
    python scripts/benchmark_tracked_js_bundle.py --output reports/tracked_js_bundle_benchmark/latest.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

ARTIFACT_DIR = REPO_ROOT / "test_samples" / "js_tracked_bundle_artifact"
SOURCE_DIR = REPO_ROOT / "test_samples" / "js_tracked_bundle_source"

BENCHMARK_REPORT_SCHEMA = "reveng.tracked_js_bundle_benchmark/1"


def _verify_manifest() -> int:
    from reveng.app_reverse_engineering.tracked_bundle_manifest import (
        load_tracked_js_bundle_manifest,
        verify_tracked_js_bundle_artifact,
    )

    manifest_path = ARTIFACT_DIR / "build_manifest.json"
    manifest = load_tracked_js_bundle_manifest(manifest_path)
    result = verify_tracked_js_bundle_artifact(ARTIFACT_DIR, manifest)
    if not result.ok:
        print(json.dumps({"ok": False, "errors": result.errors}, indent=2))
        return 1, None
    payload = {"ok": True, "files_verified": result.files_verified, "phase": "manifest"}
    print(json.dumps(payload, indent=2))
    return 0, payload


async def _benchmark() -> dict:
    from reveng.app_reverse_engineering.tracked_bundle_manifest import (
        benchmark_tracked_js_bundle_row,
    )

    bundle = ARTIFACT_DIR / "bundle.js"
    out_root = REPO_ROOT / "reports" / "tracked_js_bundle_benchmark"
    out_root.mkdir(parents=True, exist_ok=True)
    run_dir = out_root / f"run_{int(time.time())}"
    t0 = time.perf_counter()
    summary = await benchmark_tracked_js_bundle_row(
        str(bundle),
        str(SOURCE_DIR),
        output_dir=str(run_dir),
    )
    summary["wall_clock_ms"] = round((time.perf_counter() - t0) * 1000.0, 2)
    summary["phase"] = "reverse_engineer"
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-verify",
        action="store_true",
        help="Skip SHA-256 manifest verification (not recommended for CI)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only run manifest SHA-256 verification (no reverse-engineering pass)",
    )
    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Write combined benchmark report JSON (schema reveng.tracked_js_bundle_benchmark/1)",
    )
    args = parser.parse_args()

    manifest_payload = None
    if not args.skip_verify:
        verify_code, manifest_payload = _verify_manifest()
        if verify_code != 0:
            return verify_code

    if args.verify_only:
        combined = {
            "schema": BENCHMARK_REPORT_SCHEMA,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "manifest_verify": manifest_payload,
            "reverse_engineer": None,
        }
        if args.output:
            out = Path(args.output).expanduser().resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(json.dumps(combined, indent=2), encoding="utf-8")
        return 0

    report = asyncio.run(_benchmark())
    print(json.dumps(report, indent=2))

    if args.output:
        combined = {
            "schema": BENCHMARK_REPORT_SCHEMA,
            "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "manifest_verify": manifest_payload,
            "reverse_engineer": report,
        }
        out = Path(args.output).expanduser().resolve()
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(combined, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
