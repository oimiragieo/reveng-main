#!/usr/bin/env python3
"""
Rebuild the checked-in tracked JS bundle + external source map + SHA-256 manifest.

Requires Node.js and npm (network on first `npm install` in the source package).

    python scripts/build_tracked_js_bundle.py
    python scripts/build_tracked_js_bundle.py --verify-only

CI / TDD: tests/unit/test_tracked_js_bundle_manifest.py asserts committed bytes match the manifest.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

SOURCE_DIR = REPO_ROOT / "test_samples" / "js_tracked_bundle_source"
ARTIFACT_DIR = REPO_ROOT / "test_samples" / "js_tracked_bundle_artifact"
ESBUILD_VERSION = "0.21.5"
# outfile is resolved relative to SOURCE_DIR cwd
OUTFILE_REL = "../js_tracked_bundle_artifact/bundle.js"


def _esbuild_bin() -> Path:
    bin_dir = SOURCE_DIR / "node_modules" / ".bin"
    name = "esbuild.cmd" if sys.platform.startswith("win") else "esbuild"
    return bin_dir / name


def _run(cmd: list[str], *, cwd: Path) -> None:
    print("+", " ".join(cmd), file=sys.stderr)
    subprocess.run(cmd, cwd=str(cwd), check=True, shell=False)


def verify_only() -> int:
    from reveng.app_reverse_engineering.tracked_bundle_manifest import (
        load_tracked_js_bundle_manifest,
        verify_tracked_js_bundle_artifact,
    )

    manifest_path = ARTIFACT_DIR / "build_manifest.json"
    if not manifest_path.is_file():
        print(f"Missing {manifest_path}", file=sys.stderr)
        return 1
    manifest = load_tracked_js_bundle_manifest(manifest_path)
    result = verify_tracked_js_bundle_artifact(ARTIFACT_DIR, manifest)
    if not result.ok:
        for err in result.errors:
            print(err, file=sys.stderr)
        return 1
    print(f"OK: verified {result.files_verified} file(s) against manifest", file=sys.stderr)
    return 0


def build() -> int:
    if shutil.which("npm") is None:
        print(
            "npm is required to rebuild the tracked bundle (install Node.js LTS)", file=sys.stderr
        )
        return 1

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    npm = shutil.which("npm")
    assert npm is not None
    _run([npm, "install"], cwd=SOURCE_DIR)

    esbuild = _esbuild_bin()
    if not esbuild.is_file():
        print(f"esbuild not found at {esbuild}; npm install may have failed", file=sys.stderr)
        return 1

    cmd = [
        str(esbuild),
        "src/index.ts",
        "--bundle",
        "--platform=node",
        "--format=cjs",
        "--sourcemap=external",
        f"--outfile={OUTFILE_REL}",
    ]
    _run(cmd, cwd=SOURCE_DIR)

    bundle_js = ARTIFACT_DIR / "bundle.js"
    map_path = ARTIFACT_DIR / "bundle.js.map"
    if not bundle_js.is_file() or not map_path.is_file():
        print("esbuild did not emit bundle.js and bundle.js.map", file=sys.stderr)
        return 1

    from reveng.app_reverse_engineering.tracked_bundle_manifest import (
        compute_files_sha256,
        write_build_manifest,
    )

    hashes = compute_files_sha256(ARTIFACT_DIR, ["bundle.js", "bundle.js.map"])
    write_build_manifest(
        ARTIFACT_DIR,
        esbuild_version=ESBUILD_VERSION,
        command=cmd,
        file_hashes=hashes,
        extra={"source_root": "test_samples/js_tracked_bundle_source"},
    )
    print(f"Wrote {bundle_js} and build_manifest.json", file=sys.stderr)
    return verify_only()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Only verify committed artifact hashes (no npm/esbuild)",
    )
    args = parser.parse_args()
    return verify_only() if args.verify_only else build()


if __name__ == "__main__":
    raise SystemExit(main())
