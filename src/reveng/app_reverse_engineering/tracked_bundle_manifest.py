"""Tracked, reproducible JavaScript bundle artifacts — manifest and integrity proofs."""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, MutableMapping, Optional

TRACKED_BUNDLE_MANIFEST_SCHEMA = "reveng.tracked_js_bundle/1"


@dataclass
class TrackedBundleVerifyResult:
    """Result of comparing on-disk bytes to a committed manifest."""

    ok: bool
    files_verified: int = 0
    errors: List[str] = field(default_factory=list)


def load_tracked_js_bundle_manifest(path: Path) -> Dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != TRACKED_BUNDLE_MANIFEST_SCHEMA:
        raise ValueError(
            f"Invalid tracked bundle manifest schema: expected {TRACKED_BUNDLE_MANIFEST_SCHEMA!r}"
        )
    return data


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_tracked_js_bundle_artifact(
    artifact_dir: Path,
    manifest: Mapping[str, Any],
) -> TrackedBundleVerifyResult:
    """Return ok=True when every listed file exists and matches manifest SHA-256."""
    errors: List[str] = []
    files_section = manifest.get("files")
    if not isinstance(files_section, Mapping):
        return TrackedBundleVerifyResult(ok=False, errors=["manifest.files must be an object"])

    verified = 0
    root = artifact_dir.resolve()
    for rel_name, meta in files_section.items():
        if not isinstance(meta, Mapping):
            errors.append(f"files[{rel_name!r}] must be an object")
            continue
        expected = meta.get("sha256")
        if not isinstance(expected, str) or len(expected) != 64:
            errors.append(f"files[{rel_name!r}].sha256 must be a 64-char hex string")
            continue
        target = (root / rel_name).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            errors.append(f"illegal path escape: {rel_name!r}")
            continue
        if not target.is_file():
            errors.append(f"missing file: {rel_name}")
            continue
        actual = _sha256_file(target)
        if actual.lower() != expected.lower():
            errors.append(f"sha256 mismatch for {rel_name}: expected {expected}, got {actual}")
            continue
        verified += 1

    return TrackedBundleVerifyResult(
        ok=len(errors) == 0 and verified > 0, files_verified=verified, errors=errors
    )


def compute_files_sha256(artifact_dir: Path, relative_paths: List[str]) -> Dict[str, str]:
    """Compute lowercase SHA-256 hex digests for files under artifact_dir."""
    root = artifact_dir.resolve()
    out: Dict[str, str] = {}
    for rel in relative_paths:
        path = (root / rel).resolve()
        path.relative_to(root)
        if not path.is_file():
            raise FileNotFoundError(path)
        out[rel] = _sha256_file(path)
    return out


def write_build_manifest(
    artifact_dir: Path,
    *,
    esbuild_version: str,
    command: List[str],
    file_hashes: Mapping[str, str],
    extra: Optional[MutableMapping[str, Any]] = None,
) -> Path:
    """Write build_manifest.json (used by scripts/build_tracked_js_bundle.py)."""
    files: Dict[str, Any] = {name: {"sha256": digest} for name, digest in file_hashes.items()}
    body: Dict[str, Any] = {
        "schema": TRACKED_BUNDLE_MANIFEST_SCHEMA,
        "toolchain": {"esbuild": esbuild_version},
        "built_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "command": command,
        "files": files,
    }
    if extra:
        body.update(dict(extra))
    out_path = artifact_dir / "build_manifest.json"
    out_path.write_text(json.dumps(body, indent=2), encoding="utf-8")
    return out_path


async def benchmark_tracked_js_bundle_row(
    bundle_path: str,
    oracle_dir: str,
    *,
    output_dir: str,
) -> Dict[str, Any]:
    """
    Run the JavaScript app adapter on a tracked bundle + oracle; return summary dict for tests/reports.

    This is intentionally small and synchronous with respect to benchmarking: callers record wall time.
    """
    from . import create_default_framework

    t0 = time.perf_counter()
    framework = create_default_framework()
    result = await framework.reverse_engineer(
        bundle_path,
        output_dir,
        language="javascript",
        oracle_dir=oracle_dir,
        max_snippets=8,
        run_js_syntax_check=False,
        run_js_behavior_probe=False,
    )
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    meta = dict(result.metadata)
    summary: Dict[str, Any] = {
        "status": "ok",
        "result_type": meta.get("result_type"),
        "elapsed_ms": round(elapsed_ms, 2),
        "validation_grade": result.validation_grade,
        "source_count": result.source_count,
        "capability_report": meta.get("capability_report"),
        "benchmark_scorecard": meta.get("benchmark_scorecard"),
        "analysis_file": str(result.analysis_file),
    }
    return summary
