"""Fail-first / Wave 4 tests for JS project tree materialization."""

from __future__ import annotations

from pathlib import Path

from reveng.app_reverse_engineering.adapters.javascript import _project_recovered_root
from reveng.app_reverse_engineering.js_project_materialize import materialize_js_project_tree

REPO = Path(__file__).resolve().parents[2]
TRACKED_DIR = REPO / "test_samples" / "js_tracked_bundle_artifact"


def test_materialize_tracked_sourcemap_restores_ts_sources(tmp_path: Path) -> None:
    bundle = TRACKED_DIR / "bundle.js"
    assert (TRACKED_DIR / "bundle.js.map").is_file()
    # Copy pair into tmp so we don't write into fixtures
    local = tmp_path / "in"
    local.mkdir()
    b = local / "bundle.js"
    b.write_bytes(bundle.read_bytes())
    (local / "bundle.js.map").write_bytes((TRACKED_DIR / "bundle.js.map").read_bytes())

    result = materialize_js_project_tree(
        output_dir=tmp_path / "out",
        input_path=b,
        normalized_bundle=b,
    )
    assert result.mode == "source_map"
    assert result.recovered_root is not None
    root = _project_recovered_root(tmp_path / "out")
    assert root is not None
    names = {p.name for p in root.rglob("*") if p.is_file()}
    assert "index.ts" in names
    assert "greet.ts" in names
    greet = next(root.rglob("greet.ts"))
    assert "greet" in greet.read_text(encoding="utf-8")


def test_materialize_empty_normalized_is_absent(tmp_path: Path) -> None:
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    normalized = artifacts / "normalized.js"
    normalized.write_text("   \n", encoding="utf-8")
    result = materialize_js_project_tree(
        output_dir=tmp_path,
        normalized_bundle=normalized,
    )
    assert result.mode == "absent"
    assert result.recovered_root is None
    assert _project_recovered_root(tmp_path) is None


def test_sanitize_strips_webpack_scheme(tmp_path: Path) -> None:
    from reveng.app_reverse_engineering.js_project_materialize import _sanitize_relpath

    assert _sanitize_relpath("webpack:///./src/index.ts") == "src/index.ts"
    assert _sanitize_relpath("webpack:///src/lib/greet.ts") == "src/lib/greet.ts"
    assert _sanitize_relpath("webpack:///(webpack)/runtime") is None


def test_materialize_bun_vfs_preserves_relative_paths(tmp_path: Path) -> None:
    bunfs = tmp_path / "bunfs"
    src = bunfs / "root" / "src" / "entry.js"
    src.parent.mkdir(parents=True)
    src.write_text("export const x = 1;\n", encoding="utf-8")
    result = materialize_js_project_tree(output_dir=tmp_path, bun_vfs_dir=bunfs)
    assert result.mode == "bun_vfs"
    assert (tmp_path / "project" / "src" / "entry.js").is_file()
    assert _project_recovered_root(tmp_path) is not None
