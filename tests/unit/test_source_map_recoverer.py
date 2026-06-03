"""Tests for JavaScript source-map recovery helpers."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from reveng.javascript.source_map_recoverer import SourceMapRecoverer


def test_find_sourcemaps_local_returns_inline_data_url(tmp_path: Path):
    inline_map = (
        "data:application/json;base64,"
        + base64.b64encode(
            json.dumps(
                {
                    "version": 3,
                    "sources": ["src/index.tsx"],
                    "sourcesContent": ["export const main = () => 'ok';\n"],
                }
            ).encode("utf-8")
        ).decode("ascii")
    )
    bundle_path = tmp_path / "cli.tsx"
    bundle_path.write_text(
        f"export const run = () => 'ok';\n//# sourceMappingURL={inline_map}\n",
        encoding="utf-8",
    )

    maps = SourceMapRecoverer().find_sourcemaps(str(bundle_path))

    assert maps == [inline_map]


def test_find_sourcemaps_local_tolerates_non_utf8_bundle_bytes(tmp_path: Path):
    bundle_path = tmp_path / "cli.js"
    bundle_path.write_bytes(
        b"\x81\x8dexport const run = () => 'ok';\n//# sourceMappingURL=cli.js.map\n"
    )
    map_path = tmp_path / "cli.js.map"
    map_path.write_text(
        json.dumps({"version": 3, "sources": ["src/index.js"], "sourcesContent": ["export {};"]}),
        encoding="utf-8",
    )

    maps = SourceMapRecoverer().find_sourcemaps(str(bundle_path))

    assert maps == [str(map_path)]


def test_recover_decodes_inline_data_url_and_normalizes_duplicate_src_root():
    inline_map = (
        "data:application/json;base64,"
        + base64.b64encode(
            json.dumps(
                {
                    "version": 3,
                    "sourceRoot": "src",
                    "sources": ["src/entrypoints/cli.tsx?cache=1", "./src/lib/greet.ts"],
                    "sourcesContent": [
                        "export const main = () => 'ok';\n",
                        "export const greet = () => 'hi';\n",
                    ],
                }
            ).encode("utf-8")
        ).decode("ascii")
    )

    result = SourceMapRecoverer().recover(inline_map)

    assert result.success is True
    assert "entrypoints/cli.tsx" in result.sources
    assert "lib/greet.ts" in result.sources


def test_save_directory_writes_normalized_source_map_tree(tmp_path: Path):
    output_dir = tmp_path / "recovered"
    recoverer = SourceMapRecoverer()

    recoverer.save_directory(
        {
            "entrypoints/cli.tsx": "export const main = () => 'ok';\n",
            "lib/greet.ts": "export const greet = () => 'hi';\n",
        },
        str(output_dir),
    )

    assert (output_dir / "entrypoints" / "cli.tsx").exists()
    assert (output_dir / "lib" / "greet.ts").exists()
