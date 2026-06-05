from __future__ import annotations

import importlib.util
import json
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "provision_ga_assets.py"


def _load_module(name: str, path: Path):
    assert path.exists(), f"Expected module at {path}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.pop(name, None)
    spec.loader.exec_module(module)
    return module


def test_load_manifest_resolves_relative_destinations(tmp_path: Path):
    module = _load_module("test_provision_ga_assets_manifest", SCRIPT_PATH)
    manifest_path = tmp_path / "ga_asset_manifest.json"
    manifest_path.write_text(
        json.dumps(
            {
                "git_repos": [
                    {
                        "id": "repo",
                        "repo_url": "https://example.invalid/repo.git",
                        "dest": "external/repo",
                    }
                ],
                "release_assets": [
                    {
                        "id": "asset",
                        "url": "https://example.invalid/asset.zip",
                        "dest": "external/bin",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    manifest = module.load_manifest(manifest_path)

    assert Path(manifest["git_repos"][0]["dest"]).is_absolute()
    assert Path(manifest["release_assets"][0]["dest"]).is_absolute()


def test_extract_members_flattens_requested_files(tmp_path: Path):
    module = _load_module("test_provision_ga_assets_extract", SCRIPT_PATH)
    archive_path = tmp_path / "asset.zip"
    output_dir = tmp_path / "out"
    with zipfile.ZipFile(archive_path, "w") as archive:
        archive.writestr("nested/demo.exe", b"binary-data")

    extracted = module._extract_members(archive_path, output_dir, ["nested/demo.exe"])

    assert extracted == [str(output_dir / "demo.exe")]
    assert (output_dir / "demo.exe").read_bytes() == b"binary-data"
