from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = REPO_ROOT / ".reveng" / "ga_asset_manifest.json"
DEFAULT_OUTPUT = REPO_ROOT / "reports" / "ga_asset_provisioning_report.json"
USER_AGENT = "reveng-ga-provisioner/1.0"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _resolve_path(value: str, base_dir: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else (base_dir / path).resolve()


def load_manifest(path: Path = DEFAULT_MANIFEST) -> dict[str, Any]:
    raw = _load_json(path)
    base_dir = path.parent

    git_repos: list[dict[str, Any]] = []
    for repo in raw.get("git_repos", []):
        item = dict(repo)
        item["dest"] = str(_resolve_path(repo["dest"], base_dir))
        git_repos.append(item)

    release_assets: list[dict[str, Any]] = []
    for asset in raw.get("release_assets", []):
        item = dict(asset)
        item["dest"] = str(_resolve_path(asset["dest"], base_dir))
        release_assets.append(item)

    return {
        "schema_version": raw.get("schema_version", "1.0"),
        "notes": raw.get("notes", []),
        "git_repos": git_repos,
        "release_assets": release_assets,
    }


def _download(url: str, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def _clone_git_repo(item: dict[str, Any], force: bool) -> dict[str, Any]:
    dest = Path(item["dest"])
    if force and dest.exists():
        shutil.rmtree(dest)
    if dest.exists() and any(dest.iterdir()):
        return {"id": item["id"], "kind": "git_repo", "status": "skipped_existing", "dest": str(dest)}

    dest.parent.mkdir(parents=True, exist_ok=True)
    command = ["git", "clone", "--depth", "1"]
    ref = item.get("ref")
    if ref:
        command.extend(["--branch", ref])
    command.extend([item["repo_url"], str(dest)])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    return {
        "id": item["id"],
        "kind": "git_repo",
        "status": "completed" if completed.returncode == 0 else "failed",
        "dest": str(dest),
        "returncode": completed.returncode,
        "stdout_tail": completed.stdout[-2000:],
        "stderr_tail": completed.stderr[-2000:],
    }


def _extract_members(archive_path: Path, destination: Path, members: list[str]) -> list[str]:
    destination.mkdir(parents=True, exist_ok=True)
    extracted: list[str] = []
    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
        for member in members:
            if member not in names:
                raise FileNotFoundError(f"{member!r} not found in {archive_path}")
            target_path = destination / Path(member).name
            with archive.open(member) as source, target_path.open("wb") as target:
                shutil.copyfileobj(source, target)
            extracted.append(str(target_path))
    return extracted


def _provision_release_asset(item: dict[str, Any], force: bool) -> dict[str, Any]:
    dest = Path(item["dest"])
    asset_type = item.get("asset_type", "file")
    if force and dest.exists():
        if dest.is_dir():
            shutil.rmtree(dest)
        else:
            dest.unlink()

    if dest.exists() and (dest.is_file() or any(dest.iterdir())):
        return {
            "id": item["id"],
            "kind": "release_asset",
            "status": "skipped_existing",
            "dest": str(dest),
            "asset_type": asset_type,
        }

    if asset_type == "zip_extract":
        dest.mkdir(parents=True, exist_ok=True)
        members = list(item.get("members", []))
        if not members:
            raise ValueError(f"{item['id']} requires non-empty members for zip_extract")
        with tempfile.TemporaryDirectory(prefix="reveng-ga-asset-") as temp_dir:
            archive_path = Path(temp_dir) / "asset.zip"
            _download(item["url"], archive_path)
            extracted = _extract_members(archive_path, dest, members)
        return {
            "id": item["id"],
            "kind": "release_asset",
            "status": "completed",
            "dest": str(dest),
            "asset_type": asset_type,
            "extracted_files": extracted,
        }

    _download(item["url"], dest)
    return {
        "id": item["id"],
        "kind": "release_asset",
        "status": "completed",
        "dest": str(dest),
        "asset_type": asset_type,
    }


def provision_assets(
    manifest_path: Path = DEFAULT_MANIFEST,
    *,
    force: bool = False,
    selected_ids: list[str] | None = None,
) -> dict[str, Any]:
    manifest = load_manifest(manifest_path)
    selected = set(selected_ids or [])
    results: list[dict[str, Any]] = []

    for repo in manifest["git_repos"]:
        if selected and repo["id"] not in selected:
            continue
        results.append(_clone_git_repo(repo, force=force))

    for asset in manifest["release_assets"]:
        if selected and asset["id"] not in selected:
            continue
        results.append(_provision_release_asset(asset, force=force))

    failed = [result for result in results if result["status"] == "failed"]
    return {
        "schema_version": manifest["schema_version"],
        "result_type": "ga_asset_provisioning_report",
        "manifest_path": str(manifest_path),
        "selected_id_count": len(selected),
        "summary": {
            "asset_count": len(results),
            "completed_count": sum(1 for result in results if result["status"] == "completed"),
            "skipped_count": sum(1 for result in results if result["status"] == "skipped_existing"),
            "failed_count": len(failed),
            "overall_status": "pass" if not failed else "fail",
        },
        "results": results,
        "notes": manifest["notes"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Provision tracked GA assets and source mirrors.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT))
    parser.add_argument("--force", action="store_true")
    parser.add_argument(
        "--id",
        action="append",
        default=[],
        help="Provision only the specified manifest id. Can be provided multiple times.",
    )
    args = parser.parse_args(argv)

    report = provision_assets(Path(args.manifest), force=args.force, selected_ids=args.id)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    summary = report["summary"]
    print(f"Assets processed: {summary['asset_count']}")
    print(f"Completed: {summary['completed_count']}")
    print(f"Skipped: {summary['skipped_count']}")
    print(f"Failed: {summary['failed_count']}")
    print(f"Report written to: {output_path}")
    return 0 if summary["overall_status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
