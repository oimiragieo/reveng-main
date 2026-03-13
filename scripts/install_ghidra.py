#!/usr/bin/env python3
"""Download and install the Ghidra binary distribution for REVENG."""

from __future__ import annotations

import argparse
import os
import sys
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path


DEFAULT_GHIDRA_VERSION = "12.0.4"
DEFAULT_DIST_NAME = f"ghidra_{DEFAULT_GHIDRA_VERSION}_PUBLIC"
DEFAULT_DOWNLOAD_URL = (
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
    "Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip"
)
DOWNLOAD_PROGRESS_STEP = 5
EXTRACT_PROGRESS_STEP = 5
CHUNK_SIZE = 1024 * 1024

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIST_ROOT = REPO_ROOT / "external" / "ghidra-dist"
DEFAULT_INSTALL_ROOT = DEFAULT_DIST_ROOT / DEFAULT_DIST_NAME


def get_headless_script_name() -> str:
    """Return the platform-specific Ghidra headless launcher name."""
    return "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless"


def get_headless_path(install_root: Path) -> Path:
    """Return the expected headless launcher path for an installation."""
    return install_root / "support" / get_headless_script_name()


def is_installation_complete(install_root: Path = DEFAULT_INSTALL_ROOT) -> bool:
    """Check whether the expected Ghidra headless launcher already exists."""
    return get_headless_path(install_root).exists()


def verify_installation(install_root: Path = DEFAULT_INSTALL_ROOT) -> Path:
    """Ensure the extracted distribution contains the headless launcher."""
    headless_path = get_headless_path(install_root)
    if not headless_path.exists():
        raise FileNotFoundError(
            f"Expected Ghidra headless launcher at {headless_path}, but it was not found."
        )
    return headless_path


def format_bytes(num_bytes: int) -> str:
    """Format a byte count for console output."""
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(num_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} B"


def resolve_archive_path(url: str, dist_root: Path) -> Path:
    """Resolve the local archive path from a download URL."""
    filename = Path(urllib.parse.urlparse(url).path).name or f"{DEFAULT_DIST_NAME}.zip"
    return dist_root / filename


def download_with_progress(url: str, destination: Path, chunk_size: int = CHUNK_SIZE) -> Path:
    """Download a file while printing progress updates to stdout."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial_path = destination.with_suffix(destination.suffix + ".part")
    if partial_path.exists():
        partial_path.unlink()

    request = urllib.request.Request(url, headers={"User-Agent": "REVENG-Ghidra-Installer/1.0"})
    print(f"Downloading Ghidra from {url}")

    with urllib.request.urlopen(request) as response, partial_path.open("wb") as output_file:
        content_length = response.headers.get("Content-Length")
        total_bytes = int(content_length) if content_length else None
        downloaded_bytes = 0
        next_percent_marker = DOWNLOAD_PROGRESS_STEP
        next_size_marker = 50 * 1024 * 1024

        while True:
            chunk = response.read(chunk_size)
            if not chunk:
                break

            output_file.write(chunk)
            downloaded_bytes += len(chunk)

            if total_bytes:
                progress = int(downloaded_bytes * 100 / total_bytes)
                while progress >= next_percent_marker:
                    print(
                        f"  Downloaded {next_percent_marker}% "
                        f"({format_bytes(downloaded_bytes)} / {format_bytes(total_bytes)})"
                    )
                    next_percent_marker += DOWNLOAD_PROGRESS_STEP
            elif downloaded_bytes >= next_size_marker:
                print(f"  Downloaded {format_bytes(downloaded_bytes)}")
                next_size_marker += 50 * 1024 * 1024

    partial_path.replace(destination)
    print(f"Download complete: {destination}")
    return destination


def _is_within_directory(parent: Path, child: Path) -> bool:
    parent_resolved = parent.resolve()
    child_resolved = child.resolve()
    return child_resolved == parent_resolved or parent_resolved in child_resolved.parents


def extract_archive(archive_path: Path, destination_dir: Path) -> Path:
    """Extract the downloaded Ghidra archive with basic progress reporting."""
    destination_dir.mkdir(parents=True, exist_ok=True)
    print(f"Extracting {archive_path} to {destination_dir}")

    with zipfile.ZipFile(archive_path) as archive:
        members = archive.infolist()
        total_members = len(members)
        next_percent_marker = EXTRACT_PROGRESS_STEP

        for index, member in enumerate(members, start=1):
            member_destination = destination_dir / member.filename
            if not _is_within_directory(destination_dir, member_destination):
                raise ValueError(f"Unsafe archive entry detected: {member.filename}")

            archive.extract(member, destination_dir)

            if total_members:
                progress = int(index * 100 / total_members)
                while progress >= next_percent_marker:
                    print(f"  Extracted {next_percent_marker}% ({index}/{total_members} files)")
                    next_percent_marker += EXTRACT_PROGRESS_STEP

    print("Extraction complete")
    return destination_dir


def install_ghidra(
    url: str = DEFAULT_DOWNLOAD_URL,
    dist_root: Path = DEFAULT_DIST_ROOT,
    install_root: Path = DEFAULT_INSTALL_ROOT,
    archive_path: Path | None = None,
    *,
    keep_archive: bool = False,
) -> Path:
    """Install Ghidra if it is not already present and verified."""
    if is_installation_complete(install_root):
        print(f"Ghidra already installed at {install_root}")
        return install_root

    dist_root.mkdir(parents=True, exist_ok=True)
    archive_path = archive_path or resolve_archive_path(url, dist_root)

    if archive_path.exists():
        print(f"Using existing archive: {archive_path}")
    else:
        download_with_progress(url, archive_path)

    extract_archive(archive_path, dist_root)
    headless_path = verify_installation(install_root)
    print(f"Verified Ghidra headless launcher: {headless_path}")

    if archive_path.exists() and not keep_archive:
        archive_path.unlink()
        print(f"Removed downloaded archive: {archive_path}")

    return install_root


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments for the installer."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default=DEFAULT_DOWNLOAD_URL, help="Ghidra distribution ZIP URL")
    parser.add_argument(
        "--dist-root",
        default=str(DEFAULT_DIST_ROOT),
        help="Directory that should contain the extracted distribution",
    )
    parser.add_argument(
        "--keep-archive",
        action="store_true",
        help="Keep the downloaded ZIP after a successful installation",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = parse_args(argv)
    dist_root = Path(args.dist_root).resolve()
    install_root = dist_root / DEFAULT_DIST_NAME

    try:
        install_ghidra(
            url=args.url,
            dist_root=dist_root,
            install_root=install_root,
            keep_archive=args.keep_archive,
        )
    except Exception as exc:  # pragma: no cover - exercised by CLI runs
        print(f"Failed to install Ghidra: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
