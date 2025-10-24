#!/usr/bin/env python3
"""
Automated Ghidra Download and Setup Script
==========================================

Downloads and extracts Ghidra from the official NSA GitHub releases.
Verifies SHA256 checksum for security.

Usage:
    python scripts/setup/download_ghidra.py

Environment Variables:
    GHIDRA_INSTALL_DIR: Custom installation directory (default: ./external/ghidra)
    GHIDRA_VERSION: Specific version to download (default: latest)
"""

import hashlib
import os
import platform
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

# Ghidra release configuration
DEFAULT_GHIDRA_VERSION = "11.2.1"
GHIDRA_RELEASE_BASE_URL = "https://github.com/NationalSecurityAgency/ghidra/releases/download"
DEFAULT_INSTALL_DIR = Path(__file__).parent.parent.parent / "external" / "ghidra"

# SHA256 checksums for verification (update these with each new version)
CHECKSUMS = {
    "11.2.1": {
        "ghidra_11.2.1_PUBLIC_20241105.zip": "764d32ce1e1d7612e2fe55b8031f8f53f05c8f8f13f5a6d84f0f7"
        "c8c65a6af1b9",  # Example - REPLACE WITH ACTUAL
    },
    "11.2": {
        "ghidra_11.2_PUBLIC_20240926.zip": "8c17a5c02b7e5a8f3d6e0f4b3c7d1e6f9a2b5d8c1e4f7a0b3c6d9e",  # Example
    },
}


class GhidraInstaller:
    """Automated Ghidra installer with verification."""

    def __init__(
        self,
        version: Optional[str] = None,
        install_dir: Optional[Path] = None,
    ):
        """
        Initialize the Ghidra installer.

        Args:
            version: Ghidra version to install (default: latest)
            install_dir: Installation directory (default: ./external/ghidra)
        """
        self.version = version or os.getenv("GHIDRA_VERSION", DEFAULT_GHIDRA_VERSION)
        self.install_dir = install_dir or Path(
            os.getenv("GHIDRA_INSTALL_DIR", str(DEFAULT_INSTALL_DIR))
        )
        self.temp_dir = Path("temp_ghidra_download")

    def get_download_url(self) -> tuple[str, str]:
        """
        Get the download URL and filename for the current platform.

        Returns:
            Tuple of (download_url, filename)
        """
        # Ghidra is platform-independent (Java-based)
        filename = f"ghidra_{self.version}_PUBLIC_*.zip"

        # For latest releases, construct the URL
        # Note: You may need to adjust this based on actual release naming
        # Example: https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2.1_build/ghidra_11.2.1_PUBLIC_20241105.zip
        release_tag = f"Ghidra_{self.version}_build"
        filename_pattern = f"ghidra_{self.version}_PUBLIC_*.zip"

        # For simplicity, we'll construct a common pattern
        # Users may need to verify the exact filename from GitHub releases
        base_filename = f"ghidra_{self.version}_PUBLIC"

        # Check if we have a specific filename in checksums
        if self.version in CHECKSUMS:
            for fname in CHECKSUMS[self.version].keys():
                if fname.startswith(base_filename):
                    filename = fname
                    break

        url = f"{GHIDRA_RELEASE_BASE_URL}/{release_tag}/{filename}"
        return url, filename

    def verify_checksum(self, filepath: Path, expected_checksum: str) -> bool:
        """
        Verify SHA256 checksum of downloaded file.

        Args:
            filepath: Path to file to verify
            expected_checksum: Expected SHA256 hash

        Returns:
            True if checksum matches, False otherwise
        """
        print(f"Verifying checksum for {filepath.name}...")
        sha256_hash = hashlib.sha256()

        with open(filepath, "rb") as f:
            # Read file in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)

        actual_checksum = sha256_hash.hexdigest()

        if actual_checksum == expected_checksum:
            print("✓ Checksum verified successfully")
            return True
        else:
            print(f"✗ Checksum mismatch!")
            print(f"  Expected: {expected_checksum}")
            print(f"  Actual:   {actual_checksum}")
            return False

    def download_file(self, url: str, destination: Path) -> bool:
        """
        Download file from URL with progress indication.

        Args:
            url: URL to download from
            destination: Local file path to save to

        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"Downloading from: {url}")
            print(f"Destination: {destination}")

            # Create parent directory if needed
            destination.parent.mkdir(parents=True, exist_ok=True)

            def reporthook(block_num, block_size, total_size):
                """Show download progress."""
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = min(100, (downloaded * 100) // total_size)
                    mb_downloaded = downloaded / (1024 * 1024)
                    mb_total = total_size / (1024 * 1024)
                    print(
                        f"\rProgress: {percent}% ({mb_downloaded:.1f}/{mb_total:.1f} MB)",
                        end="",
                        flush=True,
                    )

            urllib.request.urlretrieve(url, destination, reporthook=reporthook)
            print()  # New line after progress
            print("✓ Download complete")
            return True

        except Exception as e:
            print(f"\n✗ Download failed: {e}")
            return False

    def extract_archive(self, archive_path: Path) -> bool:
        """
        Extract Ghidra archive to installation directory.

        Args:
            archive_path: Path to ZIP archive

        Returns:
            True if successful, False otherwise
        """
        try:
            print(f"Extracting to: {self.install_dir}")

            # Create installation directory
            self.install_dir.mkdir(parents=True, exist_ok=True)

            with zipfile.ZipFile(archive_path, "r") as zip_ref:
                # Get list of files to show progress
                members = zip_ref.namelist()
                total_files = len(members)

                for idx, member in enumerate(members):
                    zip_ref.extract(member, self.install_dir)
                    if idx % 100 == 0:  # Update every 100 files
                        percent = (idx * 100) // total_files
                        print(f"\rExtracting: {percent}%", end="", flush=True)

            print("\r✓ Extraction complete" + " " * 20)  # Clear progress line

            # Find the extracted Ghidra directory (usually ghidra_VERSION_PUBLIC)
            extracted_dirs = list(self.install_dir.glob("ghidra_*"))
            if extracted_dirs:
                print(f"✓ Ghidra installed to: {extracted_dirs[0]}")
                # Set environment variable hint
                print(f"\nTo use Ghidra, set the environment variable:")
                print(f"export GHIDRA_INSTALL_DIR={extracted_dirs[0]}")
            return True

        except Exception as e:
            print(f"\n✗ Extraction failed: {e}")
            return False

    def cleanup_temp_files(self):
        """Remove temporary download files."""
        if self.temp_dir.exists():
            print("Cleaning up temporary files...")
            shutil.rmtree(self.temp_dir)
            print("✓ Cleanup complete")

    def install(self) -> bool:
        """
        Main installation process.

        Returns:
            True if successful, False otherwise
        """
        print("=" * 70)
        print("REVENG - Ghidra Automated Download & Installation")
        print("=" * 70)
        print(f"Version: {self.version}")
        print(f"Install directory: {self.install_dir}")
        print("=" * 70)
        print()

        # Check if already installed
        if self.install_dir.exists() and list(self.install_dir.glob("ghidra_*")):
            print("⚠️  Ghidra appears to be already installed.")
            response = input("Reinstall? (y/N): ").lower().strip()
            if response != "y":
                print("Installation cancelled.")
                return True

        try:
            # Get download URL
            url, filename = self.get_download_url()

            # Create temporary directory
            self.temp_dir.mkdir(exist_ok=True)
            archive_path = self.temp_dir / filename

            # Download
            if not self.download_file(url, archive_path):
                return False

            # Verify checksum (if available)
            if self.version in CHECKSUMS and filename in CHECKSUMS[self.version]:
                expected_checksum = CHECKSUMS[self.version][filename]
                if not self.verify_checksum(archive_path, expected_checksum):
                    print("\n⚠️  WARNING: Checksum verification failed!")
                    print("This could indicate a corrupted or tampered download.")
                    response = input("Continue anyway? (y/N): ").lower().strip()
                    if response != "y":
                        return False
            else:
                print("⚠️  No checksum available for this version - skipping verification")

            # Extract
            if not self.extract_archive(archive_path):
                return False

            print()
            print("=" * 70)
            print("✓ Ghidra installation successful!")
            print("=" * 70)
            print()
            print("Next steps:")
            print("1. Add Ghidra to your PATH (optional)")
            print("2. Run REVENG analysis: reveng analyze <binary>")
            print()

            return True

        except Exception as e:
            print(f"\n✗ Installation failed: {e}")
            return False

        finally:
            # Cleanup
            self.cleanup_temp_files()


def main():
    """Main entry point."""
    # Parse simple command line arguments
    version = None
    install_dir = None

    if len(sys.argv) > 1:
        if sys.argv[1] in ["-h", "--help"]:
            print(__doc__)
            print("\nUsage:")
            print("  python download_ghidra.py [VERSION] [INSTALL_DIR]")
            print("\nExamples:")
            print("  python download_ghidra.py")
            print("  python download_ghidra.py 11.2.1")
            print("  python download_ghidra.py 11.2.1 /opt/ghidra")
            sys.exit(0)

        version = sys.argv[1]

    if len(sys.argv) > 2:
        install_dir = Path(sys.argv[2])

    # Create installer and run
    installer = GhidraInstaller(version=version, install_dir=install_dir)
    success = installer.install()

    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
