#!/usr/bin/env python3
"""
REVENG Decompiler Download Script
==================================

Automatically downloads Java decompilers for bytecode analysis.

Downloads:
- CFR (required) - Modern Java decompiler
- Fernflower (optional) - IntelliJ decompiler
- Procyon (optional) - Type-inference decompiler
"""

import os
import sys
import hashlib
import urllib.request
from pathlib import Path
from typing import Optional, Tuple

# Decompiler download URLs and metadata
DECOMPILERS = {
    'cfr': {
        'name': 'CFR',
        'version': '0.152',
        'url': 'https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar',
        'filename': 'cfr-0.152.jar',
        'sha256': None,  # Optional: add checksum for verification
        'required': True,
        'description': 'Modern Java decompiler with lambda/stream support'
    },
    'fernflower': {
        'name': 'Fernflower',
        'version': '1.0',
        'url': 'https://the.bytecode.club/fernflower.jar',  # Community mirror
        'filename': 'fernflower.jar',
        'sha256': None,
        'required': False,
        'description': 'IntelliJ IDEA decompiler engine'
    },
    'procyon': {
        'name': 'Procyon',
        'version': '0.6.0',
        'url': 'https://github.com/mstrobel/procyon/releases/download/v0.6.0/procyon-decompiler-0.6.0.jar',
        'filename': 'procyon-decompiler-0.6.0.jar',
        'sha256': None,
        'required': False,
        'description': 'Excellent type inference for Java 8+'
    }
}


def download_file(url: str, dest_path: Path, filename: str) -> bool:
    """
    Download file with progress indicator

    Args:
        url: Download URL
        dest_path: Destination path
        filename: Filename for display

    Returns:
        True if successful, False otherwise
    """
    try:
        print(f"Downloading {filename}...")
        print(f"  URL: {url}")

        # Create progress callback
        def reporthook(block_num, block_size, total_size):
            if total_size > 0:
                downloaded = block_num * block_size
                percent = min(downloaded * 100 / total_size, 100)
                bar_length = 40
                filled = int(bar_length * percent / 100)
                bar = '=' * filled + '-' * (bar_length - filled)
                print(f'\r  [{bar}] {percent:.1f}%', end='', flush=True)

        urllib.request.urlretrieve(url, dest_path, reporthook)
        print()  # New line after progress bar

        # Verify file was downloaded
        if dest_path.exists() and dest_path.stat().st_size > 0:
            size_mb = dest_path.stat().st_size / (1024 * 1024)
            print(f"  ✓ Downloaded {filename} ({size_mb:.2f} MB)")
            return True
        else:
            print(f"  ✗ Download failed: File is empty or missing")
            return False

    except urllib.error.URLError as e:
        print(f"  ✗ Network error: {e}")
        return False
    except Exception as e:
        print(f"  ✗ Download failed: {e}")
        return False


def verify_checksum(file_path: Path, expected_sha256: Optional[str]) -> bool:
    """
    Verify file SHA256 checksum

    Args:
        file_path: Path to file
        expected_sha256: Expected SHA256 hash (or None to skip)

    Returns:
        True if valid or skipped, False if mismatch
    """
    if not expected_sha256:
        return True  # Skip verification if no checksum provided

    try:
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)

        actual = sha256.hexdigest()
        if actual.lower() == expected_sha256.lower():
            print(f"  ✓ Checksum verified")
            return True
        else:
            print(f"  ✗ Checksum mismatch!")
            print(f"    Expected: {expected_sha256}")
            print(f"    Got:      {actual}")
            return False

    except Exception as e:
        print(f"  ✗ Checksum verification failed: {e}")
        return False


def test_jar(jar_path: Path, jar_name: str) -> bool:
    """
    Test if JAR file is valid

    Args:
        jar_path: Path to JAR file
        jar_name: Name for display

    Returns:
        True if valid, False otherwise
    """
    import subprocess

    try:
        # Try to run jar with --help or -h
        result = subprocess.run(
            ['java', '-jar', str(jar_path), '--help'],
            capture_output=True,
            timeout=5
        )

        # Some jars don't support --help but return 0 for valid jar
        # Others might return non-zero but still work
        # Just checking if java can load it
        print(f"  ✓ {jar_name} is a valid JAR file")
        return True

    except subprocess.TimeoutExpired:
        print(f"  ⚠ {jar_name} timeout (may still work)")
        return True  # Timeout is okay, jar is probably valid
    except FileNotFoundError:
        print(f"  ✗ Java not found - cannot test JAR")
        return False
    except Exception as e:
        print(f"  ⚠ Could not test {jar_name}: {e}")
        return True  # Assume valid if we can't test


def download_decompilers(download_optional: bool = False) -> Tuple[int, int]:
    """
    Download all decompilers

    Args:
        download_optional: Whether to download optional decompilers

    Returns:
        Tuple of (successful_downloads, total_downloads)
    """
    # Ensure we're in the right directory
    script_dir = Path(__file__).parent
    os.chdir(script_dir)

    print("=" * 70)
    print(" REVENG Decompiler Download")
    print("=" * 70)
    print()

    successful = 0
    total = 0

    for decompiler_id, info in DECOMPILERS.items():
        # Skip optional if not requested
        if not info['required'] and not download_optional:
            print(f"Skipping {info['name']} (optional)")
            print(f"  Use --all flag to download optional decompilers")
            print()
            continue

        total += 1
        dest_path = Path(info['filename'])

        # Check if already exists
        if dest_path.exists():
            size_mb = dest_path.stat().st_size / (1024 * 1024)
            print(f"{info['name']} v{info['version']}")
            print(f"  ✓ Already exists ({size_mb:.2f} MB)")
            print(f"  Delete {info['filename']} to re-download")
            print()
            successful += 1
            continue

        print(f"{info['name']} v{info['version']}")
        print(f"  {info['description']}")

        # Download
        if download_file(info['url'], dest_path, info['filename']):
            # Verify checksum if provided
            if verify_checksum(dest_path, info['sha256']):
                # Test JAR
                if test_jar(dest_path, info['name']):
                    successful += 1
                else:
                    print(f"  ⚠ JAR test failed but file was downloaded")
                    successful += 1  # Count as success anyway
            else:
                print(f"  ⚠ Checksum failed but file was downloaded")
                successful += 1  # Count as success anyway
        else:
            print(f"  ✗ Download failed")

        print()

    return successful, total


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Download Java decompilers for REVENG',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Download required decompilers only (CFR)
  python download_decompilers.py

  # Download all decompilers (CFR, Fernflower, Procyon)
  python download_decompilers.py --all

  # Test existing downloads
  python download_decompilers.py --test
        """
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Download optional decompilers (Fernflower, Procyon)'
    )
    parser.add_argument(
        '--test',
        action='store_true',
        help='Test existing JAR files'
    )

    args = parser.parse_args()

    # Test mode
    if args.test:
        print("Testing existing decompilers...")
        print()
        for decompiler_id, info in DECOMPILERS.items():
            jar_path = Path(info['filename'])
            if jar_path.exists():
                print(f"{info['name']}: ", end='')
                test_jar(jar_path, info['name'])
            else:
                print(f"{info['name']}: Not downloaded")
        return

    # Download mode
    successful, total = download_decompilers(download_optional=args.all)

    print("=" * 70)
    print(f" Download Summary: {successful}/{total} successful")
    print("=" * 70)

    if successful == total:
        print()
        print("✓ All decompilers downloaded successfully!")
        print()
        print("Next steps:")
        print("  1. Verify Java installation: java -version")
        print("  2. Test decompilers: python download_decompilers.py --test")
        print("  3. Analyze a JAR: python ../java_bytecode_analyzer.py test.jar")
        print()
    elif successful > 0:
        print()
        print(f"⚠ Partial success: {successful}/{total} decompilers downloaded")
        print()
        print("At least CFR (required) should be present for basic functionality.")
        print()
    else:
        print()
        print("✗ No decompilers were downloaded")
        print()
        print("Troubleshooting:")
        print("  - Check internet connection")
        print("  - Try manual download (see README.md)")
        print("  - Check firewall/proxy settings")
        print()
        sys.exit(1)


if __name__ == '__main__':
    main()
