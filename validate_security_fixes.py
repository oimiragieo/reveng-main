#!/usr/bin/env python3
"""
Validate Security Fixes - Standalone Test Script

Tests the security fixes for path traversal vulnerabilities without pytest dependency.
"""

import os
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from reveng.utils.security import (
    PathTraversalError,
    safe_extract_archive,
    safe_extract_tar,
    safe_extract_zip,
)


def test_safe_zip_normal():
    """Test that normal ZIP files extract successfully"""
    print("Testing safe ZIP extraction (normal files)...", end=" ")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "test.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create test ZIP
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("dir/file2.txt", "content2")

        # Extract
        with zipfile.ZipFile(zip_path, "r") as zf:
            safe_extract_zip(zf, extract_path)

        # Verify
        assert (extract_path / "file1.txt").exists()
        assert (extract_path / "dir" / "file2.txt").exists()
        assert (extract_path / "file1.txt").read_text() == "content1"

    print("✅ PASS")
    return True


def test_safe_zip_path_traversal():
    """Test that path traversal is blocked"""
    print("Testing ZIP path traversal prevention...", end=" ")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        zip_path = tmp_path / "malicious.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create malicious ZIP
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("../evil.txt", "malicious")

        # Attempt extraction - should fail
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                safe_extract_zip(zf, extract_path)
            print("❌ FAIL - Path traversal not blocked!")
            return False
        except PathTraversalError:
            # Verify file was NOT created
            assert not (tmp_path / "evil.txt").exists()

    print("✅ PASS")
    return True


def test_safe_tar_normal():
    """Test that normal TAR files extract successfully"""
    print("Testing safe TAR extraction (normal files)...", end=" ")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        tar_path = tmp_path / "test.tar"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create temp files
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        (temp_dir / "file1.txt").write_text("content1")

        # Create TAR
        with tarfile.open(tar_path, "w") as tf:
            tf.add(temp_dir / "file1.txt", arcname="file1.txt")

        # Extract
        with tarfile.open(tar_path, "r") as tf:
            safe_extract_tar(tf, extract_path)

        # Verify
        assert (extract_path / "file1.txt").exists()

    print("✅ PASS")
    return True


def test_safe_tar_path_traversal():
    """Test that path traversal is blocked in TAR files"""
    print("Testing TAR path traversal prevention...", end=" ")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        tar_path = tmp_path / "malicious.tar"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create temp file
        temp_file = tmp_path / "temp.txt"
        temp_file.write_text("malicious")

        # Create malicious TAR
        with tarfile.open(tar_path, "w") as tf:
            tf.add(temp_file, arcname="../evil.txt")

        # Attempt extraction - should fail
        try:
            with tarfile.open(tar_path, "r") as tf:
                safe_extract_tar(tf, extract_path)
            print("❌ FAIL - Path traversal not blocked!")
            return False
        except PathTraversalError:
            # Verify file was NOT created
            assert not (tmp_path / "evil.txt").exists()

    print("✅ PASS")
    return True


def test_safe_extract_archive_auto_detect():
    """Test automatic archive format detection"""
    print("Testing automatic format detection...", end=" ")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Test ZIP
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file.txt", "content")
        safe_extract_archive(zip_path, extract_path)
        assert (extract_path / "file.txt").exists()

        # Clean up
        (extract_path / "file.txt").unlink()

        # Test TAR
        tar_path = tmp_path / "test.tar"
        temp_file = tmp_path / "temp.txt"
        temp_file.write_text("content")
        with tarfile.open(tar_path, "w") as tf:
            tf.add(temp_file, arcname="file2.txt")
        safe_extract_archive(tar_path, extract_path)
        assert (extract_path / "file2.txt").exists()

    print("✅ PASS")
    return True


def test_imports():
    """Test that all fixed files import correctly"""
    print("Testing imports of fixed files...", end=" ")

    try:
        # Test dependency_manager imports
        from reveng.core import dependency_manager
        assert hasattr(dependency_manager, 'safe_extract_zip')

        # Test java_bytecode_analyzer imports
        from reveng.tools.languages import java_bytecode_analyzer
        assert hasattr(java_bytecode_analyzer, 'safe_extract_zip')

        # Test base_installer imports
        from reveng.installers import base_installer
        assert hasattr(base_installer, 'safe_extract_zip')
        assert hasattr(base_installer, 'safe_extract_tar')

        print("✅ PASS")
        return True
    except Exception as e:
        print(f"❌ FAIL - {e}")
        return False


def main():
    """Run all security validation tests"""
    print("=" * 70)
    print("REVENG Security Fixes Validation")
    print("=" * 70)
    print()

    tests = [
        test_imports,
        test_safe_zip_normal,
        test_safe_zip_path_traversal,
        test_safe_tar_normal,
        test_safe_tar_path_traversal,
        test_safe_extract_archive_auto_detect,
    ]

    results = []
    for test in tests:
        try:
            results.append(test())
        except Exception as e:
            print(f"❌ FAIL - Exception: {e}")
            results.append(False)

    print()
    print("=" * 70)
    print(f"Results: {sum(results)}/{len(results)} tests passed")

    if all(results):
        print("✅ ALL SECURITY FIXES VALIDATED")
        print("=" * 70)
        return 0
    else:
        print("❌ SOME TESTS FAILED")
        print("=" * 70)
        return 1


if __name__ == "__main__":
    sys.exit(main())
