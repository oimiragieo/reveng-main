#!/usr/bin/env python3
"""
Simple security test runner for REVENG v3.0.0
Tests the security utilities without pytest dependency
"""

import os
import sys
import tempfile
import zipfile
import tarfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from reveng.utils.security import (
    PathTraversalError,
    safe_extract_zip,
    safe_extract_tar,
    safe_extract_archive,
)

def test_safe_zip_extraction():
    """Test safe ZIP extraction"""
    print("Testing safe ZIP extraction...")
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        zip_path = tmp_path / "test.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()
        
        # Create normal ZIP
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("dir/file2.txt", "content2")
        
        # Test normal extraction
        with zipfile.ZipFile(zip_path, "r") as zf:
            safe_extract_zip(zf, extract_path)
        
        assert (extract_path / "file1.txt").exists()
        assert (extract_path / "dir" / "file2.txt").exists()
        print("✓ Normal ZIP extraction works")
        
        # Test malicious ZIP with path traversal
        malicious_zip = tmp_path / "malicious.zip"
        with zipfile.ZipFile(malicious_zip, "w") as zf:
            zf.writestr("../../../etc/passwd", "malicious content")
        
        try:
            with zipfile.ZipFile(malicious_zip, "r") as zf:
                safe_extract_zip(zf, extract_path)
            assert False, "Should have raised PathTraversalError"
        except PathTraversalError:
            print("✓ Path traversal attack blocked")
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    
    return True

def test_safe_tar_extraction():
    """Test safe TAR extraction"""
    print("Testing safe TAR extraction...")
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        tar_path = tmp_path / "test.tar"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()
        
        # Create normal TAR
        with tarfile.open(tar_path, "w") as tf:
            # Create test files
            test_file1 = tmp_path / "file1.txt"
            test_file1.write_text("content1")
            tf.add(test_file1, "file1.txt")
            
            test_dir = tmp_path / "dir"
            test_dir.mkdir()
            test_file2 = test_dir / "file2.txt"
            test_file2.write_text("content2")
            tf.add(test_file2, "dir/file2.txt")
        
        # Test normal extraction
        with tarfile.open(tar_path, "r") as tf:
            safe_extract_tar(tf, extract_path)
        
        assert (extract_path / "file1.txt").exists()
        assert (extract_path / "dir" / "file2.txt").exists()
        print("✓ Normal TAR extraction works")
        
        # Test malicious TAR with path traversal
        malicious_tar = tmp_path / "malicious.tar"
        with tarfile.open(malicious_tar, "w") as tf:
            # Create malicious file
            malicious_file = tmp_path / "passwd"
            malicious_file.write_text("malicious content")
            tf.add(malicious_file, "../../../etc/passwd")
        
        try:
            with tarfile.open(malicious_tar, "r") as tf:
                safe_extract_tar(tf, extract_path)
            assert False, "Should have raised PathTraversalError"
        except PathTraversalError:
            print("✓ Path traversal attack blocked")
        except Exception as e:
            print(f"✗ Unexpected error: {e}")
            return False
    
    return True

def test_safe_archive_extraction():
    """Test safe archive extraction (auto-detect format)"""
    print("Testing safe archive extraction...")
    
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        extract_path = tmp_path / "extract"
        extract_path.mkdir()
        
        # Test ZIP
        zip_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "content1")
        
        safe_extract_archive(zip_path, extract_path)
        assert (extract_path / "file1.txt").exists()
        print("✓ ZIP auto-detection works")
        
        # Test TAR
        tar_path = tmp_path / "test.tar"
        with tarfile.open(tar_path, "w") as tf:
            test_file = tmp_path / "file2.txt"
            test_file.write_text("content2")
            tf.add(test_file, "file2.txt")
        
        safe_extract_archive(tar_path, extract_path)
        assert (extract_path / "file2.txt").exists()
        print("✓ TAR auto-detection works")
    
    return True

def main():
    """Run all security tests"""
    print("=" * 60)
    print("REVENG Security Test Suite")
    print("=" * 60)
    
    tests = [
        test_safe_zip_extraction,
        test_safe_tar_extraction,
        test_safe_archive_extraction,
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                print(f"✗ {test.__name__} failed")
        except Exception as e:
            print(f"✗ {test.__name__} failed with error: {e}")
    
    print("=" * 60)
    print(f"Security Tests: {passed}/{total} passed")
    
    if passed == total:
        print("✓ All security tests passed!")
        return 0
    else:
        print("✗ Some security tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())