"""
Tests for REVENG security utilities

Validates that safe archive extraction properly prevents path traversal attacks.
"""

import os
import tarfile
import zipfile

import pytest

from reveng.utils.security import (
    PathTraversalError,
    safe_extract_archive,
    safe_extract_tar,
    safe_extract_zip,
)


class TestSafeExtractZip:
    """Test safe ZIP extraction"""

    def test_safe_zip_extraction_normal_files(self, tmp_path):
        """Test that normal ZIP files extract successfully"""
        # Create a test ZIP file with normal files
        zip_path = tmp_path / "test.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file1.txt", "content1")
            zf.writestr("dir/file2.txt", "content2")

        # Extract should succeed
        with zipfile.ZipFile(zip_path, "r") as zf:
            safe_extract_zip(zf, extract_path)

        # Verify files were extracted
        assert (extract_path / "file1.txt").exists()
        assert (extract_path / "dir" / "file2.txt").exists()
        assert (extract_path / "file1.txt").read_text() == "content1"
        assert (extract_path / "dir" / "file2.txt").read_text() == "content2"

    def test_safe_zip_extraction_prevents_parent_traversal(self, tmp_path):
        """Test that path traversal using ../ is blocked"""
        # Create a malicious ZIP file with parent directory traversal
        zip_path = tmp_path / "malicious.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        with zipfile.ZipFile(zip_path, "w") as zf:
            # Try to write outside the extraction directory
            zf.writestr("../evil.txt", "malicious content")

        # Extraction should fail with PathTraversalError
        with zipfile.ZipFile(zip_path, "r") as zf:
            with pytest.raises(PathTraversalError, match="Path traversal detected"):
                safe_extract_zip(zf, extract_path)

        # Verify the file was NOT created outside extraction directory
        assert not (tmp_path / "evil.txt").exists()

    def test_safe_zip_extraction_prevents_absolute_paths(self, tmp_path):
        """Test that absolute paths in archives are blocked"""
        # Create a malicious ZIP file with absolute paths
        zip_path = tmp_path / "malicious_abs.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create a ZIP with absolute path (simulated)
        # Note: On Windows, absolute paths start with drive letter
        if os.name == "nt":
            malicious_path = "C:/Windows/evil.txt"
        else:
            malicious_path = "/tmp/evil.txt"

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(malicious_path, "malicious content")

        # Extraction should fail
        with zipfile.ZipFile(zip_path, "r") as zf:
            with pytest.raises(PathTraversalError, match="Path traversal detected"):
                safe_extract_zip(zf, extract_path)

    def test_safe_zip_extraction_deep_nested_ok(self, tmp_path):
        """Test that deeply nested but safe paths work"""
        zip_path = tmp_path / "nested.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("a/b/c/d/e/f/file.txt", "deep content")

        with zipfile.ZipFile(zip_path, "r") as zf:
            safe_extract_zip(zf, extract_path)

        assert (extract_path / "a" / "b" / "c" / "d" / "e" / "f" / "file.txt").exists()


class TestSafeExtractTar:
    """Test safe TAR extraction"""

    def test_safe_tar_extraction_normal_files(self, tmp_path):
        """Test that normal TAR files extract successfully"""
        # Create a test TAR file
        tar_path = tmp_path / "test.tar"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create temp files to add to TAR
        temp_dir = tmp_path / "temp"
        temp_dir.mkdir()
        (temp_dir / "file1.txt").write_text("content1")
        (temp_dir / "dir").mkdir()
        (temp_dir / "dir" / "file2.txt").write_text("content2")

        with tarfile.open(tar_path, "w") as tf:
            tf.add(temp_dir / "file1.txt", arcname="file1.txt")
            tf.add(temp_dir / "dir" / "file2.txt", arcname="dir/file2.txt")

        # Extract should succeed
        with tarfile.open(tar_path, "r") as tf:
            safe_extract_tar(tf, extract_path)

        # Verify files were extracted
        assert (extract_path / "file1.txt").exists()
        assert (extract_path / "dir" / "file2.txt").exists()

    def test_safe_tar_extraction_prevents_parent_traversal(self, tmp_path):
        """Test that path traversal using ../ is blocked in TAR files"""
        # Create a malicious TAR file
        tar_path = tmp_path / "malicious.tar"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create temp file
        temp_file = tmp_path / "temp.txt"
        temp_file.write_text("malicious")

        with tarfile.open(tar_path, "w") as tf:
            tf.add(temp_file, arcname="../evil.txt")

        # Extraction should fail
        with tarfile.open(tar_path, "r") as tf:
            with pytest.raises(PathTraversalError, match="Path traversal detected"):
                safe_extract_tar(tf, extract_path)

        # Verify file not created outside extraction directory
        assert not (tmp_path / "evil.txt").exists()

    def test_safe_tar_extraction_prevents_absolute_paths(self, tmp_path):
        """Test that absolute paths in TAR archives are blocked"""
        tar_path = tmp_path / "malicious_abs.tar"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create temp file
        temp_file = tmp_path / "temp.txt"
        temp_file.write_text("malicious")

        # Use path traversal with ../ instead of absolute path
        # (tarfile automatically strips absolute paths, so we use ../ to test path traversal)
        malicious_path = "../../../evil.txt"

        with tarfile.open(tar_path, "w") as tf:
            tf.add(temp_file, arcname=malicious_path)

        # Extraction should fail
        with tarfile.open(tar_path, "r") as tf:
            with pytest.raises(PathTraversalError, match="Path traversal detected"):
                safe_extract_tar(tf, extract_path)


class TestSafeExtractArchive:
    """Test automatic archive format detection"""

    def test_auto_detect_zip(self, tmp_path):
        """Test that ZIP files are auto-detected and extracted safely"""
        zip_path = tmp_path / "test.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("file.txt", "content")

        safe_extract_archive(zip_path, extract_path)
        assert (extract_path / "file.txt").exists()

    def test_auto_detect_tar(self, tmp_path):
        """Test that TAR files are auto-detected and extracted safely"""
        tar_path = tmp_path / "test.tar"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        temp_file = tmp_path / "temp.txt"
        temp_file.write_text("content")

        with tarfile.open(tar_path, "w") as tf:
            tf.add(temp_file, arcname="file.txt")

        safe_extract_archive(tar_path, extract_path)
        assert (extract_path / "file.txt").exists()

    def test_auto_detect_tar_gz(self, tmp_path):
        """Test that TAR.GZ files are auto-detected"""
        tar_path = tmp_path / "test.tar.gz"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        temp_file = tmp_path / "temp.txt"
        temp_file.write_text("content")

        with tarfile.open(tar_path, "w:gz") as tf:
            tf.add(temp_file, arcname="file.txt")

        safe_extract_archive(tar_path, extract_path)
        assert (extract_path / "file.txt").exists()

    def test_unsupported_format_raises_error(self, tmp_path):
        """Test that unsupported archive formats raise ValueError"""
        bad_path = tmp_path / "test.rar"
        bad_path.write_bytes(b"fake rar content")
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        with pytest.raises(ValueError, match="Unsupported archive format"):
            safe_extract_archive(bad_path, extract_path)


class TestPathTraversalScenarios:
    """Test various path traversal attack scenarios"""

    @pytest.mark.parametrize(
        "malicious_path",
        [
            "../../../etc/passwd",
            "..\\..\\..\\Windows\\System32\\evil.dll",
            "./../../secret.txt",
            "subdir/../../../outside.txt",
        ],
    )
    def test_various_traversal_patterns(self, tmp_path, malicious_path):
        """Test that various path traversal patterns are blocked"""
        zip_path = tmp_path / "malicious.zip"
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr(malicious_path, "malicious")

        with zipfile.ZipFile(zip_path, "r") as zf:
            with pytest.raises(PathTraversalError):
                safe_extract_zip(zf, extract_path)


class TestSecurityUtilsIntegration:
    """Integration tests for security utilities"""

    def test_multiple_archives_sequential(self, tmp_path):
        """Test that multiple archives can be extracted sequentially"""
        extract_path = tmp_path / "extract"
        extract_path.mkdir()

        # Create and extract first archive
        zip1 = tmp_path / "archive1.zip"
        with zipfile.ZipFile(zip1, "w") as zf:
            zf.writestr("file1.txt", "content1")
        safe_extract_archive(zip1, extract_path)

        # Create and extract second archive
        zip2 = tmp_path / "archive2.zip"
        with zipfile.ZipFile(zip2, "w") as zf:
            zf.writestr("file2.txt", "content2")
        safe_extract_archive(zip2, extract_path)

        # Both files should exist
        assert (extract_path / "file1.txt").exists()
        assert (extract_path / "file2.txt").exists()

    def test_extraction_with_symlinks_blocked(self, tmp_path):
        """Test that symlink attacks are prevented (if applicable)"""
        # This is a basic test - full symlink protection would require more work
        # The current implementation prevents path traversal which is the main concern
        pass  # Placeholder for future enhancement


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
