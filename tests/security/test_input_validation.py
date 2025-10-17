"""
Security tests for input validation.
Tests the security validation module for proper input sanitization.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, mock_open

from reveng.core.validation import (
    validate_file_path, secure_hash_file, secure_temp_file,
    validate_binary_content, sanitize_filename, validate_analysis_config
)
from reveng.core.exceptions import ValidationError, SecurityError


class TestFilePathValidation:
    """Test file path validation for security."""

    def test_valid_file_path(self):
        """Test valid file path passes validation."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content")
            tmp_path = tmp.name

        try:
            result = validate_file_path(tmp_path)
            assert isinstance(result, Path)
            assert result.exists()
        finally:
            os.unlink(tmp_path)

    def test_nonexistent_file(self):
        """Test that nonexistent file raises ValidationError."""
        with pytest.raises(ValidationError, match="File not found"):
            validate_file_path("/nonexistent/file.exe")

    def test_path_traversal_prevention(self):
        """Test that path traversal is blocked."""
        with pytest.raises(SecurityError, match="Path traversal detected"):
            validate_file_path("../../../etc/passwd")

    def test_file_size_limit(self):
        """Test file size validation."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            # Create a file larger than 1MB
            tmp.write(b"x" * (2 * 1024 * 1024))  # 2MB
            tmp_path = tmp.name

        try:
            with pytest.raises(ValidationError, match="File too large"):
                validate_file_path(tmp_path, max_size_mb=1)
        finally:
            os.unlink(tmp_path)

    def test_suspicious_path_patterns(self):
        """Test detection of suspicious path patterns."""
        suspicious_paths = [
            "/etc/passwd",
            "/sys/kernel",
            "/proc/self",
            "C:\\Windows\\System32\\config"
        ]

        for path in suspicious_paths:
            with pytest.raises(SecurityError, match="Suspicious path pattern"):
                validate_file_path(path)

    def test_allowed_extensions(self):
        """Test file extension validation."""
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as tmp:
            tmp.write(b"test")
            tmp_path = tmp.name

        try:
            # Should pass with .exe extension
            result = validate_file_path(tmp_path, allowed_extensions=['.exe'])
            assert result.suffix == '.exe'

            # Should fail with wrong extension
            with pytest.raises(ValidationError, match="File extension not allowed"):
                validate_file_path(tmp_path, allowed_extensions=['.jar'])
        finally:
            os.unlink(tmp_path)


class TestSecureHashing:
    """Test secure hashing functions."""

    def test_secure_hash_file(self):
        """Test secure file hashing."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content")
            tmp_path = tmp.name

        try:
            # Test SHA256 (secure)
            sha256_hash = secure_hash_file(tmp_path, 'sha256')
            assert len(sha256_hash) == 64  # SHA256 hex length
            assert all(c in '0123456789abcdef' for c in sha256_hash)

            # Test SHA512 (secure)
            sha512_hash = secure_hash_file(tmp_path, 'sha512')
            assert len(sha512_hash) == 128  # SHA512 hex length
        finally:
            os.unlink(tmp_path)

    def test_unsafe_hash_algorithm(self):
        """Test that unsafe hash algorithms are rejected."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"test content")
            tmp_path = tmp.name

        try:
            with pytest.raises(SecurityError, match="Unsafe hash algorithm"):
                secure_hash_file(tmp_path, 'md5')
        finally:
            os.unlink(tmp_path)

    def test_nonexistent_file_hash(self):
        """Test hashing nonexistent file raises error."""
        with pytest.raises(ValidationError):
            secure_hash_file("/nonexistent/file", 'sha256')


class TestSecureTempFile:
    """Test secure temporary file creation."""

    def test_secure_temp_file_creation(self):
        """Test secure temporary file creation."""
        temp_path = secure_temp_file(prefix="test_", suffix=".tmp")

        assert isinstance(temp_path, Path)
        assert temp_path.name.startswith("test_")
        assert temp_path.name.endswith(".tmp")

        # Clean up
        if temp_path.exists():
            temp_path.unlink()

    def test_secure_temp_file_in_allowed_directory(self):
        """Test temp file creation in allowed directory."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = secure_temp_file(
                prefix="test_",
                suffix=".tmp",
                directory=temp_dir
            )

            assert temp_path.parent == Path(temp_dir)

            # Clean up
            if temp_path.exists():
                temp_path.unlink()

    def test_secure_temp_file_in_disallowed_directory(self):
        """Test temp file creation in disallowed directory."""
        with pytest.raises(SecurityError, match="Directory not allowed"):
            secure_temp_file(directory="/etc")


class TestBinaryContentValidation:
    """Test binary content validation."""

    def test_pe_executable_validation(self):
        """Test PE executable validation."""
        # Create a mock PE file (MZ header)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ\x90\x00")  # PE header start
            tmp.write(b"\x00" * 100)  # Padding
            tmp_path = tmp.name

        try:
            result = validate_binary_content(tmp_path)
            assert result['is_binary'] is True
            assert result['magic_bytes'].startswith('4d5a')  # MZ in hex
        finally:
            os.unlink(tmp_path)

    def test_text_file_validation(self):
        """Test text file validation."""
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as tmp:
            tmp.write("This is plain text content")
            tmp_path = tmp.name

        try:
            result = validate_binary_content(tmp_path)
            assert result['is_binary'] is False
            assert result['entropy'] < 5.0  # Low entropy for text
        finally:
            os.unlink(tmp_path)

    def test_high_entropy_detection(self):
        """Test high entropy detection."""
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            # Create high entropy content (random bytes)
            import random
            random_bytes = bytes([random.randint(0, 255) for _ in range(1000)])
            tmp.write(random_bytes)
            tmp_path = tmp.name

        try:
            result = validate_binary_content(tmp_path)
            assert result['high_entropy'] is True
            assert result['entropy'] > 7.0
        finally:
            os.unlink(tmp_path)


class TestFilenameSanitization:
    """Test filename sanitization."""

    def test_sanitize_dangerous_characters(self):
        """Test sanitization of dangerous characters."""
        dangerous_names = [
            "../../../etc/passwd",
            "file<name>",
            "file:name",
            "file|name",
            "file?name",
            "file*name"
        ]

        for name in dangerous_names:
            sanitized = sanitize_filename(name)
            assert "<" not in sanitized
            assert ">" not in sanitized
            assert ":" not in sanitized
            assert "|" not in sanitized
            assert "?" not in sanitized
            assert "*" not in sanitized
            assert ".." not in sanitized

    def test_sanitize_control_characters(self):
        """Test sanitization of control characters."""
        control_name = "file\x00name\x01test"
        sanitized = sanitize_filename(control_name)

        # Should not contain control characters
        for char in sanitized:
            assert ord(char) >= 32

    def test_sanitize_length_limit(self):
        """Test filename length limiting."""
        long_name = "a" * 300 + ".exe"
        sanitized = sanitize_filename(long_name)

        assert len(sanitized) <= 255
        assert sanitized.endswith('.exe')

    def test_sanitize_empty_name(self):
        """Test sanitization of empty filename."""
        sanitized = sanitize_filename("")
        assert sanitized == "unnamed_file"


class TestAnalysisConfigValidation:
    """Test analysis configuration validation."""

    def test_valid_configuration(self):
        """Test valid configuration passes validation."""
        config = {
            'timeout': 3600,
            'max_file_size_mb': 500,
            'output_directory': './test_output',
            'ai_provider': 'ollama'
        }

        result = validate_analysis_config(config)
        assert result['timeout'] == 3600
        assert result['max_file_size_mb'] == 500
        assert result['ai_provider'] == 'ollama'

    def test_invalid_timeout(self):
        """Test invalid timeout validation."""
        config = {'timeout': -1}

        with pytest.raises(ValidationError, match="Invalid timeout"):
            validate_analysis_config(config)

    def test_invalid_file_size(self):
        """Test invalid file size validation."""
        config = {'max_file_size_mb': 0}

        with pytest.raises(ValidationError, match="Invalid max_file_size_mb"):
            validate_analysis_config(config)

    def test_invalid_ai_provider(self):
        """Test invalid AI provider validation."""
        config = {'ai_provider': 'invalid_provider'}

        with pytest.raises(ValidationError, match="Invalid AI provider"):
            validate_analysis_config(config)

    def test_system_directory_output(self):
        """Test that system directories are rejected for output."""
        config = {'output_directory': '/etc'}

        with pytest.raises(SecurityError, match="Output directory in system directory"):
            validate_analysis_config(config)

    def test_default_configuration(self):
        """Test default configuration values."""
        result = validate_analysis_config({})

        assert result['timeout'] == 3600
        assert result['max_file_size_mb'] == 500
        assert result['ai_provider'] == 'ollama'


class TestSecurityIntegration:
    """Integration tests for security features."""

    def test_end_to_end_validation(self):
        """Test end-to-end security validation."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".exe") as tmp:
            tmp.write(b"MZ\x90\x00" + b"\x00" * 100)
            tmp_path = tmp.name

        try:
            # Validate file path
            validated_path = validate_file_path(tmp_path)

            # Validate binary content
            content_result = validate_binary_content(validated_path)

            # Secure hash
            file_hash = secure_hash_file(validated_path, 'sha256')

            # All should succeed without security errors
            assert validated_path.exists()
            assert content_result['is_binary'] is True
            assert len(file_hash) == 64

        finally:
            os.unlink(tmp_path)

    def test_security_error_propagation(self):
        """Test that security errors are properly propagated."""
        with pytest.raises(SecurityError):
            validate_file_path("../../../etc/passwd")

        with pytest.raises(SecurityError):
            secure_hash_file("/etc/passwd", 'md5')

        with pytest.raises(SecurityError):
            secure_temp_file(directory="/etc")
