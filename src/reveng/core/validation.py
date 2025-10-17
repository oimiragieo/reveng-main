"""
REVENG Security Validation Module
=================================

Secure input validation and file handling for the REVENG platform.
Addresses security vulnerabilities identified in the security audit.

Author: REVENG Development Team
Version: 2.1.0
License: MIT
"""

import os
import hashlib
import secrets
from pathlib import Path
from typing import Union, Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)

class ValidationError(Exception):
    """Raised when input validation fails."""
    pass

class SecurityError(Exception):
    """Raised when security constraints are violated."""
    pass

def validate_file_path(
    path: Union[str, Path],
    max_size_mb: int = 500,
    allowed_extensions: Optional[list] = None
) -> Path:
    """
    Validate file path for security.

    Args:
        path: Path to validate
        max_size_mb: Maximum file size in MB
        allowed_extensions: List of allowed file extensions (e.g., ['.exe', '.jar'])

    Returns:
        Resolved Path object

    Raises:
        ValidationError: If path is invalid
        SecurityError: If security constraints violated
    """
    try:
        path = Path(path).resolve()
    except (OSError, ValueError) as e:
        raise ValidationError(f"Invalid path: {e}") from e

    # Check file exists
    if not path.exists():
        raise ValidationError(f"File not found: {path}")

    # Check if it's a file (not directory)
    if not path.is_file():
        raise ValidationError(f"Path is not a file: {path}")

    # Check file size
    try:
        size_mb = path.stat().st_size / (1024 * 1024)
        if size_mb > max_size_mb:
            raise ValidationError(f"File too large: {size_mb:.1f}MB > {max_size_mb}MB")
    except OSError as e:
        raise ValidationError(f"Cannot access file: {e}") from e

    # Prevent path traversal
    if '..' in path.parts:
        raise SecurityError("Path traversal detected")

    # Check for suspicious patterns
    suspicious_patterns = ['/etc/', '/sys/', '/proc/', 'C:\\Windows\\System32']
    path_str = str(path).lower()
    for pattern in suspicious_patterns:
        if pattern.lower() in path_str:
            raise SecurityError(f"Suspicious path pattern detected: {pattern}")

    # Check file extension if specified
    if allowed_extensions:
        if path.suffix.lower() not in [ext.lower() for ext in allowed_extensions]:
            raise ValidationError(f"File extension not allowed: {path.suffix}")

    return path

def secure_hash_file(
    file_path: Union[str, Path],
    algorithm: str = 'sha256',
    chunk_size: int = 8192
) -> str:
    """
    Securely hash a file using the specified algorithm.

    Args:
        file_path: Path to file to hash
        algorithm: Hash algorithm ('sha256', 'sha512', 'blake2b')
        chunk_size: Size of chunks to read

    Returns:
        Hexadecimal hash string

    Raises:
        ValidationError: If file cannot be read
        SecurityError: If algorithm is not secure
    """
    # Only allow secure hash algorithms
    secure_algorithms = {'sha256', 'sha512', 'blake2b', 'blake2s'}
    if algorithm.lower() not in secure_algorithms:
        raise SecurityError(f"Unsafe hash algorithm: {algorithm}. Use: {', '.join(secure_algorithms)}")

    try:
        path = validate_file_path(file_path)
    except (ValidationError, SecurityError) as e:
        raise ValidationError(f"Cannot hash file: {e}") from e

    try:
        hash_obj = hashlib.new(algorithm.lower())
        with open(path, 'rb') as f:
            while chunk := f.read(chunk_size):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except OSError as e:
        raise ValidationError(f"Cannot read file for hashing: {e}") from e

def secure_temp_file(
    prefix: str = 'reveng_',
    suffix: str = '.tmp',
    directory: Optional[Union[str, Path]] = None
) -> Path:
    """
    Create a secure temporary file.

    Args:
        prefix: File prefix
        suffix: File suffix
        directory: Directory to create file in (default: system temp)

    Returns:
        Path to temporary file

    Raises:
        SecurityError: If directory is not secure
    """
    if directory:
        dir_path = Path(directory).resolve()
        # Ensure directory is within allowed temp directories
        allowed_temp_dirs = [
            Path.cwd() / 'temp',
            Path.cwd() / 'tmp',
            Path('/tmp'),
            Path('/var/tmp'),
            Path.home() / 'tmp'
        ]

        is_allowed = any(
            str(dir_path).startswith(str(allowed_dir))
            for allowed_dir in allowed_temp_dirs
        )

        if not is_allowed:
            raise SecurityError(f"Directory not allowed for temp files: {dir_path}")
    else:
        dir_path = None

    # Generate secure random filename
    random_part = secrets.token_hex(16)
    filename = f"{prefix}{random_part}{suffix}"

    if dir_path:
        temp_path = dir_path / filename
    else:
        import tempfile
        temp_path = Path(tempfile.mktemp(prefix=prefix, suffix=suffix))

    return temp_path

def validate_binary_content(
    file_path: Union[str, Path],
    max_magic_bytes: int = 1024
) -> Dict[str, Any]:
    """
    Validate binary file content for security.

    Args:
        file_path: Path to binary file
        max_magic_bytes: Maximum bytes to read for magic number detection

    Returns:
        Dictionary with validation results

    Raises:
        ValidationError: If file cannot be validated
        SecurityError: If suspicious content detected
    """
    try:
        path = validate_file_path(file_path)
    except (ValidationError, SecurityError) as e:
        raise ValidationError(f"Cannot validate binary: {e}") from e

    try:
        with open(path, 'rb') as f:
            magic_bytes = f.read(max_magic_bytes)
    except OSError as e:
        raise ValidationError(f"Cannot read file: {e}") from e

    # Check for suspicious magic bytes
    suspicious_signatures = [
        b'MZ',  # PE executable
        b'\x7fELF',  # ELF executable
        b'\xfe\xed\xfa',  # Mach-O
        b'PK',  # ZIP/JAR
        b'\x89PNG',  # PNG
        b'GIF8',  # GIF
    ]

    is_binary = any(magic_bytes.startswith(sig) for sig in suspicious_signatures)

    # Check for null bytes (indicates binary content)
    has_null_bytes = b'\x00' in magic_bytes

    # Check for high entropy (might be packed/encrypted)
    if len(magic_bytes) > 0:
        entropy = calculate_entropy(magic_bytes)
        high_entropy = entropy > 7.5  # Threshold for high entropy
    else:
        entropy = 0.0
        high_entropy = False

    result = {
        'is_binary': is_binary or has_null_bytes,
        'magic_bytes': magic_bytes[:16].hex(),  # First 16 bytes as hex
        'entropy': entropy,
        'high_entropy': high_entropy,
        'size_bytes': path.stat().st_size,
        'suspicious': high_entropy and not is_binary
    }

    if result['suspicious']:
        logger.warning(f"High entropy detected in {path}, might be packed/encrypted")

    return result

def calculate_entropy(data: bytes) -> float:
    """
    Calculate Shannon entropy of data.

    Args:
        data: Bytes to analyze

    Returns:
        Entropy value (0-8)
    """
    if not data:
        return 0.0

    # Count byte frequencies
    byte_counts = {}
    for byte in data:
        byte_counts[byte] = byte_counts.get(byte, 0) + 1

    # Calculate entropy
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts.values():
        probability = count / data_len
        if probability > 0:
            entropy -= probability * (probability.bit_length() - 1)

    return entropy

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename for safe storage.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove path components
    filename = Path(filename).name

    # Remove dangerous characters
    dangerous_chars = '<>:"/\\|?*'
    for char in dangerous_chars:
        filename = filename.replace(char, '_')

    # Remove control characters
    filename = ''.join(char for char in filename if ord(char) >= 32)

    # Limit length
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext

    # Ensure not empty
    if not filename:
        filename = 'unnamed_file'

    return filename

def validate_analysis_config(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate analysis configuration for security.

    Args:
        config: Configuration dictionary

    Returns:
        Validated configuration

    Raises:
        ValidationError: If configuration is invalid
        SecurityError: If configuration violates security constraints
    """
    validated_config = {}

    # Validate timeout
    timeout = config.get('timeout', 3600)
    if not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 86400:  # Max 24 hours
        raise ValidationError("Invalid timeout: must be between 1 and 86400 seconds")
    validated_config['timeout'] = int(timeout)

    # Validate max file size
    max_size = config.get('max_file_size_mb', 500)
    if not isinstance(max_size, (int, float)) or max_size <= 0 or max_size > 10000:  # Max 10GB
        raise ValidationError("Invalid max_file_size_mb: must be between 1 and 10000")
    validated_config['max_file_size_mb'] = int(max_size)

    # Validate output directory
    output_dir = config.get('output_directory', './analysis_output')
    try:
        output_path = Path(output_dir).resolve()
        # Ensure output directory is not in system directories
        system_dirs = ['/etc', '/sys', '/proc', '/dev', 'C:\\Windows\\System32']
        for sys_dir in system_dirs:
            if str(output_path).startswith(sys_dir):
                raise SecurityError(f"Output directory in system directory: {sys_dir}")

        # Create directory if it doesn't exist
        output_path.mkdir(parents=True, exist_ok=True)
        validated_config['output_directory'] = str(output_path)
    except (OSError, ValueError) as e:
        raise ValidationError(f"Invalid output directory: {e}") from e

    # Validate AI provider
    ai_provider = config.get('ai_provider', 'ollama')
    allowed_providers = {'ollama', 'claude', 'openai', 'local', 'none'}
    if ai_provider not in allowed_providers:
        raise ValidationError(f"Invalid AI provider: {ai_provider}. Allowed: {allowed_providers}")
    validated_config['ai_provider'] = ai_provider

    return validated_config
