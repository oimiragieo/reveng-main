"""
Security utilities for REVENG

Provides safe operations for security-sensitive tasks like archive extraction.
"""

import tarfile
import zipfile
from pathlib import Path
from typing import Union


class PathTraversalError(Exception):
    """Raised when a path traversal attack is detected in an archive"""

    pass


def safe_extract_zip(zip_file: zipfile.ZipFile, extract_path: Union[str, Path]) -> None:
    """
    Safely extract a ZIP file, preventing path traversal attacks.

    This function validates that all files in the archive will be extracted
    within the specified extraction directory, preventing malicious archives
    from writing to arbitrary locations on the filesystem.

    Args:
        zip_file: The ZipFile object to extract
        extract_path: Directory to extract files to

    Raises:
        PathTraversalError: If a path traversal attack is detected

    Example:
        >>> with zipfile.ZipFile('archive.zip', 'r') as zf:
        ...     safe_extract_zip(zf, '/tmp/extract')
    """
    extract_path = Path(extract_path).resolve()

    for member in zip_file.namelist():
        # Get the full path where the member would be extracted
        member_path = (extract_path / member).resolve()

        # Verify the extracted path is within the target directory
        if not str(member_path).startswith(str(extract_path)):
            raise PathTraversalError(
                f"Path traversal detected: '{member}' would extract to '{member_path}', "
                f"which is outside the target directory '{extract_path}'"
            )

    # All paths validated, safe to extract
    zip_file.extractall(extract_path)  # noqa: S202


def safe_extract_tar(tar_file: tarfile.TarFile, extract_path: Union[str, Path]) -> None:
    """
    Safely extract a TAR file, preventing path traversal attacks.

    This function validates that all files in the archive will be extracted
    within the specified extraction directory, preventing malicious archives
    from writing to arbitrary locations on the filesystem.

    Args:
        tar_file: The TarFile object to extract
        extract_path: Directory to extract files to

    Raises:
        PathTraversalError: If a path traversal attack is detected

    Example:
        >>> with tarfile.open('archive.tar.gz', 'r:gz') as tf:
        ...     safe_extract_tar(tf, '/tmp/extract')
    """
    extract_path = Path(extract_path).resolve()

    for member in tar_file.getmembers():
        # Check for absolute paths in member name
        member_name_path = Path(member.name)
        if member_name_path.is_absolute():
            raise PathTraversalError(
                f"Path traversal detected: '{member.name}' is an absolute path"
            )

        # Get the full path where the member would be extracted
        member_path = (extract_path / member.name).resolve()

        # Verify the extracted path is within the target directory
        if not str(member_path).startswith(str(extract_path)):
            raise PathTraversalError(
                f"Path traversal detected: '{member.name}' would extract to '{member_path}', "
                f"which is outside the target directory '{extract_path}'"
            )

    # All paths validated, safe to extract
    tar_file.extractall(extract_path)  # noqa: S202


def safe_extract_archive(
    archive_path: Union[str, Path], extract_path: Union[str, Path]
) -> None:
    """
    Safely extract an archive (ZIP or TAR), auto-detecting the format.

    Args:
        archive_path: Path to the archive file
        extract_path: Directory to extract files to

    Raises:
        PathTraversalError: If a path traversal attack is detected
        ValueError: If the archive format is not supported

    Example:
        >>> safe_extract_archive('archive.zip', '/tmp/extract')
        >>> safe_extract_archive('archive.tar.gz', '/tmp/extract')
    """
    archive_path = Path(archive_path)

    if zipfile.is_zipfile(archive_path):
        with zipfile.ZipFile(archive_path, "r") as zf:
            safe_extract_zip(zf, extract_path)
    elif tarfile.is_tarfile(archive_path):
        with tarfile.open(archive_path, "r:*") as tf:
            safe_extract_tar(tf, extract_path)
    else:
        raise ValueError(f"Unsupported archive format: {archive_path}")
