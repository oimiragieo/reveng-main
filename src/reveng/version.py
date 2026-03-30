"""
REVENG Version Information
========================

Version management and information for the REVENG platform.

Author: REVENG Development Team
Version: 4.0.0
"""

from pathlib import Path
from typing import Dict, List, Tuple


def _read_version_from_file() -> str:
    """
    Read version from VERSION file in project root.

    Returns:
        str: Version string from file, or fallback version
    """
    try:
        # Look for VERSION file in project root
        project_root = Path(__file__).parent.parent.parent
        version_file = project_root / "VERSION"

        if version_file.exists():
            version = version_file.read_text().strip()
            if version:
                return version
    except Exception:
        pass

    # Fallback version
    return "4.0.0"


# Version information - read from VERSION file
__version__ = _read_version_from_file()
__version_info__ = tuple(map(int, __version__.split(".")))
__version_tuple__ = __version_info__

# Build information
__build_date__ = "2025-11-16"
__build_time__ = "00:00:00"
__build_timestamp__ = "2025-11-16T00:00:00Z"

# Development status
__status__ = "Development/Beta"
__release_type__ = "beta"

# Supported Python versions
__python_versions__ = ["3.9", "3.10", "3.11", "3.12"]
__minimum_python_version__ = "3.9"

# Platform information
__platforms__ = ["Windows", "Linux", "macOS"]
__architectures__ = ["x86_64", "arm64", "amd64"]


def get_version() -> str:
    """
    Get the current version string.

    Returns:
        str: Version string (e.g., "2.1.0")
    """
    return __version__


def get_version_info() -> Tuple[int, int, int]:
    """
    Get the version as a tuple of integers.

    Returns:
        Tuple[int, int, int]: Version tuple (major, minor, patch)
    """
    return __version_info__


def get_version_string() -> str:
    """
    Get a formatted version string with additional information.

    Returns:
        str: Formatted version string
    """
    return f"REVENG v{__version__} ({__status__})"


def get_build_info() -> Dict[str, str]:
    """
    Get build information.

    Returns:
        Dict[str, str]: Build information dictionary
    """
    return {
        "version": __version__,
        "build_date": __build_date__,
        "build_time": __build_time__,
        "build_timestamp": __build_timestamp__,
        "status": __status__,
        "release_type": __release_type__,
    }


def get_system_info() -> Dict[str, List[str]]:
    """
    Get system compatibility information.

    Returns:
        Dict[str, List[str]]: System compatibility information
    """
    return {
        "python_versions": __python_versions__,
        "platforms": __platforms__,
        "architectures": __architectures__,
    }


def is_compatible_python(version: str) -> bool:
    """
    Check if the given Python version is compatible.

    Args:
        version: Python version string (e.g., "3.9.5")

    Returns:
        bool: True if compatible, False otherwise
    """
    try:
        major, minor = map(int, version.split(".")[:2])
        return (major, minor) >= (3, 9)
    except (ValueError, IndexError):
        return False


def get_minimum_requirements() -> Dict[str, str]:
    """
    Get minimum system requirements.

    Returns:
        Dict[str, str]: Minimum requirements dictionary
    """
    return {
        "python": __minimum_python_version__,
        "platform": "Windows 10 / Ubuntu 20.04 / macOS 11",
        "memory": "4GB RAM",
        "storage": "2GB free space",
        "cpu": "2 cores",
    }


def read_version_from_file() -> str:
    """
    Read version from VERSION file if it exists.

    This is a public API for reading the version - the internal
    version is already read at module import time.

    Returns:
        str: Version from file or current version
    """
    return _read_version_from_file()


# Export version information
VERSION = __version__
VERSION_INFO = __version_info__
BUILD_INFO = get_build_info()
SYSTEM_INFO = get_system_info()
MINIMUM_REQUIREMENTS = get_minimum_requirements()
