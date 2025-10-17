"""
Base installer class for REVENG tools
"""

import os
import sys
import subprocess
import platform
import shutil
import zipfile
import tarfile
import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Optional, Dict, Any, List
from enum import Enum

logger = logging.getLogger(__name__)

class InstallMethod(Enum):
    """Installation method for tools"""
    DOWNLOAD = "download"
    PACKAGE_MANAGER = "package_manager"
    PYTHON_PIP = "python_pip"
    MANUAL = "manual"

class BaseInstaller(ABC):
    """Abstract base class for tool installers"""

    def __init__(self, tools_dir: Path, tool_name: str):
        self.tools_dir = tools_dir
        self.tool_name = tool_name
        self.install_path = tools_dir / tool_name
        self.config_file = self.install_path / "install_config.json"

        # Load existing config if available
        self.config = self._load_config()

    @abstractmethod
    def get_download_url(self) -> str:
        """Get download URL for the tool"""
        pass

    @abstractmethod
    def get_version(self) -> str:
        """Get installed version of the tool"""
        pass

    @abstractmethod
    def check_installation(self) -> 'ToolStatus':
        """Check if tool is properly installed"""
        pass

    @abstractmethod
    def install(self) -> bool:
        """Install the tool"""
        pass

    @abstractmethod
    def get_install_instructions(self) -> str:
        """Get manual installation instructions"""
        pass

    def get_install_path(self) -> Optional[str]:
        """Get installation path of the tool"""
        if self.check_installation() == ToolStatus.INSTALLED:
            return str(self.install_path)
        return None

    def uninstall(self) -> bool:
        """Uninstall the tool"""
        try:
            if self.install_path.exists():
                shutil.rmtree(self.install_path)
                logger.info(f"Uninstalled {self.tool_name}")
                return True
            return True
        except Exception as e:
            logger.error(f"Failed to uninstall {self.tool_name}: {e}")
            return False

    def update(self) -> bool:
        """Update the tool to latest version"""
        try:
            logger.info(f"Updating {self.tool_name}...")
            return self.install()
        except Exception as e:
            logger.error(f"Failed to update {self.tool_name}: {e}")
            return False

    def _load_config(self) -> Dict[str, Any]:
        """Load installation configuration"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load config for {self.tool_name}: {e}")
        return {}

    def _save_config(self, config: Dict[str, Any]):
        """Save installation configuration"""
        try:
            self.install_path.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to save config for {self.tool_name}: {e}")

    def _download_file(self, url: str, filename: str) -> Path:
        """Download file from URL"""
        import urllib.request

        file_path = self.install_path / filename

        try:
            logger.info(f"Downloading {filename} from {url}...")
            urllib.request.urlretrieve(url, file_path)
            logger.info(f"Downloaded {filename}")
            return file_path
        except Exception as e:
            logger.error(f"Failed to download {filename}: {e}")
            raise

    def _extract_archive(self, archive_path: Path, extract_to: Optional[Path] = None) -> Path:
        """Extract archive file"""
        extract_to = extract_to or self.install_path

        try:
            if archive_path.suffix.lower() == '.zip':
                with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                    zip_ref.extractall(extract_to)
            elif archive_path.suffix.lower() in ['.tar', '.tar.gz', '.tgz']:
                with tarfile.open(archive_path, 'r:*') as tar_ref:
                    tar_ref.extractall(extract_to)
            else:
                raise ValueError(f"Unsupported archive format: {archive_path.suffix}")

            logger.info(f"Extracted {archive_path.name}")
            return extract_to
        except Exception as e:
            logger.error(f"Failed to extract {archive_path}: {e}")
            raise

    def _run_command(self, command: List[str], cwd: Optional[Path] = None) -> Tuple[bool, str]:
        """Run command and return success status and output"""
        try:
            result = subprocess.run(
                command,
                cwd=cwd or self.install_path,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                return True, result.stdout
            else:
                return False, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out: {' '.join(command)}")
            return False, "Command timed out"
        except Exception as e:
            logger.error(f"Failed to run command {' '.join(command)}: {e}")
            return False, str(e)

    def _check_executable(self, executable_path: Path) -> bool:
        """Check if executable exists and is runnable"""
        if not executable_path.exists():
            return False

        try:
            # Try to run the executable with --version or --help
            result = subprocess.run(
                [str(executable_path), "--version"],
                capture_output=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError):
            # If --version fails, try --help
            try:
                result = subprocess.run(
                    [str(executable_path), "--help"],
                    capture_output=True,
                    timeout=10
                )
                return result.returncode == 0
            except:
                return False

    def _get_platform_specific_path(self, base_path: Path) -> Path:
        """Get platform-specific executable path"""
        system = platform.system().lower()

        if system == "windows":
            # Look for .exe files
            for exe_file in base_path.rglob("*.exe"):
                if exe_file.name.lower() == self.tool_name.lower() or \
                   self.tool_name.lower() in exe_file.name.lower():
                    return exe_file
        else:
            # Look for executable files without extension
            for exe_file in base_path.rglob("*"):
                if exe_file.is_file() and exe_file.name == self.tool_name:
                    return exe_file

        return base_path

    def _find_executable(self, search_path: Path) -> Optional[Path]:
        """Find the main executable for the tool"""
        if not search_path.exists():
            return None

        # Common executable names to look for
        executable_names = [
            self.tool_name,
            f"{self.tool_name}.exe",
            f"{self.tool_name}.bat",
            f"{self.tool_name}.cmd"
        ]

        # Search in the installation directory
        for exe_name in executable_names:
            exe_path = search_path / exe_name
            if exe_path.exists() and self._check_executable(exe_path):
                return exe_path

        # Search recursively
        for exe_name in executable_names:
            for exe_path in search_path.rglob(exe_name):
                if exe_path.is_file() and self._check_executable(exe_path):
                    return exe_path

        return None

# Import ToolStatus from dependency_manager to avoid circular imports
from ..core.dependency_manager import ToolStatus
