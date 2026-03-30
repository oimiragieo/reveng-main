"""
REVENG Dependency Management System

Auto-detect, download, and install required analysis tools with fallback support.
Cross-platform installer support for Windows, Linux, and macOS.
"""

import hashlib
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

import yaml

from reveng.utils.security import safe_extract_zip

if TYPE_CHECKING:
    import requests

logger = logging.getLogger(__name__)

GHIDRA_VERSION = "12.0.4"
GHIDRA_DIST_NAME = f"ghidra_{GHIDRA_VERSION}_PUBLIC"
GHIDRA_DOWNLOAD_URL = (
    "https://github.com/NationalSecurityAgency/ghidra/releases/download/"
    "Ghidra_12.0.4_build/ghidra_12.0.4_PUBLIC_20260303.zip"
)


# Platform Detection Utilities
class Platform(Enum):
    """Supported platforms"""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    UNKNOWN = "unknown"


def get_platform() -> Platform:
    """Detect current platform"""
    system = platform.system().lower()
    if system == "windows":
        return Platform.WINDOWS
    elif system == "linux":
        return Platform.LINUX
    elif system == "darwin":
        return Platform.MACOS
    else:
        return Platform.UNKNOWN


def get_architecture() -> str:
    """Get system architecture (x86_64, arm64, etc.)"""
    machine = platform.machine().lower()
    # Normalize architecture names
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    elif machine in ("aarch64", "arm64"):
        return "arm64"
    elif machine in ("i386", "i686", "x86"):
        return "x86"
    else:
        return machine


def get_executable_name(base_name: str, current_platform: Platform = None) -> str:
    """Get platform-specific executable name"""
    if current_platform is None:
        current_platform = get_platform()

    if current_platform == Platform.WINDOWS:
        return f"{base_name}.exe"
    else:
        return base_name


def get_script_name(base_name: str, current_platform: Platform = None) -> str:
    """Get platform-specific script name"""
    if current_platform is None:
        current_platform = get_platform()

    if current_platform == Platform.WINDOWS:
        return f"{base_name}.bat"
    else:
        return f"{base_name}.sh"


# Checksum Validation Utilities
def load_checksums() -> Dict[str, Dict[str, str]]:
    """Load checksums from checksums.yaml file"""
    checksums_file = Path(__file__).parent / "checksums.yaml"

    if not checksums_file.exists():
        logger.warning(f"Checksums file not found: {checksums_file}")
        return {}

    try:
        with open(checksums_file, "r", encoding="utf-8") as f:
            checksums = yaml.safe_load(f)
            return checksums if checksums else {}
    except Exception as e:
        logger.error(f"Failed to load checksums: {e}")
        return {}


def calculate_sha256(file_path: Path) -> str:
    """Calculate SHA256 hash of a file"""
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            # Read file in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Failed to calculate SHA256 for {file_path}: {e}")
        raise


def validate_checksum(file_path: Path, expected_sha256: str) -> bool:
    """
    Validate file checksum against expected SHA256 hash

    Args:
        file_path: Path to file to validate
        expected_sha256: Expected SHA256 hash

    Returns:
        True if checksum matches, False otherwise

    Raises:
        ValueError: If checksum validation fails
    """
    actual_sha256 = calculate_sha256(file_path)

    if actual_sha256.lower() != expected_sha256.lower():
        error_msg = (
            f"Checksum mismatch for {file_path.name}!\n"
            f"Expected: {expected_sha256}\n"
            f"Actual:   {actual_sha256}\n"
            f"This could indicate a corrupted or malicious download."
        )
        logger.error(error_msg)
        raise ValueError(error_msg)

    logger.info(f"Checksum validated successfully for {file_path.name}")
    return True


def create_retry_session(
    retries: int = 3,
    backoff_factor: float = 0.5,
    status_forcelist: tuple = (429, 500, 502, 503, 504),
) -> "requests.Session":
    """
    Create a requests session with retry logic and exponential backoff

    Args:
        retries: Number of retry attempts (default: 3)
        backoff_factor: Multiplier for exponential backoff (default: 0.5)
            Delays will be: 0.5s, 1s, 2s for backoff_factor=0.5
        status_forcelist: HTTP status codes that trigger a retry

    Returns:
        requests.Session with retry adapter configured
    """
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()

    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=["HEAD", "GET", "OPTIONS"],  # Safe methods only
        raise_on_status=False,  # Let requests handle HTTP errors
    )

    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    logger.debug(f"Created retry session: {retries} retries, {backoff_factor}s backoff")
    return session


def download_with_retry(
    url: str,
    output_path: Path,
    max_retries: int = 3,
    chunk_size: int = 8192,
    timeout: int = 60,
) -> bool:
    """
    Download a file with retry logic and exponential backoff

    Args:
        url: URL to download from
        output_path: Path to save downloaded file
        max_retries: Maximum number of retry attempts
        chunk_size: Size of chunks for streaming download
        timeout: Timeout in seconds for the request

    Returns:
        True if download successful, False otherwise

    Raises:
        requests.RequestException: If download fails after all retries
    """
    session = create_retry_session(retries=max_retries)

    try:
        logger.info(f"Downloading from {url}...")
        logger.debug(f"Max retries: {max_retries}, timeout: {timeout}s")

        response = session.get(url, stream=True, timeout=timeout)
        response.raise_for_status()

        # Download with progress
        total_size = int(response.headers.get("content-length", 0))
        downloaded = 0

        with open(output_path, "wb") as f:
            for chunk in response.iter_content(chunk_size=chunk_size):
                if chunk:  # filter out keep-alive chunks
                    f.write(chunk)
                    downloaded += len(chunk)

                    # Log progress every 10MB
                    if total_size > 0 and downloaded % (10 * 1024 * 1024) < chunk_size:
                        progress = (downloaded / total_size) * 100
                        logger.debug(f"Download progress: {progress:.1f}%")

        logger.info(f"Download complete: {output_path.name}")
        return True

    except Exception as e:
        logger.error(f"Download failed after {max_retries} retries: {e}")
        # Clean up partial download
        if output_path.exists():
            output_path.unlink()
        raise


class ToolStatus(Enum):
    """Installation status of a tool"""

    INSTALLED = "installed"
    NOT_INSTALLED = "not_installed"
    PARTIALLY_INSTALLED = "partially_installed"
    ERROR = "error"


@dataclass
class ToolInfo:
    """Information about an analysis tool"""

    name: str
    version: str
    path: str
    executable: str
    is_installed: bool
    install_method: str
    dependencies: List[str]
    fallback_available: bool


@dataclass
class InstallationResult:
    """Result of tool installation"""

    success: bool
    tool_name: str
    install_path: str
    error_message: Optional[str] = None
    fallback_used: bool = False


class BaseInstaller(ABC):
    """Base class for tool installers"""

    def __init__(
        self,
        tool_name: str,
        tool_version: str = "latest",
        custom_install_dir: Path = None,
    ):
        self.tool_name = tool_name
        self.tool_version = tool_version

        # Support custom install directory or use default
        if custom_install_dir:
            self.install_dir = custom_install_dir
        else:
            # Check for environment variable override
            env_var = f"REVENG_{tool_name.upper()}_DIR"
            env_path = os.getenv(env_var)
            if env_path:
                self.install_dir = Path(env_path)
                logger.info(f"Using custom install path from {env_var}: {self.install_dir}")
            else:
                # Default: ~/.reveng/tools/{tool_name}
                base_dir = os.getenv("REVENG_TOOLS_DIR", str(Path.home() / ".reveng" / "tools"))
                self.install_dir = Path(base_dir) / tool_name

        self.logger = logging.getLogger(f"installer.{tool_name}")

    @abstractmethod
    def check_installed(self) -> bool:
        """Check if tool is already installed"""
        pass

    @abstractmethod
    def install(self) -> InstallationResult:
        """Install the tool"""
        pass

    @abstractmethod
    def verify_installation(self) -> bool:
        """Verify the installation works"""
        pass

    def get_executable_path(self) -> str:
        """Get path to tool executable"""
        return str(self.install_dir / self.get_executable_name())

    @abstractmethod
    def get_executable_name(self) -> str:
        """Get the name of the executable"""
        pass

    def create_install_dir(self) -> bool:
        """Create installation directory"""
        try:
            self.install_dir.mkdir(parents=True, exist_ok=True)
            return True
        except Exception as e:
            self.logger.error(f"Failed to create install directory: {e}")
            return False


class GhidraInstaller(BaseInstaller):
    """Installer for Ghidra reverse engineering tool (cross-platform)"""

    def __init__(self, custom_install_dir: Path = None):
        super().__init__("ghidra", GHIDRA_VERSION, custom_install_dir=custom_install_dir)
        self.platform = get_platform()
        self.ghidra_url = GHIDRA_DOWNLOAD_URL

    def _get_bundled_dist_root(self) -> Path:
        """Return the repository-local Ghidra dist root if available."""
        return Path(__file__).resolve().parents[3] / "external" / "ghidra-dist"

    def _iter_dist_roots(self):
        """Yield install roots to search, preferring user-configured locations."""
        yield self.install_dir
        bundled_root = self._get_bundled_dist_root()
        if bundled_root != self.install_dir:
            yield bundled_root

    def _resolve_distribution_path(self) -> Optional[Path]:
        """Find a usable Ghidra distribution under known install roots."""
        executable = get_script_name("ghidraRun", self.platform)

        for dist_root in self._iter_dist_roots():
            preferred = dist_root / GHIDRA_DIST_NAME
            candidates = [preferred]
            if dist_root.exists():
                candidates.extend(sorted(dist_root.glob("ghidra_*_PUBLIC")))

            seen = set()
            for candidate in candidates:
                if candidate in seen:
                    continue
                seen.add(candidate)
                if candidate.exists() and (candidate / executable).exists():
                    return candidate
        return None

    def check_installed(self) -> bool:
        """Check if Ghidra is installed"""
        return self._resolve_distribution_path() is not None

    def get_executable_path(self) -> str:
        """Get the resolved Ghidra launcher path."""
        ghidra_path = self._resolve_distribution_path()
        if ghidra_path is None:
            return str(self.install_dir / self.get_executable_name())
        return str(ghidra_path / self.get_executable_name())

    def install(self) -> InstallationResult:
        """Install Ghidra"""
        try:
            if self.check_installed():
                return InstallationResult(True, "ghidra", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(False, "ghidra", "", "Failed to create install directory")

            # Check Java requirement
            if not self._check_java():
                return InstallationResult(False, "ghidra", "", "Java 21+ required for Ghidra")

            # Download Ghidra with retry logic
            # Use mkstemp for secure temp file creation (avoids race condition)
            temp_fd, temp_file_str = tempfile.mkstemp(suffix=".zip")
            os.close(temp_fd)  # Close the file descriptor, we just need the path
            temp_file_path = Path(temp_file_str)

            try:
                download_with_retry(
                    url=self.ghidra_url,
                    output_path=temp_file_path,
                    max_retries=3,
                    timeout=120,  # 2 minutes for large file
                )
            except Exception as e:
                self.logger.error(f"Failed to download Ghidra: {e}")
                return InstallationResult(False, "ghidra", "", f"Download failed: {e}")

            # Validate checksum before extraction
            try:
                checksums = load_checksums()
                if "ghidra" in checksums and "sha256" in checksums["ghidra"]:
                    expected_sha256 = checksums["ghidra"]["sha256"]
                    self.logger.info("Validating download integrity...")
                    validate_checksum(temp_file_path, expected_sha256)
                else:
                    self.logger.warning("No checksum available for Ghidra - skipping validation")
                    self.logger.warning("Download integrity cannot be guaranteed")
            except ValueError as e:
                # Checksum mismatch - delete file and fail
                os.unlink(temp_file_path)
                raise ValueError(f"Download integrity check failed: {e}")

            # Extract Ghidra
            try:
                with zipfile.ZipFile(temp_file_path, "r") as zip_ref:
                    safe_extract_zip(zip_ref, self.install_dir)
            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)

            if self.verify_installation():
                return InstallationResult(True, "ghidra", str(self.install_dir))
            else:
                return InstallationResult(False, "ghidra", "", "Installation verification failed")

        except Exception as e:
            self.logger.error(f"Ghidra installation failed: {e}")
            return InstallationResult(False, "ghidra", "", str(e))

    def verify_installation(self) -> bool:
        """Verify Ghidra installation"""
        try:
            ghidra_path = self._resolve_distribution_path()
            if ghidra_path is None or not ghidra_path.exists():
                return False

            # Test Ghidra headless mode - platform-aware
            headless = get_script_name("analyzeHeadless", self.platform)
            headless_path = ghidra_path / "support" / headless

            if not headless_path.exists():
                self.logger.warning(f"Ghidra headless script not found: {headless_path}")
                return False

            # Make executable on Unix systems
            if self.platform in (Platform.LINUX, Platform.MACOS):
                os.chmod(headless_path, 0o755)
                result = subprocess.run([str(headless_path), "-help"], capture_output=True, timeout=30)
            else:
                result = subprocess.run(
                    ["cmd", "/c", str(headless_path), "-help"], capture_output=True, timeout=30
                )

            return result.returncode == 0
        except Exception as e:
            self.logger.error(f"Ghidra verification failed: {e}")
            return False

    def get_executable_name(self) -> str:
        return get_script_name("ghidraRun", self.platform)

    def _check_java(self) -> bool:
        """Check if Java 21+ is available"""
        try:
            result = subprocess.run(["java", "-version"], capture_output=True, text=True)
            if result.returncode == 0:
                version_output = result.stderr
                # Extract version number
                import re

                version_match = re.search(r'version "(\d+)', version_output)
                if version_match:
                    java_version = int(version_match.group(1))
                    return java_version >= 21
            return False
        except Exception:
            return False


class ILSpyInstaller(BaseInstaller):
    """Installer for ILSpy .NET decompiler (Windows-only, use dotnet-ilspy on Linux/macOS)"""

    def __init__(self, custom_install_dir: Path = None):
        super().__init__("ilspy", "8.0", custom_install_dir=custom_install_dir)
        self.platform = get_platform()

        # Platform-specific URLs
        if self.platform == Platform.WINDOWS:
            self.ilspy_url = "https://github.com/icsharpcode/ILSpy/releases/download/v8.0.0.7334/ILSpy_binaries_8.0.0.7334.zip"
        else:
            # For Linux/macOS, use ilspycmd (command-line version)
            self.ilspy_url = "https://github.com/icsharpcode/ILSpy/releases/download/v8.0.0.7334/ilspycmd-linux-x64.zip"

    def check_installed(self) -> bool:
        """Check if ILSpy is installed"""
        if self.platform == Platform.WINDOWS:
            ilspy_path = self.install_dir / "ILSpy.exe"
            return ilspy_path.exists()
        else:
            # Check for ilspycmd on Unix
            ilspy_path = self.install_dir / "ilspycmd"
            return ilspy_path.exists() and os.access(ilspy_path, os.X_OK)

    def install(self) -> InstallationResult:
        """Install ILSpy (platform-aware)"""
        try:
            if self.check_installed():
                return InstallationResult(True, "ilspy", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(False, "ilspy", "", "Failed to create install directory")

            # Download ILSpy
            import requests

            self.logger.info(f"Downloading ILSpy for {self.platform.value}...")
            response = requests.get(self.ilspy_url, stream=True)
            response.raise_for_status()

            # Extract ILSpy
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, "r") as zip_ref:
                    safe_extract_zip(zip_ref, self.install_dir)

            os.unlink(temp_file.name)

            # Make executable on Unix systems
            if self.platform in (Platform.LINUX, Platform.MACOS):
                ilspy_bin = self.install_dir / "ilspycmd"
                if ilspy_bin.exists():
                    os.chmod(ilspy_bin, 0o755)

            if self.verify_installation():
                return InstallationResult(True, "ilspy", str(self.install_dir))
            else:
                return InstallationResult(False, "ilspy", "", "Installation verification failed")

        except Exception as e:
            self.logger.error(f"ILSpy installation failed: {e}")
            return InstallationResult(False, "ilspy", "", str(e))

    def verify_installation(self) -> bool:
        """Verify ILSpy installation"""
        try:
            if self.platform == Platform.WINDOWS:
                ilspy_path = self.install_dir / "ILSpy.exe"
            else:
                ilspy_path = self.install_dir / "ilspycmd"

            if not ilspy_path.exists():
                return False

            # Test ILSpy CLI - skip on Windows GUI version
            if self.platform != Platform.WINDOWS or str(ilspy_path).endswith("cmd.exe"):
                result = subprocess.run(
                    [str(ilspy_path), "--help"], capture_output=True, timeout=30
                )
                return result.returncode == 0

            return True  # Windows GUI version exists
        except Exception:
            return False

    def get_executable_name(self) -> str:
        if self.platform == Platform.WINDOWS:
            return "ILSpy.exe"
        else:
            return "ilspycmd"


class CFRInstaller(BaseInstaller):
    """Installer for CFR Java decompiler"""

    def __init__(self, custom_install_dir: Path = None):
        super().__init__("cfr", "0.152", custom_install_dir=custom_install_dir)
        self.cfr_url = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"

    def check_installed(self) -> bool:
        """Check if CFR is installed"""
        cfr_path = self.install_dir / "cfr-0.152.jar"
        return cfr_path.exists()

    def install(self) -> InstallationResult:
        """Install CFR"""
        try:
            if self.check_installed():
                return InstallationResult(True, "cfr", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(False, "cfr", "", "Failed to create install directory")

            # Download CFR JAR
            import requests

            self.logger.info("Downloading CFR...")
            response = requests.get(self.cfr_url, stream=True)
            response.raise_for_status()

            cfr_path = self.install_dir / "cfr-0.152.jar"
            with open(cfr_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            if self.verify_installation():
                return InstallationResult(True, "cfr", str(self.install_dir))
            else:
                return InstallationResult(False, "cfr", "", "Installation verification failed")

        except Exception as e:
            self.logger.error(f"CFR installation failed: {e}")
            return InstallationResult(False, "cfr", "", str(e))

    def verify_installation(self) -> bool:
        """Verify CFR installation"""
        try:
            cfr_path = self.install_dir / "cfr-0.152.jar"
            if not cfr_path.exists():
                return False

            # Test CFR
            result = subprocess.run(
                ["java", "-jar", str(cfr_path), "--help"],
                capture_output=True,
                timeout=30,
            )

            return result.returncode == 0
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "cfr-0.152.jar"


class DIEInstaller(BaseInstaller):
    """Installer for Detect It Easy (Windows/Linux/macOS)"""

    def __init__(self, custom_install_dir: Path = None):
        super().__init__("detect_it_easy", "3.08", custom_install_dir=custom_install_dir)
        self.platform = get_platform()
        self.arch = get_architecture()

        # Platform-specific URLs
        if self.platform == Platform.WINDOWS:
            self.die_url = "https://github.com/horsicq/Detect-It-Easy/releases/download/3.08/die_win64_portable_3.08.zip"
        elif self.platform == Platform.LINUX:
            self.die_url = "https://github.com/horsicq/Detect-It-Easy/releases/download/3.08/die_lin64_portable_3.08.tar.gz"
        elif self.platform == Platform.MACOS:
            self.die_url = "https://github.com/horsicq/Detect-It-Easy/releases/download/3.08/die_mac_portable_3.08.dmg"
        else:
            self.die_url = None

    def check_installed(self) -> bool:
        """Check if DIE is installed"""
        if self.platform == Platform.WINDOWS:
            die_path = self.install_dir / "die.exe"
            return die_path.exists()
        elif self.platform == Platform.LINUX:
            die_path = self.install_dir / "diec"  # CLI version
            return die_path.exists() and os.access(die_path, os.X_OK)
        elif self.platform == Platform.MACOS:
            die_path = self.install_dir / "DIE.app"
            return die_path.exists()
        else:
            return False

    def install(self) -> InstallationResult:
        """Install Detect It Easy (cross-platform)"""
        try:
            if self.die_url is None:
                return InstallationResult(
                    False,
                    "detect_it_easy",
                    "",
                    f"Detect It Easy not available for {self.platform.value}",
                )

            if self.check_installed():
                return InstallationResult(True, "detect_it_easy", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(
                    False, "detect_it_easy", "", "Failed to create install directory"
                )

            # Download DIE
            import requests

            self.logger.info(f"Downloading Detect It Easy for {self.platform.value}...")
            response = requests.get(self.die_url, stream=True)
            response.raise_for_status()

            # Determine file extension
            if self.die_url.endswith(".tar.gz"):
                suffix = ".tar.gz"
            elif self.die_url.endswith(".dmg"):
                suffix = ".dmg"
            else:
                suffix = ".zip"

            # Extract DIE
            with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                # Extract based on format
                if suffix == ".zip":
                    with zipfile.ZipFile(temp_file.name, "r") as zip_ref:
                        safe_extract_zip(zip_ref, self.install_dir)
                elif suffix == ".tar.gz":
                    with tarfile.open(temp_file.name, "r:gz") as tar_ref:
                        tar_ref.extractall(self.install_dir)
                elif suffix == ".dmg":
                    # macOS DMG requires special handling
                    self.logger.warning("macOS DMG installation requires manual mounting")
                    return InstallationResult(
                        False,
                        "detect_it_easy",
                        "",
                        "macOS DMG installation requires manual setup",
                    )

            os.unlink(temp_file.name)

            # Make executable on Unix systems
            if self.platform == Platform.LINUX:
                for exe in ["diec", "die", "DIE"]:
                    exe_path = self.install_dir / exe
                    if exe_path.exists():
                        os.chmod(exe_path, 0o755)

            if self.verify_installation():
                return InstallationResult(True, "detect_it_easy", str(self.install_dir))
            else:
                return InstallationResult(
                    False, "detect_it_easy", "", "Installation verification failed"
                )

        except Exception as e:
            self.logger.error(f"DIE installation failed: {e}")
            return InstallationResult(False, "detect_it_easy", "", str(e))

    def verify_installation(self) -> bool:
        """Verify DIE installation"""
        try:
            if self.platform == Platform.WINDOWS:
                die_path = self.install_dir / "die.exe"
            elif self.platform == Platform.LINUX:
                die_path = self.install_dir / "diec"
            elif self.platform == Platform.MACOS:
                die_path = self.install_dir / "DIE.app"
            else:
                return False

            if not die_path.exists():
                return False

            # Test DIE CLI (skip GUI versions)
            if str(die_path).endswith(("diec", "die.exe")):
                result = subprocess.run([str(die_path), "--help"], capture_output=True, timeout=30)
                return result.returncode == 0

            return True  # GUI version exists
        except Exception:
            return False

    def get_executable_name(self) -> str:
        if self.platform == Platform.WINDOWS:
            return "die.exe"
        elif self.platform == Platform.LINUX:
            return "diec"
        else:
            return "DIE.app"


class ScyllaInstaller(BaseInstaller):
    """Installer for Scylla unpacker (Windows-only PE tool)"""

    def __init__(self, custom_install_dir: Path = None):
        super().__init__("scylla", "0.9.8", custom_install_dir=custom_install_dir)
        self.platform = get_platform()
        self.scylla_url = (
            "https://github.com/NtQuery/Scylla/releases/download/0.9.8/Scylla_x64_0.9.8.zip"
            if self.platform == Platform.WINDOWS
            else None
        )

    def check_installed(self) -> bool:
        """Check if Scylla is installed"""
        if self.platform != Platform.WINDOWS:
            return False
        scylla_path = self.install_dir / "Scylla_x64.exe"
        return scylla_path.exists()

    def install(self) -> InstallationResult:
        """Install Scylla (Windows-only)"""
        try:
            if self.platform != Platform.WINDOWS:
                return InstallationResult(
                    False,
                    "scylla",
                    "",
                    f"Scylla is Windows-only (PE unpacker). Use 'upx -d' on {self.platform.value}.",
                )

            if self.check_installed():
                return InstallationResult(True, "scylla", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(False, "scylla", "", "Failed to create install directory")

            # Download Scylla
            import requests

            self.logger.info("Downloading Scylla...")
            response = requests.get(self.scylla_url, stream=True)
            response.raise_for_status()

            # Extract Scylla
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, "r") as zip_ref:
                    safe_extract_zip(zip_ref, self.install_dir)

            os.unlink(temp_file.name)

            if self.verify_installation():
                return InstallationResult(True, "scylla", str(self.install_dir))
            else:
                return InstallationResult(False, "scylla", "", "Installation verification failed")

        except Exception as e:
            self.logger.error(f"Scylla installation failed: {e}")
            return InstallationResult(False, "scylla", "", str(e))

    def verify_installation(self) -> bool:
        """Verify Scylla installation"""
        try:
            scylla_path = self.install_dir / "Scylla_x64.exe"
            if not scylla_path.exists():
                return False

            # Test Scylla
            result = subprocess.run([str(scylla_path), "--help"], capture_output=True, timeout=30)

            return result.returncode == 0
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "Scylla_x64.exe"


class HxDInstaller(BaseInstaller):
    """Installer for HxD hex editor (Windows-only, use 'hexdump' or 'xxd' on Unix)"""

    def __init__(self, custom_install_dir: Path = None):
        super().__init__("hxd", "2.5.0.0", custom_install_dir=custom_install_dir)
        self.platform = get_platform()
        self.hxd_url = (
            "https://mh-nexus.de/downloads/HxD25.zip" if self.platform == Platform.WINDOWS else None
        )

    def check_installed(self) -> bool:
        """Check if HxD is installed"""
        if self.platform != Platform.WINDOWS:
            return False
        hxd_path = self.install_dir / "HxD.exe"
        return hxd_path.exists()

    def install(self) -> InstallationResult:
        """Install HxD (Windows-only)"""
        try:
            if self.platform != Platform.WINDOWS:
                return InstallationResult(
                    False,
                    "hxd",
                    "",
                    f"HxD is Windows-only. Use 'hexdump' or 'xxd' on {self.platform.value}.",
                )

            if self.check_installed():
                return InstallationResult(True, "hxd", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(False, "hxd", "", "Failed to create install directory")

            # Download HxD
            import requests

            self.logger.info("Downloading HxD...")
            response = requests.get(self.hxd_url, stream=True)
            response.raise_for_status()

            # Extract HxD
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, "r") as zip_ref:
                    safe_extract_zip(zip_ref, self.install_dir)

            os.unlink(temp_file.name)

            if self.verify_installation():
                return InstallationResult(True, "hxd", str(self.install_dir))
            else:
                return InstallationResult(False, "hxd", "", "Installation verification failed")

        except Exception as e:
            self.logger.error(f"HxD installation failed: {e}")
            return InstallationResult(False, "hxd", "", str(e))

    def verify_installation(self) -> bool:
        """Verify HxD installation"""
        try:
            hxd_path = self.install_dir / "HxD.exe"
            return hxd_path.exists()
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "HxD.exe"


class ResourceHackerInstaller(BaseInstaller):
    """Installer for Resource Hacker (Windows-only PE resource editor)"""

    def __init__(self, custom_install_dir: Path = None):
        super().__init__("resource_hacker", "5.1.7", custom_install_dir=custom_install_dir)
        self.platform = get_platform()
        self.rh_url = (
            "https://www.angusj.com/resourcehacker/resource_hacker.zip"
            if self.platform == Platform.WINDOWS
            else None
        )

    def check_installed(self) -> bool:
        """Check if Resource Hacker is installed"""
        if self.platform != Platform.WINDOWS:
            return False
        rh_path = self.install_dir / "ResourceHacker.exe"
        return rh_path.exists()

    def install(self) -> InstallationResult:
        """Install Resource Hacker (Windows-only)"""
        try:
            if self.platform != Platform.WINDOWS:
                return InstallationResult(
                    False,
                    "resource_hacker",
                    "",
                    f"Resource Hacker is Windows-only (PE resource editor). Not available on {self.platform.value}.",
                )

            if self.check_installed():
                return InstallationResult(True, "resource_hacker", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(
                    False, "resource_hacker", "", "Failed to create install directory"
                )

            # Download Resource Hacker
            import requests

            self.logger.info("Downloading Resource Hacker...")
            response = requests.get(self.rh_url, stream=True)
            response.raise_for_status()

            # Extract Resource Hacker
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, "r") as zip_ref:
                    safe_extract_zip(zip_ref, self.install_dir)

            os.unlink(temp_file.name)

            if self.verify_installation():
                return InstallationResult(True, "resource_hacker", str(self.install_dir))
            else:
                return InstallationResult(
                    False, "resource_hacker", "", "Installation verification failed"
                )

        except Exception as e:
            self.logger.error(f"Resource Hacker installation failed: {e}")
            return InstallationResult(False, "resource_hacker", "", str(e))

    def verify_installation(self) -> bool:
        """Verify Resource Hacker installation"""
        try:
            rh_path = self.install_dir / "ResourceHacker.exe"
            return rh_path.exists()
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "ResourceHacker.exe"


class DependencyManager:
    """Comprehensive dependency management system"""

    def __init__(self, config_path: Path = None):
        self.logger = logging.getLogger("dependency_manager")

        # Load configuration
        self.config = self._load_config(config_path)
        tool_overrides = self.config.get("tools", {}).get("per_tool_overrides", {})

        is_windows = sys.platform.startswith("win")

        # Create installers with custom directories if specified
        def get_install_dir(tool_name: str) -> Optional[Path]:
            """Get custom install directory for a tool from config"""
            if tool_name in tool_overrides and tool_overrides[tool_name]:
                return Path(tool_overrides[tool_name]).expanduser()
            return None

        self.tools = {
            "ghidra": GhidraInstaller(custom_install_dir=get_install_dir("ghidra")),
            "cfr": CFRInstaller(custom_install_dir=get_install_dir("cfr")),
        }

        if is_windows:
            self.tools.update(
                {
                    "ilspy": ILSpyInstaller(custom_install_dir=get_install_dir("ilspy")),
                    "detect_it_easy": DIEInstaller(
                        custom_install_dir=get_install_dir("detect_it_easy")
                    ),
                    "scylla": ScyllaInstaller(custom_install_dir=get_install_dir("scylla")),
                    "hxd": HxDInstaller(custom_install_dir=get_install_dir("hxd")),
                    "resource_hacker": ResourceHackerInstaller(
                        custom_install_dir=get_install_dir("resource_hacker")
                    ),
                }
            )
        else:
            self.tools.update(
                {
                    "ilspy": None,
                    "detect_it_easy": None,
                    "scylla": None,
                    "hxd": None,
                    "resource_hacker": None,
                }
            )

        self.tools.update(
            {
                "dnspy": None,  # TODO: Implement DnSpy installer
                "uncompyle6": None,  # TODO: Implement Python installer
                "exeinfo_pe": None,  # TODO: Implement Exeinfo PE installer
                "x64dbg": None,  # TODO: Implement x64dbg installer
                "imhex": None,  # TODO: Implement ImHex installer
                "lordpe": None,  # TODO: Implement LordPE installer
            }
        )
        self.fallback_analyzers = {}
        self._setup_fallback_analyzers()

    def _load_config(self, config_path: Path = None) -> Dict[str, Any]:
        """Load configuration from YAML file

        Args:
            config_path: Optional path to config file. Defaults to ~/.reveng/config.yaml

        Returns:
            Dictionary containing configuration, or empty dict if file not found
        """
        if config_path is None:
            config_path = Path.home() / ".reveng" / "config.yaml"

        if not config_path.exists():
            self.logger.warning(f"Config file not found: {config_path}, using defaults")
            return {}

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f)
                return config if config else {}
        except Exception as e:
            self.logger.error(f"Failed to load config: {e}")
            return {}

    def _setup_fallback_analyzers(self):
        """Setup fallback analyzers for when tools are unavailable"""
        self.fallback_analyzers = {
            "ghidra": "basic_pe_analyzer",
            "ilspy": "basic_dotnet_analyzer",
            "cfr": "basic_java_analyzer",
            "detect_it_easy": "entropy_analyzer",
            "scylla": "manual_unpacker",
            "hxd": "python_hex_analyzer",
            "resource_hacker": "basic_resource_extractor",
        }

    def check_all_dependencies(self) -> Dict[str, bool]:
        """Check status of all dependencies"""
        results = {}
        for tool_name, installer in self.tools.items():
            if installer is None:
                results[tool_name] = False
                continue

            try:
                results[tool_name] = installer.check_installed()
            except Exception as e:
                self.logger.error(f"Error checking {tool_name}: {e}")
                results[tool_name] = False

        return results

    def install_missing_tools(
        self, tools: List[str], auto_install: bool = True, dry_run: bool = False
    ) -> Dict[str, InstallationResult]:
        """
        Install missing tools

        Args:
            tools: List of tool names to install
            auto_install: Whether to automatically install tools
            dry_run: If True, simulate installation without actually downloading/installing

        Returns:
            Dictionary mapping tool names to installation results
        """
        results = {}

        for tool_name in tools:
            if tool_name not in self.tools or self.tools[tool_name] is None:
                results[tool_name] = InstallationResult(
                    False, tool_name, "", f"Tool {tool_name} not supported"
                )
                continue

            if not auto_install:
                results[tool_name] = InstallationResult(
                    False, tool_name, "", "Auto-installation disabled"
                )
                continue

            try:
                installer = self.tools[tool_name]
                if installer.check_installed():
                    results[tool_name] = InstallationResult(
                        True, tool_name, str(installer.install_dir)
                    )
                else:
                    if dry_run:
                        # Dry run mode - simulate installation
                        self.logger.info(
                            f"[DRY RUN] Would install {tool_name} to {installer.install_dir}"
                        )
                        results[tool_name] = InstallationResult(
                            True,
                            tool_name,
                            str(installer.install_dir),
                            f"DRY RUN: Would install {tool_name} version {installer.tool_version}",
                        )
                    else:
                        # Actual installation
                        results[tool_name] = installer.install()
            except Exception as e:
                self.logger.error(f"Error installing {tool_name}: {e}")
                results[tool_name] = InstallationResult(False, tool_name, "", str(e))

        return results

    def get_fallback_analyzer(self, tool_name: str) -> Optional[str]:
        """Get fallback analyzer for unavailable tool"""
        return self.fallback_analyzers.get(tool_name)

    def get_tool_path(self, tool_name: str) -> Optional[str]:
        """Get path to installed tool"""
        if tool_name not in self.tools or self.tools[tool_name] is None:
            return None

        installer = self.tools[tool_name]
        if installer.check_installed():
            return installer.get_executable_path()

        return None

    def get_installation_status(self) -> Dict[str, ToolInfo]:
        """Get detailed installation status of all tools"""
        status = {}

        for tool_name, installer in self.tools.items():
            if installer is None:
                status[tool_name] = ToolInfo(
                    name=tool_name,
                    version="unknown",
                    path="",
                    executable="",
                    is_installed=False,
                    install_method="not_supported",
                    dependencies=[],
                    fallback_available=tool_name in self.fallback_analyzers,
                )
                continue

            try:
                is_installed = installer.check_installed()
                tool_path = installer.get_executable_path() if is_installed else ""

                status[tool_name] = ToolInfo(
                    name=tool_name,
                    version=installer.tool_version,
                    path=tool_path,
                    executable=installer.get_executable_name(),
                    is_installed=is_installed,
                    install_method="auto_install",
                    dependencies=[],
                    fallback_available=tool_name in self.fallback_analyzers,
                )
            except Exception as e:
                self.logger.error(f"Error getting status for {tool_name}: {e}")
                status[tool_name] = ToolInfo(
                    name=tool_name,
                    version="unknown",
                    path="",
                    executable="",
                    is_installed=False,
                    install_method="error",
                    dependencies=[],
                    fallback_available=tool_name in self.fallback_analyzers,
                )

        return status

    def cleanup_failed_installations(self) -> int:
        """Clean up failed installations"""
        cleaned = 0
        for tool_name, installer in self.tools.items():
            if installer is None:
                continue

            try:
                install_dir = installer.install_dir
                if install_dir.exists() and not installer.check_installed():
                    shutil.rmtree(install_dir)
                    cleaned += 1
            except Exception as e:
                self.logger.error(f"Error cleaning up {tool_name}: {e}")

        return cleaned

    def export_configuration(self, config_path: str) -> bool:
        """Export dependency configuration"""
        try:
            config = {
                "tools": {},
                "fallback_analyzers": self.fallback_analyzers,
                "timestamp": str(Path().cwd()),
            }

            for tool_name, installer in self.tools.items():
                if installer is None:
                    continue

                config["tools"][tool_name] = {
                    "version": installer.tool_version,
                    "install_dir": str(installer.install_dir),
                    "executable": installer.get_executable_name(),
                }

            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)

            return True
        except Exception as e:
            self.logger.error(f"Error exporting configuration: {e}")
            return False

    def import_configuration(self, config_path: str) -> bool:
        """Import dependency configuration"""
        try:
            with open(config_path, "r") as f:
                config = json.load(f)

            # Update fallback analyzers
            if "fallback_analyzers" in config:
                self.fallback_analyzers.update(config["fallback_analyzers"])

            return True
        except Exception as e:
            self.logger.error(f"Error importing configuration: {e}")
            return False
