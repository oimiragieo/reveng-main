"""
Ghidra installer for REVENG
"""

import os
import sys
import subprocess
import platform
import shutil
import zipfile
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any
from urllib.parse import urljoin

from .base_installer import BaseInstaller, InstallMethod
from ..core.dependency_manager import ToolStatus

logger = logging.getLogger(__name__)

class GhidraInstaller(BaseInstaller):
    """Installer for Ghidra reverse engineering framework"""

    def __init__(self, tools_dir: Path):
        super().__init__(tools_dir, "ghidra")
        self.ghidra_url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.4_build/ghidra_11.0.4_PUBLIC_20230928.zip"
        self.ghidra_version = "11.0.4"
        self.java_required = "21"

    def get_download_url(self) -> str:
        """Get Ghidra download URL"""
        return self.ghidra_url

    def get_version(self) -> str:
        """Get installed Ghidra version"""
        if self.config.get('version'):
            return self.config['version']

        # Try to get version from Ghidra executable
        ghidra_exe = self._find_ghidra_executable()
        if ghidra_exe:
            try:
                result = subprocess.run(
                    [str(ghidra_exe), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    version_line = result.stdout.strip().split('\n')[0]
                    if 'Ghidra' in version_line:
                        version = version_line.split()[-1]
                        self.config['version'] = version
                        self._save_config(self.config)
                        return version
            except Exception as e:
                logger.warning(f"Failed to get Ghidra version: {e}")

        return "unknown"

    def check_installation(self) -> ToolStatus:
        """Check if Ghidra is properly installed"""
        try:
            # Check if Java is available
            if not self._check_java():
                return ToolStatus.ERROR

            # Check if Ghidra executable exists
            ghidra_exe = self._find_ghidra_executable()
            if not ghidra_exe:
                return ToolStatus.MISSING

            # Test if Ghidra can run
            if not self._test_ghidra_execution():
                return ToolStatus.ERROR

            return ToolStatus.INSTALLED

        except Exception as e:
            logger.error(f"Error checking Ghidra installation: {e}")
            return ToolStatus.ERROR

    def install(self) -> bool:
        """Install Ghidra"""
        try:
            logger.info("Installing Ghidra...")

            # Check Java requirement
            if not self._check_java():
                logger.error("Java 21+ is required for Ghidra. Please install Java first.")
                return False

            # Download Ghidra
            archive_path = self._download_file(self.ghidra_url, "ghidra.zip")

            # Extract Ghidra
            extract_path = self.install_path / "extracted"
            self._extract_archive(archive_path, extract_path)

            # Find the main Ghidra directory
            ghidra_dir = self._find_ghidra_directory(extract_path)
            if not ghidra_dir:
                logger.error("Could not find Ghidra directory in extracted files")
                return False

            # Move Ghidra to final location
            final_path = self.install_path / "ghidra"
            if final_path.exists():
                shutil.rmtree(final_path)
            shutil.move(ghidra_dir, final_path)

            # Clean up
            shutil.rmtree(extract_path)
            archive_path.unlink()

            # Update config
            self.config.update({
                'version': self.ghidra_version,
                'install_path': str(final_path),
                'install_method': InstallMethod.DOWNLOAD.value
            })
            self._save_config(self.config)

            logger.info("Ghidra installed successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to install Ghidra: {e}")
            return False

    def get_install_instructions(self) -> str:
        """Get manual installation instructions for Ghidra"""
        return f"""
Manual Ghidra Installation:

1. Install Java 21+ (required for Ghidra):
   - Windows: Download from https://adoptium.net/
   - Linux: sudo apt install openjdk-21-jdk
   - macOS: brew install openjdk@21

2. Download Ghidra:
   - Go to: https://github.com/NationalSecurityAgency/ghidra/releases
   - Download the latest release (ghidra_X.X.X_PUBLIC_YYYYMMDD.zip)

3. Extract and setup:
   - Extract to: {self.install_path}
   - Rename extracted folder to 'ghidra'
   - Ensure ghidraRun script is executable

4. Test installation:
   - Run: {self.install_path}/ghidra/ghidraRun --version
"""

    def _check_java(self) -> bool:
        """Check if Java 21+ is available"""
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                version_output = result.stderr.strip()
                # Parse Java version (e.g., "openjdk version "21.0.1"")
                if "version" in version_output:
                    version_line = version_output.split('\n')[0]
                    version_str = version_line.split('"')[1]
                    major_version = int(version_str.split('.')[0])
                    return major_version >= 21

            return False

        except Exception as e:
            logger.warning(f"Failed to check Java version: {e}")
            return False

    def _find_ghidra_executable(self) -> Optional[Path]:
        """Find the Ghidra executable"""
        ghidra_dir = self.install_path / "ghidra"
        if not ghidra_dir.exists():
            return None

        # Look for ghidraRun script
        ghidra_run = ghidra_dir / "ghidraRun"
        if ghidra_run.exists():
            return ghidra_run

        # Look for ghidraRun.bat on Windows
        if platform.system().lower() == "windows":
            ghidra_run_bat = ghidra_dir / "ghidraRun.bat"
            if ghidra_run_bat.exists():
                return ghidra_run_bat

        return None

    def _find_ghidra_directory(self, extract_path: Path) -> Optional[Path]:
        """Find the main Ghidra directory after extraction"""
        # Look for directory containing ghidraRun
        for item in extract_path.iterdir():
            if item.is_dir():
                ghidra_run = item / "ghidraRun"
                if ghidra_run.exists():
                    return item

        return None

    def _test_ghidra_execution(self) -> bool:
        """Test if Ghidra can execute properly"""
        ghidra_exe = self._find_ghidra_executable()
        if not ghidra_exe:
            return False

        try:
            # Test with --help flag (non-interactive)
            result = subprocess.run(
                [str(ghidra_exe), "--help"],
                capture_output=True,
                text=True,
                timeout=30
            )

            # Ghidra help should return non-zero exit code but show help text
            return "Ghidra" in result.stdout or "Ghidra" in result.stderr

        except Exception as e:
            logger.warning(f"Failed to test Ghidra execution: {e}")
            return False

    def get_headless_command(self, script_path: str, binary_path: str) -> list:
        """Get command to run Ghidra in headless mode"""
        ghidra_exe = self._find_ghidra_executable()
        if not ghidra_exe:
            raise RuntimeError("Ghidra not found")

        return [
            str(ghidra_exe),
            "headless",
            str(script_path),
            str(binary_path)
        ]

    def get_analysis_command(self, binary_path: str, output_dir: str) -> list:
        """Get command to analyze binary with Ghidra"""
        ghidra_exe = self._find_ghidra_executable()
        if not ghidra_exe:
            raise RuntimeError("Ghidra not found")

        return [
            str(ghidra_exe),
            "headless",
            str(binary_path),
            "-import",
            str(binary_path),
            "-analysisTimeoutPerFile", "300",
            "-deleteProject"
        ]
