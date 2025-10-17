"""
ILSpy installer for REVENG
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

from .base_installer import BaseInstaller, InstallMethod
from ..core.dependency_manager import ToolStatus

logger = logging.getLogger(__name__)

class ILSpyInstaller(BaseInstaller):
    """Installer for ILSpy .NET decompiler"""

    def __init__(self, tools_dir: Path):
        super().__init__(tools_dir, "ilspy")
        self.ilspy_url = "https://github.com/icsharpcode/ILSpy/releases/download/v8.0.0.7330/ILSpy_binaries_8.0.0.7330.zip"
        self.ilspy_version = "8.0.0.7330"

    def get_download_url(self) -> str:
        """Get ILSpy download URL"""
        return self.ilspy_url

    def get_version(self) -> str:
        """Get installed ILSpy version"""
        if self.config.get('version'):
            return self.config['version']

        # Try to get version from ILSpy executable
        ilspy_exe = self._find_ilspy_executable()
        if ilspy_exe:
            try:
                result = subprocess.run(
                    [str(ilspy_exe), "--version"],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                if result.returncode == 0:
                    version = result.stdout.strip()
                    self.config['version'] = version
                    self._save_config(self.config)
                    return version
            except Exception as e:
                logger.warning(f"Failed to get ILSpy version: {e}")

        return "unknown"

    def check_installation(self) -> ToolStatus:
        """Check if ILSpy is properly installed"""
        try:
            # Check if .NET runtime is available
            if not self._check_dotnet_runtime():
                return ToolStatus.ERROR

            # Check if ILSpy executable exists
            ilspy_exe = self._find_ilspy_executable()
            if not ilspy_exe:
                return ToolStatus.MISSING

            # Test if ILSpy can run
            if not self._test_ilspy_execution():
                return ToolStatus.ERROR

            return ToolStatus.INSTALLED

        except Exception as e:
            logger.error(f"Error checking ILSpy installation: {e}")
            return ToolStatus.ERROR

    def install(self) -> bool:
        """Install ILSpy"""
        try:
            logger.info("Installing ILSpy...")

            # Check .NET runtime requirement
            if not self._check_dotnet_runtime():
                logger.error(".NET 6.0+ runtime is required for ILSpy. Please install .NET runtime first.")
                return False

            # Download ILSpy
            archive_path = self._download_file(self.ilspy_url, "ilspy.zip")

            # Extract ILSpy
            self._extract_archive(archive_path, self.install_path)

            # Clean up
            archive_path.unlink()

            # Update config
            self.config.update({
                'version': self.ilspy_version,
                'install_path': str(self.install_path),
                'install_method': InstallMethod.DOWNLOAD.value
            })
            self._save_config(self.config)

            logger.info("ILSpy installed successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to install ILSpy: {e}")
            return False

    def get_install_instructions(self) -> str:
        """Get manual installation instructions for ILSpy"""
        return f"""
Manual ILSpy Installation:

1. Install .NET 6.0+ Runtime:
   - Windows: Download from https://dotnet.microsoft.com/download
   - Linux: sudo apt install dotnet-runtime-6.0
   - macOS: brew install dotnet

2. Download ILSpy:
   - Go to: https://github.com/icsharpcode/ILSpy/releases
   - Download the latest ILSpy_binaries_X.X.X.X.zip

3. Extract and setup:
   - Extract to: {self.install_path}
   - Ensure ILSpy.exe is in the root directory

4. Test installation:
   - Run: dotnet {self.install_path}/ILSpy.exe --help
"""

    def _check_dotnet_runtime(self) -> bool:
        """Check if .NET runtime is available"""
        try:
            result = subprocess.run(
                ["dotnet", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                version = result.stdout.strip()
                # Parse .NET version (e.g., "6.0.100")
                major_version = int(version.split('.')[0])
                return major_version >= 6

            return False

        except Exception as e:
            logger.warning(f"Failed to check .NET version: {e}")
            return False

    def _find_ilspy_executable(self) -> Optional[Path]:
        """Find the ILSpy executable"""
        # Look for ILSpy.exe in the installation directory
        ilspy_exe = self.install_path / "ILSpy.exe"
        if ilspy_exe.exists() and self._check_executable(ilspy_exe):
            return ilspy_exe

        # Search recursively
        for exe_file in self.install_path.rglob("ILSpy.exe"):
            if exe_file.is_file() and self._check_executable(exe_file):
                return exe_file

        return None

    def _test_ilspy_execution(self) -> bool:
        """Test if ILSpy can execute properly"""
        ilspy_exe = self._find_ilspy_executable()
        if not ilspy_exe:
            return False

        try:
            # Test with --help flag
            result = subprocess.run(
                ["dotnet", str(ilspy_exe), "--help"],
                capture_output=True,
                text=True,
                timeout=30
            )

            # ILSpy help should show usage information
            return "ILSpy" in result.stdout or "ILSpy" in result.stderr

        except Exception as e:
            logger.warning(f"Failed to test ILSpy execution: {e}")
            return False

    def get_decompile_command(self, assembly_path: str, output_dir: str) -> list:
        """Get command to decompile assembly with ILSpy"""
        ilspy_exe = self._find_ilspy_executable()
        if not ilspy_exe:
            raise RuntimeError("ILSpy not found")

        return [
            "dotnet",
            str(ilspy_exe),
            str(assembly_path),
            "--outputdir",
            str(output_dir)
        ]

    def get_export_command(self, assembly_path: str, output_file: str) -> list:
        """Get command to export decompiled code to file"""
        ilspy_exe = self._find_ilspy_executable()
        if not ilspy_exe:
            raise RuntimeError("ILSpy not found")

        return [
            "dotnet",
            str(ilspy_exe),
            str(assembly_path),
            "--outputdir",
            str(Path(output_file).parent),
            "--outputfile",
            str(Path(output_file).name)
        ]
