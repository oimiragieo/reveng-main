"""
Python package installer for REVENG
"""

import os
import sys
import subprocess
import platform
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from .base_installer import BaseInstaller, InstallMethod
from ..core.dependency_manager import ToolStatus

logger = logging.getLogger(__name__)

class PythonInstaller(BaseInstaller):
    """Installer for Python packages"""

    def __init__(self, tools_dir: Path, package_name: str):
        super().__init__(tools_dir, package_name)
        self.package_name = package_name
        self.package_versions = {
            'uncompyle6': '3.9.0',
            'decompyle3': '3.9.4',
            'pycdc': '1.4.0'
        }

    def get_download_url(self) -> str:
        """Get package download URL (PyPI)"""
        return f"https://pypi.org/project/{self.package_name}/"

    def get_version(self) -> str:
        """Get installed package version"""
        if self.config.get('version'):
            return self.config['version']

        # Try to get version from package
        try:
            result = subprocess.run(
                [sys.executable, "-c", f"import {self.package_name}; print({self.package_name}.__version__)"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                version = result.stdout.strip()
                self.config['version'] = version
                self._save_config(self.config)
                return version
        except Exception as e:
            logger.warning(f"Failed to get {self.package_name} version: {e}")

        return "unknown"

    def check_installation(self) -> ToolStatus:
        """Check if package is properly installed"""
        try:
            # Check if package can be imported
            result = subprocess.run(
                [sys.executable, "-c", f"import {self.package_name}"],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                return ToolStatus.INSTALLED
            else:
                return ToolStatus.MISSING

        except Exception as e:
            logger.error(f"Error checking {self.package_name} installation: {e}")
            return ToolStatus.ERROR

    def install(self) -> bool:
        """Install Python package"""
        try:
            logger.info(f"Installing {self.package_name}...")

            # Install package using pip
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", self.package_name],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            if result.returncode == 0:
                # Update config
                version = self.get_version()
                self.config.update({
                    'version': version,
                    'install_method': InstallMethod.PYTHON_PIP.value,
                    'package_name': self.package_name
                })
                self._save_config(self.config)

                logger.info(f"{self.package_name} installed successfully")
                return True
            else:
                logger.error(f"Failed to install {self.package_name}: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Failed to install {self.package_name}: {e}")
            return False

    def get_install_instructions(self) -> str:
        """Get manual installation instructions for Python package"""
        return f"""
Manual {self.package_name} Installation:

1. Install using pip:
   pip install {self.package_name}

2. Or install in virtual environment:
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\\Scripts\\activate
   pip install {self.package_name}

3. Test installation:
   python -c "import {self.package_name}; print({self.package_name}.__version__)"
"""

    def get_command(self, *args) -> list:
        """Get command to run the package"""
        return [sys.executable, "-m", self.package_name] + list(args)

    def get_uncompyle6_command(self, pyc_file: str, output_file: str) -> list:
        """Get command to decompile Python bytecode with uncompyle6"""
        if self.package_name != 'uncompyle6':
            raise ValueError("This method is only for uncompyle6")

        return [
            sys.executable,
            "-m",
            "uncompyle6",
            "-o",
            output_file,
            pyc_file
        ]

    def get_decompyle3_command(self, pyc_file: str, output_file: str) -> list:
        """Get command to decompile Python bytecode with decompyle3"""
        if self.package_name != 'decompyle3':
            raise ValueError("This method is only for decompyle3")

        return [
            sys.executable,
            "-m",
            "decompyle3",
            "-o",
            output_file,
            pyc_file
        ]
