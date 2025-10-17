"""
CFR Java decompiler installer for REVENG
"""

import os
import sys
import subprocess
import platform
import shutil
import json
import logging
from pathlib import Path
from typing import Optional, Dict, Any

from .base_installer import BaseInstaller, InstallMethod
from ..core.dependency_manager import ToolStatus

logger = logging.getLogger(__name__)

class CFRInstaller(BaseInstaller):
    """Installer for CFR Java decompiler"""

    def __init__(self, tools_dir: Path):
        super().__init__(tools_dir, "cfr")
        self.cfr_url = "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"
        self.cfr_version = "0.152"

    def get_download_url(self) -> str:
        """Get CFR download URL"""
        return self.cfr_url

    def get_version(self) -> str:
        """Get installed CFR version"""
        if self.config.get('version'):
            return self.config['version']

        # Try to get version from CFR JAR
        cfr_jar = self._find_cfr_jar()
        if cfr_jar:
            try:
                result = subprocess.run(
                    ["java", "-jar", str(cfr_jar), "--version"],
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
                logger.warning(f"Failed to get CFR version: {e}")

        return "unknown"

    def check_installation(self) -> ToolStatus:
        """Check if CFR is properly installed"""
        try:
            # Check if Java is available
            if not self._check_java():
                return ToolStatus.ERROR

            # Check if CFR JAR exists
            cfr_jar = self._find_cfr_jar()
            if not cfr_jar:
                return ToolStatus.MISSING

            # Test if CFR can run
            if not self._test_cfr_execution():
                return ToolStatus.ERROR

            return ToolStatus.INSTALLED

        except Exception as e:
            logger.error(f"Error checking CFR installation: {e}")
            return ToolStatus.ERROR

    def install(self) -> bool:
        """Install CFR"""
        try:
            logger.info("Installing CFR...")

            # Check Java requirement
            if not self._check_java():
                logger.error("Java is required for CFR. Please install Java first.")
                return False

            # Download CFR JAR
            cfr_jar_path = self._download_file(self.cfr_url, "cfr.jar")

            # Update config
            self.config.update({
                'version': self.cfr_version,
                'jar_path': str(cfr_jar_path),
                'install_method': InstallMethod.DOWNLOAD.value
            })
            self._save_config(self.config)

            logger.info("CFR installed successfully")
            return True

        except Exception as e:
            logger.error(f"Failed to install CFR: {e}")
            return False

    def get_install_instructions(self) -> str:
        """Get manual installation instructions for CFR"""
        return f"""
Manual CFR Installation:

1. Install Java (required for CFR):
   - Windows: Download from https://adoptium.net/
   - Linux: sudo apt install openjdk-11-jdk
   - macOS: brew install openjdk@11

2. Download CFR:
   - Go to: https://github.com/leibnitz27/cfr/releases
   - Download the latest cfr-X.X.jar

3. Setup:
   - Place cfr.jar in: {self.install_path}/cfr.jar

4. Test installation:
   - Run: java -jar {self.install_path}/cfr.jar --version
"""

    def _check_java(self) -> bool:
        """Check if Java is available"""
        try:
            result = subprocess.run(
                ["java", "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )

            return result.returncode == 0

        except Exception as e:
            logger.warning(f"Failed to check Java: {e}")
            return False

    def _find_cfr_jar(self) -> Optional[Path]:
        """Find the CFR JAR file"""
        cfr_jar = self.install_path / "cfr.jar"
        if cfr_jar.exists():
            return cfr_jar

        # Search for any CFR JAR file
        for jar_file in self.install_path.rglob("cfr*.jar"):
            if jar_file.is_file():
                return jar_file

        return None

    def _test_cfr_execution(self) -> bool:
        """Test if CFR can execute properly"""
        cfr_jar = self._find_cfr_jar()
        if not cfr_jar:
            return False

        try:
            # Test with --version flag
            result = subprocess.run(
                ["java", "-jar", str(cfr_jar), "--version"],
                capture_output=True,
                text=True,
                timeout=30
            )

            # CFR should show version information
            return "CFR" in result.stdout or "CFR" in result.stderr

        except Exception as e:
            logger.warning(f"Failed to test CFR execution: {e}")
            return False

    def get_decompile_command(self, class_file: str, output_dir: str) -> list:
        """Get command to decompile class file with CFR"""
        cfr_jar = self._find_cfr_jar()
        if not cfr_jar:
            raise RuntimeError("CFR not found")

        return [
            "java",
            "-jar",
            str(cfr_jar),
            str(class_file),
            "--outputdir",
            str(output_dir)
        ]

    def get_decompile_jar_command(self, jar_file: str, output_dir: str) -> list:
        """Get command to decompile JAR file with CFR"""
        cfr_jar = self._find_cfr_jar()
        if not cfr_jar:
            raise RuntimeError("CFR not found")

        return [
            "java",
            "-jar",
            str(cfr_jar),
            str(jar_file),
            "--outputdir",
            str(output_dir)
        ]
