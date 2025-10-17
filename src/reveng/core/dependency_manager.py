"""
REVENG Dependency Management System

Auto-detect, download, and install required analysis tools with fallback support.
"""

import os
import sys
import json
import shutil
import subprocess
import tempfile
import zipfile
import tarfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from abc import ABC, abstractmethod
import logging

logger = logging.getLogger(__name__)

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

    def __init__(self, tool_name: str, tool_version: str = "latest"):
        self.tool_name = tool_name
        self.tool_version = tool_version
        self.install_dir = Path.home() / ".reveng" / "tools" / tool_name
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
    """Installer for Ghidra reverse engineering tool"""

    def __init__(self):
        super().__init__("ghidra", "11.0")
        self.ghidra_url = "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20241210.zip"

    def check_installed(self) -> bool:
        """Check if Ghidra is installed"""
        ghidra_path = self.install_dir / "ghidra_11.0_PUBLIC"
        return ghidra_path.exists() and (ghidra_path / "ghidraRun.bat").exists()

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

            # Download Ghidra
            import requests
            self.logger.info("Downloading Ghidra...")
            response = requests.get(self.ghidra_url, stream=True)
            response.raise_for_status()

            # Extract Ghidra
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, 'r') as zip_ref:
                    zip_ref.extractall(self.install_dir)

            os.unlink(temp_file.name)

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
            ghidra_path = self.install_dir / "ghidra_11.0_PUBLIC"
            if not ghidra_path.exists():
                return False

            # Test Ghidra headless mode
            result = subprocess.run([
                str(ghidra_path / "support" / "analyzeHeadless.bat"),
                "-help"
            ], capture_output=True, timeout=30)

            return result.returncode == 0
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "ghidraRun.bat"

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
    """Installer for ILSpy .NET decompiler"""

    def __init__(self):
        super().__init__("ilspy", "8.0")
        self.ilspy_url = "https://github.com/icsharpcode/ILSpy/releases/download/v8.0.0.7334/ILSpy_binaries_8.0.0.7334.zip"

    def check_installed(self) -> bool:
        """Check if ILSpy is installed"""
        ilspy_path = self.install_dir / "ILSpy.exe"
        return ilspy_path.exists()

    def install(self) -> InstallationResult:
        """Install ILSpy"""
        try:
            if self.check_installed():
                return InstallationResult(True, "ilspy", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(False, "ilspy", "", "Failed to create install directory")

            # Download ILSpy
            import requests
            self.logger.info("Downloading ILSpy...")
            response = requests.get(self.ilspy_url, stream=True)
            response.raise_for_status()

            # Extract ILSpy
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, 'r') as zip_ref:
                    zip_ref.extractall(self.install_dir)

            os.unlink(temp_file.name)

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
            ilspy_path = self.install_dir / "ILSpy.exe"
            if not ilspy_path.exists():
                return False

            # Test ILSpy CLI
            result = subprocess.run([
                str(ilspy_path),
                "--help"
            ], capture_output=True, timeout=30)

            return result.returncode == 0
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "ILSpy.exe"

class CFRInstaller(BaseInstaller):
    """Installer for CFR Java decompiler"""

    def __init__(self):
        super().__init__("cfr", "0.152")
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
            with open(cfr_path, 'wb') as f:
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
            result = subprocess.run([
                "java", "-jar", str(cfr_path), "--help"
            ], capture_output=True, timeout=30)

            return result.returncode == 0
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "cfr-0.152.jar"

class DIEInstaller(BaseInstaller):
    """Installer for Detect It Easy"""

    def __init__(self):
        super().__init__("detect_it_easy", "3.08")
        self.die_url = "https://github.com/horsicq/Detect-It-Easy/releases/download/3.08/die_win64_portable_3.08.zip"

    def check_installed(self) -> bool:
        """Check if DIE is installed"""
        die_path = self.install_dir / "die.exe"
        return die_path.exists()

    def install(self) -> InstallationResult:
        """Install Detect It Easy"""
        try:
            if self.check_installed():
                return InstallationResult(True, "detect_it_easy", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(False, "detect_it_easy", "", "Failed to create install directory")

            # Download DIE
            import requests
            self.logger.info("Downloading Detect It Easy...")
            response = requests.get(self.die_url, stream=True)
            response.raise_for_status()

            # Extract DIE
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, 'r') as zip_ref:
                    zip_ref.extractall(self.install_dir)

            os.unlink(temp_file.name)

            if self.verify_installation():
                return InstallationResult(True, "detect_it_easy", str(self.install_dir))
            else:
                return InstallationResult(False, "detect_it_easy", "", "Installation verification failed")

        except Exception as e:
            self.logger.error(f"DIE installation failed: {e}")
            return InstallationResult(False, "detect_it_easy", "", str(e))

    def verify_installation(self) -> bool:
        """Verify DIE installation"""
        try:
            die_path = self.install_dir / "die.exe"
            if not die_path.exists():
                return False

            # Test DIE
            result = subprocess.run([
                str(die_path),
                "--help"
            ], capture_output=True, timeout=30)

            return result.returncode == 0
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "die.exe"

class ScyllaInstaller(BaseInstaller):
    """Installer for Scylla unpacker"""

    def __init__(self):
        super().__init__("scylla", "0.9.8")
        self.scylla_url = "https://github.com/NtQuery/Scylla/releases/download/0.9.8/Scylla_x64_0.9.8.zip"

    def check_installed(self) -> bool:
        """Check if Scylla is installed"""
        scylla_path = self.install_dir / "Scylla_x64.exe"
        return scylla_path.exists()

    def install(self) -> InstallationResult:
        """Install Scylla"""
        try:
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
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, 'r') as zip_ref:
                    zip_ref.extractall(self.install_dir)

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
            result = subprocess.run([
                str(scylla_path),
                "--help"
            ], capture_output=True, timeout=30)

            return result.returncode == 0
        except Exception:
            return False

    def get_executable_name(self) -> str:
        return "Scylla_x64.exe"

class HxDInstaller(BaseInstaller):
    """Installer for HxD hex editor"""

    def __init__(self):
        super().__init__("hxd", "2.5.0.0")
        self.hxd_url = "https://mh-nexus.de/downloads/HxD25.zip"

    def check_installed(self) -> bool:
        """Check if HxD is installed"""
        hxd_path = self.install_dir / "HxD.exe"
        return hxd_path.exists()

    def install(self) -> InstallationResult:
        """Install HxD"""
        try:
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
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, 'r') as zip_ref:
                    zip_ref.extractall(self.install_dir)

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
    """Installer for Resource Hacker"""

    def __init__(self):
        super().__init__("resource_hacker", "5.1.7")
        self.rh_url = "https://www.angusj.com/resourcehacker/resource_hacker.zip"

    def check_installed(self) -> bool:
        """Check if Resource Hacker is installed"""
        rh_path = self.install_dir / "ResourceHacker.exe"
        return rh_path.exists()

    def install(self) -> InstallationResult:
        """Install Resource Hacker"""
        try:
            if self.check_installed():
                return InstallationResult(True, "resource_hacker", str(self.install_dir))

            if not self.create_install_dir():
                return InstallationResult(False, "resource_hacker", "", "Failed to create install directory")

            # Download Resource Hacker
            import requests
            self.logger.info("Downloading Resource Hacker...")
            response = requests.get(self.rh_url, stream=True)
            response.raise_for_status()

            # Extract Resource Hacker
            with tempfile.NamedTemporaryFile(suffix='.zip', delete=False) as temp_file:
                for chunk in response.iter_content(chunk_size=8192):
                    temp_file.write(chunk)
                temp_file.flush()

                with zipfile.ZipFile(temp_file.name, 'r') as zip_ref:
                    zip_ref.extractall(self.install_dir)

            os.unlink(temp_file.name)

            if self.verify_installation():
                return InstallationResult(True, "resource_hacker", str(self.install_dir))
            else:
                return InstallationResult(False, "resource_hacker", "", "Installation verification failed")

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

    def __init__(self):
        self.logger = logging.getLogger("dependency_manager")
        self.tools = {
            'ghidra': GhidraInstaller(),
            'ilspy': ILSpyInstaller(),
            'cfr': CFRInstaller(),
            'dnspy': None,  # TODO: Implement DnSpy installer
            'uncompyle6': None,  # TODO: Implement Python installer
            'detect_it_easy': DIEInstaller(),
            'exeinfo_pe': None,  # TODO: Implement Exeinfo PE installer
            'scylla': ScyllaInstaller(),
            'x64dbg': None,  # TODO: Implement x64dbg installer
            'hxd': HxDInstaller(),
            'imhex': None,  # TODO: Implement ImHex installer
            'resource_hacker': ResourceHackerInstaller(),
            'lordpe': None,  # TODO: Implement LordPE installer
        }
        self.fallback_analyzers = {}
        self._setup_fallback_analyzers()

    def _setup_fallback_analyzers(self):
        """Setup fallback analyzers for when tools are unavailable"""
        self.fallback_analyzers = {
            'ghidra': 'basic_pe_analyzer',
            'ilspy': 'basic_dotnet_analyzer',
            'cfr': 'basic_java_analyzer',
            'detect_it_easy': 'entropy_analyzer',
            'scylla': 'manual_unpacker',
            'hxd': 'python_hex_analyzer',
            'resource_hacker': 'basic_resource_extractor',
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

    def install_missing_tools(self, tools: List[str], auto_install: bool = True) -> Dict[str, InstallationResult]:
        """Install missing tools"""
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
                    results[tool_name] = InstallationResult(True, tool_name, str(installer.install_dir))
                else:
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
                    fallback_available=tool_name in self.fallback_analyzers
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
                    fallback_available=tool_name in self.fallback_analyzers
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
                    fallback_available=tool_name in self.fallback_analyzers
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
                'tools': {},
                'fallback_analyzers': self.fallback_analyzers,
                'timestamp': str(Path().cwd())
            }

            for tool_name, installer in self.tools.items():
                if installer is None:
                    continue

                config['tools'][tool_name] = {
                    'version': installer.tool_version,
                    'install_dir': str(installer.install_dir),
                    'executable': installer.get_executable_name()
                }

            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)

            return True
        except Exception as e:
            self.logger.error(f"Error exporting configuration: {e}")
            return False

    def import_configuration(self, config_path: str) -> bool:
        """Import dependency configuration"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)

            # Update fallback analyzers
            if 'fallback_analyzers' in config:
                self.fallback_analyzers.update(config['fallback_analyzers'])

            return True
        except Exception as e:
            self.logger.error(f"Error importing configuration: {e}")
            return False
