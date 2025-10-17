"""
REVENG .NET Assembly Analyzer

Comprehensive .NET assembly analysis with framework detection, GUI recognition,
and business logic extraction.
"""

import os
import sys
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
import logging
import json
import xml.etree.ElementTree as ET

from ..core.errors import AnalysisFailureError, MissingDependencyError, create_error_context
from ..core.logger import get_logger

class DotNetFramework(Enum):
    """.NET Framework versions"""
    FRAMEWORK_2_0 = "2.0"
    FRAMEWORK_3_0 = "3.0"
    FRAMEWORK_3_5 = "3.5"
    FRAMEWORK_4_0 = "4.0"
    FRAMEWORK_4_5 = "4.5"
    FRAMEWORK_4_6 = "4.6"
    FRAMEWORK_4_7 = "4.7"
    FRAMEWORK_4_8 = "4.8"
    NET_5_0 = "5.0"
    NET_6_0 = "6.0"
    NET_7_0 = "7.0"
    NET_8_0 = "8.0"

class GUIFramework(Enum):
    """GUI Framework types"""
    WINFORMS = "Windows Forms"
    WPF = "Windows Presentation Foundation"
    UWP = "Universal Windows Platform"
    CONSOLE = "Console Application"
    WEB = "Web Application"
    SERVICE = "Windows Service"
    UNKNOWN = "Unknown"

@dataclass
class DotNetAnalysisResult:
    """Result of .NET analysis"""
    framework_version: str
    runtime_version: str
    assembly_name: str
    assembly_version: str
    gui_framework: str
    dependencies: List[str]
    resources: Dict[str, Any]
    entry_points: List[str]
    business_logic: Dict[str, Any]
    is_packed: bool
    obfuscation_level: str
    api_calls: List[str]
    pe_sections: Dict[str, Any]
    analysis_confidence: float

@dataclass
class AssemblyInfo:
    """Assembly information"""
    name: str
    version: str
    culture: str
    public_key_token: str
    processor_architecture: str

class DotNetAnalyzer:
    """Comprehensive .NET assembly analyzer"""

    def __init__(self):
        self.logger = get_logger("dotnet_analyzer")
        self.temp_dir = Path(tempfile.gettempdir()) / "reveng_dotnet"
        self.temp_dir.mkdir(exist_ok=True)

    def analyze_assembly(self, binary_path: str) -> DotNetAnalysisResult:
        """Analyze .NET assembly comprehensively"""
        try:
            self.logger.info(f"Starting .NET analysis of {binary_path}")

            # Basic assembly info
            assembly_info = self._get_assembly_info(binary_path)

            # Framework detection
            framework_version = self._detect_framework_version(binary_path)
            runtime_version = self._detect_runtime_version(binary_path)

            # GUI framework detection
            gui_framework = self._detect_gui_framework(binary_path)

            # Dependencies
            dependencies = self._extract_dependencies(binary_path)

            # Resources
            resources = self._extract_embedded_resources(binary_path)

            # Entry points
            entry_points = self._find_entry_points(binary_path)

            # Business logic
            business_logic = self._extract_business_logic(binary_path)

            # Packing detection
            is_packed = self._detect_packing(binary_path)

            # Obfuscation analysis
            obfuscation_level = self._analyze_obfuscation(binary_path)

            # API calls
            api_calls = self._extract_api_calls(binary_path)

            # PE sections
            pe_sections = self._analyze_pe_sections(binary_path)

            # Calculate confidence
            confidence = self._calculate_analysis_confidence(
                framework_version, gui_framework, business_logic
            )

            result = DotNetAnalysisResult(
                framework_version=framework_version,
                runtime_version=runtime_version,
                assembly_name=assembly_info.name,
                assembly_version=assembly_info.version,
                gui_framework=gui_framework,
                dependencies=dependencies,
                resources=resources,
                entry_points=entry_points,
                business_logic=business_logic,
                is_packed=is_packed,
                obfuscation_level=obfuscation_level,
                api_calls=api_calls,
                pe_sections=pe_sections,
                analysis_confidence=confidence
            )

            self.logger.info(f"Completed .NET analysis with {confidence:.2f} confidence")
            return result

        except Exception as e:
            context = create_error_context(
                "dotnet_analyzer",
                "analyze_assembly",
                binary_path=binary_path
            )
            raise AnalysisFailureError(
                "dotnet_analysis",
                binary_path,
                context=context,
                fallback_available=True,
                original_exception=e
            )

    def _get_assembly_info(self, binary_path: str) -> AssemblyInfo:
        """Get basic assembly information"""
        try:
            # Use ILSpy to get assembly info
            ilspy_path = self._get_ilspy_path()
            if not ilspy_path:
                raise MissingDependencyError("ilspy")

            # Run ILSpy to get assembly metadata
            result = subprocess.run([
                ilspy_path,
                "--list",
                binary_path
            ], capture_output=True, text=True, timeout=30)

            if result.returncode != 0:
                raise AnalysisFailureError("ilspy_metadata", binary_path)

            # Parse ILSpy output
            assembly_info = self._parse_ilspy_output(result.stdout)
            return assembly_info

        except Exception as e:
            self.logger.warning(f"Failed to get assembly info: {e}")
            return AssemblyInfo(
                name="Unknown",
                version="Unknown",
                culture="",
                public_key_token="",
                processor_architecture=""
            )

    def _detect_framework_version(self, binary_path: str) -> str:
        """Detect .NET framework version"""
        try:
            # Check PE headers for .NET metadata
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Look for .NET metadata directory
            if b'.NET' in data:
                # Try to extract version from metadata
                version = self._extract_framework_version_from_metadata(data)
                if version:
                    return version

            # Fallback: check file properties
            version = self._check_file_properties(binary_path)
            if version:
                return version

            # Default fallback
            return "Unknown"

        except Exception as e:
            self.logger.warning(f"Failed to detect framework version: {e}")
            return "Unknown"

    def _detect_runtime_version(self, binary_path: str) -> str:
        """Detect .NET runtime version"""
        try:
            # Check for runtime version in PE headers
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Look for runtime version string
            runtime_version = self._extract_runtime_version_from_metadata(data)
            if runtime_version:
                return runtime_version

            return "Unknown"

        except Exception as e:
            self.logger.warning(f"Failed to detect runtime version: {e}")
            return "Unknown"

    def _detect_gui_framework(self, binary_path: str) -> str:
        """Detect GUI framework (WinForms, WPF, Console, etc.)"""
        try:
            # Check for GUI framework references
            gui_frameworks = []

            # Check for Windows Forms
            if self._has_winforms_references(binary_path):
                gui_frameworks.append(GUIFramework.WINFORMS)

            # Check for WPF
            if self._has_wpf_references(binary_path):
                gui_frameworks.append(GUIFramework.WPF)

            # Check for UWP
            if self._has_uwp_references(binary_path):
                gui_frameworks.append(GUIFramework.UWP)

            # Check for Web references
            if self._has_web_references(binary_path):
                gui_frameworks.append(GUIFramework.WEB)

            # Check for Service references
            if self._has_service_references(binary_path):
                gui_frameworks.append(GUIFramework.SERVICE)

            # Determine primary GUI framework
            if gui_frameworks:
                # Prioritize WinForms and WPF
                if GUIFramework.WINFORMS in gui_frameworks:
                    return GUIFramework.WINFORMS.value
                elif GUIFramework.WPF in gui_frameworks:
                    return GUIFramework.WPF.value
                else:
                    return gui_frameworks[0].value

            # Check for console application indicators
            if self._is_console_application(binary_path):
                return GUIFramework.CONSOLE.value

            return GUIFramework.UNKNOWN.value

        except Exception as e:
            self.logger.warning(f"Failed to detect GUI framework: {e}")
            return GUIFramework.UNKNOWN.value

    def _extract_dependencies(self, binary_path: str) -> List[str]:
        """Extract assembly dependencies"""
        try:
            dependencies = []

            # Use ILSpy to get dependencies
            ilspy_path = self._get_ilspy_path()
            if ilspy_path:
                result = subprocess.run([
                    ilspy_path,
                    "--list",
                    binary_path
                ], capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    dependencies = self._parse_dependencies_from_ilspy(result.stdout)

            return dependencies

        except Exception as e:
            self.logger.warning(f"Failed to extract dependencies: {e}")
            return []

    def _extract_embedded_resources(self, binary_path: str) -> Dict[str, Any]:
        """Extract embedded resources"""
        try:
            resources = {
                'icons': [],
                'strings': [],
                'manifests': [],
                'custom_resources': []
            }

            # Use Resource Hacker to extract resources
            rh_path = self._get_resource_hacker_path()
            if rh_path:
                resources = self._extract_resources_with_rh(binary_path, rh_path)

            return resources

        except Exception as e:
            self.logger.warning(f"Failed to extract resources: {e}")
            return {}

    def _find_entry_points(self, binary_path: str) -> List[str]:
        """Find .NET entry points"""
        try:
            entry_points = []

            # Use ILSpy to find entry points
            ilspy_path = self._get_ilspy_path()
            if ilspy_path:
                result = subprocess.run([
                    ilspy_path,
                    "--list",
                    binary_path
                ], capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    entry_points = self._parse_entry_points_from_ilspy(result.stdout)

            return entry_points

        except Exception as e:
            self.logger.warning(f"Failed to find entry points: {e}")
            return []

    def _extract_business_logic(self, binary_path: str) -> Dict[str, Any]:
        """Extract business logic and application purpose"""
        try:
            business_logic = {
                'application_domain': 'Unknown',
                'data_flows': [],
                'file_operations': [],
                'report_generation': False,
                'network_operations': [],
                'database_operations': [],
                'security_features': []
            }

            # Analyze strings for business logic indicators
            strings = self._extract_strings(binary_path)
            business_logic.update(self._analyze_strings_for_business_logic(strings))

            # Analyze API calls for business logic
            api_calls = self._extract_api_calls(binary_path)
            business_logic.update(self._analyze_api_calls_for_business_logic(api_calls))

            return business_logic

        except Exception as e:
            self.logger.warning(f"Failed to extract business logic: {e}")
            return {}

    def _detect_packing(self, binary_path: str) -> bool:
        """Detect if binary is packed"""
        try:
            # Use Detect It Easy
            die_path = self._get_die_path()
            if die_path:
                result = subprocess.run([
                    die_path,
                    binary_path
                ], capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    return self._parse_die_output_for_packing(result.stdout)

            # Fallback: entropy analysis
            return self._analyze_entropy_for_packing(binary_path)

        except Exception as e:
            self.logger.warning(f"Failed to detect packing: {e}")
            return False

    def _analyze_obfuscation(self, binary_path: str) -> str:
        """Analyze obfuscation level"""
        try:
            # Analyze string obfuscation
            strings = self._extract_strings(binary_path)
            obfuscation_indicators = self._detect_obfuscation_indicators(strings)

            if obfuscation_indicators['high']:
                return "High"
            elif obfuscation_indicators['medium']:
                return "Medium"
            elif obfuscation_indicators['low']:
                return "Low"
            else:
                return "None"

        except Exception as e:
            self.logger.warning(f"Failed to analyze obfuscation: {e}")
            return "Unknown"

    def _extract_api_calls(self, binary_path: str) -> List[str]:
        """Extract API calls from binary"""
        try:
            api_calls = []

            # Use strings to find API calls
            strings = self._extract_strings(binary_path)
            api_calls = self._filter_api_calls_from_strings(strings)

            return api_calls

        except Exception as e:
            self.logger.warning(f"Failed to extract API calls: {e}")
            return []

    def _analyze_pe_sections(self, binary_path: str) -> Dict[str, Any]:
        """Analyze PE sections"""
        try:
            sections = {
                'text': {},
                'data': {},
                'resources': {},
                'imports': {},
                'exports': {}
            }

            # Basic PE section analysis
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Analyze .text section
            sections['text'] = self._analyze_text_section(data)

            # Analyze .data section
            sections['data'] = self._analyze_data_section(data)

            # Analyze .rsrc section
            sections['resources'] = self._analyze_resource_section(data)

            return sections

        except Exception as e:
            self.logger.warning(f"Failed to analyze PE sections: {e}")
            return {}

    def _calculate_analysis_confidence(
        self,
        framework_version: str,
        gui_framework: str,
        business_logic: Dict[str, Any]
    ) -> float:
        """Calculate analysis confidence score"""
        confidence = 0.0

        # Framework detection confidence
        if framework_version != "Unknown":
            confidence += 0.3

        # GUI framework confidence
        if gui_framework != "Unknown":
            confidence += 0.2

        # Business logic confidence
        if business_logic.get('application_domain') != 'Unknown':
            confidence += 0.2

        if business_logic.get('data_flows'):
            confidence += 0.1

        if business_logic.get('file_operations'):
            confidence += 0.1

        if business_logic.get('report_generation'):
            confidence += 0.1

        return min(confidence, 1.0)

    # Helper methods
    def _get_ilspy_path(self) -> Optional[str]:
        """Get ILSpy executable path"""
        # Check if ILSpy is installed
        from ..core.dependency_manager import DependencyManager
        dm = DependencyManager()
        return dm.get_tool_path("ilspy")

    def _get_resource_hacker_path(self) -> Optional[str]:
        """Get Resource Hacker executable path"""
        from ..core.dependency_manager import DependencyManager
        dm = DependencyManager()
        return dm.get_tool_path("resource_hacker")

    def _get_die_path(self) -> Optional[str]:
        """Get Detect It Easy executable path"""
        from ..core.dependency_manager import DependencyManager
        dm = DependencyManager()
        return dm.get_tool_path("detect_it_easy")

    def _extract_strings(self, binary_path: str) -> List[str]:
        """Extract strings from binary"""
        try:
            strings = []
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Simple string extraction
            current_string = ""
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:
                        strings.append(current_string)
                    current_string = ""

            return strings
        except Exception:
            return []

    def _has_winforms_references(self, binary_path: str) -> bool:
        """Check for Windows Forms references"""
        strings = self._extract_strings(binary_path)
        winforms_indicators = [
            "System.Windows.Forms",
            "Form",
            "Button",
            "TextBox",
            "MessageBox"
        ]
        return any(indicator in strings for indicator in winforms_indicators)

    def _has_wpf_references(self, binary_path: str) -> bool:
        """Check for WPF references"""
        strings = self._extract_strings(binary_path)
        wpf_indicators = [
            "System.Windows",
            "XAML",
            "WPF",
            "PresentationFramework"
        ]
        return any(indicator in strings for indicator in wpf_indicators)

    def _has_uwp_references(self, binary_path: str) -> bool:
        """Check for UWP references"""
        strings = self._extract_strings(binary_path)
        uwp_indicators = [
            "Windows.UI",
            "Windows.ApplicationModel",
            "UWP"
        ]
        return any(indicator in strings for indicator in uwp_indicators)

    def _has_web_references(self, binary_path: str) -> bool:
        """Check for Web application references"""
        strings = self._extract_strings(binary_path)
        web_indicators = [
            "System.Web",
            "ASP.NET",
            "HttpContext",
            "WebRequest"
        ]
        return any(indicator in strings for indicator in web_indicators)

    def _has_service_references(self, binary_path: str) -> bool:
        """Check for Windows Service references"""
        strings = self._extract_strings(binary_path)
        service_indicators = [
            "System.ServiceProcess",
            "ServiceBase",
            "Windows Service"
        ]
        return any(indicator in strings for indicator in service_indicators)

    def _is_console_application(self, binary_path: str) -> bool:
        """Check if application is console application"""
        strings = self._extract_strings(binary_path)
        console_indicators = [
            "Console.WriteLine",
            "Console.Read",
            "System.Console"
        ]
        return any(indicator in strings for indicator in console_indicators)

    def _analyze_strings_for_business_logic(self, strings: List[str]) -> Dict[str, Any]:
        """Analyze strings for business logic indicators"""
        business_logic = {}

        # Check for application domain indicators
        domain_indicators = {
            'security': ['vulnerability', 'security', 'scan', 'audit'],
            'reporting': ['report', 'export', 'generate', 'template'],
            'database': ['database', 'sql', 'query', 'connection'],
            'web': ['http', 'url', 'web', 'api'],
            'malware': ['inject', 'hook', 'persist', 'steal']
        }

        for domain, indicators in domain_indicators.items():
            if any(indicator in ' '.join(strings).lower() for indicator in indicators):
                business_logic['application_domain'] = domain
                break

        # Check for file operations
        file_indicators = ['.xml', '.xlsx', '.pdf', '.csv', '.json']
        business_logic['file_operations'] = [
            indicator for indicator in file_indicators
            if any(indicator in string.lower() for string in strings)
        ]

        # Check for report generation
        report_indicators = ['excel', 'pdf', 'html', 'report', 'template']
        business_logic['report_generation'] = any(
            indicator in ' '.join(strings).lower() for indicator in report_indicators
        )

        return business_logic

    def _analyze_api_calls_for_business_logic(self, api_calls: List[str]) -> Dict[str, Any]:
        """Analyze API calls for business logic"""
        business_logic = {}

        # Categorize API calls
        api_categories = {
            'file_io': ['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile'],
            'network': ['socket', 'connect', 'send', 'recv'],
            'registry': ['RegOpenKey', 'RegSetValue', 'RegQueryValue'],
            'process': ['CreateProcess', 'TerminateProcess', 'OpenProcess'],
            'crypto': ['CryptEncrypt', 'CryptDecrypt', 'CryptHash']
        }

        for category, apis in api_categories.items():
            business_logic[f'{category}_apis'] = [
                api for api in api_calls if api in apis
            ]

        return business_logic

    def _filter_api_calls_from_strings(self, strings: List[str]) -> List[str]:
        """Filter API calls from strings"""
        api_calls = []
        common_apis = [
            'CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile',
            'CreateProcess', 'TerminateProcess', 'OpenProcess',
            'RegOpenKey', 'RegSetValue', 'RegQueryValue',
            'socket', 'connect', 'send', 'recv',
            'CryptEncrypt', 'CryptDecrypt', 'CryptHash'
        ]

        for string in strings:
            if string in common_apis:
                api_calls.append(string)

        return api_calls

    def _detect_obfuscation_indicators(self, strings: List[str]) -> Dict[str, bool]:
        """Detect obfuscation indicators"""
        indicators = {
            'high': False,
            'medium': False,
            'low': False
        }

        # High obfuscation indicators
        high_indicators = ['obfuscated', 'encrypted', 'packed']
        if any(indicator in ' '.join(strings).lower() for indicator in high_indicators):
            indicators['high'] = True

        # Medium obfuscation indicators
        medium_indicators = ['xor', 'base64', 'encoded']
        if any(indicator in ' '.join(strings).lower() for indicator in medium_indicators):
            indicators['medium'] = True

        # Low obfuscation indicators
        low_indicators = ['random', 'temp', 'tmp']
        if any(indicator in ' '.join(strings).lower() for indicator in low_indicators):
            indicators['low'] = True

        return indicators

    def _analyze_entropy_for_packing(self, binary_path: str) -> bool:
        """Analyze entropy to detect packing"""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Calculate Shannon entropy
            entropy = self._calculate_shannon_entropy(data)

            # High entropy indicates packing
            return entropy > 7.5

        except Exception:
            return False

    def _calculate_shannon_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy"""
        if not data:
            return 0.0

        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1

        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)

        return entropy

    # Placeholder methods for detailed analysis
    def _parse_ilspy_output(self, output: str) -> AssemblyInfo:
        """Parse ILSpy output for assembly info"""
        # Simplified parsing - would need actual implementation
        return AssemblyInfo(
            name="Unknown",
            version="Unknown",
            culture="",
            public_key_token="",
            processor_architecture=""
        )

    def _extract_framework_version_from_metadata(self, data: bytes) -> Optional[str]:
        """Extract framework version from metadata"""
        # Simplified implementation
        return None

    def _check_file_properties(self, binary_path: str) -> Optional[str]:
        """Check file properties for version info"""
        # Simplified implementation
        return None

    def _extract_runtime_version_from_metadata(self, data: bytes) -> Optional[str]:
        """Extract runtime version from metadata"""
        # Simplified implementation
        return None

    def _parse_dependencies_from_ilspy(self, output: str) -> List[str]:
        """Parse dependencies from ILSpy output"""
        # Simplified implementation
        return []

    def _extract_resources_with_rh(self, binary_path: str, rh_path: str) -> Dict[str, Any]:
        """Extract resources using Resource Hacker"""
        # Simplified implementation
        return {}

    def _parse_entry_points_from_ilspy(self, output: str) -> List[str]:
        """Parse entry points from ILSpy output"""
        # Simplified implementation
        return []

    def _parse_die_output_for_packing(self, output: str) -> bool:
        """Parse DIE output for packing detection"""
        # Simplified implementation
        return False

    def _analyze_text_section(self, data: bytes) -> Dict[str, Any]:
        """Analyze .text section"""
        # Simplified implementation
        return {}

    def _analyze_data_section(self, data: bytes) -> Dict[str, Any]:
        """Analyze .data section"""
        # Simplified implementation
        return {}

    def _analyze_resource_section(self, data: bytes) -> Dict[str, Any]:
        """Analyze .rsrc section"""
        # Simplified implementation
        return {}
