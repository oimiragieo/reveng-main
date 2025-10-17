"""
REVENG PE Import Table Analyzer

Analyze PE import table for API usage, categorization, and behavioral analysis.
"""

import os
import sys
import struct
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import logging
import json

from ..core.errors import AnalysisFailureError, create_error_context
from ..core.logger import get_logger

class APICategory(Enum):
    """API categories"""
    FILE_IO = "file_io"
    NETWORK = "network"
    PROCESS = "process"
    REGISTRY = "registry"
    CRYPTO = "crypto"
    GUI = "gui"
    MEMORY = "memory"
    SYSTEM = "system"
    SECURITY = "security"
    UNKNOWN = "unknown"

class SuspiciousLevel(Enum):
    """Suspicious API levels"""
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class APIInfo:
    """API information"""
    name: str
    dll: str
    category: APICategory
    suspicious_level: SuspiciousLevel
    description: str
    usage_context: Optional[str] = None

@dataclass
class ImportAnalysis:
    """Import analysis result"""
    dlls: List[str]
    api_calls: List[APIInfo]
    suspicious_apis: List[APIInfo]
    api_categories: Dict[APICategory, List[APIInfo]]
    behavioral_indicators: Dict[str, List[str]]
    risk_score: float
    analysis_confidence: float

@dataclass
class BehavioralIndicator:
    """Behavioral indicator"""
    category: str
    apis: List[str]
    description: str
    risk_level: str

class ImportAnalyzer:
    """Analyze PE import table for API usage"""

    def __init__(self):
        self.logger = get_logger("import_analyzer")
        self.api_database = self._load_api_database()
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.behavioral_indicators = self._load_behavioral_indicators()

    def analyze_imports(self, binary_path: str) -> ImportAnalysis:
        """Analyze all imported APIs"""
        try:
            self.logger.info(f"Starting import analysis of {binary_path}")

            # Parse PE structure to get imports
            imports_data = self._parse_import_table(binary_path)

            # Extract DLLs and APIs
            dlls = self._extract_dlls(imports_data)
            api_calls = self._extract_api_calls(imports_data)

            # Categorize APIs
            categorized_apis = self._categorize_apis(api_calls)

            # Detect suspicious APIs
            suspicious_apis = self._detect_suspicious_apis(api_calls)

            # Analyze behavioral indicators
            behavioral_indicators = self._analyze_behavioral_indicators(api_calls)

            # Calculate risk score
            risk_score = self._calculate_risk_score(suspicious_apis, behavioral_indicators)

            # Calculate analysis confidence
            confidence = self._calculate_analysis_confidence(api_calls, categorized_apis)

            result = ImportAnalysis(
                dlls=dlls,
                api_calls=api_calls,
                suspicious_apis=suspicious_apis,
                api_categories=categorized_apis,
                behavioral_indicators=behavioral_indicators,
                risk_score=risk_score,
                analysis_confidence=confidence
            )

            self.logger.info(f"Completed import analysis with {confidence:.2f} confidence")
            return result

        except Exception as e:
            context = create_error_context(
                "import_analyzer",
                "analyze_imports",
                binary_path=binary_path
            )
            raise AnalysisFailureError(
                "import_analysis",
                binary_path,
                context=context,
                fallback_available=True,
                original_exception=e
            )

    def _parse_import_table(self, binary_path: str) -> Dict[str, Any]:
        """Parse PE import table"""
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Parse PE header
            pe_header = self._parse_pe_header(data)
            if not pe_header:
                return {}

            # Find import table
            import_table = self._find_import_table(data, pe_header)
            if not import_table:
                return {}

            # Parse import descriptors
            import_descriptors = self._parse_import_descriptors(data, import_table)

            return {
                'pe_header': pe_header,
                'import_table': import_table,
                'import_descriptors': import_descriptors
            }

        except Exception as e:
            self.logger.warning(f"Failed to parse import table: {e}")
            return {}

    def _extract_dlls(self, imports_data: Dict[str, Any]) -> List[str]:
        """Extract imported DLLs"""
        try:
            dlls = []

            if 'import_descriptors' in imports_data:
                for descriptor in imports_data['import_descriptors']:
                    if 'dll_name' in descriptor:
                        dlls.append(descriptor['dll_name'])

            return dlls

        except Exception as e:
            self.logger.warning(f"Failed to extract DLLs: {e}")
            return []

    def _extract_api_calls(self, imports_data: Dict[str, Any]) -> List[APIInfo]:
        """Extract API calls from import table"""
        try:
            api_calls = []

            if 'import_descriptors' in imports_data:
                for descriptor in imports_data['import_descriptors']:
                    dll_name = descriptor.get('dll_name', '')
                    functions = descriptor.get('functions', [])

                    for function in functions:
                        api_info = self._create_api_info(function, dll_name)
                        if api_info:
                            api_calls.append(api_info)

            return api_calls

        except Exception as e:
            self.logger.warning(f"Failed to extract API calls: {e}")
            return []

    def _categorize_apis(self, api_calls: List[APIInfo]) -> Dict[APICategory, List[APIInfo]]:
        """Categorize APIs by functionality"""
        try:
            categorized = {category: [] for category in APICategory}

            for api in api_calls:
                category = self._determine_api_category(api)
                categorized[category].append(api)

            return categorized

        except Exception as e:
            self.logger.warning(f"Failed to categorize APIs: {e}")
            return {category: [] for category in APICategory}

    def _detect_suspicious_apis(self, api_calls: List[APIInfo]) -> List[APIInfo]:
        """Detect potentially suspicious APIs"""
        try:
            suspicious_apis = []

            for api in api_calls:
                suspicious_level = self._assess_api_suspiciousness(api)
                if suspicious_level != SuspiciousLevel.SAFE:
                    api.suspicious_level = suspicious_level
                    suspicious_apis.append(api)

            return suspicious_apis

        except Exception as e:
            self.logger.warning(f"Failed to detect suspicious APIs: {e}")
            return []

    def _analyze_behavioral_indicators(self, api_calls: List[APIInfo]) -> Dict[str, List[str]]:
        """Analyze behavioral indicators from API calls"""
        try:
            indicators = {}

            for indicator in self.behavioral_indicators:
                matching_apis = []
                for api in api_calls:
                    if api.name in indicator.apis:
                        matching_apis.append(api.name)

                if matching_apis:
                    indicators[indicator.category] = matching_apis

            return indicators

        except Exception as e:
            self.logger.warning(f"Failed to analyze behavioral indicators: {e}")
            return {}

    def _calculate_risk_score(self, suspicious_apis: List[APIInfo], behavioral_indicators: Dict[str, List[str]]) -> float:
        """Calculate risk score based on suspicious APIs and behavioral indicators"""
        try:
            risk_score = 0.0

            # Risk from suspicious APIs
            for api in suspicious_apis:
                if api.suspicious_level == SuspiciousLevel.CRITICAL:
                    risk_score += 1.0
                elif api.suspicious_level == SuspiciousLevel.HIGH:
                    risk_score += 0.8
                elif api.suspicious_level == SuspiciousLevel.MEDIUM:
                    risk_score += 0.5
                elif api.suspicious_level == SuspiciousLevel.LOW:
                    risk_score += 0.2

            # Risk from behavioral indicators
            for category, apis in behavioral_indicators.items():
                if category in ['malware', 'persistence', 'stealth']:
                    risk_score += 0.3 * len(apis)
                elif category in ['network', 'file_operations']:
                    risk_score += 0.1 * len(apis)

            return min(risk_score, 1.0)

        except Exception as e:
            self.logger.warning(f"Failed to calculate risk score: {e}")
            return 0.0

    def _calculate_analysis_confidence(self, api_calls: List[APIInfo], categorized_apis: Dict[APICategory, List[APIInfo]]) -> float:
        """Calculate analysis confidence"""
        try:
            confidence = 0.0

            # Base confidence from number of APIs analyzed
            if len(api_calls) > 0:
                confidence += 0.3

            # Confidence from categorization success
            categorized_count = sum(len(apis) for apis in categorized_apis.values())
            if categorized_count > 0:
                confidence += 0.3

            # Confidence from known APIs
            known_apis = sum(1 for api in api_calls if api.category != APICategory.UNKNOWN)
            if len(api_calls) > 0:
                confidence += 0.4 * (known_apis / len(api_calls))

            return min(confidence, 1.0)

        except Exception as e:
            self.logger.warning(f"Failed to calculate analysis confidence: {e}")
            return 0.0

    def _create_api_info(self, function: str, dll_name: str) -> Optional[APIInfo]:
        """Create API info from function name and DLL"""
        try:
            # Look up API in database
            api_key = f"{dll_name}.{function}"
            if api_key in self.api_database:
                api_data = self.api_database[api_key]
                return APIInfo(
                    name=function,
                    dll=dll_name,
                    category=APICategory(api_data.get('category', 'unknown')),
                    suspicious_level=SuspiciousLevel(api_data.get('suspicious_level', 'safe')),
                    description=api_data.get('description', ''),
                    usage_context=api_data.get('usage_context')
                )
            else:
                # Unknown API
                return APIInfo(
                    name=function,
                    dll=dll_name,
                    category=APICategory.UNKNOWN,
                    suspicious_level=SuspiciousLevel.SAFE,
                    description="Unknown API",
                    usage_context=None
                )

        except Exception as e:
            self.logger.warning(f"Failed to create API info for {function}: {e}")
            return None

    def _determine_api_category(self, api: APIInfo) -> APICategory:
        """Determine API category"""
        try:
            # Use database category if available
            if api.category != APICategory.UNKNOWN:
                return api.category

            # Fallback: determine by name patterns
            api_name = api.name.lower()
            dll_name = api.dll.lower()

            # File I/O APIs
            if any(pattern in api_name for pattern in ['createfile', 'readfile', 'writefile', 'deletefile']):
                return APICategory.FILE_IO

            # Network APIs
            if any(pattern in api_name for pattern in ['socket', 'connect', 'send', 'recv', 'bind', 'listen']):
                return APICategory.NETWORK

            # Process APIs
            if any(pattern in api_name for pattern in ['createprocess', 'terminateprocess', 'openprocess']):
                return APICategory.PROCESS

            # Registry APIs
            if any(pattern in api_name for pattern in ['regopenkey', 'regsetvalue', 'regqueryvalue']):
                return APICategory.REGISTRY

            # Crypto APIs
            if any(pattern in api_name for pattern in ['crypt', 'encrypt', 'decrypt', 'hash']):
                return APICategory.CRYPTO

            # GUI APIs
            if any(pattern in api_name for pattern in ['createwindow', 'showwindow', 'messagebox']):
                return APICategory.GUI

            # Memory APIs
            if any(pattern in api_name for pattern in ['virtualalloc', 'virtualfree', 'heapalloc']):
                return APICategory.MEMORY

            # System APIs
            if any(pattern in api_name for pattern in ['getsysteminfo', 'getversion', 'getcomputername']):
                return APICategory.SYSTEM

            return APICategory.UNKNOWN

        except Exception as e:
            self.logger.warning(f"Failed to determine API category: {e}")
            return APICategory.UNKNOWN

    def _assess_api_suspiciousness(self, api: APIInfo) -> SuspiciousLevel:
        """Assess API suspiciousness level"""
        try:
            # Use database suspicious level if available
            if api.suspicious_level != SuspiciousLevel.SAFE:
                return api.suspicious_level

            # Fallback: assess by name patterns
            api_name = api.name.lower()

            # Critical suspicious APIs
            critical_patterns = ['inject', 'hook', 'steal', 'persist', 'hide']
            if any(pattern in api_name for pattern in critical_patterns):
                return SuspiciousLevel.CRITICAL

            # High suspicious APIs
            high_patterns = ['bypass', 'elevate', 'privilege', 'token']
            if any(pattern in api_name for pattern in high_patterns):
                return SuspiciousLevel.HIGH

            # Medium suspicious APIs
            medium_patterns = ['monitor', 'keylog', 'screenshot', 'capture']
            if any(pattern in api_name for pattern in medium_patterns):
                return SuspiciousLevel.MEDIUM

            # Low suspicious APIs
            low_patterns = ['network', 'socket', 'connect', 'send']
            if any(pattern in api_name for pattern in low_patterns):
                return SuspiciousLevel.LOW

            return SuspiciousLevel.SAFE

        except Exception as e:
            self.logger.warning(f"Failed to assess API suspiciousness: {e}")
            return SuspiciousLevel.SAFE

    # PE structure parsing methods
    def _parse_pe_header(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Parse PE header"""
        try:
            # Check DOS header
            if data[:2] != b'MZ':
                return None

            # Get PE header offset
            pe_offset = struct.unpack('<L', data[60:64])[0]

            # Check PE signature
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return None

            # Parse COFF header
            coff_header = struct.unpack('<HHHHHH', data[pe_offset+4:pe_offset+16])

            # Parse optional header
            optional_header_size = coff_header[5]
            optional_header = data[pe_offset+16:pe_offset+16+optional_header_size]

            return {
                'pe_offset': pe_offset,
                'coff_header': coff_header,
                'optional_header': optional_header
            }

        except Exception as e:
            self.logger.warning(f"Failed to parse PE header: {e}")
            return None

    def _find_import_table(self, data: bytes, pe_header: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Find import table in PE structure"""
        try:
            # This is a simplified implementation
            # In practice, you would need to parse the data directory entries

            return {
                'rva': 0,
                'size': 0
            }

        except Exception as e:
            self.logger.warning(f"Failed to find import table: {e}")
            return None

    def _parse_import_descriptors(self, data: bytes, import_table: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse import descriptors"""
        try:
            # This is a simplified implementation
            # In practice, you would need to parse the import descriptor array

            return []

        except Exception as e:
            self.logger.warning(f"Failed to parse import descriptors: {e}")
            return []

    # Database and pattern loading methods
    def _load_api_database(self) -> Dict[str, Dict[str, Any]]:
        """Load API database"""
        try:
            # This would load from a JSON file or database
            # For now, return a simplified database
            return {
                'kernel32.dll.CreateFile': {
                    'category': 'file_io',
                    'suspicious_level': 'safe',
                    'description': 'Create or open a file',
                    'usage_context': 'File operations'
                },
                'kernel32.dll.ReadFile': {
                    'category': 'file_io',
                    'suspicious_level': 'safe',
                    'description': 'Read data from a file',
                    'usage_context': 'File operations'
                },
                'kernel32.dll.WriteFile': {
                    'category': 'file_io',
                    'suspicious_level': 'safe',
                    'description': 'Write data to a file',
                    'usage_context': 'File operations'
                },
                'ws2_32.dll.socket': {
                    'category': 'network',
                    'suspicious_level': 'low',
                    'description': 'Create a socket',
                    'usage_context': 'Network operations'
                },
                'ws2_32.dll.connect': {
                    'category': 'network',
                    'suspicious_level': 'low',
                    'description': 'Connect to a remote host',
                    'usage_context': 'Network operations'
                },
                'advapi32.dll.RegOpenKey': {
                    'category': 'registry',
                    'suspicious_level': 'medium',
                    'description': 'Open a registry key',
                    'usage_context': 'Registry operations'
                },
                'advapi32.dll.RegSetValue': {
                    'category': 'registry',
                    'suspicious_level': 'medium',
                    'description': 'Set a registry value',
                    'usage_context': 'Registry operations'
                },
                'kernel32.dll.CreateProcess': {
                    'category': 'process',
                    'suspicious_level': 'high',
                    'description': 'Create a new process',
                    'usage_context': 'Process creation'
                },
                'kernel32.dll.TerminateProcess': {
                    'category': 'process',
                    'suspicious_level': 'high',
                    'description': 'Terminate a process',
                    'usage_context': 'Process termination'
                },
                'user32.dll.CreateWindow': {
                    'category': 'gui',
                    'suspicious_level': 'safe',
                    'description': 'Create a window',
                    'usage_context': 'GUI operations'
                },
                'user32.dll.MessageBox': {
                    'category': 'gui',
                    'suspicious_level': 'safe',
                    'description': 'Display a message box',
                    'usage_context': 'GUI operations'
                }
            }

        except Exception as e:
            self.logger.warning(f"Failed to load API database: {e}")
            return {}

    def _load_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Load suspicious API patterns"""
        try:
            return {
                'malware': [
                    'inject', 'hook', 'steal', 'persist', 'hide',
                    'bypass', 'elevate', 'privilege', 'token'
                ],
                'network': [
                    'socket', 'connect', 'send', 'recv', 'bind', 'listen'
                ],
                'file_operations': [
                    'createfile', 'readfile', 'writefile', 'deletefile'
                ],
                'registry': [
                    'regopenkey', 'regsetvalue', 'regqueryvalue'
                ],
                'process': [
                    'createprocess', 'terminateprocess', 'openprocess'
                ]
            }

        except Exception as e:
            self.logger.warning(f"Failed to load suspicious patterns: {e}")
            return {}

    def _load_behavioral_indicators(self) -> List[BehavioralIndicator]:
        """Load behavioral indicators"""
        try:
            return [
                BehavioralIndicator(
                    category='file_operations',
                    apis=['CreateFile', 'ReadFile', 'WriteFile', 'DeleteFile'],
                    description='File I/O operations',
                    risk_level='low'
                ),
                BehavioralIndicator(
                    category='network_operations',
                    apis=['socket', 'connect', 'send', 'recv'],
                    description='Network operations',
                    risk_level='medium'
                ),
                BehavioralIndicator(
                    category='registry_operations',
                    apis=['RegOpenKey', 'RegSetValue', 'RegQueryValue'],
                    description='Registry operations',
                    risk_level='medium'
                ),
                BehavioralIndicator(
                    category='process_operations',
                    apis=['CreateProcess', 'TerminateProcess', 'OpenProcess'],
                    description='Process operations',
                    risk_level='high'
                ),
                BehavioralIndicator(
                    category='gui_operations',
                    apis=['CreateWindow', 'ShowWindow', 'MessageBox'],
                    description='GUI operations',
                    risk_level='low'
                )
            ]

        except Exception as e:
            self.logger.warning(f"Failed to load behavioral indicators: {e}")
            return []
