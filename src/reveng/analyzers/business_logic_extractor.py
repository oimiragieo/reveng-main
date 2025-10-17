"""
REVENG Business Logic Extractor

Extract high-level business logic from binaries including application domain,
data flows, file operations, and behavioral patterns.
"""

import os
import sys
import re
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass
from enum import Enum
import logging
import json

from ..core.errors import AnalysisFailureError, create_error_context
from ..core.logger import get_logger

class ApplicationDomain(Enum):
    """Application domain categories"""
    SECURITY = "security"
    REPORTING = "reporting"
    DATABASE = "database"
    WEB_SERVICE = "web_service"
    MALWARE = "malware"
    UTILITY = "utility"
    GAME = "game"
    MEDIA = "media"
    UNKNOWN = "unknown"

class DataFlowType(Enum):
    """Data flow types"""
    INPUT = "input"
    PROCESSING = "processing"
    OUTPUT = "output"
    STORAGE = "storage"
    NETWORK = "network"

@dataclass
class DataFlow:
    """Data flow information"""
    source: str
    destination: str
    flow_type: DataFlowType
    data_format: str
    description: str
    confidence: float

@dataclass
class FileOperation:
    """File operation information"""
    operation_type: str  # read, write, create, delete
    file_extension: str
    file_path_pattern: str
    description: str
    frequency: int

@dataclass
class ReportInfo:
    """Report generation information"""
    report_type: str
    output_format: str
    template_indicators: List[str]
    data_sources: List[str]
    confidence: float

@dataclass
class BusinessLogicAnalysis:
    """Business logic analysis result"""
    application_domain: str
    data_flows: List[DataFlow]
    file_operations: List[FileOperation]
    report_generation: Optional[ReportInfo]
    network_operations: List[str]
    database_operations: List[str]
    security_features: List[str]
    behavioral_patterns: Dict[str, List[str]]
    confidence_score: float

class BusinessLogicExtractor:
    """Extract high-level business logic from binaries"""

    def __init__(self):
        self.logger = get_logger("business_logic_extractor")
        self.domain_indicators = self._load_domain_indicators()
        self.data_flow_patterns = self._load_data_flow_patterns()
        self.file_operation_patterns = self._load_file_operation_patterns()
        self.report_indicators = self._load_report_indicators()

    def analyze_application_domain(self, binary_path: str) -> BusinessLogicAnalysis:
        """Classify application domain and extract business logic"""
        try:
            self.logger.info(f"Starting business logic analysis of {binary_path}")

            # Extract strings for analysis
            strings = self._extract_strings(binary_path)

            # Classify application domain
            domain = self._classify_application_domain(strings)

            # Extract data flows
            data_flows = self._extract_data_flows(strings)

            # Extract file operations
            file_operations = self._extract_file_operations(strings)

            # Detect report generation
            report_generation = self._detect_report_generation(strings)

            # Extract network operations
            network_operations = self._extract_network_operations(strings)

            # Extract database operations
            database_operations = self._extract_database_operations(strings)

            # Extract security features
            security_features = self._extract_security_features(strings)

            # Analyze behavioral patterns
            behavioral_patterns = self._analyze_behavioral_patterns(strings)

            # Calculate confidence score
            confidence_score = self._calculate_confidence_score(
                domain, data_flows, file_operations, report_generation
            )

            result = BusinessLogicAnalysis(
                application_domain=domain,
                data_flows=data_flows,
                file_operations=file_operations,
                report_generation=report_generation,
                network_operations=network_operations,
                database_operations=database_operations,
                security_features=security_features,
                behavioral_patterns=behavioral_patterns,
                confidence_score=confidence_score
            )

            self.logger.info(f"Completed business logic analysis with {confidence_score:.2f} confidence")
            return result

        except Exception as e:
            context = create_error_context(
                "business_logic_extractor",
                "analyze_application_domain",
                binary_path=binary_path
            )
            raise AnalysisFailureError(
                "business_logic_analysis",
                binary_path,
                context=context,
                fallback_available=True,
                original_exception=e
            )

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

        except Exception as e:
            self.logger.warning(f"Failed to extract strings: {e}")
            return []

    def _classify_application_domain(self, strings: List[str]) -> str:
        """Classify application domain based on strings"""
        try:
            domain_scores = {}
            text = ' '.join(strings).lower()

            for domain, indicators in self.domain_indicators.items():
                score = 0
                for indicator in indicators:
                    if indicator in text:
                        score += 1
                domain_scores[domain] = score

            # Find domain with highest score
            if domain_scores:
                best_domain = max(domain_scores, key=domain_scores.get)
                if domain_scores[best_domain] > 0:
                    return best_domain

            return ApplicationDomain.UNKNOWN.value

        except Exception as e:
            self.logger.warning(f"Failed to classify application domain: {e}")
            return ApplicationDomain.UNKNOWN.value

    def _extract_data_flows(self, strings: List[str]) -> List[DataFlow]:
        """Extract data flows from strings"""
        try:
            data_flows = []
            text = ' '.join(strings).lower()

            for pattern in self.data_flow_patterns:
                matches = re.findall(pattern['regex'], text)
                for match in matches:
                    data_flow = DataFlow(
                        source=pattern['source'],
                        destination=pattern['destination'],
                        flow_type=DataFlowType(pattern['flow_type']),
                        data_format=pattern['data_format'],
                        description=pattern['description'],
                        confidence=pattern['confidence']
                    )
                    data_flows.append(data_flow)

            return data_flows

        except Exception as e:
            self.logger.warning(f"Failed to extract data flows: {e}")
            return []

    def _extract_file_operations(self, strings: List[str]) -> List[FileOperation]:
        """Extract file operations from strings"""
        try:
            file_operations = []
            text = ' '.join(strings).lower()

            for pattern in self.file_operation_patterns:
                matches = re.findall(pattern['regex'], text)
                for match in matches:
                    file_op = FileOperation(
                        operation_type=pattern['operation_type'],
                        file_extension=pattern['file_extension'],
                        file_path_pattern=pattern['file_path_pattern'],
                        description=pattern['description'],
                        frequency=len(matches)
                    )
                    file_operations.append(file_op)

            return file_operations

        except Exception as e:
            self.logger.warning(f"Failed to extract file operations: {e}")
            return []

    def _detect_report_generation(self, strings: List[str]) -> Optional[ReportInfo]:
        """Detect report generation capabilities"""
        try:
            text = ' '.join(strings).lower()

            for indicator in self.report_indicators:
                if indicator['pattern'] in text:
                    return ReportInfo(
                        report_type=indicator['report_type'],
                        output_format=indicator['output_format'],
                        template_indicators=indicator['template_indicators'],
                        data_sources=indicator['data_sources'],
                        confidence=indicator['confidence']
                    )

            return None

        except Exception as e:
            self.logger.warning(f"Failed to detect report generation: {e}")
            return None

    def _extract_network_operations(self, strings: List[str]) -> List[str]:
        """Extract network operations from strings"""
        try:
            network_operations = []
            text = ' '.join(strings).lower()

            network_patterns = [
                r'https?://[^\s]+',
                r'ftp://[^\s]+',
                r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
                r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
            ]

            for pattern in network_patterns:
                matches = re.findall(pattern, text)
                network_operations.extend(matches)

            return list(set(network_operations))  # Remove duplicates

        except Exception as e:
            self.logger.warning(f"Failed to extract network operations: {e}")
            return []

    def _extract_database_operations(self, strings: List[str]) -> List[str]:
        """Extract database operations from strings"""
        try:
            database_operations = []
            text = ' '.join(strings).lower()

            database_patterns = [
                r'sql',
                r'select',
                r'insert',
                r'update',
                r'delete',
                r'from',
                r'where',
                r'join',
                r'database',
                r'table',
                r'query'
            ]

            for pattern in database_patterns:
                if re.search(pattern, text):
                    database_operations.append(pattern)

            return database_operations

        except Exception as e:
            self.logger.warning(f"Failed to extract database operations: {e}")
            return []

    def _extract_security_features(self, strings: List[str]) -> List[str]:
        """Extract security features from strings"""
        try:
            security_features = []
            text = ' '.join(strings).lower()

            security_patterns = [
                'encrypt', 'decrypt', 'hash', 'signature', 'certificate',
                'ssl', 'tls', 'authentication', 'authorization', 'permission',
                'access control', 'firewall', 'antivirus', 'malware', 'virus'
            ]

            for pattern in security_patterns:
                if pattern in text:
                    security_features.append(pattern)

            return security_features

        except Exception as e:
            self.logger.warning(f"Failed to extract security features: {e}")
            return []

    def _analyze_behavioral_patterns(self, strings: List[str]) -> Dict[str, List[str]]:
        """Analyze behavioral patterns from strings"""
        try:
            behavioral_patterns = {
                'file_operations': [],
                'network_operations': [],
                'registry_operations': [],
                'process_operations': [],
                'gui_operations': []
            }

            text = ' '.join(strings).lower()

            # File operations
            file_patterns = ['createfile', 'readfile', 'writefile', 'deletefile', 'copyfile', 'movefile']
            for pattern in file_patterns:
                if pattern in text:
                    behavioral_patterns['file_operations'].append(pattern)

            # Network operations
            network_patterns = ['socket', 'connect', 'send', 'recv', 'bind', 'listen']
            for pattern in network_patterns:
                if pattern in text:
                    behavioral_patterns['network_operations'].append(pattern)

            # Registry operations
            registry_patterns = ['regopenkey', 'regsetvalue', 'regqueryvalue', 'regdeletevalue']
            for pattern in registry_patterns:
                if pattern in text:
                    behavioral_patterns['registry_operations'].append(pattern)

            # Process operations
            process_patterns = ['createprocess', 'terminateprocess', 'openprocess', 'getprocessid']
            for pattern in process_patterns:
                if pattern in text:
                    behavioral_patterns['process_operations'].append(pattern)

            # GUI operations
            gui_patterns = ['createwindow', 'showwindow', 'messagebox', 'getwindowtext']
            for pattern in gui_patterns:
                if pattern in text:
                    behavioral_patterns['gui_operations'].append(pattern)

            return behavioral_patterns

        except Exception as e:
            self.logger.warning(f"Failed to analyze behavioral patterns: {e}")
            return {}

    def _calculate_confidence_score(
        self,
        domain: str,
        data_flows: List[DataFlow],
        file_operations: List[FileOperation],
        report_generation: Optional[ReportInfo]
    ) -> float:
        """Calculate confidence score for business logic analysis"""
        try:
            confidence = 0.0

            # Domain classification confidence
            if domain != ApplicationDomain.UNKNOWN.value:
                confidence += 0.3

            # Data flows confidence
            if data_flows:
                confidence += 0.2

            # File operations confidence
            if file_operations:
                confidence += 0.2

            # Report generation confidence
            if report_generation:
                confidence += 0.2

            # Additional confidence from pattern matching
            confidence += 0.1

            return min(confidence, 1.0)

        except Exception as e:
            self.logger.warning(f"Failed to calculate confidence score: {e}")
            return 0.0

    # Pattern loading methods
    def _load_domain_indicators(self) -> Dict[str, List[str]]:
        """Load domain classification indicators"""
        try:
            return {
                ApplicationDomain.SECURITY.value: [
                    'vulnerability', 'security', 'scan', 'audit', 'penetration',
                    'malware', 'virus', 'trojan', 'backdoor', 'exploit',
                    'firewall', 'antivirus', 'intrusion', 'detection'
                ],
                ApplicationDomain.REPORTING.value: [
                    'report', 'export', 'generate', 'template', 'format',
                    'excel', 'pdf', 'html', 'csv', 'json', 'xml',
                    'dashboard', 'chart', 'graph', 'statistics'
                ],
                ApplicationDomain.DATABASE.value: [
                    'database', 'sql', 'query', 'table', 'record',
                    'select', 'insert', 'update', 'delete', 'join',
                    'mysql', 'postgresql', 'oracle', 'sqlite'
                ],
                ApplicationDomain.WEB_SERVICE.value: [
                    'http', 'https', 'api', 'rest', 'soap', 'web',
                    'server', 'client', 'request', 'response',
                    'json', 'xml', 'url', 'endpoint'
                ],
                ApplicationDomain.MALWARE.value: [
                    'inject', 'hook', 'steal', 'persist', 'hide',
                    'bypass', 'elevate', 'privilege', 'token',
                    'keylog', 'screenshot', 'capture', 'monitor'
                ],
                ApplicationDomain.UTILITY.value: [
                    'utility', 'tool', 'helper', 'assistant',
                    'converter', 'formatter', 'validator', 'checker'
                ],
                ApplicationDomain.GAME.value: [
                    'game', 'player', 'score', 'level', 'character',
                    'graphics', 'sound', 'music', 'animation'
                ],
                ApplicationDomain.MEDIA.value: [
                    'media', 'video', 'audio', 'image', 'picture',
                    'player', 'editor', 'converter', 'encoder'
                ]
            }

        except Exception as e:
            self.logger.warning(f"Failed to load domain indicators: {e}")
            return {}

    def _load_data_flow_patterns(self) -> List[Dict[str, Any]]:
        """Load data flow patterns"""
        try:
            return [
                {
                    'regex': r'\.nessus.*\.xlsx',
                    'source': 'Nessus XML',
                    'destination': 'Excel Report',
                    'flow_type': 'processing',
                    'data_format': 'XML to XLSX',
                    'description': 'Nessus vulnerability data to Excel report',
                    'confidence': 0.9
                },
                {
                    'regex': r'\.xml.*\.pdf',
                    'source': 'XML Data',
                    'destination': 'PDF Report',
                    'flow_type': 'processing',
                    'data_format': 'XML to PDF',
                    'description': 'XML data to PDF report',
                    'confidence': 0.8
                },
                {
                    'regex': r'\.csv.*\.json',
                    'source': 'CSV Data',
                    'destination': 'JSON Output',
                    'flow_type': 'processing',
                    'data_format': 'CSV to JSON',
                    'description': 'CSV data to JSON format',
                    'confidence': 0.7
                }
            ]

        except Exception as e:
            self.logger.warning(f"Failed to load data flow patterns: {e}")
            return []

    def _load_file_operation_patterns(self) -> List[Dict[str, Any]]:
        """Load file operation patterns"""
        try:
            return [
                {
                    'regex': r'\.nessus',
                    'operation_type': 'read',
                    'file_extension': '.nessus',
                    'file_path_pattern': '*.nessus',
                    'description': 'Read Nessus vulnerability files'
                },
                {
                    'regex': r'\.xlsx',
                    'operation_type': 'write',
                    'file_extension': '.xlsx',
                    'file_path_pattern': '*.xlsx',
                    'description': 'Write Excel report files'
                },
                {
                    'regex': r'\.pdf',
                    'operation_type': 'write',
                    'file_extension': '.pdf',
                    'file_path_pattern': '*.pdf',
                    'description': 'Write PDF report files'
                },
                {
                    'regex': r'\.csv',
                    'operation_type': 'write',
                    'file_extension': '.csv',
                    'file_path_pattern': '*.csv',
                    'description': 'Write CSV data files'
                },
                {
                    'regex': r'\.json',
                    'operation_type': 'write',
                    'file_extension': '.json',
                    'file_path_pattern': '*.json',
                    'description': 'Write JSON data files'
                }
            ]

        except Exception as e:
            self.logger.warning(f"Failed to load file operation patterns: {e}")
            return []

    def _load_report_indicators(self) -> List[Dict[str, Any]]:
        """Load report generation indicators"""
        try:
            return [
                {
                    'pattern': 'excel',
                    'report_type': 'Excel Report',
                    'output_format': 'XLSX',
                    'template_indicators': ['template', 'format', 'style'],
                    'data_sources': ['nessus', 'vulnerability', 'scan'],
                    'confidence': 0.9
                },
                {
                    'pattern': 'pdf',
                    'report_type': 'PDF Report',
                    'output_format': 'PDF',
                    'template_indicators': ['template', 'format', 'style'],
                    'data_sources': ['data', 'information', 'results'],
                    'confidence': 0.8
                },
                {
                    'pattern': 'html',
                    'report_type': 'HTML Report',
                    'output_format': 'HTML',
                    'template_indicators': ['template', 'format', 'style'],
                    'data_sources': ['data', 'information', 'results'],
                    'confidence': 0.7
                }
            ]

        except Exception as e:
            self.logger.warning(f"Failed to load report indicators: {e}")
            return []
