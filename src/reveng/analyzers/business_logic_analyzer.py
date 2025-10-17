"""
Business Logic Analyzer for REVENG

Extract high-level business logic from binaries including domain classification,
data flow analysis, and behavioral pattern recognition.
"""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

from ..core.errors import REVENGError, AnalysisFailureError, create_error_context
from ..core.logger import get_logger

logger = get_logger()

class ApplicationDomain(Enum):
    """Application domain classifications"""
    SECURITY_SCANNER = "security_scanner"
    REPORT_GENERATOR = "report_generator"
    DATABASE_APP = "database_app"
    WEB_SERVICE = "web_service"
    MALWARE = "malware"
    GENERAL_APP = "general_app"
    UNKNOWN = "unknown"

class DataFlowType(Enum):
    """Data flow types"""
    FILE_TO_FILE = "file_to_file"
    NETWORK_TO_FILE = "network_to_file"
    FILE_TO_NETWORK = "file_to_network"
    DATABASE_TO_FILE = "database_to_file"
    FILE_TO_DATABASE = "file_to_database"
    MEMORY_TO_FILE = "memory_to_file"
    FILE_TO_MEMORY = "file_to_memory"

@dataclass
class DataFlow:
    """Data flow information"""
    flow_type: DataFlowType
    input_source: str
    output_destination: str
    transformation: str
    confidence: float

@dataclass
class FileOperation:
    """File operation information"""
    operation_type: str
    file_pattern: str
    purpose: str
    frequency: int

@dataclass
class DomainAnalysis:
    """Domain analysis result"""
    domain: ApplicationDomain
    confidence: float
    indicators: List[str]
    patterns: List[str]

class BusinessLogicAnalyzer:
    """Extract high-level business logic from binaries"""

    def __init__(self):
        self.logger = get_logger()

        # Domain-specific patterns
        self.domain_patterns = {
            ApplicationDomain.SECURITY_SCANNER: [
                'vulnerability', 'scanner', 'security', 'penetration', 'audit',
                'nessus', 'openvas', 'qualys', 'rapid7', 'nmap', 'metasploit',
                'cve', 'exploit', 'payload', 'injection', 'xss', 'sql'
            ],
            ApplicationDomain.REPORT_GENERATOR: [
                'report', 'export', 'generate', 'template', 'output', 'format',
                'excel', 'pdf', 'html', 'csv', 'json', 'xml', 'dashboard',
                'summary', 'analysis', 'statistics', 'chart', 'graph'
            ],
            ApplicationDomain.DATABASE_APP: [
                'database', 'sql', 'oracle', 'mysql', 'postgresql', 'sqlite',
                'connection', 'query', 'table', 'record', 'insert', 'update',
                'delete', 'select', 'join', 'index', 'transaction'
            ],
            ApplicationDomain.WEB_SERVICE: [
                'http', 'web', 'service', 'api', 'rest', 'soap', 'endpoint',
                'controller', 'route', 'request', 'response', 'json', 'xml',
                'authentication', 'authorization', 'session', 'cookie'
            ],
            ApplicationDomain.MALWARE: [
                'keylogger', 'backdoor', 'trojan', 'virus', 'malware', 'rootkit',
                'botnet', 'cryptocurrency', 'mining', 'ransomware', 'spyware',
                'adware', 'worm', 'payload', 'injection', 'hook', 'inject'
            ]
        }

        # File operation patterns
        self.file_patterns = {
            'nessus_files': ['.nessus', 'nessus', 'vulnerability'],
            'excel_files': ['.xlsx', '.xls', 'excel', 'spreadsheet'],
            'pdf_files': ['.pdf', 'pdf', 'document'],
            'html_files': ['.html', '.htm', 'html', 'web'],
            'csv_files': ['.csv', 'csv', 'comma'],
            'xml_files': ['.xml', 'xml', 'markup'],
            'json_files': ['.json', 'json', 'javascript'],
            'config_files': ['.config', '.ini', '.cfg', 'configuration'],
            'log_files': ['.log', 'log', 'logging']
        }

        # Behavioral patterns
        self.behavioral_patterns = {
            'report_generation': [
                'template', 'format', 'export', 'generate', 'create',
                'excel', 'pdf', 'html', 'csv', 'output'
            ],
            'data_processing': [
                'parse', 'process', 'analyze', 'filter', 'transform',
                'convert', 'extract', 'validate', 'clean'
            ],
            'network_communication': [
                'http', 'tcp', 'udp', 'socket', 'connect', 'send', 'receive',
                'download', 'upload', 'fetch', 'request', 'response'
            ],
            'file_operations': [
                'read', 'write', 'create', 'delete', 'copy', 'move',
                'open', 'close', 'save', 'load', 'import', 'export'
            ],
            'security_operations': [
                'encrypt', 'decrypt', 'hash', 'sign', 'verify', 'authenticate',
                'authorize', 'validate', 'check', 'scan', 'audit'
            ]
        }

    def analyze_application_domain(self, binary_path: str) -> DomainAnalysis:
        """Classify application domain"""

        context = create_error_context(
            tool_name="business_logic_analyzer",
            binary_path=binary_path,
            analysis_stage="domain_classification"
        )

        try:
            self.logger.info(f"Analyzing application domain for {binary_path}")

            # Read binary content for pattern matching
            with open(binary_path, 'rb') as f:
                content = f.read()

            # Convert to string for pattern matching (handle encoding issues)
            try:
                text_content = content.decode('utf-8', errors='ignore')
            except:
                text_content = str(content)

            # Score each domain
            domain_scores = {}
            for domain, patterns in self.domain_patterns.items():
                score = self._calculate_domain_score(text_content, patterns)
                domain_scores[domain] = score

            # Find best match
            best_domain = max(domain_scores.items(), key=lambda x: x[1])

            # Get indicators and patterns
            indicators = self._extract_domain_indicators(text_content, best_domain[0])
            patterns = self._extract_domain_patterns(text_content, best_domain[0])

            result = DomainAnalysis(
                domain=best_domain[0],
                confidence=best_domain[1],
                indicators=indicators,
                patterns=patterns
            )

            self.logger.info(f"Classified as {best_domain[0].value} with confidence {best_domain[1]:.2f}")
            return result

        except Exception as e:
            self.logger.error(f"Failed to analyze application domain: {e}")
            return DomainAnalysis(
                domain=ApplicationDomain.UNKNOWN,
                confidence=0.0,
                indicators=[],
                patterns=[]
            )

    def _calculate_domain_score(self, content: str, patterns: List[str]) -> float:
        """Calculate domain score based on pattern matches"""

        matches = 0
        total_patterns = len(patterns)

        for pattern in patterns:
            if pattern.lower() in content.lower():
                matches += 1

        return matches / total_patterns if total_patterns > 0 else 0.0

    def _extract_domain_indicators(self, content: str, domain: ApplicationDomain) -> List[str]:
        """Extract specific indicators for the domain"""

        indicators = []
        patterns = self.domain_patterns.get(domain, [])

        for pattern in patterns:
            if pattern.lower() in content.lower():
                indicators.append(pattern)

        return indicators[:10]  # Limit to top 10 indicators

    def _extract_domain_patterns(self, content: str, domain: ApplicationDomain) -> List[str]:
        """Extract domain-specific patterns"""

        patterns = []

        if domain == ApplicationDomain.SECURITY_SCANNER:
            # Look for security-specific patterns
            security_patterns = ['cve-', 'exploit', 'payload', 'injection', 'xss', 'sql']
            for pattern in security_patterns:
                if pattern.lower() in content.lower():
                    patterns.append(pattern)

        elif domain == ApplicationDomain.REPORT_GENERATOR:
            # Look for report-specific patterns
            report_patterns = ['template', 'format', 'export', 'generate', 'output']
            for pattern in report_patterns:
                if pattern.lower() in content.lower():
                    patterns.append(pattern)

        elif domain == ApplicationDomain.DATABASE_APP:
            # Look for database-specific patterns
            db_patterns = ['select', 'insert', 'update', 'delete', 'join', 'table']
            for pattern in db_patterns:
                if pattern.lower() in content.lower():
                    patterns.append(pattern)

        return patterns[:5]  # Limit to top 5 patterns

    def extract_data_flows(self, binary_path: str) -> List[DataFlow]:
        """Map input → processing → output flows"""

        try:
            self.logger.info(f"Extracting data flows for {binary_path}")

            with open(binary_path, 'rb') as f:
                content = f.read()

            text_content = content.decode('utf-8', errors='ignore')

            data_flows = []

            # Detect file-to-file flows
            file_flows = self._detect_file_flows(text_content)
            data_flows.extend(file_flows)

            # Detect network flows
            network_flows = self._detect_network_flows(text_content)
            data_flows.extend(network_flows)

            # Detect database flows
            database_flows = self._detect_database_flows(text_content)
            data_flows.extend(database_flows)

            self.logger.info(f"Found {len(data_flows)} data flows")
            return data_flows

        except Exception as e:
            self.logger.error(f"Failed to extract data flows: {e}")
            return []

    def _detect_file_flows(self, content: str) -> List[DataFlow]:
        """Detect file-to-file data flows"""

        flows = []

        # Check for common file processing patterns
        if '.nessus' in content.lower() and '.xlsx' in content.lower():
            flows.append(DataFlow(
                flow_type=DataFlowType.FILE_TO_FILE,
                input_source='Nessus file',
                output_destination='Excel file',
                transformation='Vulnerability data processing',
                confidence=0.9
            ))

        if '.xml' in content.lower() and '.pdf' in content.lower():
            flows.append(DataFlow(
                flow_type=DataFlowType.FILE_TO_FILE,
                input_source='XML file',
                output_destination='PDF file',
                transformation='XML to PDF conversion',
                confidence=0.8
            ))

        if '.csv' in content.lower() and '.html' in content.lower():
            flows.append(DataFlow(
                flow_type=DataFlowType.FILE_TO_FILE,
                input_source='CSV file',
                output_destination='HTML file',
                transformation='CSV to HTML conversion',
                confidence=0.7
            ))

        return flows

    def _detect_network_flows(self, content: str) -> List[DataFlow]:
        """Detect network-related data flows"""

        flows = []

        # Check for network patterns
        if any(pattern in content.lower() for pattern in ['http', 'tcp', 'socket', 'connect']):
            if '.xml' in content.lower() or '.json' in content.lower():
                flows.append(DataFlow(
                    flow_type=DataFlowType.NETWORK_TO_FILE,
                    input_source='Network data',
                    output_destination='File',
                    transformation='Network data processing',
                    confidence=0.6
                ))

        return flows

    def _detect_database_flows(self, content: str) -> List[DataFlow]:
        """Detect database-related data flows"""

        flows = []

        # Check for database patterns
        if any(pattern in content.lower() for pattern in ['sql', 'database', 'query', 'select']):
            if '.xlsx' in content.lower() or '.csv' in content.lower():
                flows.append(DataFlow(
                    flow_type=DataFlowType.DATABASE_TO_FILE,
                    input_source='Database',
                    output_destination='File',
                    transformation='Database export',
                    confidence=0.7
                ))

        return flows

    def identify_file_operations(self, binary_path: str) -> List[FileOperation]:
        """Detect file I/O patterns"""

        try:
            self.logger.info(f"Identifying file operations for {binary_path}")

            with open(binary_path, 'rb') as f:
                content = f.read()

            text_content = content.decode('utf-8', errors='ignore')

            file_operations = []

            # Check for file patterns
            for pattern_name, patterns in self.file_patterns.items():
                matches = sum(1 for pattern in patterns if pattern.lower() in text_content.lower())
                if matches > 0:
                    file_operations.append(FileOperation(
                        operation_type=pattern_name,
                        file_pattern=patterns[0],
                        purpose=self._get_file_purpose(pattern_name),
                        frequency=matches
                    ))

            self.logger.info(f"Found {len(file_operations)} file operation patterns")
            return file_operations

        except Exception as e:
            self.logger.error(f"Failed to identify file operations: {e}")
            return []

    def _get_file_purpose(self, pattern_name: str) -> str:
        """Get purpose description for file pattern"""

        purposes = {
            'nessus_files': 'Vulnerability scan data',
            'excel_files': 'Spreadsheet data',
            'pdf_files': 'Document generation',
            'html_files': 'Web content',
            'csv_files': 'Tabular data',
            'xml_files': 'Structured data',
            'json_files': 'API data',
            'config_files': 'Configuration data',
            'log_files': 'Logging data'
        }

        return purposes.get(pattern_name, 'Unknown purpose')

    def detect_report_generation(self, binary_path: str) -> Dict[str, Any]:
        """Identify report generation capabilities"""

        try:
            self.logger.info(f"Detecting report generation for {binary_path}")

            with open(binary_path, 'rb') as f:
                content = f.read()

            text_content = content.decode('utf-8', errors='ignore')

            report_info = {
                'has_report_generation': False,
                'supported_formats': [],
                'libraries_used': [],
                'templates': [],
                'confidence': 0.0
            }

            # Check for report generation indicators
            report_indicators = [
                'report', 'export', 'generate', 'template', 'output',
                'excel', 'pdf', 'html', 'csv', 'json', 'xml'
            ]

            matches = sum(1 for indicator in report_indicators if indicator.lower() in text_content.lower())
            confidence = matches / len(report_indicators)

            if confidence > 0.3:
                report_info['has_report_generation'] = True
                report_info['confidence'] = confidence

                # Detect supported formats
                formats = []
                if 'excel' in text_content.lower() or '.xlsx' in text_content.lower():
                    formats.append('Excel')
                if 'pdf' in text_content.lower() or '.pdf' in text_content.lower():
                    formats.append('PDF')
                if 'html' in text_content.lower() or '.html' in text_content.lower():
                    formats.append('HTML')
                if 'csv' in text_content.lower() or '.csv' in text_content.lower():
                    formats.append('CSV')

                report_info['supported_formats'] = formats

                # Detect libraries
                libraries = []
                if 'openpyxl' in text_content.lower():
                    libraries.append('openpyxl')
                if 'xlsxwriter' in text_content.lower():
                    libraries.append('xlsxwriter')
                if 'pandas' in text_content.lower():
                    libraries.append('pandas')
                if 'jinja' in text_content.lower():
                    libraries.append('jinja2')

                report_info['libraries_used'] = libraries

            self.logger.info(f"Report generation detected: {report_info['has_report_generation']}")
            return report_info

        except Exception as e:
            self.logger.error(f"Failed to detect report generation: {e}")
            return {
                'has_report_generation': False,
                'supported_formats': [],
                'libraries_used': [],
                'templates': [],
                'confidence': 0.0
            }

    def detect_malicious_indicators(self, binary_path: str) -> List[str]:
        """Identify potential malware indicators"""

        try:
            self.logger.info(f"Detecting malicious indicators for {binary_path}")

            with open(binary_path, 'rb') as f:
                content = f.read()

            text_content = content.decode('utf-8', errors='ignore')

            malicious_indicators = []

            # Check for malicious patterns
            malicious_patterns = [
                'keylogger', 'backdoor', 'trojan', 'virus', 'malware',
                'rootkit', 'botnet', 'cryptocurrency', 'mining', 'ransomware',
                'spyware', 'adware', 'worm', 'payload', 'injection',
                'hook', 'inject', 'persistence', 'autorun', 'startup'
            ]

            for pattern in malicious_patterns:
                if pattern.lower() in text_content.lower():
                    malicious_indicators.append(pattern)

            self.logger.info(f"Found {len(malicious_indicators)} malicious indicators")
            return malicious_indicators

        except Exception as e:
            self.logger.error(f"Failed to detect malicious indicators: {e}")
            return []

    def map_api_to_behavior(self, apis: List[str]) -> Dict[str, Any]:
        """Map API calls to high-level behaviors"""

        behavior_map = {
            'file_operations': [],
            'network_operations': [],
            'process_operations': [],
            'registry_operations': [],
            'cryptographic_operations': [],
            'memory_operations': [],
            'gui_operations': [],
            'system_operations': []
        }

        # Map APIs to behaviors
        for api in apis:
            api_lower = api.lower()

            # File operations
            if any(pattern in api_lower for pattern in ['file', 'read', 'write', 'create', 'delete']):
                behavior_map['file_operations'].append(api)

            # Network operations
            if any(pattern in api_lower for pattern in ['socket', 'http', 'tcp', 'udp', 'connect', 'send', 'recv']):
                behavior_map['network_operations'].append(api)

            # Process operations
            if any(pattern in api_lower for pattern in ['process', 'thread', 'create', 'terminate']):
                behavior_map['process_operations'].append(api)

            # Registry operations
            if any(pattern in api_lower for pattern in ['reg', 'registry', 'key', 'value']):
                behavior_map['registry_operations'].append(api)

            # Cryptographic operations
            if any(pattern in api_lower for pattern in ['crypt', 'encrypt', 'decrypt', 'hash', 'sign']):
                behavior_map['cryptographic_operations'].append(api)

            # Memory operations
            if any(pattern in api_lower for pattern in ['virtual', 'heap', 'memory', 'alloc', 'free']):
                behavior_map['memory_operations'].append(api)

            # GUI operations
            if any(pattern in api_lower for pattern in ['window', 'gui', 'form', 'control', 'button']):
                behavior_map['gui_operations'].append(api)

            # System operations
            if any(pattern in api_lower for pattern in ['system', 'time', 'tick', 'version', 'info']):
                behavior_map['system_operations'].append(api)

        return behavior_map
