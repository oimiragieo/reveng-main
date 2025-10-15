#!/usr/bin/env python3
"""
Corporate Data Exposure Detection Engine

This module implements comprehensive detection of sensitive corporate data
that can be extracted from binaries, including credentials, API keys,
business logic, and network topology information.

Part of the AI-Enhanced Universal Binary Analysis Engine.
"""

import re
import json
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from enum import Enum


class ExposureType(Enum):
    """Types of corporate data exposure"""
    CREDENTIAL = "credential"
    DATABASE_CONNECTION = "database_connection"
    BUSINESS_LOGIC = "business_logic"
    API_ENDPOINT = "api_endpoint"
    NETWORK_TOPOLOGY = "network_topology"
    LICENSING = "licensing"
    COMPETITIVE_INTEL = "competitive_intel"


class SeverityLevel(Enum):
    """Severity levels for exposure findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ExposureEvidence:
    """Evidence supporting an exposure finding"""
    location: str
    context: str
    pattern_matched: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CorporateExposure:
    """Represents a detected corporate data exposure"""
    exposure_type: ExposureType
    severity: SeverityLevel
    title: str
    description: str
    value: str
    evidence: List[ExposureEvidence]
    confidence: float
    business_impact: str
    remediation: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class CredentialDetector:
    """Detects various types of credentials and secrets in code"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def scan_for_credentials(self, code: str, file_path: str = "") -> List[CorporateExposure]:
        """Scan code for embedded credentials and secrets"""
        exposures = []
        patterns = {
            'aws_access_key': (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', SeverityLevel.CRITICAL),
            'google_api_key': (r'AIza[0-9A-Za-z\\-_]{35}', 'Google API Key', SeverityLevel.HIGH),
            'github_token': (r'ghp_[A-Za-z0-9]{36}', 'GitHub Personal Access Token', SeverityLevel.HIGH),
            'jwt_token': (r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*', 'JWT Token', SeverityLevel.MEDIUM),
            'password_field': (r'["\']?[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]["\']?\s*[:=]\s*["\']([^"\']{8,})["\']', 'Password Field', SeverityLevel.HIGH)
        }
        
        lines = code.split('\n')
        for pattern_name, (pattern, description, severity) in patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                evidence = ExposureEvidence(
                    location=f"{file_path}:{line_num}",
                    context=line_content.strip(),
                    pattern_matched=pattern_name,
                    confidence=0.8,
                    metadata={'match_text': match.group()}
                )
                
                exposure = CorporateExposure(
                    exposure_type=ExposureType.CREDENTIAL,
                    severity=severity,
                    title=f"Hardcoded {description}",
                    description=f"Found hardcoded {description.lower()} in source code",
                    value=self._sanitize_value(match.group()),
                    evidence=[evidence],
                    confidence=0.8,
                    business_impact="Credential exposure enables unauthorized access",
                    remediation="Remove hardcoded credentials and use secure configuration",
                    metadata={'pattern_type': pattern_name}
                )
                exposures.append(exposure)
        
        return exposures
    
    def scan_database_connections(self, code: str, file_path: str = "") -> List[CorporateExposure]:
        """Scan for database connection strings"""
        exposures = []
        db_patterns = {
            'mysql_connection': (r'mysql://[^"\s]+', 'MySQL Connection String'),
            'mongodb_connection': (r'mongodb://[^"\s]+', 'MongoDB Connection String'),
            'jdbc_connection': (r'jdbc:[a-zA-Z0-9]+://[^"\s]+', 'JDBC Connection String')
        }
        
        lines = code.split('\n')
        for pattern_name, (pattern, description) in db_patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                evidence = ExposureEvidence(
                    location=f"{file_path}:{line_num}",
                    context=line_content.strip(),
                    pattern_matched=pattern_name,
                    confidence=0.9,
                    metadata={}
                )
                
                exposure = CorporateExposure(
                    exposure_type=ExposureType.DATABASE_CONNECTION,
                    severity=SeverityLevel.HIGH,
                    title=f"Hardcoded {description}",
                    description=f"Database connection string found",
                    value=self._sanitize_connection_string(match.group()),
                    evidence=[evidence],
                    confidence=0.9,
                    business_impact="Direct database access with potential for data breach",
                    remediation="Move connection strings to secure configuration",
                    metadata={'database_type': pattern_name}
                )
                exposures.append(exposure)
        
        return exposures
    
    def _sanitize_value(self, value: str) -> str:
        """Sanitize sensitive values for reporting"""
        if len(value) <= 8:
            return value[:2] + '*' * (len(value) - 4) + value[-2:]
        return value[:4] + '*' * (len(value) - 8) + value[-4:]
    
    def _sanitize_connection_string(self, conn_string: str) -> str:
        """Sanitize database connection strings"""
        sanitized = re.sub(r'(password|pwd)=[^;]+', r'\1=***', conn_string, flags=re.IGNORECASE)
        return re.sub(r'(user|uid)=[^;]+', r'\1=***', sanitized, flags=re.IGNORECASE)


class BusinessLogicAnalyzer:
    """Analyzes decompiled code for business logic and proprietary algorithms"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def extract_pricing_algorithms(self, code: str, file_path: str = "") -> List[CorporateExposure]:
        """Extract pricing algorithms and business rules from decompiled code"""
        exposures = []
        patterns = {
            'price_calculation': (r'(?:price|cost|amount|fee|charge)\s*[*+\-/=]\s*[\d.]+', 'Price Calculation Logic', SeverityLevel.HIGH),
            'discount_logic': (r'(?:discount|rebate|coupon|promo)\s*[*=]\s*[\d.]+', 'Discount/Pricing Algorithm', SeverityLevel.HIGH),
            'tax_calculation': (r'(?:tax|vat|gst)\s*[*=]\s*[\d.]+', 'Tax Calculation Logic', SeverityLevel.MEDIUM),
            'commission_logic': (r'(?:commission|fee|margin)\s*[*=]\s*[\d.]+', 'Commission/Fee Structure', SeverityLevel.HIGH)
        }
        
        lines = code.split('\n')
        for pattern_name, (pattern, description, severity) in patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                evidence = ExposureEvidence(
                    location=f"{file_path}:{line_num}",
                    context=line_content.strip(),
                    pattern_matched=pattern_name,
                    confidence=0.8,
                    metadata={}
                )
                
                exposure = CorporateExposure(
                    exposure_type=ExposureType.BUSINESS_LOGIC,
                    severity=severity,
                    title=f"Exposed {description}",
                    description=f"Found {description.lower()} that reveals business pricing strategy",
                    value=self._sanitize_business_value(match.group()),
                    evidence=[evidence],
                    confidence=0.8,
                    business_impact="Reveals proprietary pricing strategy and competitive positioning",
                    remediation="Obfuscate business logic and move sensitive calculations to server-side",
                    metadata={'algorithm_type': pattern_name}
                )
                exposures.append(exposure)
        
        return exposures
    
    def identify_licensing_mechanisms(self, code: str, file_path: str = "") -> List[CorporateExposure]:
        """Identify licensing validation mechanisms and potential bypasses"""
        exposures = []
        patterns = {
            'license_check': (r'(?:license|activation|serial|key).*(?:valid|check|verify)', 'License Validation Logic', SeverityLevel.HIGH),
            'expiration_check': (r'(?:expir|trial|demo).*(?:date|time|period)', 'License Expiration Logic', SeverityLevel.MEDIUM),
            'feature_flag': (r'(?:premium|pro|enterprise|paid).*(?:feature|function|capability)', 'Feature Licensing Logic', SeverityLevel.MEDIUM)
        }
        
        lines = code.split('\n')
        for pattern_name, (pattern, description, severity) in patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                evidence = ExposureEvidence(
                    location=f"{file_path}:{line_num}",
                    context=line_content.strip(),
                    pattern_matched=pattern_name,
                    confidence=0.9,
                    metadata={}
                )
                
                exposure = CorporateExposure(
                    exposure_type=ExposureType.LICENSING,
                    severity=severity,
                    title=f"Exposed {description}",
                    description=f"Found {description.lower()} that could enable license bypass",
                    value=self._sanitize_business_value(match.group()),
                    evidence=[evidence],
                    confidence=0.9,
                    business_impact="License validation can be bypassed, enabling software piracy",
                    remediation="Implement server-side license validation and code obfuscation",
                    metadata={'license_type': pattern_name}
                )
                exposures.append(exposure)
        
        return exposures
    
    def analyze_proprietary_algorithms(self, code: str, file_path: str = "") -> List[CorporateExposure]:
        """Analyze proprietary algorithms and competitive intelligence"""
        exposures = []
        patterns = {
            'encryption_algorithm': (r'(?:aes|des|rsa|sha|md5|hmac|pbkdf2).*(?:encrypt|decrypt|hash)', 'Cryptographic Algorithm Implementation', SeverityLevel.HIGH),
            'ml_algorithm': (r'(?:neural|network|regression|classification|clustering).*(?:train|predict|model)', 'Machine Learning Algorithm', SeverityLevel.HIGH),
            'sorting_algorithm': (r'(?:quicksort|mergesort|heapsort|bubblesort).*(?:sort|order)', 'Sorting Algorithm Implementation', SeverityLevel.LOW)
        }
        
        lines = code.split('\n')
        for pattern_name, (pattern, description, severity) in patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                evidence = ExposureEvidence(
                    location=f"{file_path}:{line_num}",
                    context=line_content.strip(),
                    pattern_matched=pattern_name,
                    confidence=0.7,
                    metadata={}
                )
                
                exposure = CorporateExposure(
                    exposure_type=ExposureType.COMPETITIVE_INTEL,
                    severity=severity,
                    title=f"Exposed {description}",
                    description=f"Found {description.lower()} revealing proprietary implementation",
                    value=self._sanitize_business_value(match.group()),
                    evidence=[evidence],
                    confidence=0.7,
                    business_impact="Reveals proprietary algorithms that provide competitive advantage",
                    remediation="Implement algorithm obfuscation and consider server-side processing",
                    metadata={'algorithm_type': pattern_name}
                )
                exposures.append(exposure)
        
        return exposures
    
    def _sanitize_business_value(self, value: str) -> str:
        """Sanitize business logic values for reporting"""
        sanitized = re.sub(r'\d+\.?\d*', '[VALUE]', value)
        return sanitized[:100] + '...' if len(sanitized) > 100 else sanitized


class NetworkTopologyAnalyzer:
    """Analyzes network communication code for API endpoints and topology"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def discover_api_endpoints(self, code: str, file_path: str = "") -> List[CorporateExposure]:
        """Discover API endpoints and network communication patterns"""
        exposures = []
        patterns = {
            'http_endpoint': (r'https?://[^\s\'"<>)]+', 'HTTP/HTTPS Endpoint', SeverityLevel.MEDIUM),
            'api_endpoint': (r'(?:api|rest|graphql|soap)/[^\s\'"<>)]*', 'API Endpoint Path', SeverityLevel.MEDIUM),
            'internal_ip': (r'(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}', 'Internal IP Address', SeverityLevel.MEDIUM),
            'localhost': (r'(?:localhost|127\.0\.0\.1|::1)(?::\d+)?', 'Localhost Reference', SeverityLevel.LOW),
            'internal_hostname': (r'[a-zA-Z0-9\-]+\.(?:internal|local|corp|lan)(?::\d+)?', 'Internal Hostname', SeverityLevel.MEDIUM)
        }
        
        lines = code.split('\n')
        for pattern_name, (pattern, description, severity) in patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                endpoint = match.group()
                confidence = 0.9 if self._is_internal_endpoint(endpoint) else 0.7
                
                evidence = ExposureEvidence(
                    location=f"{file_path}:{line_num}",
                    context=line_content.strip(),
                    pattern_matched=pattern_name,
                    confidence=confidence,
                    metadata={}
                )
                
                exposure = CorporateExposure(
                    exposure_type=ExposureType.API_ENDPOINT,
                    severity=severity,
                    title=f"Discovered {description}",
                    description=f"Found {description.lower()} in network communication code",
                    value=self._sanitize_endpoint(endpoint),
                    evidence=[evidence],
                    confidence=confidence,
                    business_impact="Reveals network architecture and potential attack vectors",
                    remediation="Remove hardcoded endpoints and use service discovery",
                    metadata={'endpoint_type': pattern_name}
                )
                exposures.append(exposure)
        
        return exposures
    
    def extract_authentication_mechanisms(self, code: str, file_path: str = "") -> List[CorporateExposure]:
        """Extract authentication mechanisms and security implementations"""
        exposures = []
        patterns = {
            'auth_header': (r'(?:Authorization|X-API-Key|X-Auth-Token|Bearer)["\']?\s*[:=]\s*["\']?([^"\'\\s)]+)["\']?', 'Authentication Header', SeverityLevel.HIGH),
            'bearer_token': (r'["\']Bearer\s+([A-Za-z0-9\-._~+/]+=*)["\']', 'Bearer Token', SeverityLevel.HIGH)
        }
        
        lines = code.split('\n')
        for pattern_name, (pattern, description, severity) in patterns.items():
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                line_content = lines[line_num - 1] if line_num <= len(lines) else ""
                
                auth_value = match.group(1) if match.groups() else match.group()
                
                evidence = ExposureEvidence(
                    location=f"{file_path}:{line_num}",
                    context=line_content.strip(),
                    pattern_matched=pattern_name,
                    confidence=0.8,
                    metadata={}
                )
                
                exposure = CorporateExposure(
                    exposure_type=ExposureType.API_ENDPOINT,
                    severity=severity,
                    title=f"Authentication Mechanism: {description}",
                    description=f"Found {description.lower()} in authentication code",
                    value=self._sanitize_auth_value(auth_value),
                    evidence=[evidence],
                    confidence=0.8,
                    business_impact="Hardcoded authentication credentials enable unauthorized system access",
                    remediation="Move authentication credentials to secure configuration",
                    metadata={'auth_type': pattern_name}
                )
                exposures.append(exposure)
        
        return exposures
    
    def identify_network_topology(self, code: str, file_path: str = "") -> List[CorporateExposure]:
        """Identify internal network topology and service dependencies"""
        exposures = []
        
        # Simple network topology analysis
        network_indicators = len(re.findall(r'(?:server|host|port|endpoint)', code, re.IGNORECASE))
        service_indicators = len(re.findall(r'(?:mysql|postgres|redis|api)', code, re.IGNORECASE))
        
        if network_indicators > 3 or service_indicators > 2:
            evidence = ExposureEvidence(
                location=file_path,
                context="Network topology analysis from entire file",
                pattern_matched="network_topology_analysis",
                confidence=0.8,
                metadata={'network_indicators': network_indicators, 'service_indicators': service_indicators}
            )
            
            exposure = CorporateExposure(
                exposure_type=ExposureType.NETWORK_TOPOLOGY,
                severity=SeverityLevel.MEDIUM,
                title="Network Topology Information",
                description="Discovered internal network topology and service architecture",
                value=f"{service_indicators} services, {network_indicators} network configs",
                evidence=[evidence],
                confidence=0.8,
                business_impact="Reveals internal network architecture and potential attack paths",
                remediation="Review network configuration exposure and implement network segmentation",
                metadata={'network_indicators': network_indicators, 'service_indicators': service_indicators}
            )
            exposures.append(exposure)
        
        return exposures
    
    def _is_internal_endpoint(self, endpoint: str) -> bool:
        """Check if endpoint is internal"""
        internal_patterns = [
            r'(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.)',
            r'localhost',
            r'127\.0\.0\.1',
            r'\.(?:internal|local|corp|lan)'
        ]
        return any(re.search(pattern, endpoint, re.IGNORECASE) for pattern in internal_patterns)
    
    def _sanitize_endpoint(self, endpoint: str) -> str:
        """Sanitize endpoint for reporting"""
        if '@' in endpoint:
            parts = endpoint.split('@')
            if len(parts) == 2:
                protocol_creds, domain_path = parts
                protocol = protocol_creds.split('://')[0] if '://' in protocol_creds else ''
                return f"{protocol}://***@{domain_path}"
        return endpoint
    
    def _sanitize_auth_value(self, value: str) -> str:
        """Sanitize authentication values for reporting"""
        if len(value) > 16:
            return value[:8] + '***' + value[-4:]
        elif len(value) > 8:
            return value[:4] + '***' + value[-2:]
        else:
            return '***'


class CorporateExposureDetector:
    """Main class for detecting corporate data exposure in binaries"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.credential_detector = CredentialDetector()
        self.business_logic_analyzer = BusinessLogicAnalyzer()
        self.network_analyzer = NetworkTopologyAnalyzer()
    
    def analyze_code(self, code: str, file_path: str = "", language: str = "") -> List[CorporateExposure]:
        """
        Analyze code for corporate data exposure
        
        Args:
            code: Source code or decompiled code to analyze
            file_path: Path to the file being analyzed
            language: Programming language (optional)
            
        Returns:
            List of detected exposures
        """
        exposures = []
        
        try:
            # Scan for credentials and secrets
            credential_exposures = self.credential_detector.scan_for_credentials(code, file_path)
            exposures.extend(credential_exposures)
            
            # Scan for database connections
            db_exposures = self.credential_detector.scan_database_connections(code, file_path)
            exposures.extend(db_exposures)
            
            # Extract pricing algorithms and business rules
            pricing_exposures = self.business_logic_analyzer.extract_pricing_algorithms(code, file_path)
            exposures.extend(pricing_exposures)
            
            # Identify licensing validation mechanisms
            licensing_exposures = self.business_logic_analyzer.identify_licensing_mechanisms(code, file_path)
            exposures.extend(licensing_exposures)
            
            # Analyze proprietary algorithms
            algorithm_exposures = self.business_logic_analyzer.analyze_proprietary_algorithms(code, file_path)
            exposures.extend(algorithm_exposures)
            
            # Discover API endpoints and network topology
            endpoint_exposures = self.network_analyzer.discover_api_endpoints(code, file_path)
            exposures.extend(endpoint_exposures)
            
            # Extract authentication mechanisms
            auth_exposures = self.network_analyzer.extract_authentication_mechanisms(code, file_path)
            exposures.extend(auth_exposures)
            
            # Identify network topology and service dependencies
            topology_exposures = self.network_analyzer.identify_network_topology(code, file_path)
            exposures.extend(topology_exposures)
            
            self.logger.info(f"Found {len(exposures)} corporate data exposures in {file_path}")
            
        except Exception as e:
            self.logger.error(f"Error analyzing code for corporate exposure: {e}")
        
        return exposures
    
    def generate_exposure_report(self, exposures: List[CorporateExposure]) -> Dict[str, Any]:
        """Generate comprehensive exposure report"""
        if not exposures:
            return {
                'summary': 'No corporate data exposures detected',
                'total_exposures': 0,
                'severity_breakdown': {},
                'exposures': []
            }
        
        # Calculate severity breakdown
        severity_counts = {}
        for exposure in exposures:
            severity = exposure.severity.value
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate overall risk score
        risk_score = self._calculate_risk_score(exposures)
        
        report = {
            'summary': f"Detected {len(exposures)} corporate data exposures",
            'total_exposures': len(exposures),
            'severity_breakdown': severity_counts,
            'risk_score': risk_score,
            'business_impact_assessment': self._assess_overall_business_impact(exposures),
            'recommended_actions': self._get_recommended_actions(exposures),
            'exposures': [self._serialize_exposure(exp) for exp in exposures]
        }
        
        return report
    
    def _calculate_risk_score(self, exposures: List[CorporateExposure]) -> float:
        """Calculate overall risk score (0-10)"""
        if not exposures:
            return 0.0
        
        severity_weights = {
            SeverityLevel.CRITICAL: 10,
            SeverityLevel.HIGH: 7,
            SeverityLevel.MEDIUM: 4,
            SeverityLevel.LOW: 2
        }
        
        total_score = sum(severity_weights.get(exp.severity, 1) * exp.confidence for exp in exposures)
        max_possible = len(exposures) * 10
        
        return min(10.0, (total_score / max_possible) * 10)
    
    def _assess_overall_business_impact(self, exposures: List[CorporateExposure]) -> str:
        """Assess overall business impact"""
        critical_count = sum(1 for exp in exposures if exp.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for exp in exposures if exp.severity == SeverityLevel.HIGH)
        
        if critical_count > 0:
            return f"CRITICAL: {critical_count} critical exposures found. Immediate action required to prevent data breach."
        elif high_count > 2:
            return f"HIGH: {high_count} high-severity exposures found. Significant security risk requiring prompt attention."
        elif high_count > 0:
            return f"MEDIUM: {high_count} high-severity exposures found. Security risk requiring attention."
        else:
            return "LOW: Minor security concerns identified. Address as part of security hygiene."
    
    def _get_recommended_actions(self, exposures: List[CorporateExposure]) -> List[str]:
        """Get prioritized list of recommended actions"""
        actions = []
        
        # Group by exposure type
        credential_count = sum(1 for exp in exposures if exp.exposure_type == ExposureType.CREDENTIAL)
        db_count = sum(1 for exp in exposures if exp.exposure_type == ExposureType.DATABASE_CONNECTION)
        business_count = sum(1 for exp in exposures if exp.exposure_type == ExposureType.BUSINESS_LOGIC)
        
        if credential_count > 0:
            actions.append(f"Immediately rotate {credential_count} exposed credentials")
        
        if db_count > 0:
            actions.append(f"Secure {db_count} database connection strings")
        
        if business_count > 0:
            actions.append(f"Review and obfuscate {business_count} exposed business logic implementations")
        
        actions.extend([
            "Implement secure credential management system",
            "Add pre-commit hooks to prevent credential commits",
            "Conduct security code review training",
            "Implement secrets scanning in CI/CD pipeline"
        ])
        
        return actions
    
    def _serialize_exposure(self, exposure: CorporateExposure) -> Dict[str, Any]:
        """Serialize exposure for JSON output"""
        return {
            'type': exposure.exposure_type.value,
            'severity': exposure.severity.value,
            'title': exposure.title,
            'description': exposure.description,
            'value': exposure.value,
            'confidence': exposure.confidence,
            'business_impact': exposure.business_impact,
            'remediation': exposure.remediation,
            'evidence': [
                {
                    'location': ev.location,
                    'context': ev.context,
                    'pattern': ev.pattern_matched,
                    'confidence': ev.confidence
                }
                for ev in exposure.evidence
            ],
            'metadata': exposure.metadata
        }


def main():
    """Example usage of the Corporate Exposure Detector"""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python corporate_exposure_detector.py <file_path>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            code = f.read()
        
        detector = CorporateExposureDetector()
        exposures = detector.analyze_code(code, file_path)
        report = detector.generate_exposure_report(exposures)
        
        print(json.dumps(report, indent=2))
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()