#!/usr/bin/env python3
"""
AI-Enhanced Universal Analysis Data Models
==========================================

Comprehensive data structures for all analysis results, evidence tracking,
and confidence scoring systems with serialization support.

Author: REVENG Project - AI Enhancement Module
Version: 1.0
"""

import json
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Union
from enum import Enum
from datetime import datetime
import uuid


class RiskLevel(Enum):
    """Risk level enumeration"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class Severity(Enum):
    """Vulnerability severity enumeration"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class ConfidenceLevel(Enum):
    """Confidence level enumeration"""
    VERY_HIGH = "VERY_HIGH"  # 90-100%
    HIGH = "HIGH"            # 70-89%
    MEDIUM = "MEDIUM"        # 50-69%
    LOW = "LOW"              # 30-49%
    VERY_LOW = "VERY_LOW"    # 0-29%


@dataclass
class Evidence:
    """Evidence item with confidence scoring"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""
    description: str = ""
    source: str = ""
    confidence: float = 0.0
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def get_confidence_level(self) -> ConfidenceLevel:
        """Get confidence level enum based on score"""
        if self.confidence >= 0.9:
            return ConfidenceLevel.VERY_HIGH
        elif self.confidence >= 0.7:
            return ConfidenceLevel.HIGH
        elif self.confidence >= 0.5:
            return ConfidenceLevel.MEDIUM
        elif self.confidence >= 0.3:
            return ConfidenceLevel.LOW
        else:
            return ConfidenceLevel.VERY_LOW


@dataclass
class FileInfo:
    """File information and metadata"""
    path: str
    name: str
    size: int
    file_type: str
    format_type: str
    detection_confidence: float
    hash_md5: Optional[str] = None
    hash_sha1: Optional[str] = None
    hash_sha256: Optional[str] = None
    creation_time: Optional[float] = None
    modification_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CredentialExposure:
    """Exposed credential information"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""  # api_key, password, token, connection_string, etc.
    value: str = ""  # Redacted/masked value
    location: str = ""  # File/function where found
    confidence: float = 0.0
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    description: str = ""
    remediation: str = ""
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class BusinessLogicExposure:
    """Exposed business logic information"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""  # pricing, licensing, algorithm, etc.
    description: str = ""
    location: str = ""
    competitive_value: str = ""  # HIGH, MEDIUM, LOW
    confidence: float = 0.0
    extracted_logic: str = ""
    business_impact: str = ""
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class APIEndpoint:
    """Discovered API endpoint"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    url: str = ""
    method: str = ""  # GET, POST, etc.
    authentication: str = ""
    parameters: List[str] = field(default_factory=list)
    location: str = ""
    confidence: float = 0.0
    security_issues: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class CompetitiveIntel:
    """Competitive intelligence finding"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    category: str = ""
    description: str = ""
    value: str = ""
    confidence: float = 0.0
    business_impact: str = ""
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class CorporateExposureReport:
    """Corporate data exposure analysis report"""
    credentials_found: List[CredentialExposure] = field(default_factory=list)
    business_logic_exposed: List[BusinessLogicExposure] = field(default_factory=list)
    api_endpoints_discovered: List[APIEndpoint] = field(default_factory=list)
    competitive_intelligence: List[CompetitiveIntel] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.UNKNOWN
    business_impact: str = ""
    remediation_recommendations: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())


@dataclass
class MemoryVulnerability:
    """Memory-related vulnerability"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""  # buffer_overflow, use_after_free, etc.
    location: str = ""
    function: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    exploit_potential: str = ""
    remediation: str = ""
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class InjectionVulnerability:
    """Injection vulnerability"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""  # sql_injection, xss, command_injection, etc.
    location: str = ""
    parameter: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    payload_example: str = ""
    remediation: str = ""
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class AuthenticationIssue:
    """Authentication/authorization issue"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""  # weak_auth, bypass, privilege_escalation, etc.
    location: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    bypass_method: str = ""
    remediation: str = ""
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class CryptographicWeakness:
    """Cryptographic implementation weakness"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""  # weak_cipher, poor_key_management, etc.
    location: str = ""
    algorithm: str = ""
    severity: Severity = Severity.INFO
    description: str = ""
    weakness: str = ""
    remediation: str = ""
    confidence: float = 0.0
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class VulnerabilityReport:
    """Comprehensive vulnerability analysis report"""
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0

    memory_vulnerabilities: List[MemoryVulnerability] = field(default_factory=list)
    injection_vulnerabilities: List[InjectionVulnerability] = field(default_factory=list)
    authentication_issues: List[AuthenticationIssue] = field(default_factory=list)
    cryptographic_weaknesses: List[CryptographicWeakness] = field(default_factory=list)

    severity_distribution: Dict[str, int] = field(default_factory=dict)
    exploit_potential: str = ""
    remediation_priority: List[str] = field(default_factory=list)
    summary: str = ""
    confidence_score: float = 0.0
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())


@dataclass
class IOC:
    """Indicator of Compromise"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = ""  # hash, domain, ip, url, etc.
    value: str = ""
    description: str = ""
    confidence: float = 0.0
    source: str = ""
    first_seen: Optional[float] = None
    last_seen: Optional[float] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class APTAttribution:
    """APT group attribution analysis"""
    group_name: str = ""
    confidence: float = 0.0
    matching_ttps: List[str] = field(default_factory=list)
    campaign_name: str = ""
    attribution_reasons: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class AttackChain:
    """Attack chain representation for MITRE ATT&CK analysis"""
    phases: List[str] = field(default_factory=list)
    techniques_by_phase: Dict[str, List[str]] = field(default_factory=dict)
    confidence_by_phase: Dict[str, float] = field(default_factory=dict)
    timeline: List[tuple] = field(default_factory=list)  # (phase, technique, timestamp)


@dataclass
class MITREMapping:
    """MITRE ATT&CK framework mapping"""
    techniques: List[str] = field(default_factory=list)
    tactics: List[str] = field(default_factory=list)
    technique_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    kill_chain_phases: List[str] = field(default_factory=list)
    attack_chain: Optional['AttackChain'] = None


@dataclass
class MalwareClassification:
    """Malware classification result"""
    family: str = ""
    variant: str = ""
    confidence: float = 0.0
    capabilities: List[str] = field(default_factory=list)
    behavior_tags: List[str] = field(default_factory=list)
    similarity_matches: List[str] = field(default_factory=list)


@dataclass
class CampaignCorrelation:
    """Campaign correlation analysis"""
    campaign_id: str = ""
    campaign_name: str = ""
    confidence: float = 0.0
    related_samples: List[str] = field(default_factory=list)
    timeline: Dict[str, Any] = field(default_factory=dict)
    infrastructure: List[str] = field(default_factory=list)


@dataclass
class ThreatIntelligenceReport:
    """Threat intelligence correlation report"""
    apt_attribution: Optional[APTAttribution] = None
    mitre_attack_mapping: MITREMapping = field(default_factory=MITREMapping)
    iocs_extracted: List[IOC] = field(default_factory=list)
    malware_classification: Optional[MalwareClassification] = None
    campaign_correlation: Optional[CampaignCorrelation] = None
    threat_level: RiskLevel = RiskLevel.UNKNOWN
    recommended_actions: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())


@dataclass
class ReconstructionDemo:
    """Binary reconstruction demonstration"""
    original_binary: str = ""
    reconstructed_source: str = ""
    accuracy_score: float = 0.0
    functional_equivalence: bool = False
    build_instructions: str = ""
    comparison_report: str = ""
    demonstration_files: List[str] = field(default_factory=list)


@dataclass
class ExecutiveSummary:
    """Executive-level summary"""
    risk_assessment: str = ""
    business_impact: str = ""
    key_findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    compliance_implications: List[str] = field(default_factory=list)
    budget_impact: str = ""


@dataclass
class UniversalAnalysisResult:
    """Universal analysis result containing all findings"""
    # Core information
    file_info: FileInfo
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    analysis_timestamp: float = field(default_factory=lambda: datetime.now().timestamp())
    analysis_duration: float = 0.0

    # Analysis results
    reveng_analysis: Dict[str, Any] = field(default_factory=dict)
    enhanced_analysis: Dict[str, Any] = field(default_factory=dict)

    # Detailed reports
    corporate_exposure: Optional[CorporateExposureReport] = None
    vulnerabilities: Optional[VulnerabilityReport] = None
    threat_intelligence: Optional[ThreatIntelligenceReport] = None
    reconstruction_demo: Optional[ReconstructionDemo] = None
    executive_summary: Optional[ExecutiveSummary] = None

    # Meta information
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    evidence_chain: List[Evidence] = field(default_factory=list)
    analysis_modules_used: List[str] = field(default_factory=list)

    def add_evidence(self, evidence: Evidence):
        """Add evidence to the evidence chain"""
        self.evidence_chain.append(evidence)

    def get_overall_confidence(self) -> float:
        """Calculate overall confidence score"""
        if not self.confidence_scores:
            return 0.0
        return sum(self.confidence_scores.values()) / len(self.confidence_scores)

    def get_risk_level(self) -> RiskLevel:
        """Determine overall risk level"""
        if self.vulnerabilities and self.vulnerabilities.critical_count > 0:
            return RiskLevel.CRITICAL
        elif self.vulnerabilities and self.vulnerabilities.high_count > 0:
            return RiskLevel.HIGH
        elif self.corporate_exposure and self.corporate_exposure.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return self.corporate_exposure.risk_level
        elif self.threat_intelligence and self.threat_intelligence.threat_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            return self.threat_intelligence.threat_level
        else:
            return RiskLevel.MEDIUM


@dataclass
class ExecutiveReport:
    """Executive-level report for CISOs and leadership"""
    executive_summary: str
    risk_level: str
    business_impact: str
    recommendations: List[str] = field(default_factory=list)
    compliance_status: str = ""
    budget_implications: str = ""
    timeline: str = ""
    next_steps: List[str] = field(default_factory=list)


@dataclass
class DemonstrationComponent:
    """Component of a security demonstration"""
    type: str = ""  # slide, video, interactive, code_sample, etc.
    title: str = ""
    content: str = ""
    file_path: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DemonstrationPackage:
    """Security demonstration package"""
    title: str
    description: str
    components: List[DemonstrationComponent] = field(default_factory=list)
    target_audience: str = ""  # executive, technical, academic, etc.
    duration_minutes: int = 0
    presentation_files: List[str] = field(default_factory=list)
    interactive_demos: List[str] = field(default_factory=list)


@dataclass
class CorporateRiskAssessment:
    """Corporate risk assessment result"""
    risk_score: float
    exposure_categories: List[str] = field(default_factory=list)
    business_impact: str = ""
    remediation_priority: List[str] = field(default_factory=list)
    compliance_gaps: List[str] = field(default_factory=list)
    estimated_cost: str = ""
    timeline: str = ""


class UniversalAnalysisSerializer:
    """Serialization utilities for analysis results"""

    @staticmethod
    def to_json(result: UniversalAnalysisResult, indent: int = 2) -> str:
        """Serialize to JSON string"""
        return json.dumps(asdict(result), indent=indent, default=str)

    @staticmethod
    def from_json(json_str: str) -> UniversalAnalysisResult:
        """Deserialize from JSON string"""
        data = json.loads(json_str)
        return UniversalAnalysisResult(**data)

    @staticmethod
    def to_xml(result: UniversalAnalysisResult) -> str:
        """Serialize to XML string"""
        root = ET.Element("UniversalAnalysisResult")

        # Add basic info
        info_elem = ET.SubElement(root, "FileInfo")
        for key, value in asdict(result.file_info).items():
            elem = ET.SubElement(info_elem, key)
            elem.text = str(value)

        # Add analysis metadata
        meta_elem = ET.SubElement(root, "AnalysisMetadata")
        ET.SubElement(meta_elem, "analysis_id").text = result.analysis_id
        ET.SubElement(meta_elem, "timestamp").text = str(result.analysis_timestamp)
        ET.SubElement(meta_elem, "duration").text = str(result.analysis_duration)

        # Add confidence scores
        conf_elem = ET.SubElement(root, "ConfidenceScores")
        for module, score in result.confidence_scores.items():
            score_elem = ET.SubElement(conf_elem, "Score")
            score_elem.set("module", module)
            score_elem.text = str(score)

        return ET.tostring(root, encoding='unicode')

    @staticmethod
    def save_to_file(result: UniversalAnalysisResult, file_path: str, format_type: str = "json"):
        """Save analysis result to file"""
        if format_type.lower() == "json":
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(UniversalAnalysisSerializer.to_json(result))
        elif format_type.lower() == "xml":
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(UniversalAnalysisSerializer.to_xml(result))
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    @staticmethod
    def load_from_file(file_path: str, format_type: str = "json") -> UniversalAnalysisResult:
        """Load analysis result from file"""
        if format_type.lower() == "json":
            with open(file_path, 'r', encoding='utf-8') as f:
                return UniversalAnalysisSerializer.from_json(f.read())
        else:
            raise ValueError(f"Unsupported format for loading: {format_type}")


class EvidenceTracker:
    """Evidence tracking and confidence scoring system"""

    def __init__(self):
        self.evidence_chain: List[Evidence] = []

    def add_evidence(self, evidence_type: str, description: str, source: str,
                    confidence: float, metadata: Dict[str, Any] = None) -> Evidence:
        """Add new evidence to the chain"""
        evidence = Evidence(
            type=evidence_type,
            description=description,
            source=source,
            confidence=confidence,
            metadata=metadata or {}
        )
        self.evidence_chain.append(evidence)
        return evidence

    def get_evidence_by_type(self, evidence_type: str) -> List[Evidence]:
        """Get all evidence of a specific type"""
        return [e for e in self.evidence_chain if e.type == evidence_type]

    def get_confidence_for_finding(self, finding_id: str) -> float:
        """Calculate confidence score for a specific finding"""
        related_evidence = [e for e in self.evidence_chain
                          if e.metadata.get('finding_id') == finding_id]
        if not related_evidence:
            return 0.0

        # Weighted average of evidence confidence
        total_weight = sum(e.confidence for e in related_evidence)
        if total_weight == 0:
            return 0.0

        weighted_sum = sum(e.confidence * e.confidence for e in related_evidence)
        return weighted_sum / total_weight

    def generate_evidence_report(self) -> Dict[str, Any]:
        """Generate comprehensive evidence report"""
        return {
            'total_evidence': len(self.evidence_chain),
            'evidence_types': list(set(e.type for e in self.evidence_chain)),
            'average_confidence': sum(e.confidence for e in self.evidence_chain) / len(self.evidence_chain) if self.evidence_chain else 0.0,
            'high_confidence_count': len([e for e in self.evidence_chain if e.confidence >= 0.8]),
            'evidence_sources': list(set(e.source for e in self.evidence_chain)),
            'evidence_timeline': sorted([(e.timestamp, e.type, e.confidence) for e in self.evidence_chain])
        }


# Utility functions for data model operations
def create_file_info_from_path(file_path: str) -> FileInfo:
    """Create FileInfo from file path"""
    from pathlib import Path
    import hashlib

    path = Path(file_path)
    if not path.exists():
        return FileInfo(
            path=file_path,
            name=path.name,
            size=0,
            file_type="unknown",
            format_type="unknown",
            detection_confidence=0.0
        )

    stat = path.stat()

    # Calculate hashes
    with open(path, 'rb') as f:
        content = f.read()
        # Use secure hashing algorithms
        sha256_hash = hashlib.sha256(content).hexdigest()
        sha512_hash = hashlib.sha512(content).hexdigest()
        # Keep MD5/SHA1 only for compatibility with existing databases
        md5_hash = hashlib.md5(content).hexdigest()  # nosec B303 - Compatibility only
        sha1_hash = hashlib.sha1(content).hexdigest()  # nosec B303 - Compatibility only

    return FileInfo(
        path=file_path,
        name=path.name,
        size=stat.st_size,
        file_type="unknown",  # Will be filled by language detector
        format_type="unknown",  # Will be filled by language detector
        detection_confidence=0.0,  # Will be filled by language detector
        hash_md5=md5_hash,
        hash_sha1=sha1_hash,
        hash_sha256=sha256_hash,
        creation_time=stat.st_ctime,
        modification_time=stat.st_mtime
    )


def merge_confidence_scores(scores: List[float], weights: List[float] = None) -> float:
    """Merge multiple confidence scores with optional weights"""
    if not scores:
        return 0.0

    if weights is None:
        weights = [1.0] * len(scores)

    if len(scores) != len(weights):
        raise ValueError("Scores and weights must have the same length")

    weighted_sum = sum(score * weight for score, weight in zip(scores, weights))
    total_weight = sum(weights)

    return weighted_sum / total_weight if total_weight > 0 else 0.0


# Example usage and testing
if __name__ == "__main__":
    # Create sample analysis result
    file_info = FileInfo(
        path="test_binary.exe",
        name="test_binary.exe",
        size=1024000,
        file_type="pe",
        format_type="executable",
        detection_confidence=0.95
    )

    # Create evidence tracker
    tracker = EvidenceTracker()
    evidence1 = tracker.add_evidence(
        "credential_detection",
        "Found hardcoded API key in string table",
        "static_analysis",
        0.9,
        {"finding_id": "cred_001", "location": "0x401000"}
    )

    # Create analysis result
    result = UniversalAnalysisResult(
        file_info=file_info,
        confidence_scores={"corporate_exposure": 0.8, "vulnerability_discovery": 0.7},
        evidence_chain=tracker.evidence_chain
    )

    # Test serialization
    json_output = UniversalAnalysisSerializer.to_json(result)
    print("JSON serialization successful")

    xml_output = UniversalAnalysisSerializer.to_xml(result)
    print("XML serialization successful")

    # Test evidence tracking
    evidence_report = tracker.generate_evidence_report()
    print(f"Evidence report: {evidence_report}")

    print("Data models validation completed successfully!")


# ML-Enhanced Data Models for Advanced AI Features
# ================================================

@dataclass
class VulnerabilityPrediction:
    """ML-based vulnerability prediction result"""
    vulnerability_type: str
    confidence: float
    is_vulnerable: bool
    severity: Severity
    description: str
    features_used: List[str] = field(default_factory=list)
    model_version: str = "1.0"
    evidence: List['Evidence'] = field(default_factory=list)


@dataclass
class MLModelResult:
    """Result from machine learning model"""
    model_name: str
    model_type: str  # "classification", "regression", "clustering", etc.
    prediction: Any
    confidence: float
    features_used: List[str] = field(default_factory=list)
    model_version: str = "1.0"
    training_date: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FeatureVector:
    """Feature vector for ML models"""
    features: List[float]
    feature_names: List[str]
    normalization_method: str = "standard"
    extraction_method: str = "manual"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralPattern:
    """Behavioral pattern detected in malware"""
    type: str
    description: str
    confidence: float
    mitre_techniques: List[str] = field(default_factory=list)
    indicators: List[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM


@dataclass
class ThreatFamily:
    """Malware family information"""
    name: str
    aliases: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    attribution: Optional[str] = None
    ttps: List[str] = field(default_factory=list)  # MITRE ATT&CK techniques


@dataclass
class MalwareClassification:
    """ML-based malware classification result"""
    family: str
    confidence: float
    is_malware: bool
    behavioral_patterns: List[BehavioralPattern] = field(default_factory=list)
    similarity_scores: Dict[str, float] = field(default_factory=dict)
    classification_method: str = "ml_ensemble"
    anomaly_score: float = 0.0
    behavioral_cluster: int = -1
    evidence: List['Evidence'] = field(default_factory=list)


@dataclass
class CodeSummary:
    """NLP-generated code summary"""
    overview: str
    key_functions: List[str] = field(default_factory=list)
    algorithms_used: List[str] = field(default_factory=list)
    design_patterns: List[str] = field(default_factory=list)
    data_structures: List[str] = field(default_factory=list)
    complexity_analysis: Dict[str, Any] = field(default_factory=dict)
    documentation_suggestions: List['DocumentationSuggestion'] = field(default_factory=list)
    semantic_analysis: Optional['CodeSemantics'] = None
    evidence: List['Evidence'] = field(default_factory=list)


@dataclass
class SemanticAnalysis:
    """Semantic analysis of code using NLP"""
    language_detected: str
    semantic_tokens: List[str] = field(default_factory=list)
    concept_clusters: Dict[str, List[str]] = field(default_factory=dict)
    similarity_matrix: List[List[float]] = field(default_factory=list)
    topic_modeling_results: Dict[str, Any] = field(default_factory=dict)
    sentiment_analysis: Dict[str, float] = field(default_factory=dict)


@dataclass
class DocumentationSuggestion:
    """Suggestion for improving code documentation"""
    type: str  # "comment_coverage", "function_documentation", etc.
    priority: str  # "high", "medium", "low"
    description: str
    suggestion: str
    location: str  # Where to apply the suggestion
    confidence: float = 0.8


@dataclass
class MLTrainingData:
    """Training data for ML models"""
    dataset_name: str
    samples: List[Dict[str, Any]] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    feature_names: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    creation_date: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ModelPerformanceMetrics:
    """Performance metrics for ML models"""
    model_name: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    confusion_matrix: List[List[int]] = field(default_factory=list)
    roc_auc: Optional[float] = None
    training_time: float = 0.0
    inference_time: float = 0.0
    model_size: int = 0  # in bytes
    evaluation_date: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class NeuralNetworkArchitecture:
    """Neural network architecture description"""
    model_type: str  # "cnn", "rnn", "transformer", etc.
    layers: List[Dict[str, Any]] = field(default_factory=list)
    input_shape: List[int] = field(default_factory=list)
    output_shape: List[int] = field(default_factory=list)
    parameters_count: int = 0
    optimizer: str = "adam"
    loss_function: str = "categorical_crossentropy"
    metrics: List[str] = field(default_factory=list)


@dataclass
class DeepLearningResult:
    """Result from deep learning model"""
    model_architecture: NeuralNetworkArchitecture
    prediction: Any
    confidence_scores: List[float] = field(default_factory=list)
    attention_weights: Optional[List[List[float]]] = None
    feature_importance: Dict[str, float] = field(default_factory=dict)
    intermediate_outputs: Dict[str, Any] = field(default_factory=dict)
    inference_metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class EmbeddingVector:
    """Vector embedding for similarity analysis"""
    vector: List[float]
    dimension: int
    embedding_model: str
    source_text: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SimilarityAnalysis:
    """Code/malware similarity analysis using embeddings"""
    query_embedding: EmbeddingVector
    similar_samples: List[Dict[str, Any]] = field(default_factory=list)
    similarity_scores: List[float] = field(default_factory=list)
    clustering_results: Dict[str, Any] = field(default_factory=dict)
    anomaly_detection: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MLPipelineResult:
    """Complete ML pipeline execution result"""
    pipeline_name: str
    stages_completed: List[str] = field(default_factory=list)
    vulnerability_predictions: List[VulnerabilityPrediction] = field(default_factory=list)
    malware_classifications: List[MalwareClassification] = field(default_factory=list)
    code_summaries: List[CodeSummary] = field(default_factory=list)
    performance_metrics: Dict[str, ModelPerformanceMetrics] = field(default_factory=dict)
    execution_time: float = 0.0
    success: bool = True
    error_messages: List[str] = field(default_factory=list)
    evidence: List['Evidence'] = field(default_factory=list)


# Enhanced Universal Analysis Result with ML Integration
@dataclass
class EnhancedUniversalAnalysisResult:
    """Enhanced universal analysis result with ML capabilities"""
    # Original analysis results
    file_info: 'FileInfo'
    reveng_analysis: Dict[str, Any] = field(default_factory=dict)
    enhanced_analysis: Dict[str, Any] = field(default_factory=dict)

    # ML-enhanced results
    ml_pipeline_result: Optional[MLPipelineResult] = None
    vulnerability_predictions: List[VulnerabilityPrediction] = field(default_factory=list)
    malware_classification: Optional[MalwareClassification] = None
    code_summary: Optional[CodeSummary] = None
    similarity_analysis: Optional[SimilarityAnalysis] = None

    # Metadata
    analysis_timestamp: float = 0.0
    analysis_duration: float = 0.0
    ml_models_used: List[str] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    evidence_chain: List['Evidence'] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def save_to_file(self, file_path: str, format_type: str = "json"):
        """Save results to file in specified format"""
        if format_type.lower() == "json":
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(self.to_json())
        elif format_type.lower() == "xml":
            self._save_as_xml(file_path)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def _save_as_xml(self, file_path: str):
        """Save results as XML"""
        root = ET.Element("EnhancedAnalysisResult")

        # Add file info
        file_elem = ET.SubElement(root, "FileInfo")
        if self.file_info:
            for key, value in asdict(self.file_info).items():
                elem = ET.SubElement(file_elem, key)
                elem.text = str(value)

        # Add ML results
        if self.ml_pipeline_result:
            ml_elem = ET.SubElement(root, "MLPipelineResult")
            ml_elem.set("pipeline_name", self.ml_pipeline_result.pipeline_name)
            ml_elem.set("success", str(self.ml_pipeline_result.success))

        # Write to file
        tree = ET.ElementTree(root)
        tree.write(file_path, encoding='utf-8', xml_declaration=True)


# Update existing UniversalAnalysisResult to include ML features
UniversalAnalysisResult = EnhancedUniversalAnalysisResult
