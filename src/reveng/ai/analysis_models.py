#!/usr/bin/env python3
"""
REVENG Analysis Models
=====================

Structured data models for AI-optimized analysis results.
These models are designed for easy consumption by AI systems.

Author: REVENG Development Team
Version: 2.2.0
License: MIT
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
import json
import time


class AnalysisType(Enum):
    """Types of analysis that can be performed"""

    COMPREHENSIVE = "comprehensive"
    SECURITY = "security"
    TRIAGE = "triage"
    PERFORMANCE = "performance"
    CUSTOM = "custom"


class ThreatLevel(Enum):
    """Threat level classifications"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ConfidenceLevel(Enum):
    """Confidence levels for analysis results"""

    VERY_LOW = "very_low"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERY_HIGH = "very_high"


@dataclass
class BinaryInfo:
    """Information about the binary being analyzed"""

    name: str
    path: str
    size: int
    file_type: str
    architecture: Optional[str] = None
    compiler: Optional[str] = None
    language: Optional[str] = None
    entry_point: Optional[str] = None
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FunctionAnalysis:
    """Analysis result for a single function"""

    name: str
    address: str
    size: int
    purpose: str
    complexity: str
    security_issues: List[str] = field(default_factory=list)
    performance_issues: List[str] = field(default_factory=list)
    calls_made: List[str] = field(default_factory=list)
    called_by: List[str] = field(default_factory=list)
    variables: List[str] = field(default_factory=list)
    confidence: float = 0.0
    suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    """Vulnerability information"""

    id: str
    type: str
    severity: str
    description: str
    location: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    remediation: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatIndicator:
    """Threat intelligence indicator"""

    type: str  # IP, domain, hash, etc.
    value: str
    threat_level: ThreatLevel
    description: str
    source: str
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Recommendation:
    """Analysis recommendation"""

    id: str
    type: str  # security, performance, code_quality, etc.
    priority: str  # low, medium, high, critical
    title: str
    description: str
    implementation: Optional[str] = None
    impact: Optional[str] = None
    effort: Optional[str] = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalysisMetadata:
    """Metadata about the analysis process"""

    analysis_id: str
    start_time: float
    end_time: float
    duration: float
    tools_used: List[str] = field(default_factory=list)
    analysis_type: AnalysisType = AnalysisType.COMPREHENSIVE
    binary_type: str = "unknown"
    complexity: str = "unknown"
    confidence_overall: float = 0.0
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIAnalysisResult:
    """Comprehensive AI analysis result optimized for AI consumption"""

    binary_info: BinaryInfo
    functions: List[FunctionAnalysis]
    vulnerabilities: List[Vulnerability]
    threat_indicators: List[ThreatIndicator]
    recommendations: List[Recommendation]
    metadata: AnalysisMetadata

    # AI-optimized fields
    natural_language_summary: str = ""
    structured_prompt: str = ""
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    key_findings: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "binary_info": self._dict_from_dataclass(self.binary_info),
            "functions": [self._dict_from_dataclass(f) for f in self.functions],
            "vulnerabilities": [
                self._dict_from_dataclass(v) for v in self.vulnerabilities
            ],
            "threat_indicators": [
                self._dict_from_dataclass(t) for t in self.threat_indicators
            ],
            "recommendations": [
                self._dict_from_dataclass(r) for r in self.recommendations
            ],
            "metadata": self._dict_from_dataclass(self.metadata),
            "natural_language_summary": self.natural_language_summary,
            "structured_prompt": self.structured_prompt,
            "confidence_scores": self.confidence_scores,
            "key_findings": self.key_findings,
            "next_steps": self.next_steps,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string"""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def to_natural_language(self) -> str:
        """Convert to natural language summary"""
        if self.natural_language_summary:
            return self.natural_language_summary

        # Generate basic summary if not provided
        summary_parts = [
            f"Analysis of {self.binary_info.name} ({self.binary_info.size} bytes)",
            f"Found {len(self.functions)} functions",
            f"Identified {len(self.vulnerabilities)} vulnerabilities",
            f"Detected {len(self.threat_indicators)} threat indicators",
            f"Generated {len(self.recommendations)} recommendations",
        ]

        return ". ".join(summary_parts) + "."

    def to_structured_prompt(self) -> str:
        """Format for AI model consumption"""
        if self.structured_prompt:
            return self.structured_prompt

        # Generate structured prompt
        prompt = f"""
# REVENG Analysis Results

## Binary Information
- Name: {self.binary_info.name}
- Size: {self.binary_info.size} bytes
- Type: {self.binary_info.file_type}
- Architecture: {self.binary_info.architecture or "Unknown"}

## Functions ({len(self.functions)})
"""

        for func in self.functions[:10]:  # Limit to first 10 functions
            prompt += f"- {func.name}: {func.purpose} (complexity: {func.complexity})\n"

        prompt += f"""
## Vulnerabilities ({len(self.vulnerabilities)})
"""

        for vuln in self.vulnerabilities[:5]:  # Limit to first 5 vulnerabilities
            prompt += f"- {vuln.type}: {vuln.description} (severity: {vuln.severity})\n"

        prompt += f"""
## Threat Indicators ({len(self.threat_indicators)})
"""

        for indicator in self.threat_indicators[:5]:  # Limit to first 5 indicators
            prompt += f"- {indicator.type}: {indicator.value} (threat level: {indicator.threat_level.value})\n"

        prompt += f"""
## Recommendations ({len(self.recommendations)})
"""

        for rec in self.recommendations[:5]:  # Limit to first 5 recommendations
            prompt += f"- {rec.title}: {rec.description}\n"

        return prompt

    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics"""
        return {
            "binary_name": self.binary_info.name,
            "binary_size": self.binary_info.size,
            "total_functions": len(self.functions),
            "total_vulnerabilities": len(self.vulnerabilities),
            "total_threat_indicators": len(self.threat_indicators),
            "total_recommendations": len(self.recommendations),
            "analysis_duration": self.metadata.duration,
            "overall_confidence": self.metadata.confidence_overall,
            "threat_level": self._calculate_overall_threat_level(),
            "complexity": self.metadata.complexity,
        }

    def _calculate_overall_threat_level(self) -> str:
        """Calculate overall threat level"""
        if not self.vulnerabilities and not self.threat_indicators:
            return "low"

        high_severity_vulns = sum(
            1 for v in self.vulnerabilities if v.severity in ["high", "critical"]
        )
        high_threat_indicators = sum(
            1
            for t in self.threat_indicators
            if t.threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]
        )

        if high_severity_vulns > 0 or high_threat_indicators > 0:
            return "high"
        elif len(self.vulnerabilities) > 0 or len(self.threat_indicators) > 0:
            return "medium"
        else:
            return "low"

    def _dict_from_dataclass(self, obj) -> Dict[str, Any]:
        """Convert dataclass to dictionary"""
        if hasattr(obj, "__dataclass_fields__"):
            result = {}
            for field_name, field_info in obj.__dataclass_fields__.items():
                value = getattr(obj, field_name)
                if hasattr(value, "__dataclass_fields__"):
                    result[field_name] = self._dict_from_dataclass(value)
                elif isinstance(value, list):
                    result[field_name] = [
                        self._dict_from_dataclass(item)
                        if hasattr(item, "__dataclass_fields__")
                        else item
                        for item in value
                    ]
                elif isinstance(value, Enum):
                    result[field_name] = value.value
                else:
                    result[field_name] = value
            return result
        return obj


@dataclass
class AIAnalysisRequest:
    """Request for AI analysis"""

    binary_path: str
    analysis_type: AnalysisType = AnalysisType.COMPREHENSIVE
    goals: List[str] = field(
        default_factory=lambda: [
            "understand_functionality",
            "find_vulnerabilities",
            "assess_threats",
        ]
    )
    context: Dict[str, Any] = field(default_factory=dict)
    preferences: Dict[str, Any] = field(default_factory=dict)
    session_id: Optional[str] = None

    def __post_init__(self):
        if not self.session_id:
            self.session_id = f"session_{int(time.time())}"


@dataclass
class WorkflowSuggestion:
    """Suggested analysis workflow"""

    binary_type: str
    complexity: str
    recommended_tools: List[str]
    estimated_time: int  # seconds
    resource_requirements: Dict[str, str]
    alternative_workflows: List[Dict[str, Any]] = field(default_factory=list)
    confidence: float = 0.0
    reasoning: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "binary_type": self.binary_type,
            "complexity": self.complexity,
            "recommended_tools": self.recommended_tools,
            "estimated_time": self.estimated_time,
            "resource_requirements": self.resource_requirements,
            "alternative_workflows": self.alternative_workflows,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
        }


# Factory functions for easy creation
def create_binary_info(
    name: str, path: str, size: int, file_type: str, **kwargs
) -> BinaryInfo:
    """Create BinaryInfo with default values"""
    return BinaryInfo(name=name, path=path, size=size, file_type=file_type, **kwargs)


def create_function_analysis(
    name: str, address: str, size: int, purpose: str, **kwargs
) -> FunctionAnalysis:
    """Create FunctionAnalysis with default values"""
    return FunctionAnalysis(
        name=name, address=address, size=size, purpose=purpose, **kwargs
    )


def create_vulnerability(
    id: str, type: str, severity: str, description: str, **kwargs
) -> Vulnerability:
    """Create Vulnerability with default values"""
    return Vulnerability(
        id=id, type=type, severity=severity, description=description, **kwargs
    )


def create_threat_indicator(
    type: str, value: str, threat_level: ThreatLevel, description: str, **kwargs
) -> ThreatIndicator:
    """Create ThreatIndicator with default values"""
    return ThreatIndicator(
        type=type,
        value=value,
        threat_level=threat_level,
        description=description,
        **kwargs,
    )


def create_recommendation(
    id: str, type: str, priority: str, title: str, description: str, **kwargs
) -> Recommendation:
    """Create Recommendation with default values"""
    return Recommendation(
        id=id,
        type=type,
        priority=priority,
        title=title,
        description=description,
        **kwargs,
    )


def create_analysis_metadata(
    analysis_id: str, start_time: float, end_time: float, **kwargs
) -> AnalysisMetadata:
    """Create AnalysisMetadata with calculated values"""
    return AnalysisMetadata(
        analysis_id=analysis_id,
        start_time=start_time,
        end_time=end_time,
        duration=end_time - start_time,
        **kwargs,
    )
