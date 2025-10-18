"""
Security Analysis Tools

Tools for security analysis, vulnerability detection, and threat intelligence.
"""

# Lazy imports to avoid circular import issues
# Import only what's needed to avoid loading all modules at once

__all__ = [
    "ComplexityScorer",
    "CorporateExposureDetector",
    "MITREAttackMapper",
    "MLMalwareClassifier",
    "MLVulnerabilityPredictor",
    "NLPCodeAnalyzer",
    "ThreatIntelligenceCorrelator",
    "VulnerabilityDiscoveryEngine",
]


def __getattr__(name):
    """Lazy import security tools on demand"""
    if name == "ComplexityScorer":
        from .complexity_scorer import ComplexityScorer

        return ComplexityScorer
    elif name == "CorporateExposureDetector":
        from .corporate_exposure_detector import CorporateExposureDetector

        return CorporateExposureDetector
    elif name == "MITREAttackMapper":
        from .mitre_attack_mapper import MITREAttackMapper

        return MITREAttackMapper
    elif name == "MLMalwareClassifier":
        from .ml_malware_classifier import MLMalwareClassifier

        return MLMalwareClassifier
    elif name == "MLVulnerabilityPredictor":
        from .ml_vulnerability_predictor import MLVulnerabilityPredictor

        return MLVulnerabilityPredictor
    elif name == "NLPCodeAnalyzer":
        from .nlp_code_analyzer import NLPCodeAnalyzer

        return NLPCodeAnalyzer
    elif name == "ThreatIntelligenceCorrelator":
        from .threat_intelligence_correlator import ThreatIntelligenceCorrelator

        return ThreatIntelligenceCorrelator
    elif name == "VulnerabilityDiscoveryEngine":
        from .vulnerability_discovery_engine import VulnerabilityDiscoveryEngine

        return VulnerabilityDiscoveryEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
