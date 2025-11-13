"""Security analysis tool exports with defensive optional dependency handling."""

import logging
from typing import Any, Callable

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

_LOGGER = logging.getLogger(__name__)


def _optional_import(importer: Callable[[], Any], display_name: str) -> Any:
    try:
        return importer()
    except (ImportError, AttributeError) as e:
        _LOGGER.warning("%s unavailable: %s", display_name, e)
        # Store exception for use in nested class
        saved_exception = e

        class _Unavailable:
            def __init__(self, *args, **kwargs):
                raise ImportError(
                    f"{display_name} is unavailable because optional dependencies could not be loaded"
                ) from saved_exception

        _Unavailable.__name__ = display_name
        return _Unavailable


def __getattr__(name):
    """Lazy import security tools on demand with graceful degradation."""
    loaders = {
        "ComplexityScorer": lambda: __import__(
            "reveng.security.complexity_scorer", fromlist=["ComplexityScorer"]
        ).ComplexityScorer,
        "CorporateExposureDetector": lambda: __import__(
            "reveng.security.corporate_exposure_detector",
            fromlist=["CorporateExposureDetector"],
        ).CorporateExposureDetector,
        "MITREAttackMapper": lambda: __import__(
            "reveng.security.mitre_attack_mapper", fromlist=["MITREAttackMapper"]
        ).MITREAttackMapper,
        "MLMalwareClassifier": lambda: __import__(
            "reveng.security.ml_malware_classifier", fromlist=["MLMalwareClassifier"]
        ).MLMalwareClassifier,
        "MLVulnerabilityPredictor": lambda: __import__(
            "reveng.security.ml_vulnerability_predictor",
            fromlist=["MLVulnerabilityPredictor"],
        ).MLVulnerabilityPredictor,
        "NLPCodeAnalyzer": lambda: __import__(
            "reveng.security.nlp_code_analyzer", fromlist=["NLPCodeAnalyzer"]
        ).NLPCodeAnalyzer,
        "ThreatIntelligenceCorrelator": lambda: __import__(
            "reveng.security.threat_intelligence_correlator",
            fromlist=["ThreatIntelligenceCorrelator"],
        ).ThreatIntelligenceCorrelator,
        "VulnerabilityDiscoveryEngine": lambda: __import__(
            "reveng.security.vulnerability_discovery_engine",
            fromlist=["VulnerabilityDiscoveryEngine"],
        ).VulnerabilityDiscoveryEngine,
    }

    if name in loaders:
        return _optional_import(loaders[name], name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
