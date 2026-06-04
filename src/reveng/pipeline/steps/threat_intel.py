"""Threat intelligence correlation step."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from reveng.analysis.analyzer import REVENGAnalyzer


logger = logging.getLogger(__name__)


def run_threat_intelligence(analyzer: "REVENGAnalyzer") -> None:
    """Execute step 11 of the enhanced pipeline."""

    try:
        if not getattr(analyzer, "threat_intelligence_correlator", None):
            from reveng.security.threat_intelligence_correlator import (
                ThreatIntelligenceCorrelator,
            )

            analyzer.threat_intelligence_correlator = ThreatIntelligenceCorrelator()

        crypto_candidates = []
        if getattr(analyzer, "ghidra_extractor", None):
            logger.info("Using Ghidra behavioral analysis for threat intelligence")
            crypto_candidates = analyzer.ghidra_extractor.get_crypto_candidates()
            logger.info("Found %d potential cryptographic functions", len(crypto_candidates))
            for crypto in crypto_candidates[:5]:
                logger.info(
                    "  - Function at %s (crypto score: %s)",
                    crypto["address"],
                    crypto["crypto_score"],
                )

        threat_report = analyzer.threat_intelligence_correlator.analyze_file(analyzer.binary_path)

        logger.info(
            "Threat intelligence correlation completed - threat level: %s",
            threat_report.threat_level,
        )
        logger.info("Analysis mode: BEHAVIORAL with Ghidra integration")

        analyzer.enhanced_results["step11"] = {
            "status": "success",
            "mode": "behavioral_ghidra",
            "crypto_functions_detected": len(crypto_candidates),
            "threat_level": threat_report.threat_level,
            "apt_attribution": threat_report.apt_attribution,
            "iocs_count": len(threat_report.iocs_extracted),
            "malware_classification": threat_report.malware_classification,
            "report": threat_report,
        }

    except ImportError as exc:
        logger.warning("Threat intelligence correlator not available: %s", exc)
        analyzer.enhanced_results["step11"] = {
            "status": "skipped",
            "error": "module_not_found",
        }
    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Error in threat intelligence correlation: %s", exc)
        analyzer.enhanced_results["step11"] = {"status": "error", "error": str(exc)}
