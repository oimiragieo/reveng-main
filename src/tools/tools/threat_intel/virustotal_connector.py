"""
VirusTotal Integration for REVENG

Provides threat intelligence enrichment via VirusTotal API including:
- Hash reputation lookups
- Malware family identification
- Related sample discovery
- Behavioral analysis reports
- Community threat intelligence
"""

import hashlib
import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime

try:
    import vt
    VT_AVAILABLE = True
except ImportError:
    VT_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class VTEnrichment:
    """VirusTotal enrichment data"""
    sha256: str
    detections: Dict[str, int]
    detection_score: str
    threat_labels: List[str]
    tags: List[str]
    names: List[str]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    popular_threat_classification: Optional[Dict[str, Any]]
    suggested_family: Optional[str]
    capabilities: List[str]
    sigma_rules: List[str]
    crowdsourced_yara_rules: List[Dict[str, str]]
    sandbox_verdicts: Dict[str, str]
    vhash: Optional[str]
    similar_files: List[str]
    contacted_domains: List[str]
    contacted_ips: List[str]
    raw_response: Optional[Dict[str, Any]] = None


class VirusTotalConnector:
    """
    VirusTotal API connector for threat intelligence enrichment.

    Provides comprehensive threat intelligence from VirusTotal including
    malware detection, family classification, behavioral analysis, and
    IOC extraction.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize VirusTotal connector.

        Args:
            api_key: VirusTotal API key. If None, will try to read from
                    environment variable VT_API_KEY or config file.
        """
        if not VT_AVAILABLE:
            raise ImportError(
                "VirusTotal integration requires 'vt-py' package. "
                "Install with: pip install vt-py"
            )

        self.api_key = api_key or self._get_api_key()
        if not self.api_key:
            raise ValueError(
                "VirusTotal API key not provided. Set VT_API_KEY environment "
                "variable or provide api_key parameter."
            )

        self.client = vt.Client(self.api_key)
        logger.info("VirusTotal connector initialized")

    def _get_api_key(self) -> Optional[str]:
        """Get API key from environment or config file"""
        import os

        # Try environment variable
        api_key = os.environ.get('VT_API_KEY')
        if api_key:
            return api_key

        # Try config file
        try:
            from ...config.config_manager import ConfigManager
            config = ConfigManager.load_config()
            return config.get('threat_intel', {}).get('virustotal_api_key')
        except Exception:
            return None

    def calculate_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of file"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def lookup_hash(self, sha256: str) -> Optional[VTEnrichment]:
        """
        Lookup file hash on VirusTotal.

        Args:
            sha256: SHA256 hash to lookup

        Returns:
            VTEnrichment object with threat intelligence, or None if not found
        """
        try:
            file_obj = self.client.get_object(f"/files/{sha256}")

            # Extract detection statistics
            stats = file_obj.last_analysis_stats
            detections = {
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'timeout': stats.get('timeout', 0),
                'confirmed-timeout': stats.get('confirmed-timeout', 0),
                'failure': stats.get('failure', 0),
                'type-unsupported': stats.get('type-unsupported', 0),
            }

            total_scanners = sum(detections.values())
            detection_score = f"{detections['malicious']}/{total_scanners}"

            # Extract threat classification
            threat_classification = file_obj.get('popular_threat_classification')
            suggested_family = None
            if threat_classification:
                suggested_family = threat_classification.get('suggested_threat_label')

            # Extract capabilities from sandbox reports
            capabilities = []
            sandbox_verdicts = {}

            try:
                # Get last analysis results for sandbox verdicts
                last_analysis = file_obj.last_analysis_results
                for engine, result in last_analysis.items():
                    if result.get('category') in ['malicious', 'suspicious']:
                        sandbox_verdicts[engine] = result.get('result', 'Unknown')
            except Exception:
                pass

            # Extract network IOCs if available
            contacted_domains = []
            contacted_ips = []

            try:
                # These require additional API calls - only fetch if needed
                # For now, leave empty and add detailed fetching later
                pass
            except Exception:
                pass

            # Extract YARA rules
            crowdsourced_yara = []
            try:
                yara_rulesets = file_obj.get('crowdsourced_yara_results', [])
                for ruleset in yara_rulesets[:10]:  # Limit to 10 rules
                    crowdsourced_yara.append({
                        'rule_name': ruleset.get('rule_name', ''),
                        'ruleset_name': ruleset.get('ruleset_name', ''),
                        'author': ruleset.get('author', ''),
                        'description': ruleset.get('description', ''),
                    })
            except Exception:
                pass

            # Create enrichment object
            enrichment = VTEnrichment(
                sha256=sha256,
                detections=detections,
                detection_score=detection_score,
                threat_labels=file_obj.get('tags', []),
                tags=file_obj.get('tags', []),
                names=file_obj.get('names', []),
                first_seen=file_obj.get('first_submission_date'),
                last_seen=file_obj.get('last_submission_date'),
                popular_threat_classification=threat_classification,
                suggested_family=suggested_family,
                capabilities=capabilities,
                sigma_rules=[],  # Sigma rules not directly available
                crowdsourced_yara_rules=crowdsourced_yara,
                sandbox_verdicts=sandbox_verdicts,
                vhash=file_obj.get('vhash'),
                similar_files=[],  # Requires additional API call
                contacted_domains=contacted_domains,
                contacted_ips=contacted_ips,
                raw_response=file_obj.to_dict() if hasattr(file_obj, 'to_dict') else None
            )

            logger.info(f"Successfully retrieved VT intel for {sha256}: {detection_score}")
            return enrichment

        except vt.error.APIError as e:
            if e.code == 'NotFoundError':
                logger.info(f"Hash {sha256} not found on VirusTotal")
                return None
            else:
                logger.error(f"VirusTotal API error: {e}")
                raise

    def lookup_file(self, file_path: str) -> Optional[VTEnrichment]:
        """
        Lookup file on VirusTotal by calculating its hash.

        Args:
            file_path: Path to file to lookup

        Returns:
            VTEnrichment object or None if not found
        """
        sha256 = self.calculate_file_hash(file_path)
        logger.info(f"Calculated SHA256 for {file_path}: {sha256}")
        return self.lookup_hash(sha256)

    def submit_file(self, file_path: str, wait_for_analysis: bool = False) -> str:
        """
        Submit file to VirusTotal for analysis.

        Args:
            file_path: Path to file to submit
            wait_for_analysis: If True, wait for analysis to complete

        Returns:
            File hash (SHA256)
        """
        try:
            with open(file_path, "rb") as f:
                analysis = self.client.scan_file(f)

            file_id = analysis.id
            sha256 = self.calculate_file_hash(file_path)

            logger.info(f"Submitted {file_path} to VirusTotal (ID: {file_id})")

            if wait_for_analysis:
                logger.info("Waiting for analysis to complete...")
                while True:
                    analysis = self.client.get_object(f"/analyses/{file_id}")
                    if analysis.status == "completed":
                        logger.info("Analysis completed")
                        break
                    time.sleep(10)

            return sha256

        except Exception as e:
            logger.error(f"Failed to submit file to VirusTotal: {e}")
            raise

    def get_similar_files(self, sha256: str, limit: int = 10) -> List[str]:
        """
        Get similar files based on VHash similarity.

        Args:
            sha256: Hash of file to find similar files for
            limit: Maximum number of similar files to return

        Returns:
            List of SHA256 hashes of similar files
        """
        try:
            # Get file object to extract vhash
            file_obj = self.client.get_object(f"/files/{sha256}")
            vhash = file_obj.get('vhash')

            if not vhash:
                logger.warning(f"No vhash available for {sha256}")
                return []

            # Search for files with similar vhash
            similar = []
            query = f'vhash:"{vhash}"'

            for file in self.client.iterator(f"/intelligence/search", params={"query": query}, limit=limit):
                file_hash = file.sha256
                if file_hash != sha256:  # Exclude original file
                    similar.append(file_hash)

            logger.info(f"Found {len(similar)} similar files for {sha256}")
            return similar

        except Exception as e:
            logger.error(f"Failed to get similar files: {e}")
            return []

    def enrich_analysis(self, analysis_results: Dict[str, Any], file_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Enrich REVENG analysis results with VirusTotal intelligence.

        Args:
            analysis_results: Existing REVENG analysis results
            file_path: Optional path to original file (if hash not in results)

        Returns:
            Enhanced analysis results with VT intelligence
        """
        enriched = analysis_results.copy()

        # Get hash from results or calculate from file
        sha256 = analysis_results.get('sha256')
        if not sha256 and file_path:
            sha256 = self.calculate_file_hash(file_path)
            enriched['sha256'] = sha256

        if not sha256:
            logger.warning("No SHA256 hash available for VT enrichment")
            return enriched

        # Lookup on VirusTotal
        vt_intel = self.lookup_hash(sha256)

        if vt_intel:
            # Add VT intelligence to results
            if 'threat_intel' not in enriched:
                enriched['threat_intel'] = {}

            enriched['threat_intel']['virustotal'] = {
                'detection_score': vt_intel.detection_score,
                'detections': vt_intel.detections,
                'suggested_family': vt_intel.suggested_family,
                'threat_labels': vt_intel.threat_labels,
                'tags': vt_intel.tags,
                'names': vt_intel.names,
                'first_seen': vt_intel.first_seen.isoformat() if vt_intel.first_seen else None,
                'last_seen': vt_intel.last_seen.isoformat() if vt_intel.last_seen else None,
                'sandbox_verdicts': vt_intel.sandbox_verdicts,
                'crowdsourced_yara_rules': vt_intel.crowdsourced_yara_rules,
                'vhash': vt_intel.vhash,
            }

            # Update threat score if VT detections are high
            malicious_count = vt_intel.detections.get('malicious', 0)
            if malicious_count > 10:  # More than 10 AVs detected it
                enriched['threat_score'] = max(
                    enriched.get('threat_score', 0),
                    min(100, 50 + malicious_count * 2)  # Scale based on detections
                )

            # Use VT family suggestion if not already classified
            if not enriched.get('family') and vt_intel.suggested_family:
                enriched['family'] = vt_intel.suggested_family

            logger.info(f"Enhanced analysis with VT intelligence: {vt_intel.detection_score}")
        else:
            logger.info(f"File {sha256} not found on VirusTotal - consider submitting")
            enriched['threat_intel']['virustotal'] = {
                'status': 'not_found',
                'message': 'File not found on VirusTotal. Consider submitting for analysis.'
            }

        return enriched

    def generate_report(self, vt_enrichment: VTEnrichment, format: str = 'text') -> str:
        """
        Generate human-readable report from VT enrichment data.

        Args:
            vt_enrichment: VT enrichment data
            format: Report format ('text' or 'markdown')

        Returns:
            Formatted report string
        """
        if format == 'markdown':
            report = f"# VirusTotal Intelligence Report\n\n"
            report += f"**SHA256:** `{vt_enrichment.sha256}`\n\n"
            report += f"## Detection Results\n\n"
            report += f"**Detection Score:** {vt_enrichment.detection_score}\n\n"
            report += f"| Category | Count |\n"
            report += f"|----------|-------|\n"
            for category, count in vt_enrichment.detections.items():
                if count > 0:
                    report += f"| {category.title()} | {count} |\n"

            if vt_enrichment.suggested_family:
                report += f"\n**Suggested Family:** {vt_enrichment.suggested_family}\n"

            if vt_enrichment.threat_labels:
                report += f"\n**Threat Labels:** {', '.join(vt_enrichment.threat_labels)}\n"

            if vt_enrichment.crowdsourced_yara_rules:
                report += f"\n## YARA Rule Matches\n\n"
                for rule in vt_enrichment.crowdsourced_yara_rules:
                    report += f"- **{rule['rule_name']}** ({rule['ruleset_name']})\n"
                    if rule.get('description'):
                        report += f"  - {rule['description']}\n"

            if vt_enrichment.sandbox_verdicts:
                report += f"\n## Sandbox Verdicts\n\n"
                for engine, verdict in list(vt_enrichment.sandbox_verdicts.items())[:10]:
                    report += f"- **{engine}:** {verdict}\n"

        else:  # text format
            report = f"VirusTotal Intelligence Report\n"
            report += f"{'=' * 60}\n\n"
            report += f"SHA256: {vt_enrichment.sha256}\n\n"
            report += f"Detection Score: {vt_enrichment.detection_score}\n"
            report += f"Detections:\n"
            for category, count in vt_enrichment.detections.items():
                if count > 0:
                    report += f"  - {category.title()}: {count}\n"

            if vt_enrichment.suggested_family:
                report += f"\nSuggested Family: {vt_enrichment.suggested_family}\n"

            if vt_enrichment.threat_labels:
                report += f"Threat Labels: {', '.join(vt_enrichment.threat_labels)}\n"

            if vt_enrichment.crowdsourced_yara_rules:
                report += f"\nYARA Rule Matches: {len(vt_enrichment.crowdsourced_yara_rules)}\n"
                for rule in vt_enrichment.crowdsourced_yara_rules[:5]:
                    report += f"  - {rule['rule_name']} ({rule['ruleset_name']})\n"

        return report

    def close(self):
        """Close VirusTotal client connection"""
        if self.client:
            self.client.close()
            logger.info("VirusTotal client closed")

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()


# Convenience function for quick lookups
def quick_lookup(file_path: str, api_key: Optional[str] = None) -> Optional[VTEnrichment]:
    """
    Quick VirusTotal lookup for a file.

    Args:
        file_path: Path to file to lookup
        api_key: Optional VT API key

    Returns:
        VTEnrichment object or None
    """
    with VirusTotalConnector(api_key) as vt:
        return vt.lookup_file(file_path)
