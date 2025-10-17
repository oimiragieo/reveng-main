"""
YARA Scanner for REVENG

Scans binaries using YARA rules for threat detection and classification.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class YARAMatch:
    """YARA match result"""
    rule_name: str
    namespace: str
    tags: List[str]
    meta: Dict[str, Any]
    strings: List[Tuple[int, str, bytes]]  # (offset, identifier, data)


class YARAScanner:
    """
    YARA rule scanner for binary analysis.

    Provides scanning capabilities using YARA rules from files or directories.
    """

    def __init__(self, rules_path: Optional[str] = None):
        """
        Initialize YARA scanner.

        Args:
            rules_path: Path to YARA rules file or directory
        """
        if not YARA_AVAILABLE:
            raise ImportError(
                "YARA scanner requires 'yara-python' package. "
                "Install with: pip install yara-python"
            )

        self.rules = None
        if rules_path:
            self.load_rules(rules_path)

        logger.info("YARA scanner initialized")

    def load_rules(self, rules_path: str):
        """
        Load YARA rules from file or directory.

        Args:
            rules_path: Path to rules file (.yar) or directory
        """
        path = Path(rules_path)

        try:
            if path.is_file():
                # Single rule file
                self.rules = yara.compile(filepath=str(path))
                logger.info(f"Loaded YARA rules from {path}")

            elif path.is_dir():
                # Directory of rule files
                rule_files = {}
                for rule_file in path.glob('*.yar'):
                    namespace = rule_file.stem
                    rule_files[namespace] = str(rule_file)

                if rule_files:
                    self.rules = yara.compile(filepaths=rule_files)
                    logger.info(f"Loaded {len(rule_files)} YARA rule files from {path}")
                else:
                    logger.warning(f"No .yar files found in {path}")

            else:
                raise ValueError(f"Invalid rules path: {rules_path}")

        except Exception as e:
            logger.error(f"Failed to load YARA rules: {e}")
            raise

    def scan_file(self, file_path: str) -> List[YARAMatch]:
        """
        Scan file with YARA rules.

        Args:
            file_path: Path to file to scan

        Returns:
            List of YARA matches
        """
        if not self.rules:
            logger.warning("No YARA rules loaded")
            return []

        matches = []

        try:
            yara_matches = self.rules.match(file_path)

            for match in yara_matches:
                # Extract string matches
                string_matches = [
                    (offset, identifier, data)
                    for offset, identifier, data in match.strings
                ]

                yara_match = YARAMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=match.tags,
                    meta=match.meta,
                    strings=string_matches
                )

                matches.append(yara_match)

            if matches:
                logger.info(f"Found {len(matches)} YARA matches in {file_path}")

        except Exception as e:
            logger.error(f"YARA scan failed: {e}")

        return matches

    def scan_data(self, data: bytes) -> List[YARAMatch]:
        """
        Scan binary data with YARA rules.

        Args:
            data: Binary data to scan

        Returns:
            List of YARA matches
        """
        if not self.rules:
            logger.warning("No YARA rules loaded")
            return []

        matches = []

        try:
            yara_matches = self.rules.match(data=data)

            for match in yara_matches:
                string_matches = [
                    (offset, identifier, data)
                    for offset, identifier, data in match.strings
                ]

                yara_match = YARAMatch(
                    rule_name=match.rule,
                    namespace=match.namespace,
                    tags=match.tags,
                    meta=match.meta,
                    strings=string_matches
                )

                matches.append(yara_match)

        except Exception as e:
            logger.error(f"YARA scan failed: {e}")

        return matches

    def enrich_analysis(
        self,
        analysis_results: Dict[str, Any],
        file_path: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enrich REVENG analysis with YARA scan results.

        Args:
            analysis_results: Existing analysis results
            file_path: Optional path to binary file

        Returns:
            Enhanced analysis results
        """
        enriched = analysis_results.copy()

        # Get file path from results if not provided
        if not file_path:
            file_path = analysis_results.get('binary_path')

        if not file_path:
            logger.warning("No file path available for YARA scan")
            return enriched

        # Scan with YARA
        matches = self.scan_file(file_path)

        if matches:
            if 'threat_intel' not in enriched:
                enriched['threat_intel'] = {}

            enriched['threat_intel']['yara_matches'] = [
                {
                    'rule': match.rule_name,
                    'namespace': match.namespace,
                    'tags': match.tags,
                    'meta': match.meta,
                    'string_count': len(match.strings)
                }
                for match in matches
            ]

            # Extract family info from YARA matches if available
            for match in matches:
                if 'family' in match.meta and not enriched.get('family'):
                    enriched['family'] = match.meta['family']

            logger.info(f"Enhanced analysis with {len(matches)} YARA matches")

        return enriched
