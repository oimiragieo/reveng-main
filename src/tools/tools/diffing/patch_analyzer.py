"""
Patch Analyzer for REVENG

Analyzes security patches to identify what vulnerabilities were fixed.
Performs "vulnerability archaeology" - working backwards from patch to vuln.
"""

import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

from .binary_differ import BinaryDiffer, DiffResult

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class Vulnerability:
    """Identified vulnerability from patch analysis"""
    function_name: str
    vuln_type: str  # 'buffer_overflow', 'integer_overflow', 'use_after_free', etc.
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    cve: Optional[str]  # CVE identifier if known
    exploitability: str  # 'high', 'medium', 'low', 'unknown'
    changes_description: str
    affected_code: Optional[str]
    patched_code: Optional[str]


class PatchAnalyzer:
    """
    Security patch analyzer.

    Analyzes differences between unpatched and patched binaries
    to identify what vulnerabilities were fixed.
    """

    def __init__(self, use_ai: bool = True):
        """
        Initialize patch analyzer.

        Args:
            use_ai: Whether to use AI for vulnerability analysis
        """
        self.differ = BinaryDiffer(similarity_threshold=0.7)
        self.use_ai = use_ai and OLLAMA_AVAILABLE
        logger.info(f"Patch analyzer initialized (AI: {self.use_ai})")

    def analyze_patch(
        self,
        unpatched_binary: str,
        patched_binary: str,
        cve: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Analyze security patch to identify fixed vulnerabilities.

        Args:
            unpatched_binary: Path to unpatched binary
            patched_binary: Path to patched binary
            cve: Optional CVE identifier for reference

        Returns:
            List of identified vulnerabilities
        """
        logger.info(f"Analyzing patch: {unpatched_binary} -> {patched_binary}")

        # First, perform binary diff
        diff_result = self.differ.diff(
            unpatched_binary,
            patched_binary,
            deep_analysis=True
        )

        # Analyze modified functions for security fixes
        vulnerabilities = []

        for mod_func in diff_result.modified_functions:
            # Focus on functions with significant changes
            if mod_func.similarity < 0.95:  # More than 5% changed
                vuln = self._analyze_function_changes(
                    mod_func,
                    diff_result,
                    cve
                )

                if vuln:
                    vulnerabilities.append(vuln)

        # Also check new functions (might be new security checks)
        for new_func in diff_result.new_functions[:5]:  # Check first 5 new functions
            if self._is_security_function(new_func):
                logger.info(f"New security function added: {new_func}")

        logger.info(f"Identified {len(vulnerabilities)} potential vulnerabilities")

        return vulnerabilities

    def _analyze_function_changes(
        self,
        mod_func,
        diff_result: DiffResult,
        cve: Optional[str]
    ) -> Optional[Vulnerability]:
        """Analyze changes in a modified function to identify vulnerability"""
        if self.use_ai:
            return self._ai_analyze_changes(mod_func, cve)
        else:
            return self._heuristic_analyze_changes(mod_func, cve)

    def _ai_analyze_changes(
        self,
        mod_func,
        cve: Optional[str]
    ) -> Optional[Vulnerability]:
        """Use AI to analyze function changes"""
        # Prepare context for AI
        changes_desc = '\n'.join(mod_func.changes) if mod_func.changes else "Code modified"

        prompt = f"""Analyze this security patch to identify the vulnerability that was fixed.

Function: {mod_func.func_v1_name} -> {mod_func.func_v2_name}
Similarity: {mod_func.similarity:.1%}
Changes: {changes_desc}
{f'CVE: {cve}' if cve else ''}

Based on these changes, determine:
1. What type of vulnerability was likely fixed (buffer overflow, integer overflow, use-after-free, etc.)
2. How severe is this vulnerability (critical, high, medium, low)
3. How exploitable is it (high, medium, low)
4. Brief description of the vulnerability

Return JSON format:
{{
  "vuln_type": "type_here",
  "severity": "severity_here",
  "exploitability": "level_here",
  "description": "description_here"
}}"""

        try:
            response = ollama.chat(
                model='llama3',
                messages=[{'role': 'user', 'content': prompt}],
                options={'temperature': 0.3}
            )

            content = response['message']['content']

            # Parse JSON response
            import json
            import re

            json_match = re.search(r'\{[^}]+\}', content, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())

                return Vulnerability(
                    function_name=mod_func.func_v1_name,
                    vuln_type=analysis.get('vuln_type', 'unknown'),
                    severity=analysis.get('severity', 'unknown'),
                    description=analysis.get('description', 'Unknown vulnerability'),
                    cve=cve,
                    exploitability=analysis.get('exploitability', 'unknown'),
                    changes_description=changes_desc,
                    affected_code=None,  # Would need actual code
                    patched_code=None
                )

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")

        return None

    def _heuristic_analyze_changes(
        self,
        mod_func,
        cve: Optional[str]
    ) -> Optional[Vulnerability]:
        """Use heuristics to analyze function changes"""
        changes = mod_func.changes if mod_func.changes else []
        changes_text = ' '.join(changes).lower()

        # Pattern matching for common vulnerability types
        vuln_patterns = {
            'buffer_overflow': ['bounds check', 'buffer', 'overflow', 'length check'],
            'integer_overflow': ['integer', 'overflow', 'arithmetic', 'size check'],
            'use_after_free': ['free', 'delete', 'null check', 'freed'],
            'null_pointer': ['null', 'nullptr', 'null check'],
            'format_string': ['format', 'printf', 'sprintf'],
            'injection': ['validation', 'sanitize', 'escape'],
        }

        detected_type = 'unknown'
        confidence = 0.0

        for vuln_type, keywords in vuln_patterns.items():
            matches = sum(1 for keyword in keywords if keyword in changes_text)
            if matches > confidence:
                confidence = matches
                detected_type = vuln_type

        if detected_type != 'unknown':
            # Estimate severity based on type
            severity_map = {
                'buffer_overflow': 'high',
                'integer_overflow': 'medium',
                'use_after_free': 'high',
                'null_pointer': 'medium',
                'format_string': 'high',
                'injection': 'critical',
            }

            exploitability_map = {
                'buffer_overflow': 'high',
                'integer_overflow': 'medium',
                'use_after_free': 'high',
                'null_pointer': 'low',
                'format_string': 'medium',
                'injection': 'high',
            }

            return Vulnerability(
                function_name=mod_func.func_v1_name,
                vuln_type=detected_type,
                severity=severity_map.get(detected_type, 'medium'),
                description=f"Potential {detected_type.replace('_', ' ')} vulnerability fixed",
                cve=cve,
                exploitability=exploitability_map.get(detected_type, 'unknown'),
                changes_description=' '.join(changes),
                affected_code=None,
                patched_code=None
            )

        return None

    def _is_security_function(self, func_name: str) -> bool:
        """Check if function name suggests security-related functionality"""
        security_keywords = [
            'check', 'validate', 'verify', 'sanitize',
            'secure', 'safe', 'bounds', 'guard'
        ]

        func_lower = func_name.lower()
        return any(keyword in func_lower for keyword in security_keywords)

    def generate_report(
        self,
        vulnerabilities: List[Vulnerability],
        format: str = 'text'
    ) -> str:
        """Generate vulnerability report from patch analysis"""
        if format == 'markdown':
            report = f"# Security Patch Analysis Report\n\n"
            report += f"**Vulnerabilities Identified:** {len(vulnerabilities)}\n\n"

            # Group by severity
            by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
            for vuln in vulnerabilities:
                severity = vuln.severity.lower()
                if severity in by_severity:
                    by_severity[severity].append(vuln)

            for severity in ['critical', 'high', 'medium', 'low']:
                vulns = by_severity[severity]
                if vulns:
                    report += f"## {severity.upper()} Severity ({len(vulns)})\n\n"

                    for vuln in vulns:
                        report += f"### {vuln.function_name}\n\n"
                        if vuln.cve:
                            report += f"**CVE:** {vuln.cve}\n\n"
                        report += f"**Type:** {vuln.vuln_type.replace('_', ' ').title()}\n"
                        report += f"**Exploitability:** {vuln.exploitability}\n\n"
                        report += f"**Description:** {vuln.description}\n\n"
                        report += f"**Changes:** {vuln.changes_description}\n\n"
                        report += "---\n\n"

        else:  # text format
            report = f"Security Patch Analysis Report\n"
            report += f"{'=' * 60}\n\n"
            report += f"Vulnerabilities Identified: {len(vulnerabilities)}\n\n"

            for idx, vuln in enumerate(vulnerabilities, 1):
                report += f"{idx}. {vuln.function_name}\n"
                if vuln.cve:
                    report += f"   CVE: {vuln.cve}\n"
                report += f"   Type: {vuln.vuln_type.replace('_', ' ').title()}\n"
                report += f"   Severity: {vuln.severity.upper()}\n"
                report += f"   Exploitability: {vuln.exploitability}\n"
                report += f"   Description: {vuln.description}\n"
                report += f"   Changes: {vuln.changes_description}\n\n"

        return report


# Convenience function
def analyze_patch(unpatched: str, patched: str, cve: Optional[str] = None) -> List[Vulnerability]:
    """Quick patch analysis"""
    analyzer = PatchAnalyzer()
    return analyzer.analyze_patch(unpatched, patched, cve)
