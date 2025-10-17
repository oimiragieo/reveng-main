"""
Instant Triage Engine for REVENG

Provides rapid threat assessment in <30 seconds for incident response.
Includes threat scoring, capability detection, and automated hypothesis generation.
"""

import hashlib
import logging
import time
import struct
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from datetime import datetime

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class TriageResult:
    """Instant triage analysis result"""
    sha256: str
    file_path: str
    threat_score: int  # 0-100
    priority: str  # critical, high, medium, low, benign
    classification: str
    capabilities: List[str]
    quick_iocs: List[Dict[str, str]]
    hypothesis: str
    confidence: float
    analysis_time: float
    recommendations: List[str]
    packing_detected: bool
    entropy: float


class InstantTriageEngine:
    """
    Rapid threat assessment engine for incident response.

    Performs quick (<30 second) analysis to classify threats and
    prioritize investigation efforts.
    """

    def __init__(self, time_limit: int = 30, use_ml: bool = True):
        """
        Initialize instant triage engine.

        Args:
            time_limit: Maximum analysis time in seconds
            use_ml: Whether to use ML-based classification
        """
        self.time_limit = time_limit
        self.use_ml = use_ml
        logger.info(f"Instant triage engine initialized (limit: {time_limit}s)")

    def triage(self, file_path: str) -> TriageResult:
        """
        Perform rapid triage analysis on binary.

        Args:
            file_path: Path to binary file

        Returns:
            Triage result with threat assessment
        """
        start_time = time.time()

        # Calculate hash
        sha256 = self._calculate_hash(file_path)

        # Initialize result
        result = TriageResult(
            sha256=sha256,
            file_path=file_path,
            threat_score=0,
            priority='unknown',
            classification='unknown',
            capabilities=[],
            quick_iocs=[],
            hypothesis='',
            confidence=0.0,
            analysis_time=0.0,
            recommendations=[],
            packing_detected=False,
            entropy=0.0
        )

        # Quick static analysis (10-15 seconds)
        try:
            static_results = self._quick_static_scan(file_path)
            result.capabilities = static_results['capabilities']
            result.quick_iocs = static_results['iocs']
            result.packing_detected = static_results['packing_detected']
            result.entropy = static_results['entropy']
        except Exception as e:
            logger.error(f"Quick static scan failed: {e}")

        # Threat scoring (5 seconds)
        try:
            result.threat_score = self._calculate_threat_score(static_results)
            result.classification = self._classify_threat(result.threat_score, static_results)
        except Exception as e:
            logger.error(f"Threat scoring failed: {e}")

        # Priority determination
        result.priority = self._determine_priority(result.threat_score, result.capabilities)

        # Generate hypothesis (5-10 seconds)
        try:
            result.hypothesis = self._generate_hypothesis(result, static_results)
            result.confidence = self._calculate_confidence(result)
        except Exception as e:
            logger.error(f"Hypothesis generation failed: {e}")
            result.hypothesis = "Unable to generate hypothesis."

        # Generate recommendations
        result.recommendations = self._generate_recommendations(result)

        result.analysis_time = time.time() - start_time

        logger.info(
            f"Triage complete: {file_path} -> {result.priority} "
            f"(score: {result.threat_score}) in {result.analysis_time:.1f}s"
        )

        return result

    def _calculate_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash"""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data"""
        if not data:
            return 0.0

        entropy = 0.0
        byte_counts = [0] * 256

        for byte in data:
            byte_counts[byte] += 1

        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                prob = count / data_len
                entropy -= prob * (prob ** 0.5)  # Simplified entropy

        return min(entropy, 8.0)  # Normalize to 0-8

    def _quick_static_scan(self, file_path: str) -> Dict[str, Any]:
        """
        Quick static analysis (10-15 seconds).

        Returns dict with:
        - capabilities: List of detected capabilities
        - iocs: List of IOCs (IPs, domains, URLs)
        - packing_detected: Boolean
        - entropy: File entropy
        - suspicious_imports: List of suspicious API calls
        """
        results = {
            'capabilities': [],
            'iocs': [],
            'packing_detected': False,
            'entropy': 0.0,
            'suspicious_imports': [],
            'file_type': 'unknown',
            'pe_characteristics': {}
        }

        try:
            with open(file_path, 'rb') as f:
                data = f.read(min(1024 * 1024, f.seek(0, 2)))  # Read up to 1MB
                f.seek(0)

                # Calculate entropy
                results['entropy'] = self._calculate_entropy(data)

                # Packing detection (entropy > 7.2 suggests compression/packing)
                if results['entropy'] > 7.2:
                    results['packing_detected'] = True
                    results['capabilities'].append('packed_or_encrypted')

                # Check PE header
                if data[:2] == b'MZ':
                    results['file_type'] = 'PE'
                    results.update(self._analyze_pe_quick(data))

                # Extract strings for capability/IOC detection
                strings = self._extract_quick_strings(data)
                results.update(self._analyze_strings(strings))

        except Exception as e:
            logger.error(f"Quick static scan error: {e}")

        return results

    def _analyze_pe_quick(self, data: bytes) -> Dict[str, Any]:
        """Quick PE file analysis"""
        results = {
            'pe_characteristics': {},
            'suspicious_imports': []
        }

        try:
            # Read PE header offset
            if len(data) < 0x3C + 4:
                return results

            pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]

            if pe_offset + 24 > len(data):
                return results

            # Check PE signature
            if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                return results

            # Read characteristics
            characteristics = struct.unpack('<H', data[pe_offset+22:pe_offset+24])[0]

            results['pe_characteristics'] = {
                'executable': bool(characteristics & 0x0002),
                'dll': bool(characteristics & 0x2000),
                'system': bool(characteristics & 0x1000)
            }

        except Exception as e:
            logger.error(f"PE analysis error: {e}")

        return results

    def _extract_quick_strings(self, data: bytes, min_length: int = 6) -> List[str]:
        """Quick string extraction (ASCII only for speed)"""
        strings = []

        # ASCII pattern
        pattern = rb'[\x20-\x7E]{' + str(min_length).encode() + rb',}'
        matches = re.findall(pattern, data[:500000])  # Limit to 500KB for speed

        for match in matches[:200]:  # Limit results
            try:
                strings.append(match.decode('ascii'))
            except:
                pass

        return strings

    def _analyze_strings(self, strings: List[str]) -> Dict[str, Any]:
        """Analyze strings for capabilities and IOCs"""
        results = {
            'capabilities': [],
            'iocs': []
        }

        # Capability detection patterns
        capability_patterns = {
            'network': [
                r'(socket|connect|send|recv|http|ftp|tcp|udp)',
                r'(wininet|urlmon|ws2_32)',
                r'(internet|download|upload)'
            ],
            'file_operations': [
                r'(createfile|readfile|writefile|deletefile)',
                r'(copy|move|rename).*file'
            ],
            'registry': [
                r'(regopen|regset|regquery|regdelete)',
                r'(hkey_|software\\)',
                r'registry'
            ],
            'process': [
                r'(createprocess|shellexecute|winexec)',
                r'(process|thread)',
                r'(inject|hook)'
            ],
            'persistence': [
                r'(startup|autorun|service)',
                r'(schtasks|at\.exe)',
                r'(run|runonce)'
            ],
            'crypto': [
                r'(crypt|encrypt|decrypt|cipher)',
                r'(aes|rsa|md5|sha|base64)',
                r'(key|iv|salt)'
            ],
            'evasion': [
                r'(debug|isdebuggerpresent)',
                r'(virtual|vmware|vbox)',
                r'(sleep|delay|wait)'
            ],
            'data_theft': [
                r'(password|credential|cookie|keylog)',
                r'(chrome|firefox|outlook|wallet)',
                r'(screenshot|clipboard)'
            ]
        }

        # IOC patterns
        ioc_patterns = {
            'ip': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
            'domain': r'\b[a-z0-9][a-z0-9-]*\.[a-z]{2,}\b',
            'url': r'https?://[^\s]+',
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        }

        for string in strings:
            string_lower = string.lower()

            # Check capabilities
            for capability, patterns in capability_patterns.items():
                if capability not in results['capabilities']:
                    for pattern in patterns:
                        if re.search(pattern, string_lower, re.IGNORECASE):
                            results['capabilities'].append(capability)
                            break

            # Extract IOCs
            for ioc_type, pattern in ioc_patterns.items():
                matches = re.findall(pattern, string, re.IGNORECASE)
                for match in matches:
                    # Filter out common false positives
                    if ioc_type == 'ip' and match.startswith(('127.', '0.0.', '255.')):
                        continue
                    if ioc_type == 'domain' and match in ['microsoft.com', 'windows.com']:
                        continue

                    results['iocs'].append({
                        'type': ioc_type,
                        'value': match
                    })

        # Remove duplicate IOCs
        seen = set()
        unique_iocs = []
        for ioc in results['iocs']:
            ioc_tuple = (ioc['type'], ioc['value'])
            if ioc_tuple not in seen:
                seen.add(ioc_tuple)
                unique_iocs.append(ioc)

        results['iocs'] = unique_iocs[:50]  # Limit to 50 IOCs

        return results

    def _calculate_threat_score(self, static_results: Dict[str, Any]) -> int:
        """Calculate threat score (0-100)"""
        score = 0

        # Base score from entropy (packed files are suspicious)
        entropy = static_results.get('entropy', 0)
        if entropy > 7.5:
            score += 30
        elif entropy > 7.0:
            score += 20
        elif entropy > 6.5:
            score += 10

        # Capability-based scoring
        capabilities = static_results.get('capabilities', [])
        capability_scores = {
            'process': 15,  # Process manipulation
            'persistence': 20,  # Persistence mechanisms
            'evasion': 25,  # Anti-analysis
            'data_theft': 30,  # Credential stealing
            'crypto': 10,  # Encryption (could be ransomware)
            'network': 10,  # Network communication
            'registry': 5,
            'file_operations': 5
        }

        for capability in capabilities:
            score += capability_scores.get(capability, 5)

        # IOC count boost
        ioc_count = len(static_results.get('iocs', []))
        if ioc_count > 10:
            score += 20
        elif ioc_count > 5:
            score += 10

        # Suspicious import bonus
        suspicious_imports = static_results.get('suspicious_imports', [])
        score += min(len(suspicious_imports) * 5, 20)

        # Cap at 100
        return min(score, 100)

    def _classify_threat(self, threat_score: int, static_results: Dict[str, Any]) -> str:
        """Classify threat type based on score and capabilities"""
        capabilities = static_results.get('capabilities', [])

        # High-confidence classifications
        if 'data_theft' in capabilities and 'network' in capabilities:
            return 'infostealer'
        elif 'crypto' in capabilities and 'file_operations' in capabilities:
            return 'ransomware'
        elif 'process' in capabilities and 'evasion' in capabilities:
            return 'trojan'
        elif 'network' in capabilities and threat_score > 60:
            return 'backdoor'
        elif 'persistence' in capabilities:
            return 'malware'

        # Score-based classification
        if threat_score >= 70:
            return 'malware'
        elif threat_score >= 40:
            return 'suspicious'
        else:
            return 'unknown'

    def _determine_priority(self, threat_score: int, capabilities: List[str]) -> str:
        """Determine investigation priority"""
        # Critical: Immediate threat
        if threat_score >= 80:
            return 'critical'

        # High: Significant threat indicators
        if threat_score >= 60:
            return 'high'

        # High for certain capabilities regardless of score
        critical_capabilities = {'data_theft', 'persistence', 'evasion'}
        if any(cap in critical_capabilities for cap in capabilities):
            return 'high'

        # Medium: Some suspicious behavior
        if threat_score >= 40:
            return 'medium'

        # Low: Minimal indicators
        if threat_score >= 20:
            return 'low'

        # Benign: No significant threats
        return 'benign'

    def _generate_hypothesis(
        self,
        result: TriageResult,
        static_results: Dict[str, Any]
    ) -> str:
        """Generate hypothesis about binary's purpose"""
        if OLLAMA_AVAILABLE:
            return self._llm_hypothesis(result, static_results)
        else:
            return self._heuristic_hypothesis(result, static_results)

    def _llm_hypothesis(
        self,
        result: TriageResult,
        static_results: Dict[str, Any]
    ) -> str:
        """Generate hypothesis using LLM"""
        try:
            # Prepare context
            context = f"""
Rapid triage analysis results:

Threat Score: {result.threat_score}/100
Priority: {result.priority}
Classification: {result.classification}
Capabilities: {', '.join(result.capabilities[:10])}
Packing Detected: {result.packing_detected}
Entropy: {result.entropy:.2f}
IOC Count: {len(result.quick_iocs)}
"""

            prompt = f"""{context}

Based on this quick analysis, provide a 2-3 sentence hypothesis about what this binary likely is and what it does. Be concise and specific."""

            response = ollama.chat(
                model='llama3',
                messages=[{'role': 'user', 'content': prompt}],
                options={'num_predict': 100}  # Limit response length
            )

            return response['message']['content']

        except Exception as e:
            logger.error(f"LLM hypothesis failed: {e}")
            return self._heuristic_hypothesis(result, static_results)

    def _heuristic_hypothesis(
        self,
        result: TriageResult,
        static_results: Dict[str, Any]
    ) -> str:
        """Generate hypothesis using heuristics"""
        capabilities = result.capabilities

        # Build hypothesis based on capabilities
        if 'data_theft' in capabilities and 'network' in capabilities:
            return "This binary appears to be an information stealer designed to harvest credentials and exfiltrate data over the network."

        elif 'crypto' in capabilities and 'file_operations' in capabilities:
            return "This binary shows characteristics of ransomware, with file encryption and manipulation capabilities."

        elif 'persistence' in capabilities and 'process' in capabilities:
            return "This binary demonstrates malware behavior with persistence mechanisms and process manipulation, likely a trojan."

        elif 'evasion' in capabilities:
            return "This binary contains anti-analysis techniques, suggesting malicious intent to evade detection."

        elif result.packing_detected:
            return "This binary is packed or encrypted, which is often used by malware to evade signature-based detection."

        elif result.threat_score >= 60:
            return "This binary exhibits multiple suspicious behaviors consistent with malicious software."

        elif result.threat_score >= 30:
            return "This binary shows some suspicious characteristics that warrant further investigation."

        else:
            return "This binary shows minimal threat indicators and may be legitimate software."

    def _calculate_confidence(self, result: TriageResult) -> float:
        """Calculate confidence in assessment"""
        confidence = 0.5  # Base confidence

        # Higher confidence for clear indicators
        if result.threat_score >= 80:
            confidence += 0.3
        elif result.threat_score >= 60:
            confidence += 0.2
        elif result.threat_score >= 40:
            confidence += 0.1

        # Capability diversity increases confidence
        if len(result.capabilities) >= 5:
            confidence += 0.1
        elif len(result.capabilities) >= 3:
            confidence += 0.05

        # IOC presence increases confidence
        if len(result.quick_iocs) >= 10:
            confidence += 0.1
        elif len(result.quick_iocs) >= 5:
            confidence += 0.05

        return min(confidence, 1.0)

    def _generate_recommendations(self, result: TriageResult) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []

        if result.priority == 'critical':
            recommendations.append("⚠️  URGENT: Quarantine immediately and begin full forensic analysis")
            recommendations.append("Isolate affected systems from network")
            recommendations.append("Alert security operations center (SOC)")

        elif result.priority == 'high':
            recommendations.append("Run full REVENG analysis with all enhanced features")
            recommendations.append("Submit to sandbox for dynamic analysis")
            recommendations.append("Check VirusTotal for known detections")

        elif result.priority == 'medium':
            recommendations.append("Perform detailed static analysis")
            recommendations.append("Scan with YARA rules")
            recommendations.append("Monitor for network connections if executed")

        elif result.priority == 'low':
            recommendations.append("Consider deeper analysis if context suggests suspicion")
            recommendations.append("Document findings for reference")

        else:  # benign
            recommendations.append("No immediate action required")
            recommendations.append("Archive for future reference if needed")

        # Specific recommendations based on capabilities
        if 'data_theft' in result.capabilities:
            recommendations.append("🔍 Check for credential harvesting and data exfiltration")

        if result.packing_detected:
            recommendations.append("📦 Unpack binary before deeper analysis")

        if 'persistence' in result.capabilities:
            recommendations.append("🔒 Check for persistence mechanisms (startup, services, registry)")

        return recommendations

    def batch_triage(
        self,
        file_paths: List[str],
        parallel: bool = False
    ) -> List[TriageResult]:
        """
        Batch triage multiple files.

        Args:
            file_paths: List of file paths to triage
            parallel: Whether to process in parallel (future enhancement)

        Returns:
            List of triage results
        """
        results = []

        logger.info(f"Batch triage: processing {len(file_paths)} files")

        for file_path in file_paths:
            try:
                result = self.triage(file_path)
                results.append(result)
            except Exception as e:
                logger.error(f"Triage failed for {file_path}: {e}")

        # Sort by priority/threat score
        results.sort(key=lambda r: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'benign': 4}.get(r.priority, 5),
            -r.threat_score
        ))

        logger.info(f"Batch triage complete: {len(results)} files processed")

        return results

    def generate_report(self, result: TriageResult, format: str = 'text') -> str:
        """Generate triage report"""
        if format == 'markdown':
            report = f"# Instant Triage Report\n\n"
            report += f"**File:** `{Path(result.file_path).name}`\n"
            report += f"**SHA256:** `{result.sha256}`\n"
            report += f"**Analysis Time:** {result.analysis_time:.2f}s\n\n"

            report += f"## Threat Assessment\n\n"
            report += f"- **Priority:** {result.priority.upper()}\n"
            report += f"- **Threat Score:** {result.threat_score}/100\n"
            report += f"- **Classification:** {result.classification}\n"
            report += f"- **Confidence:** {result.confidence:.0%}\n\n"

            if result.packing_detected:
                report += f"⚠️  **Packing Detected** (Entropy: {result.entropy:.2f})\n\n"

            report += f"## Hypothesis\n\n{result.hypothesis}\n\n"

            if result.capabilities:
                report += f"## Detected Capabilities\n\n"
                for cap in result.capabilities:
                    report += f"- {cap}\n"
                report += "\n"

            if result.quick_iocs:
                report += f"## Quick IOCs ({len(result.quick_iocs)})\n\n"
                for ioc in result.quick_iocs[:10]:
                    report += f"- **{ioc['type']}:** {ioc['value']}\n"
                if len(result.quick_iocs) > 10:
                    report += f"- ...and {len(result.quick_iocs) - 10} more\n"
                report += "\n"

            if result.recommendations:
                report += f"## Recommendations\n\n"
                for rec in result.recommendations:
                    report += f"- {rec}\n"

        else:  # text format
            report = f"Instant Triage Report\n"
            report += f"{'=' * 60}\n\n"
            report += f"File: {Path(result.file_path).name}\n"
            report += f"SHA256: {result.sha256}\n"
            report += f"Analysis Time: {result.analysis_time:.2f}s\n\n"

            report += f"THREAT ASSESSMENT:\n"
            report += f"  Priority: {result.priority.upper()}\n"
            report += f"  Threat Score: {result.threat_score}/100\n"
            report += f"  Classification: {result.classification}\n"
            report += f"  Confidence: {result.confidence:.0%}\n\n"

            if result.packing_detected:
                report += f"  ⚠️  PACKED (Entropy: {result.entropy:.2f})\n\n"

            report += f"HYPOTHESIS:\n{result.hypothesis}\n\n"

            if result.capabilities:
                report += f"CAPABILITIES ({len(result.capabilities)}):\n"
                for cap in result.capabilities:
                    report += f"  - {cap}\n"
                report += "\n"

            if result.recommendations:
                report += f"RECOMMENDATIONS:\n"
                for rec in result.recommendations:
                    report += f"  - {rec}\n"

        return report


# Convenience function
def quick_triage(file_path: str) -> TriageResult:
    """Quick triage of a single file"""
    engine = InstantTriageEngine()
    return engine.triage(file_path)
