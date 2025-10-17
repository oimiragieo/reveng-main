"""
AI-Optimized Python API for REVENG

Provides a clean, type-hinted programmatic interface designed specifically
for AI agents (Claude, GPT, etc.) to use REVENG for binary analysis and
reverse engineering tasks.

Key features for AI agents:
- Structured responses with dataclasses (not raw strings)
- Confidence scores for all responses
- JSON serialization built-in
- Comprehensive type hints
- Synchronous API (simple for AI agents)
- Clear error handling
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Import REVENG components
from ..tools.instant_triage import InstantTriageEngine, ThreatLevel
from ..tools.tools.ai_enhanced.nl_interface import NaturalLanguageInterface, NLResponse
from ..tools.tools.translation import generate_translation_hints, generate_translation_guide

logger = logging.getLogger(__name__)


class AnalysisMode(Enum):
    """Analysis depth levels"""

    QUICK = "quick"  # Triage only (fastest)
    STANDARD = "standard"  # Standard analysis
    DEEP = "deep"  # Full analysis with all features
    REBUILD = "rebuild"  # Analysis + translation hints for code rebuild


@dataclass
class TriageResult:
    """Results from instant triage analysis."""

    threat_level: str  # ThreatLevel enum value
    threat_score: int  # 0-100
    is_malicious: bool
    confidence: float  # 0.0-1.0
    detected_capabilities: List[str]
    recommended_action: str
    analysis_time_ms: int
    metadata: Dict[str, Any]

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


@dataclass
class CryptoDetails:
    """Cryptography-related findings."""

    algorithms: List[str]
    key_operations: List[str]
    confidence: float
    suspicious_patterns: List[str]
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class NetworkDetails:
    """Network-related findings."""

    protocols: List[str]
    endpoints: List[str]  # IPs, domains, URLs
    ports: List[int]
    c2_indicators: List[str]
    confidence: float
    notes: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TranslationGuide:
    """C-to-Python translation guide."""

    hints: List[Dict[str, Any]]  # List of TranslationHint dicts
    complexity: str  # simple, moderate, complex
    imports_needed: List[str]
    summary: Dict[str, Any]
    statistics: Dict[str, Any]

    def to_dict(self) -> dict:
        return asdict(self)

    def to_markdown(self) -> str:
        """Generate markdown translation guide."""
        # This would be populated by generate_translation_guide
        return ""


class REVENG_AI_API:
    """
    AI-optimized Python API for REVENG.

    Designed for AI agents to programmatically control REVENG and
    retrieve structured analysis results.

    Example usage:
    ```python
    api = REVENG_AI_API()

    # Quick triage
    triage = api.triage_binary("suspicious.exe")
    if triage.is_malicious:
        print(f"Threat: {triage.threat_level} (score: {triage.threat_score})")

    # Natural language queries
    response = api.ask("What does this binary do?", "suspicious.exe")
    print(f"Answer: {response.answer} (confidence: {response.confidence})")

    # Get translation hints for rebuild
    hints = api.get_translation_hints("decompiled_code.c")
    print(f"Need to import: {hints.imports_needed}")
    ```
    """

    def __init__(
        self, use_ollama: bool = True, ollama_model: str = "auto", output_dir: Optional[str] = None
    ):
        """
        Initialize AI-optimized API.

        Args:
            use_ollama: Enable local LLM via Ollama (recommended)
            ollama_model: Ollama model to use ('auto', 'llama3', 'mistral')
            output_dir: Custom output directory for analysis results
        """
        self.use_ollama = use_ollama
        self.ollama_model = ollama_model
        self.output_dir = Path(output_dir) if output_dir else None

        # Initialize components
        self.triage_engine = InstantTriageEngine()
        self.nl_interface = NaturalLanguageInterface(model=ollama_model, use_ollama=use_ollama)

        logger.info("REVENG AI API initialized")

    def triage_binary(self, binary_path: str, include_reasoning: bool = True) -> TriageResult:
        """
        Perform instant triage on a binary.

        Fast (<30 second) initial assessment to determine if binary is
        malicious and what capabilities it has.

        Args:
            binary_path: Path to binary file
            include_reasoning: Include detailed reasoning in metadata

        Returns:
            TriageResult with threat level, score, and capabilities
        """
        import time

        start_time = time.time()

        # Run triage
        triage_data = self.triage_engine.triage(binary_path)

        elapsed_ms = int((time.time() - start_time) * 1000)

        # Extract key information
        threat_level = triage_data.get("threat_level", ThreatLevel.UNKNOWN.value)
        threat_score = triage_data.get("threat_score", 0)
        capabilities = triage_data.get("capabilities", [])

        # Determine if malicious
        is_malicious = (
            threat_level in [ThreatLevel.HIGH.value, ThreatLevel.CRITICAL.value]
            or threat_score >= 70
        )

        # Calculate confidence based on number of indicators
        indicators = triage_data.get("indicators", [])
        confidence = min(len(indicators) / 10, 0.95)  # 10+ indicators = high confidence

        # Recommended action
        if threat_score >= 80:
            action = "Immediate containment recommended. Do not execute."
        elif threat_score >= 60:
            action = "High risk. Perform deep analysis in sandbox."
        elif threat_score >= 40:
            action = "Medium risk. Standard analysis recommended."
        else:
            action = "Low risk. Monitor and analyze if needed."

        # Metadata
        metadata = {
            "indicators_count": len(indicators),
            "file_type": triage_data.get("file_type"),
            "architecture": triage_data.get("architecture"),
        }

        if include_reasoning:
            metadata["reasoning"] = triage_data.get("reasoning", "")
            metadata["indicators"] = indicators

        return TriageResult(
            threat_level=threat_level,
            threat_score=threat_score,
            is_malicious=is_malicious,
            confidence=confidence,
            detected_capabilities=capabilities,
            recommended_action=action,
            analysis_time_ms=elapsed_ms,
            metadata=metadata,
        )

    def ask(
        self,
        question: str,
        binary_path: Optional[str] = None,
        analysis_results: Optional[Dict[str, Any]] = None,
    ) -> NLResponse:
        """
        Ask a natural language question about a binary.

        Examples:
        - "What does this binary do?"
        - "Is this malware dangerous?"
        - "Show me network-related functions"
        - "Extract all IOCs"

        Args:
            question: Natural language question
            binary_path: Path to binary (if not already analyzed)
            analysis_results: Pre-existing analysis results (optional)

        Returns:
            NLResponse with answer, confidence score, and metadata
        """
        response = self.nl_interface.query(
            question=question, binary_path=binary_path, analysis_results=analysis_results
        )

        return response

    def get_crypto_details(
        self, binary_path: str, analysis_results: Optional[Dict[str, Any]] = None
    ) -> CryptoDetails:
        """
        Extract cryptography-related details from binary.

        Identifies:
        - Crypto algorithms (AES, RSA, MD5, SHA, etc.)
        - Key generation/management
        - Suspicious crypto usage (weak algorithms, hardcoded keys)

        Args:
            binary_path: Path to binary
            analysis_results: Pre-existing analysis results (optional)

        Returns:
            CryptoDetails with algorithms, operations, and confidence
        """
        # Use NL interface to extract crypto info
        response = self.ask(
            "What cryptographic algorithms and operations does this binary use?",
            binary_path=binary_path,
            analysis_results=analysis_results,
        )

        # Parse response for crypto details
        # (In production, would parse structured data from analysis results)
        answer_lower = response.answer.lower()

        algorithms = []
        if "aes" in answer_lower:
            algorithms.append("AES")
        if "rsa" in answer_lower:
            algorithms.append("RSA")
        if "md5" in answer_lower:
            algorithms.append("MD5")
        if "sha" in answer_lower:
            algorithms.append("SHA")

        suspicious = []
        if "md5" in answer_lower:
            suspicious.append("MD5 is cryptographically broken, avoid for security")
        if "hardcoded" in answer_lower:
            suspicious.append("Potential hardcoded keys detected")

        return CryptoDetails(
            algorithms=algorithms,
            key_operations=[],  # Would extract from structured data
            confidence=response.confidence,
            suspicious_patterns=suspicious,
            notes=response.answer,
        )

    def get_network_details(
        self, binary_path: str, analysis_results: Optional[Dict[str, Any]] = None
    ) -> NetworkDetails:
        """
        Extract network-related details from binary.

        Identifies:
        - Network protocols (HTTP, TCP, UDP, etc.)
        - Endpoints (IPs, domains, URLs)
        - Port usage
        - C2 infrastructure indicators

        Args:
            binary_path: Path to binary
            analysis_results: Pre-existing analysis results (optional)

        Returns:
            NetworkDetails with protocols, endpoints, and confidence
        """
        # Use NL interface to extract network info
        response = self.ask(
            "What network communication does this binary perform? List all IPs, domains, and URLs.",
            binary_path=binary_path,
            analysis_results=analysis_results,
        )

        # Parse response for network details
        # (In production, would parse structured IOCs from analysis results)
        answer = response.answer

        # Extract protocols
        protocols = []
        for proto in ["HTTP", "HTTPS", "TCP", "UDP", "DNS", "FTP"]:
            if proto.lower() in answer.lower():
                protocols.append(proto)

        return NetworkDetails(
            protocols=protocols,
            endpoints=[],  # Would extract from IOCs
            ports=[],  # Would extract from analysis
            c2_indicators=[],  # Would check against threat intel
            confidence=response.confidence,
            notes=response.answer,
        )

    def get_translation_hints(
        self, code_path: str, output_format: str = "structured"
    ) -> Union[TranslationGuide, str]:
        """
        Generate C-to-Python translation hints for decompiled code.

        Analyzes C code and provides:
        - Windows API → Python equivalents
        - Required imports
        - Code examples
        - Translation complexity estimate

        Args:
            code_path: Path to C source code file
            output_format: 'structured', 'markdown', or 'json'

        Returns:
            TranslationGuide (structured) or string (markdown/json)
        """
        # Read code
        with open(code_path, "r", encoding="utf-8", errors="ignore") as f:
            code = f.read()

        if output_format == "markdown":
            return generate_translation_guide(code, output_format="markdown")

        elif output_format == "json":
            return generate_translation_guide(code, output_format="json")

        else:  # structured
            result = generate_translation_hints(code, include_patterns=True)

            return TranslationGuide(
                hints=result["hints"],
                complexity=result["complexity"],
                imports_needed=result["imports_needed"],
                summary=result["summary"],
                statistics=result["statistics"],
            )

    def analyze_binary(
        self,
        binary_path: str,
        mode: AnalysisMode = AnalysisMode.STANDARD,
        save_results: bool = True,
    ) -> Dict[str, Any]:
        """
        Perform comprehensive binary analysis.

        Args:
            binary_path: Path to binary file
            mode: Analysis depth (QUICK, STANDARD, DEEP, REBUILD)
            save_results: Save results to output directory

        Returns:
            Dictionary with comprehensive analysis results
        """
        results = {}

        # Always start with triage
        logger.info(f"Triaging {binary_path}...")
        triage = self.triage_binary(binary_path)
        results["triage"] = triage.to_dict()

        if mode == AnalysisMode.QUICK:
            # Triage only
            return results

        # Standard analysis
        logger.info(f"Performing {mode.value} analysis...")

        # Run full analysis using REVENG analyzer
        from .analyzer import REVENGAnalyzer

        analyzer = REVENGAnalyzer(binary_path)
        success = analyzer.analyze_binary()

        if success:
            # Load analysis results
            binary_name = Path(binary_path).stem
            report_path = Path(f"analysis_{binary_name}") / "universal_analysis_report.json"

            if report_path.exists():
                with open(report_path, "r") as f:
                    full_analysis = json.load(f)
                    results["full_analysis"] = full_analysis

        if mode == AnalysisMode.REBUILD:
            # Add translation hints for code rebuild
            # (Assumes decompiled code is available)
            decompiled_dir = Path(f"analysis_{Path(binary_path).stem}")

            # Find decompiled C files
            c_files = list(decompiled_dir.glob("**/*.c"))

            if c_files:
                logger.info(f"Generating translation hints for {len(c_files)} C files...")
                results["translation_hints"] = []

                for c_file in c_files[:5]:  # Limit to first 5 files
                    hints = self.get_translation_hints(str(c_file))
                    results["translation_hints"].append(
                        {"file": str(c_file), "hints": hints.to_dict()}
                    )

        if save_results and self.output_dir:
            # Save to custom output directory
            output_file = self.output_dir / f"{Path(binary_path).stem}_ai_analysis.json"
            with open(output_file, "w") as f:
                json.dump(results, f, indent=2)
            logger.info(f"Results saved to {output_file}")

        return results

    def explain_binary(self, binary_path: str, detail_level: str = "standard") -> NLResponse:
        """
        Get a comprehensive explanation of what a binary does.

        Args:
            binary_path: Path to binary file
            detail_level: 'brief', 'standard', or 'detailed'

        Returns:
            NLResponse with explanation and confidence
        """
        if detail_level == "brief":
            question = "In 2-3 sentences, what does this binary do?"
        elif detail_level == "detailed":
            question = "Provide a detailed technical explanation of this binary's functionality, capabilities, and threat assessment."
        else:  # standard
            question = "What does this binary do?"

        return self.ask(question, binary_path=binary_path)

    def find_vulnerabilities(
        self, binary_path: str, vuln_types: Optional[List[str]] = None
    ) -> NLResponse:
        """
        Find potential vulnerabilities in a binary.

        Args:
            binary_path: Path to binary file
            vuln_types: Optional list of specific vulnerability types to search for
                       (e.g., ['buffer overflow', 'sql injection'])

        Returns:
            NLResponse with vulnerability findings and confidence
        """
        if vuln_types:
            vuln_str = ", ".join(vuln_types)
            question = f"Find {vuln_str} vulnerabilities in this binary."
        else:
            question = "Find all potential security vulnerabilities in this binary."

        return self.ask(question, binary_path=binary_path)

    def extract_iocs(self, binary_path: str, ioc_types: Optional[List[str]] = None) -> NLResponse:
        """
        Extract indicators of compromise (IOCs) from binary.

        Args:
            binary_path: Path to binary file
            ioc_types: Optional list of IOC types ('ip', 'domain', 'url', 'hash')

        Returns:
            NLResponse with extracted IOCs and confidence
        """
        if ioc_types:
            ioc_str = ", ".join(ioc_types)
            question = f"Extract all {ioc_str} IOCs from this binary."
        else:
            question = "Extract all indicators of compromise (IOCs) including IPs, domains, URLs, and hashes."

        return self.ask(question, binary_path=binary_path)

    def compare_binaries(self, binary1_path: str, binary2_path: str) -> Dict[str, Any]:
        """
        Compare two binaries to find similarities and differences.

        Args:
            binary1_path: Path to first binary
            binary2_path: Path to second binary

        Returns:
            Dictionary with comparison results
        """
        # Triage both
        triage1 = self.triage_binary(binary1_path)
        triage2 = self.triage_binary(binary2_path)

        comparison = {
            "binary1": {
                "path": binary1_path,
                "threat_score": triage1.threat_score,
                "capabilities": triage1.detected_capabilities,
            },
            "binary2": {
                "path": binary2_path,
                "threat_score": triage2.threat_score,
                "capabilities": triage2.detected_capabilities,
            },
            "similarity": {
                "threat_score_diff": abs(triage1.threat_score - triage2.threat_score),
                "common_capabilities": list(
                    set(triage1.detected_capabilities) & set(triage2.detected_capabilities)
                ),
                "unique_to_binary1": list(
                    set(triage1.detected_capabilities) - set(triage2.detected_capabilities)
                ),
                "unique_to_binary2": list(
                    set(triage2.detected_capabilities) - set(triage1.detected_capabilities)
                ),
            },
        }

        return comparison


# Convenience functions for quick access
def quick_triage(binary_path: str) -> TriageResult:
    """Quick triage of a binary."""
    api = REVENG_AI_API()
    return api.triage_binary(binary_path)


def quick_ask(question: str, binary_path: str) -> str:
    """Quick natural language query, returns just the answer string."""
    api = REVENG_AI_API()
    response = api.ask(question, binary_path)
    return response.answer
