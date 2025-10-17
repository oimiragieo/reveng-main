"""
Natural Language Interface for REVENG

Allows analysts to query binaries using natural language instead of complex CLI commands.
Examples:
- "What does this binary do?"
- "Find all network functions"
- "Is this malware dangerous?"
- "Show me crypto functions"
"""

import logging
import json
import re
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict

try:
    import ollama

    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

logger = logging.getLogger(__name__)


class QueryIntent(Enum):
    """Types of natural language queries"""

    EXPLAIN_BINARY = "explain_binary"  # "What does this do?"
    FIND_FUNCTIONS = "find_functions"  # "Show me network functions"
    FIND_VULNERABILITY = "find_vulnerability"  # "Are there any vulnerabilities?"
    EXPLAIN_FUNCTION = "explain_function"  # "What does function_X do?"
    THREAT_ASSESSMENT = "threat_assessment"  # "Is this dangerous?"
    FIND_IOC = "find_ioc"  # "Extract IOCs"
    CAPABILITY_DETECTION = "capability_detection"  # "What can this malware do?"
    COMPARE_BINARIES = "compare_binaries"  # "Compare X and Y"
    UNKNOWN = "unknown"


@dataclass
class ParsedQuery:
    """Parsed natural language query"""

    original_query: str
    intent: QueryIntent
    parameters: Dict[str, Any]
    confidence: float


@dataclass
class NLResponse:
    """
    Structured response from natural language interface.

    Provides AI agents with confidence scores and metadata alongside
    the natural language answer.
    """

    answer: str
    confidence: float  # 0.0-1.0
    intent: str  # Detected query intent
    sources: List[str]  # Data sources used for answer
    metadata: Optional[Dict[str, Any]] = None  # Additional context

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class NaturalLanguageInterface:
    """
    Natural language interface for binary analysis.

    Translates natural language questions into analysis operations
    and provides human-readable responses.
    """

    def __init__(self, model: str = "auto", use_ollama: bool = True):
        """
        Initialize natural language interface.

        Args:
            model: LLM model to use ('auto', 'llama3', 'mistral', etc.')
            use_ollama: Whether to use Ollama (local) or external APIs
        """
        self.use_ollama = use_ollama and OLLAMA_AVAILABLE
        self.model = model

        if self.use_ollama:
            # Test Ollama connection
            try:
                ollama.list()  # Test if server is reachable
                # Auto-detect available model
                if model == "auto":
                    self.model = self._detect_ollama_model()
                logger.info(f"Using Ollama model: {self.model}")
            except Exception as e:
                logger.warning(f"Ollama server not reachable: {e}")
                logger.warning("Falling back to heuristic answers")
                self.use_ollama = False
        else:
            logger.warning("Ollama not available, using fallback heuristics")

    def _detect_ollama_model(self) -> str:
        """Detect available Ollama model"""
        try:
            models = ollama.list()
            if models and "models" in models:
                available = [m["name"] for m in models["models"]]
                # Prefer certain models
                for preferred in ["llama3", "mistral", "codellama"]:
                    for model in available:
                        if preferred in model.lower():
                            return model
                # Return first available
                if available:
                    return available[0]
        except Exception:
            pass

        # Default fallback
        return "llama3"

    def parse_query(self, query: str) -> ParsedQuery:
        """
        Parse natural language query to determine intent.

        Args:
            query: Natural language question

        Returns:
            Parsed query with intent and parameters
        """
        query_lower = query.lower()

        # Pattern matching for intent detection
        intent_patterns = {
            QueryIntent.EXPLAIN_BINARY: [
                r"what (does|is) (this|the) (binary|file|program|malware)",
                r"explain (this|the) (binary|file)",
                r"describe (this|the) (binary|file)",
                r"(tell me|show me) about (this|the) (binary|file)",
            ],
            QueryIntent.FIND_FUNCTIONS: [
                r"(find|show|list|get) .* functions?",
                r"functions? .* (network|crypto|file|registry)",
                r"which functions? .* (send|receive|encrypt|decrypt)",
            ],
            QueryIntent.FIND_VULNERABILITY: [
                r"(vulnerability|vulnerabilities|bugs?|exploits?)",
                r"(are there|find) .* (vulnerability|bug|exploit)",
                r"security (issues?|problems?|flaws?)",
                r"buffer overflow",
                r"sql injection",
            ],
            QueryIntent.EXPLAIN_FUNCTION: [
                r"what does .* function",
                r"explain .* function",
                r"(function|sub)_\w+ does",
            ],
            QueryIntent.THREAT_ASSESSMENT: [
                r"(is (this|it)|how) (dangerous|malicious|harmful)",
                r"threat (level|score|assessment)",
                r"(should i|can i) (be worried|trust)",
                r"is (this|it) (safe|malware|virus)",
            ],
            QueryIntent.FIND_IOC: [
                r"(ioc|indicator|artifact)",
                r"(extract|find|show) .* (ioc|ip|domain|url|hash)",
                r"network (indicators?|connections?|communication)",
            ],
            QueryIntent.CAPABILITY_DETECTION: [
                r"what (can (this|it)|capabilities)",
                r"what does (this|it) do",
                r"(features?|functionality|behavior)",
            ],
        }

        # Try to match patterns and calculate confidence
        matched_intent = QueryIntent.UNKNOWN
        confidence = 0.0
        matched_patterns = 0

        for intent, patterns in intent_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query_lower):
                    matched_intent = intent
                    matched_patterns += 1
                    # Higher confidence for more specific/longer patterns
                    pattern_confidence = min(0.7 + (len(pattern) / 200), 0.95)
                    confidence = max(confidence, pattern_confidence)

        # Boost confidence if multiple patterns match
        if matched_patterns > 1:
            confidence = min(confidence + 0.05 * matched_patterns, 0.98)

        # Lower confidence for very short queries
        if len(query.split()) < 3:
            confidence *= 0.8

        # Extract parameters from query
        parameters = self._extract_parameters(query, matched_intent)

        # Boost confidence if specific parameters extracted
        if parameters:
            confidence = min(confidence + 0.05, 0.99)

        return ParsedQuery(
            original_query=query,
            intent=matched_intent,
            parameters=parameters,
            confidence=confidence,
        )

    def _extract_parameters(self, query: str, intent: QueryIntent) -> Dict[str, Any]:
        """Extract parameters from query based on intent"""
        params = {}

        query_lower = query.lower()

        # Extract function-related keywords
        if intent == QueryIntent.FIND_FUNCTIONS:
            # Extract capability keywords
            capabilities = {
                "network": r"(network|socket|send|receive|connect|http|tcp|udp)",
                "crypto": r"(crypt|encrypt|decrypt|aes|rsa|hash|md5|sha)",
                "file": r"(file|read|write|create|delete|open)",
                "registry": r"(registry|reg(key|value)|hkey)",
                "process": r"(process|thread|createprocess|execu)",
                "api": r"(api|call|invoke)",
            }

            for cap_name, pattern in capabilities.items():
                if re.search(pattern, query_lower):
                    params["capability"] = cap_name
                    break

        # Extract function name if mentioned
        func_match = re.search(r"(function|sub)_([0-9a-fx]+)", query_lower)
        if func_match:
            params["function_name"] = func_match.group(0)

        return params

    def _calculate_response_confidence(
        self, parsed: ParsedQuery, analysis_results: Dict[str, Any], answer: str
    ) -> float:
        """
        Calculate confidence score for response based on multiple factors.

        Args:
            parsed: Parsed query with intent
            analysis_results: Available analysis data
            answer: Generated answer

        Returns:
            Confidence score (0.0-1.0)
        """
        # Start with query parsing confidence
        confidence = parsed.confidence

        # Factor 1: Data availability for this query type
        data_completeness = 0.0

        if parsed.intent == QueryIntent.EXPLAIN_BINARY:
            # Check if we have key fields
            has_classification = bool(analysis_results.get("classification"))
            has_capabilities = bool(analysis_results.get("capabilities"))
            has_threat_score = "threat_score" in analysis_results
            data_completeness = sum([has_classification, has_capabilities, has_threat_score]) / 3

        elif parsed.intent == QueryIntent.FIND_FUNCTIONS:
            functions = analysis_results.get("functions", {})
            data_completeness = min(len(functions) / 10, 1.0)  # Scale: 10+ functions = 1.0

        elif parsed.intent == QueryIntent.THREAT_ASSESSMENT:
            has_threat_score = "threat_score" in analysis_results
            has_classification = bool(analysis_results.get("classification"))
            data_completeness = sum([has_threat_score, has_classification]) / 2

        elif parsed.intent == QueryIntent.FIND_IOC:
            iocs = analysis_results.get("iocs", [])
            data_completeness = min(len(iocs) / 5, 1.0)  # Scale: 5+ IOCs = 1.0

        elif parsed.intent == QueryIntent.CAPABILITY_DETECTION:
            capabilities = analysis_results.get("capabilities", [])
            data_completeness = min(len(capabilities) / 5, 1.0)

        elif parsed.intent == QueryIntent.FIND_VULNERABILITY:
            vulns = analysis_results.get("vulnerabilities", [])
            data_completeness = min(len(vulns) / 3, 1.0)

        else:
            # Default: check if we have any data
            data_completeness = 0.5 if analysis_results else 0.1

        # Factor 2: Answer specificity (longer, more detailed answers = higher confidence)
        answer_length_score = min(len(answer) / 500, 1.0)  # 500+ chars = full score

        # Factor 3: Use of LLM vs fallback
        llm_bonus = 0.1 if self.use_ollama else 0.0

        # Combine factors
        # Weight: 40% query confidence, 40% data completeness, 15% answer length, 5% LLM
        final_confidence = (
            0.40 * confidence
            + 0.40 * data_completeness
            + 0.15 * answer_length_score
            + 0.05 * (1.0 if llm_bonus else 0.0)
        )

        # Penalty for "unable to" or "not found" in answer
        if any(phrase in answer.lower() for phrase in ["unable to", "not found", "no information"]):
            final_confidence *= 0.6

        return min(final_confidence, 0.99)  # Cap at 0.99

    def query(
        self,
        question: str,
        analysis_results: Optional[Dict[str, Any]] = None,
        binary_path: Optional[str] = None,
        return_structured: bool = True,
    ) -> NLResponse:
        """
        Process natural language query about binary.

        Args:
            question: Natural language question
            analysis_results: Optional existing analysis results
            binary_path: Optional path to binary (if not in analysis_results)
            return_structured: Return NLResponse object (default) or just string

        Returns:
            NLResponse with answer, confidence, and metadata
        """
        # Parse query to understand intent
        parsed = self.parse_query(question)

        logger.info(f"Query intent: {parsed.intent.value}, confidence: {parsed.confidence}")

        # Track data sources used
        sources = []

        # If analysis results not provided, need to analyze first
        if not analysis_results and binary_path:
            logger.info(f"No analysis results provided, analyzing {binary_path}...")
            from reveng.analyzer import REVENGAnalyzer

            analyzer = REVENGAnalyzer(binary_path)
            success = analyzer.analyze_binary()
            if success:
                # Load results from output
                analysis_results = self._load_analysis_results(binary_path)
                sources.append("fresh_analysis")

        if not analysis_results:
            error_response = NLResponse(
                answer="Unable to analyze binary. Please provide analysis results or binary path.",
                confidence=0.0,
                intent=parsed.intent.value,
                sources=[],
                metadata={"error": "no_analysis_data"},
            )
            return error_response

        sources.append("analysis_results")

        # Route to appropriate handler based on intent
        handlers = {
            QueryIntent.EXPLAIN_BINARY: self._handle_explain_binary,
            QueryIntent.FIND_FUNCTIONS: self._handle_find_functions,
            QueryIntent.FIND_VULNERABILITY: self._handle_find_vulnerability,
            QueryIntent.EXPLAIN_FUNCTION: self._handle_explain_function,
            QueryIntent.THREAT_ASSESSMENT: self._handle_threat_assessment,
            QueryIntent.FIND_IOC: self._handle_find_ioc,
            QueryIntent.CAPABILITY_DETECTION: self._handle_capability_detection,
        }

        handler = handlers.get(parsed.intent, self._handle_unknown)
        answer = handler(parsed, analysis_results)

        # Add LLM to sources if used
        if self.use_ollama and parsed.intent != QueryIntent.UNKNOWN:
            sources.append(f"llm_{self.model}")

        # Calculate final confidence
        confidence = self._calculate_response_confidence(parsed, analysis_results, answer)

        # Create structured response
        response = NLResponse(
            answer=answer,
            confidence=confidence,
            intent=parsed.intent.value,
            sources=sources,
            metadata={
                "query_confidence": parsed.confidence,
                "parameters": parsed.parameters,
                "ollama_available": self.use_ollama,
            },
        )

        return response

    def _handle_explain_binary(self, parsed: ParsedQuery, analysis_results: Dict[str, Any]) -> str:
        """Handle 'explain binary' queries"""
        if not self.use_ollama:
            return self._fallback_explain_binary(analysis_results)

        # Prepare context for LLM
        context = self._prepare_analysis_context(analysis_results)

        prompt = f"""Analyze this binary and provide a comprehensive explanation:

{context}

Question: {parsed.original_query}

Provide a clear, concise answer that explains:
1. What this binary does
2. Its primary capabilities
3. Any security concerns
4. Overall assessment

Answer in 2-4 paragraphs suitable for a security analyst."""

        try:
            response = ollama.chat(model=self.model, messages=[{"role": "user", "content": prompt}])
            return response["message"]["content"]

        except Exception as e:
            logger.error(f"Ollama query failed: {e}")
            return self._fallback_explain_binary(analysis_results)

    def _fallback_explain_binary(self, analysis_results: Dict[str, Any]) -> str:
        """Fallback explanation without LLM"""
        explanation = []

        # Basic info
        if analysis_results.get("file_type"):
            explanation.append(f"This is a {analysis_results['file_type']} file.")

        # Classification
        if analysis_results.get("classification"):
            classification = analysis_results["classification"]
            threat_score = analysis_results.get("threat_score", 0)
            explanation.append(
                f"Classification: {classification} (threat score: {threat_score}/100)."
            )

        # Family
        if analysis_results.get("family"):
            explanation.append(f"Identified as: {analysis_results['family']}")

        # Capabilities
        capabilities = analysis_results.get("capabilities", [])
        if capabilities:
            cap_list = ", ".join(capabilities[:5])
            explanation.append(f"Detected capabilities: {cap_list}")

        return " ".join(explanation) if explanation else "No detailed analysis available."

    def _handle_find_functions(self, parsed: ParsedQuery, analysis_results: Dict[str, Any]) -> str:
        """Handle 'find functions' queries"""
        capability = parsed.parameters.get("capability")

        functions = analysis_results.get("functions", {})
        if not functions:
            return "No function analysis available."

        # Filter by capability if specified
        if capability:
            matching_functions = []
            for func_name, func_data in functions.items():
                if isinstance(func_data, dict):
                    func_category = func_data.get("category", "").lower()
                    if capability in func_category:
                        matching_functions.append(func_name)

            if matching_functions:
                func_list = "\n".join(f"- {func}" for func in matching_functions[:10])
                return (
                    f"Found {len(matching_functions)} {capability}-related functions:\n{func_list}"
                )
            else:
                return f"No {capability}-related functions found."
        else:
            # Return all functions categorized
            categories = {}
            for func_name, func_data in functions.items():
                if isinstance(func_data, dict):
                    category = func_data.get("category", "unknown")
                    if category not in categories:
                        categories[category] = []
                    categories[category].append(func_name)

            result = f"Found {len(functions)} functions in {len(categories)} categories:\n\n"
            for category, funcs in categories.items():
                result += f"**{category}**: {len(funcs)} functions\n"

            return result

    def _handle_find_vulnerability(
        self, parsed: ParsedQuery, analysis_results: Dict[str, Any]
    ) -> str:
        """Handle 'find vulnerability' queries"""
        vulnerabilities = analysis_results.get("vulnerabilities", [])

        if not vulnerabilities:
            return "No vulnerabilities detected in this binary."

        vuln_summary = []
        for vuln in vulnerabilities[:5]:  # Top 5 vulnerabilities
            if isinstance(vuln, dict):
                vuln_type = vuln.get("type", "Unknown")
                severity = vuln.get("severity", "Unknown")
                location = vuln.get("location", "Unknown")
                vuln_summary.append(f"- **{vuln_type}** ({severity}) at {location}")

        result = f"Found {len(vulnerabilities)} potential vulnerabilities:\n\n"
        result += "\n".join(vuln_summary)

        if len(vulnerabilities) > 5:
            result += f"\n\n...and {len(vulnerabilities) - 5} more."

        return result

    def _handle_explain_function(
        self, parsed: ParsedQuery, analysis_results: Dict[str, Any]
    ) -> str:
        """Handle 'explain function' queries"""
        function_name = parsed.parameters.get("function_name")

        if not function_name:
            return "Please specify which function you want explained."

        functions = analysis_results.get("functions", {})
        func_data = functions.get(function_name)

        if not func_data:
            return f"Function {function_name} not found in analysis results."

        if isinstance(func_data, dict):
            category = func_data.get("category", "unknown")
            purpose = func_data.get("purpose", "Unknown purpose")
            complexity = func_data.get("complexity", "Unknown")

            explanation = f"**{function_name}**\n\n"
            explanation += f"Category: {category}\n"
            explanation += f"Purpose: {purpose}\n"
            explanation += f"Complexity: {complexity}\n"

            return explanation
        else:
            return f"Limited information available for {function_name}."

    def _handle_threat_assessment(
        self, parsed: ParsedQuery, analysis_results: Dict[str, Any]
    ) -> str:
        """Handle 'threat assessment' queries"""
        threat_score = analysis_results.get("threat_score", 0)
        classification = analysis_results.get("classification", "unknown")
        family = analysis_results.get("family", "Unknown")

        assessment = f"**Threat Assessment:**\n\n"

        # Threat level
        if threat_score >= 80:
            level = "CRITICAL"
            recommendation = "This binary is highly dangerous. Immediate action recommended."
        elif threat_score >= 60:
            level = "HIGH"
            recommendation = "This binary poses a significant threat. Investigate urgently."
        elif threat_score >= 40:
            level = "MEDIUM"
            recommendation = "This binary shows suspicious behavior. Further analysis needed."
        elif threat_score >= 20:
            level = "LOW"
            recommendation = "This binary shows minimal threat indicators. Monitor cautiously."
        else:
            level = "MINIMAL"
            recommendation = "This binary appears benign based on current analysis."

        assessment += f"Threat Level: **{level}** (Score: {threat_score}/100)\n"
        assessment += f"Classification: {classification}\n"

        if family != "Unknown":
            assessment += f"Family: {family}\n"

        assessment += f"\n{recommendation}"

        return assessment

    def _handle_find_ioc(self, parsed: ParsedQuery, analysis_results: Dict[str, Any]) -> str:
        """Handle 'find IOC' queries"""
        iocs = analysis_results.get("iocs", [])

        if not iocs:
            return "No indicators of compromise (IOCs) extracted from this binary."

        ioc_summary = {"ip": [], "domain": [], "url": [], "hash": [], "other": []}

        for ioc in iocs:
            if isinstance(ioc, dict):
                ioc_type = ioc.get("type", "other")
                ioc_value = ioc.get("value", "")

                if ioc_type in ioc_summary:
                    ioc_summary[ioc_type].append(ioc_value)
                else:
                    ioc_summary["other"].append(ioc_value)

        result = f"**Indicators of Compromise (IOCs):**\n\n"

        for ioc_type, values in ioc_summary.items():
            if values:
                result += f"**{ioc_type.upper()}s:** {len(values)}\n"
                for value in values[:5]:
                    result += f"  - {value}\n"
                if len(values) > 5:
                    result += f"  ...and {len(values) - 5} more\n"
                result += "\n"

        return result

    def _handle_capability_detection(
        self, parsed: ParsedQuery, analysis_results: Dict[str, Any]
    ) -> str:
        """Handle 'capability detection' queries"""
        capabilities = analysis_results.get("capabilities", [])

        if not capabilities:
            return "No specific capabilities detected."

        cap_list = "\n".join(f"- {cap}" for cap in capabilities)

        result = f"**Detected Capabilities:**\n\n{cap_list}\n\n"
        result += f"This binary demonstrates {len(capabilities)} distinct capabilities."

        return result

    def _handle_unknown(self, parsed: ParsedQuery, analysis_results: Dict[str, Any]) -> str:
        """Handle unknown query types"""
        if self.use_ollama:
            # Let LLM try to answer
            context = self._prepare_analysis_context(analysis_results)

            prompt = f"""Based on this binary analysis, answer the following question:

{context}

Question: {parsed.original_query}

Provide a helpful answer based on the available analysis data."""

            try:
                response = ollama.chat(
                    model=self.model, messages=[{"role": "user", "content": prompt}]
                )
                return response["message"]["content"]

            except Exception as e:
                logger.error(f"Ollama query failed: {e}")

        return "I'm not sure how to answer that question. Try asking about capabilities, functions, or threats."

    def _prepare_analysis_context(self, analysis_results: Dict[str, Any]) -> str:
        """Prepare analysis results as context for LLM"""
        context = []

        # File info
        if analysis_results.get("file_type"):
            context.append(f"File Type: {analysis_results['file_type']}")

        # Classification
        if analysis_results.get("classification"):
            context.append(f"Classification: {analysis_results['classification']}")

        if analysis_results.get("threat_score"):
            context.append(f"Threat Score: {analysis_results['threat_score']}/100")

        if analysis_results.get("family"):
            context.append(f"Family: {analysis_results['family']}")

        # Capabilities
        capabilities = analysis_results.get("capabilities", [])
        if capabilities:
            context.append(f"Capabilities: {', '.join(capabilities[:10])}")

        # Function summary
        functions = analysis_results.get("functions", {})
        if functions:
            context.append(f"Functions: {len(functions)} identified")

            # Categorize functions
            categories = {}
            for _, func_data in functions.items():
                if isinstance(func_data, dict):
                    category = func_data.get("category", "unknown")
                    categories[category] = categories.get(category, 0) + 1

            if categories:
                cat_summary = ", ".join(f"{cat}: {count}" for cat, count in categories.items())
                context.append(f"Function Categories: {cat_summary}")

        # Vulnerabilities
        vulnerabilities = analysis_results.get("vulnerabilities", [])
        if vulnerabilities:
            context.append(f"Vulnerabilities: {len(vulnerabilities)} found")

        # IOCs
        iocs = analysis_results.get("iocs", [])
        if iocs:
            context.append(f"IOCs: {len(iocs)} extracted")

        return "\n".join(context)

    def _load_analysis_results(self, binary_path: str) -> Optional[Dict[str, Any]]:
        """Load analysis results from output directory"""
        # Try to load universal analysis report
        binary_name = Path(binary_path).stem
        report_path = Path(f"analysis_{binary_name}") / "universal_analysis_report.json"

        try:
            if report_path.exists():
                with open(report_path, "r") as f:
                    return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load analysis results: {e}")

        return None


# Convenience functions for quick queries
def ask(question: str, binary_path: str, return_structured: bool = False):
    """
    Quick natural language query about a binary.

    Args:
        question: Natural language question
        binary_path: Path to binary file
        return_structured: If True, returns NLResponse; if False, returns just answer string

    Returns:
        NLResponse object or answer string (based on return_structured)
    """
    nl = NaturalLanguageInterface()
    response = nl.query(question, binary_path=binary_path)

    if return_structured:
        return response
    else:
        return response.answer


def ask_with_confidence(question: str, binary_path: str) -> Tuple[str, float]:
    """
    Query with confidence score.

    Args:
        question: Natural language question
        binary_path: Path to binary file

    Returns:
        Tuple of (answer, confidence_score)
    """
    nl = NaturalLanguageInterface()
    response = nl.query(question, binary_path=binary_path)
    return response.answer, response.confidence
