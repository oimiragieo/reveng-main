#!/usr/bin/env python3
"""
REVENG AI Assistant
==================

Unified AI interface that combines all REVENG capabilities for AI-powered reverse engineering.
This is the main entry point for AI assistants to interact with REVENG.

Author: REVENG Development Team
Version: 2.2.0
License: MIT
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

# Import REVENG components
from ..analyzer import REVENGAnalyzer
from ..ghidra.scripting_engine import GhidraScriptingEngine
from ..agents.ai.ollama_analyzer import OllamaAnalyzer
from ..agents.ai.ai_enhanced_analyzer import AIEnhancedAnalyzer
from ..security.vulnerability_discovery_engine import VulnerabilityDiscoveryEngine
from ..security.threat_intelligence_correlator import ThreatIntelligenceCorrelator
from ..integrations.ghidra.ghidra_mcp_connector import GhidraMCPConnector
from ..tools.languages.language_detector import LanguageDetector
from ..tools.core.optimal_binary_analysis import OptimalBinaryAnalyzer

# Import structured models
from .analysis_models import (
    AIAnalysisResult,
    AIAnalysisRequest,
    BinaryInfo,
    FunctionAnalysis,
    Vulnerability,
    ThreatIndicator,
    Recommendation,
    AnalysisMetadata,
    AnalysisType,
    ThreatLevel,
    create_binary_info,
    create_function_analysis,
    create_vulnerability,
    create_threat_indicator,
    create_recommendation,
    create_analysis_metadata,
)

logger = logging.getLogger(__name__)


# AIAnalysisRequest and AIAnalysisResult are now imported from analysis_models


class REVENGAIAssistant:
    """
    Unified AI Assistant for REVENG

    Combines all REVENG capabilities into a single AI-friendly interface:
    - Natural language interaction
    - Intelligent analysis orchestration
    - Context-aware analysis
    - Multi-model ensemble analysis
    - Learning and adaptation
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize the REVENG AI Assistant

        Args:
            config: Configuration dictionary for AI assistant
        """
        self.config = config or {}
        self.logger = logging.getLogger(__name__)

        # Initialize components
        self.analyzer = REVENGAnalyzer()
        self.ghidra_engine = GhidraScriptingEngine()
        self.ollama_analyzer = OllamaAnalyzer()
        self.enhanced_analyzer = AIEnhancedAnalyzer()
        self.vuln_engine = VulnerabilityDiscoveryEngine()
        self.threat_correlator = ThreatIntelligenceCorrelator()
        self.ghidra_mcp = GhidraMCPConnector()
        self.language_detector = LanguageDetector()
        self.optimal_analyzer = OptimalBinaryAnalyzer()

        # Analysis history for learning
        self.analysis_history = []
        self.user_feedback = {}

        self.logger.info("REVENG AI Assistant initialized")

    async def analyze_binary_ai(self, request: AIAnalysisRequest) -> AIAnalysisResult:
        """
        AI-powered binary analysis with natural language interaction

        Args:
            request: Analysis request with binary path and preferences

        Returns:
            Comprehensive AI analysis result
        """
        start_time = time.time()
        self.logger.info(f"Starting AI analysis of {request.binary_path}")

        try:
            # Step 1: Detect binary type and select optimal analysis strategy
            binary_type = await self._detect_binary_type(request.binary_path)
            analysis_strategy = await self._select_analysis_strategy(
                request, binary_type
            )

            # Step 2: Run comprehensive analysis pipeline
            analysis_results = await self._run_analysis_pipeline(
                request, analysis_strategy
            )

            # Step 3: Generate AI-powered insights and recommendations
            insights = await self._generate_ai_insights(analysis_results, request)

            # Step 4: Create structured data models
            binary_info = self._create_binary_info(
                request.binary_path, analysis_results
            )
            functions = self._create_function_analyses(analysis_results)
            vulnerabilities = self._create_vulnerabilities(analysis_results)
            threat_indicators = self._create_threat_indicators(analysis_results)
            recommendations = self._create_recommendations(insights)
            metadata = await self._create_analysis_metadata(
                request, start_time, time.time(), analysis_strategy, binary_type
            )

            # Step 5: Create natural language summary
            summary = await self._create_natural_language_summary(
                analysis_results, insights
            )

            # Step 6: Format for AI model consumption
            structured_prompt = await self._create_structured_prompt(
                analysis_results, insights
            )

            # Create comprehensive result
            result = AIAnalysisResult(
                binary_info=binary_info,
                functions=functions,
                vulnerabilities=vulnerabilities,
                threat_indicators=threat_indicators,
                recommendations=recommendations,
                metadata=metadata,
                natural_language_summary=summary,
                structured_prompt=structured_prompt,
                confidence_scores=insights.get("confidence_scores", {}),
                key_findings=insights.get("key_findings", []),
                next_steps=insights.get("next_steps", []),
            )

            # Store in history for learning
            self.analysis_history.append(
                {"request": request, "result": result, "timestamp": time.time()}
            )

            self.logger.info(
                f"AI analysis completed in {time.time() - start_time:.2f} seconds"
            )
            return result

        except Exception as e:
            self.logger.error(f"AI analysis failed: {e}")
            raise

    async def ask_question(
        self,
        question: str,
        binary_path: Optional[str] = None,
        analysis_result: Optional[AIAnalysisResult] = None,
    ) -> str:
        """
        Ask natural language questions about a binary or analysis result

        Args:
            question: Natural language question
            binary_path: Path to binary (if not using existing analysis)
            analysis_result: Previous analysis result (if available)

        Returns:
            Natural language answer
        """
        try:
            if analysis_result:
                # Use existing analysis result
                context = analysis_result.to_dict()
            elif binary_path:
                # Perform quick analysis for context
                request = AIAnalysisRequest(
                    binary_path=binary_path, analysis_type="triage"
                )
                analysis_result = await self.analyze_binary_ai(request)
                context = analysis_result.to_dict()
            else:
                raise ValueError(
                    "Either binary_path or analysis_result must be provided"
                )

            # Use Ollama for natural language processing
            answer = await self.ollama_analyzer.ask_question(question, context)

            return answer

        except Exception as e:
            self.logger.error(f"Question answering failed: {e}")
            return f"I'm sorry, I couldn't answer that question: {e}"

    async def suggest_workflow(
        self, binary_path: str, goals: List[str]
    ) -> Dict[str, Any]:
        """
        Suggest optimal analysis workflow based on binary characteristics and goals

        Args:
            binary_path: Path to binary file
            goals: List of analysis goals

        Returns:
            Workflow suggestion with tool sequence and estimates
        """
        try:
            # Analyze binary characteristics
            binary_type = await self._detect_binary_type(binary_path)
            complexity = await self._assess_complexity(binary_path)

            # Generate workflow suggestion
            workflow = {
                "binary_type": binary_type,
                "complexity": complexity,
                "recommended_tools": [],
                "estimated_time": 0,
                "resource_requirements": {},
                "alternative_workflows": [],
            }

            # Select tools based on binary type and goals
            if binary_type == "native":
                workflow["recommended_tools"] = [
                    "ghidra_analysis",
                    "vulnerability_scan",
                    "threat_intelligence",
                    "binary_reconstruction",
                ]
            elif binary_type == "java":
                workflow["recommended_tools"] = [
                    "java_bytecode_analysis",
                    "deobfuscation",
                    "vulnerability_scan",
                    "source_reconstruction",
                ]
            elif binary_type == "csharp":
                workflow["recommended_tools"] = [
                    "csharp_il_analysis",
                    "deobfuscation",
                    "vulnerability_scan",
                    "source_reconstruction",
                ]

            # Estimate time and resources
            workflow["estimated_time"] = (
                len(workflow["recommended_tools"]) * 30
            )  # 30 seconds per tool
            workflow["resource_requirements"] = {
                "memory": "2GB" if complexity == "high" else "1GB",
                "cpu": "4 cores" if complexity == "high" else "2 cores",
                "storage": "1GB" if complexity == "high" else "500MB",
            }

            return workflow

        except Exception as e:
            self.logger.error(f"Workflow suggestion failed: {e}")
            return {"error": str(e)}

    async def _detect_binary_type(self, binary_path: str) -> str:
        """Detect binary type using language detector"""
        try:
            result = self.language_detector.detect_file_type(binary_path)
            return result.get("type", "unknown")
        except Exception as e:
            self.logger.warning(f"Binary type detection failed: {e}")
            return "unknown"

    async def _select_analysis_strategy(
        self, request: AIAnalysisRequest, binary_type: str
    ) -> str:
        """Select optimal analysis strategy based on binary type and goals"""
        if request.analysis_type == "triage":
            return "rapid_triage"
        elif request.analysis_type == "security":
            return "security_focused"
        elif request.analysis_type == "comprehensive":
            return "comprehensive_analysis"
        else:
            return "custom_analysis"

    async def _run_analysis_pipeline(
        self, request: AIAnalysisRequest, strategy: str
    ) -> Dict[str, Any]:
        """Run the analysis pipeline based on selected strategy"""
        results = {}

        try:
            if strategy == "rapid_triage":
                # Quick analysis for incident response
                results = await self._run_triage_analysis(request)
            elif strategy == "security_focused":
                # Security-focused analysis
                results = await self._run_security_analysis(request)
            elif strategy == "comprehensive_analysis":
                # Full comprehensive analysis
                results = await self._run_comprehensive_analysis(request)
            else:
                # Custom analysis based on goals
                results = await self._run_custom_analysis(request)

            return results

        except Exception as e:
            self.logger.error(f"Analysis pipeline failed: {e}")
            return {"error": str(e)}

    async def _run_triage_analysis(self, request: AIAnalysisRequest) -> Dict[str, Any]:
        """Run rapid triage analysis"""
        results = {}

        # Basic binary info
        results["binary_info"] = await self._get_binary_info(request.binary_path)

        # Quick security scan
        if self.vuln_engine:
            results["vulnerabilities"] = await self._quick_vulnerability_scan(
                request.binary_path
            )

        # Threat intelligence lookup
        if self.threat_correlator:
            results["threat_indicators"] = await self._quick_threat_lookup(
                request.binary_path
            )

        return results

    async def _run_security_analysis(
        self, request: AIAnalysisRequest
    ) -> Dict[str, Any]:
        """Run security-focused analysis"""
        results = {}

        # Comprehensive vulnerability scan
        if self.vuln_engine:
            results["vulnerabilities"] = await self._comprehensive_vulnerability_scan(
                request.binary_path
            )

        # Threat intelligence correlation
        if self.threat_correlator:
            results["threat_indicators"] = await self._comprehensive_threat_analysis(
                request.binary_path
            )

        # Security recommendations
        results["security_recommendations"] = (
            await self._generate_security_recommendations(results)
        )

        return results

    async def _run_comprehensive_analysis(
        self, request: AIAnalysisRequest
    ) -> Dict[str, Any]:
        """Run comprehensive analysis using all available tools"""
        results = {}

        # Use enhanced analyzer for comprehensive analysis
        if self.enhanced_analyzer:
            enhanced_result = await self.enhanced_analyzer.analyze_universal(
                request.binary_path
            )
            results.update(enhanced_result)

        # Add Ghidra analysis if available
        if self.ghidra_engine:
            ghidra_result = await self._run_ghidra_analysis(request.binary_path)
            results["ghidra_analysis"] = ghidra_result

        return results

    async def _run_custom_analysis(self, request: AIAnalysisRequest) -> Dict[str, Any]:
        """Run custom analysis based on specific goals"""
        results = {}

        # Analyze based on goals
        for goal in request.goals:
            if goal == "understand_functionality":
                results["functionality"] = await self._analyze_functionality(
                    request.binary_path
                )
            elif goal == "find_vulnerabilities":
                results["vulnerabilities"] = (
                    await self._comprehensive_vulnerability_scan(request.binary_path)
                )
            elif goal == "assess_threats":
                results["threat_assessment"] = await self._assess_threats(
                    request.binary_path
                )

        return results

    async def _generate_ai_insights(
        self, analysis_results: Dict[str, Any], request: AIAnalysisRequest
    ) -> Dict[str, Any]:
        """Generate AI-powered insights and recommendations"""
        insights = {
            "recommendations": [],
            "confidence_scores": {},
            "key_findings": [],
            "next_steps": [],
        }

        try:
            # Use Ollama for insight generation
            if self.ollama_analyzer:
                ai_insights = await self.ollama_analyzer.generate_insights(
                    analysis_results
                )
                insights.update(ai_insights)

            return insights

        except Exception as e:
            self.logger.error(f"AI insight generation failed: {e}")
            return insights

    async def _create_natural_language_summary(
        self, analysis_results: Dict[str, Any], insights: Dict[str, Any]
    ) -> str:
        """Create natural language summary of analysis results"""
        try:
            # Use Ollama to generate natural language summary
            if self.ollama_analyzer:
                summary = await self.ollama_analyzer.generate_summary(
                    analysis_results, insights
                )
                return summary
            else:
                return "Analysis completed. Please check the detailed results."

        except Exception as e:
            self.logger.error(f"Summary generation failed: {e}")
            return "Analysis completed with some errors. Please check the detailed results."

    async def _create_structured_prompt(
        self, analysis_results: Dict[str, Any], insights: Dict[str, Any]
    ) -> str:
        """Create structured prompt for AI model consumption"""
        prompt = f"""
# REVENG Analysis Results

## Binary Information
{json.dumps(analysis_results.get("binary_info", {}), indent=2)}

## Functions
{json.dumps(analysis_results.get("functions", []), indent=2)}

## Vulnerabilities
{json.dumps(analysis_results.get("vulnerabilities", []), indent=2)}

## Threat Indicators
{json.dumps(analysis_results.get("threat_indicators", []), indent=2)}

## AI Insights
{json.dumps(insights, indent=2)}

## Recommendations
{json.dumps(insights.get("recommendations", []), indent=2)}
"""
        return prompt

    # Helper methods for analysis components
    async def _get_binary_info(self, binary_path: str) -> Dict[str, Any]:
        """Get basic binary information"""
        try:
            path = Path(binary_path)
            return {
                "name": path.name,
                "size": path.stat().st_size,
                "path": str(path),
                "exists": path.exists(),
            }
        except Exception as e:
            return {"error": str(e)}

    async def _quick_vulnerability_scan(self, binary_path: str) -> List[Dict[str, Any]]:
        """Quick vulnerability scan"""
        try:
            if self.vuln_engine:
                # This would need to be implemented in the vulnerability engine
                return []
            return []
        except Exception as e:
            return [{"error": str(e)}]

    async def _quick_threat_lookup(self, binary_path: str) -> List[Dict[str, Any]]:
        """Quick threat intelligence lookup"""
        try:
            if self.threat_correlator:
                # This would need to be implemented in the threat correlator
                return []
            return []
        except Exception as e:
            return [{"error": str(e)}]

    async def _comprehensive_vulnerability_scan(
        self, binary_path: str
    ) -> List[Dict[str, Any]]:
        """Comprehensive vulnerability scan"""
        try:
            if self.vuln_engine:
                # This would need to be implemented in the vulnerability engine
                return []
            return []
        except Exception as e:
            return [{"error": str(e)}]

    async def _comprehensive_threat_analysis(
        self, binary_path: str
    ) -> List[Dict[str, Any]]:
        """Comprehensive threat intelligence analysis"""
        try:
            if self.threat_correlator:
                # This would need to be implemented in the threat correlator
                return []
            return []
        except Exception as e:
            return [{"error": str(e)}]

    async def _generate_security_recommendations(
        self, results: Dict[str, Any]
    ) -> List[str]:
        """Generate security recommendations"""
        recommendations = []

        # Add recommendations based on findings
        if results.get("vulnerabilities"):
            recommendations.append("Review and patch identified vulnerabilities")

        if results.get("threat_indicators"):
            recommendations.append("Investigate threat indicators")

        return recommendations

    async def _run_ghidra_analysis(self, binary_path: str) -> Dict[str, Any]:
        """Run Ghidra analysis"""
        try:
            if self.ghidra_engine:
                result = await self.ghidra_engine.analyze_binary(binary_path)
                return result
            return {}
        except Exception as e:
            return {"error": str(e)}

    async def _analyze_functionality(self, binary_path: str) -> Dict[str, Any]:
        """Analyze binary functionality"""
        try:
            # Use language detector and appropriate analyzer
            binary_type = await self._detect_binary_type(binary_path)

            if binary_type == "java":
                # Use Java analyzer
                return await self._analyze_java_functionality(binary_path)
            elif binary_type == "csharp":
                # Use C# analyzer
                return await self._analyze_csharp_functionality(binary_path)
            else:
                # Use general analyzer
                return await self._analyze_native_functionality(binary_path)

        except Exception as e:
            return {"error": str(e)}

    async def _analyze_java_functionality(self, binary_path: str) -> Dict[str, Any]:
        """Analyze Java binary functionality"""
        # Implementation would go here
        return {}

    async def _analyze_csharp_functionality(self, binary_path: str) -> Dict[str, Any]:
        """Analyze C# binary functionality"""
        # Implementation would go here
        return {}

    async def _analyze_native_functionality(self, binary_path: str) -> Dict[str, Any]:
        """Analyze native binary functionality"""
        # Implementation would go here
        return {}

    async def _assess_threats(self, binary_path: str) -> Dict[str, Any]:
        """Assess threats in binary"""
        try:
            if self.threat_correlator:
                # This would need to be implemented in the threat correlator
                return {}
            return {}
        except Exception as e:
            return {"error": str(e)}

    async def _assess_complexity(self, binary_path: str) -> str:
        """Assess binary complexity"""
        try:
            # Simple complexity assessment based on file size
            size = Path(binary_path).stat().st_size
            if size < 1024 * 1024:  # < 1MB
                return "low"
            elif size < 10 * 1024 * 1024:  # < 10MB
                return "medium"
            else:
                return "high"
        except Exception:
            return "unknown"

    # Helper methods for creating structured data models
    def _create_binary_info(
        self, binary_path: str, analysis_results: Dict[str, Any]
    ) -> BinaryInfo:
        """Create BinaryInfo from analysis results"""
        path = Path(binary_path)
        return create_binary_info(
            name=path.name,
            path=str(path),
            size=path.stat().st_size,
            file_type=analysis_results.get("file_type", "unknown"),
            architecture=analysis_results.get("architecture"),
            compiler=analysis_results.get("compiler"),
            language=analysis_results.get("language"),
            entry_point=analysis_results.get("entry_point"),
            imports=analysis_results.get("imports", []),
            exports=analysis_results.get("exports", []),
            strings=analysis_results.get("strings", []),
            metadata=analysis_results.get("binary_metadata", {}),
        )

    def _create_function_analyses(
        self, analysis_results: Dict[str, Any]
    ) -> List[FunctionAnalysis]:
        """Create FunctionAnalysis objects from analysis results"""
        functions = []
        for func_data in analysis_results.get("functions", []):
            func = create_function_analysis(
                name=func_data.get("name", "unknown"),
                address=func_data.get("address", "0x00000000"),
                size=func_data.get("size", 0),
                purpose=func_data.get("purpose", "Unknown function"),
                complexity=func_data.get("complexity", "medium"),
                security_issues=func_data.get("security_issues", []),
                performance_issues=func_data.get("performance_issues", []),
                calls_made=func_data.get("calls_made", []),
                called_by=func_data.get("called_by", []),
                variables=func_data.get("variables", []),
                confidence=func_data.get("confidence", 0.0),
                suggestions=func_data.get("suggestions", []),
                metadata=func_data.get("metadata", {}),
            )
            functions.append(func)
        return functions

    def _create_vulnerabilities(
        self, analysis_results: Dict[str, Any]
    ) -> List[Vulnerability]:
        """Create Vulnerability objects from analysis results"""
        vulnerabilities = []
        for vuln_data in analysis_results.get("vulnerabilities", []):
            vuln = create_vulnerability(
                id=vuln_data.get("id", f"vuln_{len(vulnerabilities)}"),
                type=vuln_data.get("type", "unknown"),
                severity=vuln_data.get("severity", "medium"),
                description=vuln_data.get("description", "Unknown vulnerability"),
                location=vuln_data.get("location", "unknown"),
                cwe_id=vuln_data.get("cwe_id"),
                cvss_score=vuln_data.get("cvss_score"),
                remediation=vuln_data.get("remediation"),
                evidence=vuln_data.get("evidence", []),
                confidence=vuln_data.get("confidence", 0.0),
                metadata=vuln_data.get("metadata", {}),
            )
            vulnerabilities.append(vuln)
        return vulnerabilities

    def _create_threat_indicators(
        self, analysis_results: Dict[str, Any]
    ) -> List[ThreatIndicator]:
        """Create ThreatIndicator objects from analysis results"""
        indicators = []
        for indicator_data in analysis_results.get("threat_indicators", []):
            threat_level = ThreatLevel(indicator_data.get("threat_level", "unknown"))
            indicator = create_threat_indicator(
                type=indicator_data.get("type", "unknown"),
                value=indicator_data.get("value", ""),
                threat_level=threat_level,
                description=indicator_data.get(
                    "description", "Unknown threat indicator"
                ),
                source=indicator_data.get("source", "unknown"),
                first_seen=indicator_data.get("first_seen"),
                last_seen=indicator_data.get("last_seen"),
                tags=indicator_data.get("tags", []),
                confidence=indicator_data.get("confidence", 0.0),
                metadata=indicator_data.get("metadata", {}),
            )
            indicators.append(indicator)
        return indicators

    def _create_recommendations(self, insights: Dict[str, Any]) -> List[Recommendation]:
        """Create Recommendation objects from insights"""
        recommendations = []
        for rec_data in insights.get("recommendations", []):
            rec = create_recommendation(
                id=rec_data.get("id", f"rec_{len(recommendations)}"),
                type=rec_data.get("type", "general"),
                priority=rec_data.get("priority", "medium"),
                title=rec_data.get("title", "Recommendation"),
                description=rec_data.get("description", "No description provided"),
                implementation=rec_data.get("implementation"),
                impact=rec_data.get("impact"),
                effort=rec_data.get("effort"),
                confidence=rec_data.get("confidence", 0.0),
                metadata=rec_data.get("metadata", {}),
            )
            recommendations.append(rec)
        return recommendations

    async def _create_analysis_metadata(
        self,
        request: AIAnalysisRequest,
        start_time: float,
        end_time: float,
        strategy: str,
        binary_type: str,
    ) -> AnalysisMetadata:
        """Create AnalysisMetadata from analysis process"""
        return create_analysis_metadata(
            analysis_id=request.session_id or f"analysis_{int(start_time)}",
            start_time=start_time,
            end_time=end_time,
            tools_used=self._get_tools_used(strategy),
            analysis_type=request.analysis_type,
            binary_type=binary_type,
            complexity=await self._assess_complexity(request.binary_path),
            confidence_overall=self._calculate_overall_confidence(),
            errors=[],
            warnings=[],
            metadata={"strategy": strategy},
        )

    def _get_tools_used(self, strategy: str) -> List[str]:
        """Get list of tools used based on strategy"""
        tool_mapping = {
            "rapid_triage": [
                "language_detector",
                "vulnerability_scanner",
                "threat_correlator",
            ],
            "security_focused": [
                "vulnerability_discovery_engine",
                "threat_intelligence_correlator",
            ],
            "comprehensive_analysis": [
                "enhanced_analyzer",
                "ghidra_engine",
                "vulnerability_discovery_engine",
            ],
            "custom_analysis": ["language_detector", "custom_analyzer"],
        }
        return tool_mapping.get(strategy, ["basic_analyzer"])

    def _calculate_overall_confidence(self) -> float:
        """Calculate overall confidence score"""
        # Simple confidence calculation - would be more sophisticated in practice
        return 0.8


# Convenience functions for easy usage
async def analyze_binary(
    binary_path: str,
    analysis_type: AnalysisType = AnalysisType.COMPREHENSIVE,
    goals: List[str] = None,
) -> AIAnalysisResult:
    """
    Convenience function for AI binary analysis

    Args:
        binary_path: Path to binary file
        analysis_type: Type of analysis (comprehensive, security, triage)
        goals: List of analysis goals

    Returns:
        AI analysis result
    """
    assistant = REVENGAIAssistant()
    request = AIAnalysisRequest(
        binary_path=binary_path,
        analysis_type=analysis_type,
        goals=goals
        or ["understand_functionality", "find_vulnerabilities", "assess_threats"],
    )
    return await assistant.analyze_binary_ai(request)


async def ask_about_binary(question: str, binary_path: str) -> str:
    """
    Convenience function for asking questions about a binary

    Args:
        question: Natural language question
        binary_path: Path to binary file

    Returns:
        Natural language answer
    """
    assistant = REVENGAIAssistant()
    return await assistant.ask_question(question, binary_path)


async def suggest_analysis_workflow(
    binary_path: str, goals: List[str]
) -> Dict[str, Any]:
    """
    Convenience function for workflow suggestions

    Args:
        binary_path: Path to binary file
        goals: List of analysis goals

    Returns:
        Workflow suggestion
    """
    assistant = REVENGAIAssistant()
    return await assistant.suggest_workflow(binary_path, goals)
