#!/usr/bin/env python3
"""
Ghidra MCP Connector
===================

Enhanced Ghidra MCP integration for AI-powered reverse engineering.
Extends the basic Ghidra MCP with AI-specific capabilities.

Author: REVENG Development Team
Version: 2.2.0
License: MIT
"""

import json
import logging
import subprocess
import time
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from reveng.tools.config.ghidra_http_client import GhidraHTTPClient

logger = logging.getLogger(__name__)


class GhidraMCPConnector:
    """
    Enhanced Ghidra MCP Connector for AI Integration

    Provides AI-specific tools for Ghidra interaction:
    - AI-powered function analysis
    - Smart renaming suggestions
    - Similar function detection
    - Interactive analysis sessions
    - Context-aware analysis
    """

    def __init__(self, ghidra_server_url: str = "http://127.0.0.1:8080/"):
        """
        Initialize Ghidra MCP Connector

        Args:
            ghidra_server_url: URL of the Ghidra MCP server
        """
        self.ghidra_server_url = ghidra_server_url
        self.logger = logging.getLogger(__name__)
        self.session_id = None
        self.analysis_context = {}

        # Initialize HTTP client for Ghidra communication
        self.http_client = GhidraHTTPClient(base_url=ghidra_server_url, timeout=30)

        # Check if Ghidra MCP server is available
        self._check_server_availability()

    def _check_server_availability(self) -> bool:
        """Check if Ghidra MCP server is available"""
        try:
            if self.http_client.health_check():
                self.logger.info("Ghidra MCP server is available")
                return True
            else:
                self.logger.warning("Ghidra MCP server not responding")
                return False
        except Exception as e:
            self.logger.warning(f"Ghidra MCP server not available: {e}")
            return False

    def start_session(self, binary_path: str) -> Dict[str, Any]:
        """
        Start a new Ghidra analysis session

        Args:
            binary_path: Path to binary file

        Returns:
            Session information
        """
        try:
            self.session_id = f"session_{int(time.time())}"
            self.analysis_context = {
                "binary_path": binary_path,
                "session_id": self.session_id,
                "start_time": time.time(),
                "functions_analyzed": [],
                "vulnerabilities_found": [],
                "threat_indicators": [],
            }

            self.logger.info(f"Started Ghidra session {self.session_id} for {binary_path}")
            return {"session_id": self.session_id, "binary_path": binary_path, "status": "active"}

        except Exception as e:
            self.logger.error(f"Failed to start Ghidra session: {e}")
            return {"error": str(e)}

    def ai_analyze_function(
        self, function_name: str, analysis_type: str = "comprehensive"
    ) -> Dict[str, Any]:
        """
        AI-powered function analysis with multiple analysis types

        Args:
            function_name: Name of function to analyze
            analysis_type: Type of analysis (comprehensive, security, performance, etc.)

        Returns:
            AI analysis result
        """
        try:
            # Get function decompilation
            decompiled_code = self._get_function_decompilation(function_name)

            # Analyze based on type
            if analysis_type == "comprehensive":
                result = self._comprehensive_function_analysis(function_name, decompiled_code)
            elif analysis_type == "security":
                result = self._security_function_analysis(function_name, decompiled_code)
            elif analysis_type == "performance":
                result = self._performance_function_analysis(function_name, decompiled_code)
            else:
                result = self._basic_function_analysis(function_name, decompiled_code)

            # Store in session context
            if self.session_id:
                self.analysis_context["functions_analyzed"].append(
                    {
                        "function_name": function_name,
                        "analysis_type": analysis_type,
                        "result": result,
                        "timestamp": time.time(),
                    }
                )

            return result

        except Exception as e:
            self.logger.error(f"AI function analysis failed: {e}")
            return {"error": str(e)}

    def ai_rename_smart(self, old_name: str, context: str = None) -> Dict[str, Any]:
        """
        AI-suggested renaming based on function behavior and context

        Args:
            old_name: Current function name
            context: Additional context for renaming

        Returns:
            Renaming suggestions
        """
        try:
            # Get function information
            function_info = self._get_function_info(old_name)

            # Analyze function behavior
            behavior_analysis = self._analyze_function_behavior(old_name)

            # Generate naming suggestions
            suggestions = self._generate_naming_suggestions(
                old_name, function_info, behavior_analysis, context
            )

            return {
                "original_name": old_name,
                "suggestions": suggestions,
                "confidence": self._calculate_naming_confidence(suggestions),
                "reasoning": self._explain_naming_reasoning(suggestions),
            }

        except Exception as e:
            self.logger.error(f"AI renaming failed: {e}")
            return {"error": str(e)}

    def ai_find_similar_functions(
        self, pattern: str, similarity_threshold: float = 0.8
    ) -> List[Dict[str, Any]]:
        """
        Find functions similar to a given pattern using AI

        Args:
            pattern: Pattern to search for
            similarity_threshold: Minimum similarity score (0.0-1.0)

        Returns:
            List of similar functions
        """
        try:
            # Get all functions
            all_functions = self._get_all_functions()

            # Find similar functions
            similar_functions = []
            for func in all_functions:
                similarity = self._calculate_function_similarity(pattern, func)
                if similarity >= similarity_threshold:
                    similar_functions.append(
                        {
                            "function_name": func["name"],
                            "similarity_score": similarity,
                            "reason": self._explain_similarity(pattern, func),
                        }
                    )

            # Sort by similarity score
            similar_functions.sort(key=lambda x: x["similarity_score"], reverse=True)

            return similar_functions

        except Exception as e:
            self.logger.error(f"Similar function search failed: {e}")
            return []

    def ask_about_function(self, function_name: str, question: str) -> str:
        """
        Ask natural language questions about a specific function

        Args:
            function_name: Name of function
            question: Natural language question

        Returns:
            Natural language answer
        """
        try:
            # Get function context
            function_context = self._get_function_context(function_name)

            # Use AI to answer question
            answer = self._ai_answer_question(question, function_context)

            return answer

        except Exception as e:
            self.logger.error(f"Function Q&A failed: {e}")
            return f"I'm sorry, I couldn't answer that question: {e}"

    def get_analysis_summary(self) -> Dict[str, Any]:
        """
        Get summary of current analysis session

        Returns:
            Analysis session summary
        """
        if not self.session_id:
            return {"error": "No active session"}

        return {
            "session_id": self.session_id,
            "binary_path": self.analysis_context.get("binary_path"),
            "duration": time.time() - self.analysis_context.get("start_time", time.time()),
            "functions_analyzed": len(self.analysis_context.get("functions_analyzed", [])),
            "vulnerabilities_found": len(self.analysis_context.get("vulnerabilities_found", [])),
            "threat_indicators": len(self.analysis_context.get("threat_indicators", [])),
            "context": self.analysis_context,
        }

    def export_analysis_results(self, format: str = "json") -> Dict[str, Any]:
        """
        Export analysis results in specified format

        Args:
            format: Export format (json, xml, yaml)

        Returns:
            Exported analysis results
        """
        try:
            if format == "json":
                return self.analysis_context
            elif format == "xml":
                return self._export_to_xml()
            elif format == "yaml":
                return self._export_to_yaml()
            else:
                return {"error": f"Unsupported format: {format}"}

        except Exception as e:
            self.logger.error(f"Export failed: {e}")
            return {"error": str(e)}

    # Helper methods for AI analysis
    @lru_cache(maxsize=128)
    def _get_function_decompilation(self, function_name: str) -> str:
        """Get decompiled code for a function from Ghidra server"""
        try:
            response = self.http_client.post("decompile", data=function_name, timeout=30)
            return response.text
        except Exception as e:
            self.logger.error(f"Failed to decompile {function_name}: {e}")
            return f"// Error getting decompilation: {e}"

    def _comprehensive_function_analysis(self, function_name: str, code: str) -> Dict[str, Any]:
        """Comprehensive function analysis"""
        return {
            "function_name": function_name,
            "analysis_type": "comprehensive",
            "purpose": self._infer_function_purpose(code),
            "complexity": self._assess_complexity(code),
            "security_issues": self._find_security_issues(code),
            "performance_issues": self._find_performance_issues(code),
            "suggestions": self._generate_improvement_suggestions(code),
        }

    def _security_function_analysis(self, function_name: str, code: str) -> Dict[str, Any]:
        """Security-focused function analysis"""
        return {
            "function_name": function_name,
            "analysis_type": "security",
            "vulnerabilities": self._find_security_issues(code),
            "threat_level": self._assess_threat_level(code),
            "recommendations": self._generate_security_recommendations(code),
        }

    def _performance_function_analysis(self, function_name: str, code: str) -> Dict[str, Any]:
        """Performance-focused function analysis"""
        return {
            "function_name": function_name,
            "analysis_type": "performance",
            "performance_issues": self._find_performance_issues(code),
            "optimization_suggestions": self._generate_optimization_suggestions(code),
            "complexity_score": self._assess_complexity(code),
        }

    def _basic_function_analysis(self, function_name: str, code: str) -> Dict[str, Any]:
        """Basic function analysis"""
        return {
            "function_name": function_name,
            "analysis_type": "basic",
            "purpose": self._infer_function_purpose(code),
            "complexity": self._assess_complexity(code),
        }

    def _get_function_info(self, function_name: str) -> Dict[str, Any]:
        """Get function information"""
        return {
            "name": function_name,
            "type": "function",
            "address": "0x00000000",  # Placeholder
            "size": 100,  # Placeholder
        }

    def _analyze_function_behavior(self, function_name: str) -> Dict[str, Any]:
        """Analyze function behavior"""
        return {
            "calls_made": [],
            "variables_used": [],
            "control_flow": "linear",
            "side_effects": [],
        }

    def _generate_naming_suggestions(
        self, old_name: str, function_info: Dict, behavior: Dict, context: str
    ) -> List[str]:
        """Generate naming suggestions"""
        suggestions = []

        # Basic suggestions based on common patterns
        if "main" in old_name.lower():
            suggestions.append("entry_point")
        elif "init" in old_name.lower():
            suggestions.append("initialize")
        elif "clean" in old_name.lower():
            suggestions.append("cleanup")

        # Add context-based suggestions
        if context:
            suggestions.append(f"{context}_handler")

        return suggestions[:5]  # Limit to 5 suggestions

    def _calculate_naming_confidence(self, suggestions: List[str]) -> float:
        """Calculate confidence in naming suggestions"""
        return min(0.9, len(suggestions) * 0.2)  # Simple confidence calculation

    def _explain_naming_reasoning(self, suggestions: List[str]) -> str:
        """Explain reasoning for naming suggestions"""
        return f"Generated {len(suggestions)} naming suggestions based on function behavior and context."

    @lru_cache(maxsize=1)
    def _get_all_functions(self) -> List[Dict[str, Any]]:
        """Get all functions in the binary from Ghidra server"""
        try:
            functions = self.http_client.get_json(
                "list_functions", params={"limit": 10000}, default=[]
            )
            self.logger.info(f"Retrieved {len(functions)} functions from Ghidra")
            return functions
        except Exception as e:
            self.logger.error(f"Failed to get function list: {e}")
            return []

    def _calculate_function_similarity(self, pattern: str, function: Dict[str, Any]) -> float:
        """Calculate similarity between pattern and function"""
        # Simple similarity calculation
        name = function.get("name", "")
        if pattern.lower() in name.lower():
            return 0.8
        elif any(word in name.lower() for word in pattern.lower().split()):
            return 0.6
        else:
            return 0.2

    def _explain_similarity(self, pattern: str, function: Dict[str, Any]) -> str:
        """Explain why functions are similar"""
        return f"Function '{function.get('name')}' contains pattern '{pattern}'"

    def _get_function_context(self, function_name: str) -> Dict[str, Any]:
        """Get context for a function"""
        return {
            "function_name": function_name,
            "decompiled_code": self._get_function_decompilation(function_name),
            "calls": [],
            "called_by": [],
            "variables": [],
        }

    def _ai_answer_question(self, question: str, context: Dict[str, Any]) -> str:
        """Use AI to answer questions about functions"""
        # This would integrate with Ollama or other AI services
        return f"Based on the analysis of {context.get('function_name')}, here's what I found: [AI analysis would go here]"

    # Placeholder methods for analysis components
    def _infer_function_purpose(self, code: str) -> str:
        """Infer function purpose from code"""
        return "Function purpose analysis"

    def _assess_complexity(self, code: str) -> str:
        """Assess code complexity"""
        return "medium"

    def _find_security_issues(self, code: str) -> List[str]:
        """Find security issues in code"""
        return []

    def _find_performance_issues(self, code: str) -> List[str]:
        """Find performance issues in code"""
        return []

    def _generate_improvement_suggestions(self, code: str) -> List[str]:
        """Generate improvement suggestions"""
        return []

    def _assess_threat_level(self, code: str) -> str:
        """Assess threat level"""
        return "low"

    def _generate_security_recommendations(self, code: str) -> List[str]:
        """Generate security recommendations"""
        return []

    def _generate_optimization_suggestions(self, code: str) -> List[str]:
        """Generate optimization suggestions"""
        return []

    def _export_to_xml(self) -> Dict[str, Any]:
        """Export to XML format"""
        return {"format": "xml", "data": self.analysis_context}

    def _export_to_yaml(self) -> Dict[str, Any]:
        """Export to YAML format"""
        return {"format": "yaml", "data": self.analysis_context}

    # Real Ghidra API methods using HTTP endpoints
    @lru_cache(maxsize=256)
    def get_strings(self, min_length: int = 4) -> List[Dict[str, Any]]:
        """Get all strings from binary via Ghidra"""
        try:
            strings = self.http_client.get_json(
                "list_strings", params={"minLength": min_length}, default=[]
            )
            self.logger.info(f"Retrieved {len(strings)} strings from Ghidra")
            return strings
        except Exception as e:
            self.logger.error(f"Failed to get strings: {e}")
            return []

    @lru_cache(maxsize=512)
    def get_xrefs_to(self, address: str) -> List[Dict[str, Any]]:
        """Get cross-references to an address"""
        try:
            xrefs = self.http_client.get_json(f"get_xrefs_to/{address}", default=[])
            return xrefs
        except Exception as e:
            self.logger.error(f"Failed to get xrefs to {address}: {e}")
            return []

    @lru_cache(maxsize=512)
    def get_xrefs_from(self, address: str) -> List[Dict[str, Any]]:
        """Get cross-references from an address"""
        try:
            xrefs = self.http_client.get_json(f"get_xrefs_from/{address}", default=[])
            return xrefs
        except Exception as e:
            self.logger.error(f"Failed to get xrefs from {address}: {e}")
            return []

    @lru_cache(maxsize=256)
    def get_function_calls(self, function_name: str) -> List[str]:
        """Get all function calls made by a function"""
        try:
            calls = self.http_client.get_json(f"get_function_calls/{function_name}", default=[])
            return calls
        except Exception as e:
            self.logger.error(f"Failed to get function calls for {function_name}: {e}")
            return []

    @lru_cache(maxsize=256)
    def get_callers(self, function_name: str) -> List[str]:
        """Get all functions that call this function"""
        try:
            callers = self.http_client.get_json(f"get_callers/{function_name}", default=[])
            return callers
        except Exception as e:
            self.logger.error(f"Failed to get callers for {function_name}: {e}")
            return []

    @lru_cache(maxsize=64)
    def get_imports(self) -> List[Dict[str, Any]]:
        """Get all imported functions"""
        try:
            imports = self.http_client.get_json("list_imports", default=[])
            self.logger.info(f"Retrieved {len(imports)} imports from Ghidra")
            return imports
        except Exception as e:
            self.logger.error(f"Failed to get imports: {e}")
            return []

    @lru_cache(maxsize=64)
    def get_exports(self) -> List[Dict[str, Any]]:
        """Get all exported functions"""
        try:
            exports = self.http_client.get_json("list_exports", default=[])
            self.logger.info(f"Retrieved {len(exports)} exports from Ghidra")
            return exports
        except Exception as e:
            self.logger.error(f"Failed to get exports: {e}")
            return []

    @lru_cache(maxsize=32)
    def get_segments(self) -> List[Dict[str, Any]]:
        """Get all memory segments"""
        try:
            segments = self.http_client.get_json("list_segments", default=[])
            self.logger.info(f"Retrieved {len(segments)} segments from Ghidra")
            return segments
        except Exception as e:
            self.logger.error(f"Failed to get segments: {e}")
            return []

    def get_function_info_by_address(self, address: str) -> Optional[Dict[str, Any]]:
        """Get detailed function information by address"""
        try:
            info = self.http_client.get_json(f"get_function/{address}", default=None)
            return info
        except Exception as e:
            self.logger.error(f"Failed to get function info for {address}: {e}")
            return None

    def clear_cache(self):
        """Clear all LRU caches to force fresh data"""
        self._get_function_decompilation.cache_clear()
        self._get_all_functions.cache_clear()
        self.get_strings.cache_clear()
        self.get_xrefs_to.cache_clear()
        self.get_xrefs_from.cache_clear()
        self.get_function_calls.cache_clear()
        self.get_callers.cache_clear()
        self.get_imports.cache_clear()
        self.get_exports.cache_clear()
        self.get_segments.cache_clear()
        self.logger.info("Cleared all Ghidra data caches")
