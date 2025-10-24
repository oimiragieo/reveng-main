"""Simple natural-language response helper for REVENG AI API."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class NLResponse:
    """Structured response returned to AI agents."""

    answer: str
    confidence: float
    sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class NaturalLanguageInterface:
    """Rule-based fallback for answering questions about analysis results."""

    def __init__(self, model: str = "auto", use_ollama: bool = True):
        self.model = model
        self.use_ollama = use_ollama

    def query(
        self,
        question: str,
        binary_path: Optional[str] = None,
        analysis_results: Optional[Dict[str, Any]] = None,
    ) -> NLResponse:
        question_lower = question.lower()
        facts: List[str] = []
        confidence = 0.4
        sources: List[str] = []
        metadata: Dict[str, Any] = {}

        if analysis_results:
            summary = analysis_results.get("reveng_summary") or analysis_results.get(
                "summary"
            )
            if (
                not summary
                and isinstance(analysis_results, dict)
                and analysis_results.get("status")
            ):
                summary = analysis_results

            if isinstance(summary, dict):
                binary_info = summary.get("binary", {})
                ghidra_data = summary.get("ghidra_analysis", {})
                metadata["binary"] = binary_info

                if binary_info:
                    facts.append(
                        f"Binary '{binary_info.get('name', 'unknown')}' analysed with status {summary.get('status', 'unknown')}"
                    )
                if ghidra_data:
                    func_count = len(ghidra_data.get("functions", []))
                    import_count = len(ghidra_data.get("imports", []))
                    facts.append(
                        f"Identified {func_count} functions and {import_count} imports"
                    )
                sources.append("reveng_summary")
                confidence = 0.65

        if binary_path and Path(binary_path).exists():
            size_bytes = Path(binary_path).stat().st_size
            facts.append(f"File size is {size_bytes} bytes")
            sources.append("filesystem")
            confidence = max(confidence, 0.55)

        if "network" in question_lower:
            answer = self._describe_network_activity(analysis_results)
        elif "vulnerab" in question_lower:
            answer = self._describe_vulnerabilities(analysis_results)
        elif "ioc" in question_lower or "indicator" in question_lower:
            answer = self._describe_iocs(analysis_results)
        else:
            answer = (
                self._generic_summary(facts)
                if facts
                else "No detailed analysis data is available yet."
            )

        return NLResponse(
            answer=answer,
            confidence=min(confidence, 0.95),
            sources=sorted(set(sources)),
            metadata=metadata,
        )

    def _describe_network_activity(
        self, analysis_results: Optional[Dict[str, Any]]
    ) -> str:
        ghidra_data = self._ghidra_data(analysis_results)
        if ghidra_data:
            imports = ghidra_data.get("imports", []) or []
            network_apis = [
                imp
                for imp in imports
                if isinstance(imp, dict) and "socket" in imp.get("name", "").lower()
            ]
            if network_apis:
                names = ", ".join({imp.get("name", "unknown") for imp in network_apis})
                return f"The binary references network-related APIs such as {names}."
        return "No explicit network capabilities were detected in the available analysis data."

    def _describe_vulnerabilities(
        self, analysis_results: Optional[Dict[str, Any]]
    ) -> str:
        vuln_data = self._vulnerability_data(analysis_results)

        if isinstance(vuln_data, dict):
            status = vuln_data.get("status")
            if status and status not in {"success", "completed"}:
                return "Vulnerability discovery did not complete successfully."

            predictions = vuln_data.get("ml_predictions") or []
            if predictions:
                high_conf = [
                    pred for pred in predictions if (pred.get("confidence") or 0) >= 0.7
                ]
                if high_conf:
                    kinds = ", ".join(
                        sorted({pred.get("type", "unknown") for pred in high_conf})
                    )
                    return f"Potential vulnerabilities flagged by ML: {kinds}. Manual review recommended."

            report = vuln_data.get("report")
            if hasattr(report, "critical_count") and getattr(report, "critical_count"):
                return "Automated analysis detected critical vulnerability candidates; prioritize manual review of the Ghidra output."

        return "No high-confidence vulnerabilities were identified by the automated analysis."

    def _describe_iocs(self, analysis_results: Optional[Dict[str, Any]]) -> str:
        ghidra_data = self._ghidra_data(analysis_results)
        if ghidra_data:
            strings = ghidra_data.get("strings", []) or []
            iocs = [
                s
                for s in strings
                if isinstance(s, dict) and self._looks_like_ioc(s.get("value", ""))
            ]
            if iocs:
                sample = ", ".join({ioc.get("value", "") for ioc in iocs[:5]})
                return f"Indicators of compromise detected in strings: {sample}."
        return "No clear indicators of compromise (IPs, domains, URLs) were extracted."

    def _generic_summary(self, facts: List[str]) -> str:
        if not facts:
            return "Analysis completed, but no additional context is available."
        return "Summary: " + "; ".join(facts)

    def _ghidra_data(
        self, analysis_results: Optional[Dict[str, Any]]
    ) -> Dict[str, Any]:
        if not isinstance(analysis_results, dict):
            return {}
        if "ghidra_analysis" in analysis_results:
            return analysis_results["ghidra_analysis"] or {}
        summary = analysis_results.get("reveng_summary")
        if isinstance(summary, dict):
            return summary.get("ghidra_analysis", {}) or {}
        return {}

    def _looks_like_ioc(self, value: str) -> bool:
        value = value.lower()
        return any(
            token in value for token in ("http://", "https://", "://", ".com", ".net")
        )

    def _vulnerability_data(
        self, analysis_results: Optional[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        if not isinstance(analysis_results, dict):
            return None

        candidates: List[Dict[str, Any]] = []

        direct = analysis_results.get("enhanced_results")
        if isinstance(direct, dict):
            candidates.append(direct)

        summary = analysis_results.get("reveng_summary")
        if isinstance(summary, dict):
            enhanced = summary.get("enhanced_results")
            if isinstance(enhanced, dict):
                candidates.append(enhanced)
            enhanced_steps = summary.get("enhanced_steps")
            if isinstance(enhanced_steps, dict):
                candidates.append(enhanced_steps)

        for container in candidates:
            for key in ("step10", "step10_vulnerability_discovery"):
                data = container.get(key)
                if isinstance(data, dict):
                    return data

        return None
