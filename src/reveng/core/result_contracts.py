"""Versioned result contracts for public analyzer and API outputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

RESULT_SCHEMA_VERSION = "1.0"


def make_trace_reference(
    relationship: str,
    target: str,
    *,
    trace_id: str,
    confidence: Optional[float] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Create a normalized trace reference for provenance chains."""
    reference = {
        "relationship": relationship,
        "target": target,
        "trace_id": trace_id,
    }
    if confidence is not None:
        reference["confidence"] = confidence
    if metadata:
        reference["metadata"] = metadata
    return reference


def make_evidence_item(
    kind: str,
    *,
    path: Optional[str] = None,
    trace_id: Optional[str] = None,
    evidence_kind: Optional[str] = None,
    confidence: Optional[float] = None,
    source_result_type: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
    **extra_fields: Any,
) -> Dict[str, Any]:
    """Create a normalized provenance entity."""
    item: Dict[str, Any] = {"kind": kind}
    if path is not None:
        item["path"] = path
    if trace_id is not None:
        item["trace_id"] = trace_id
    if evidence_kind is not None:
        item["evidence_kind"] = evidence_kind
    if confidence is not None:
        item["confidence"] = confidence
    if source_result_type is not None:
        item["source_result_type"] = source_result_type
    if metadata:
        item["metadata"] = metadata
    item.update(extra_fields)
    return item


def build_mcp_tool_response(
    *,
    tool_name: str,
    text: str,
    payload: Optional[Dict[str, Any]] = None,
    provenance: Optional[Dict[str, Any]] = None,
    status: str = "success",
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a versioned MCP tool response while preserving top-level payload fields."""
    response: Dict[str, Any] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "result_type": "mcp_tool_result",
        "tool_name": tool_name,
        "status": status,
        "content": [{"type": "text", "text": text}],
        "provenance": provenance
        or {
            "inputs": [],
            "artifacts": [],
            "stages": ["mcp_tool_execution", "result_contract_serialization"],
            "references": [],
            "tools": [tool_name],
        },
    }
    if payload:
        response.update(payload)
    if error is not None:
        response["error"] = error
    return response


def build_mcp_resource_result(
    *,
    resource_name: str,
    payload: Optional[Dict[str, Any]] = None,
    provenance: Optional[Dict[str, Any]] = None,
    status: str = "success",
    error: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a versioned MCP resource payload for resource-read responses."""
    response: Dict[str, Any] = {
        "schema_version": RESULT_SCHEMA_VERSION,
        "result_type": "mcp_resource_result",
        "resource_name": resource_name,
        "provenance": provenance
        or {
            "inputs": [],
            "artifacts": [],
            "stages": ["resource_read", "result_contract_serialization"],
            "references": [],
            "tools": ["read_resource"],
        },
    }
    if payload:
        response.update(payload)
    if status != "success":
        response["status"] = status
    if error is not None:
        response["error"] = error
    return response


@dataclass
class ResultContract:
    """Base class for public result contracts."""

    result_type: str
    schema_version: str = field(init=False, default=RESULT_SCHEMA_VERSION)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the contract as a JSON-friendly dictionary."""
        return asdict(self)


@dataclass
class AnalysisResultContract(ResultContract):
    version: str
    timestamp: str
    binary: Dict[str, Any]
    classification: Dict[str, Any]
    analysis: Dict[str, Any]
    ml_insights: Dict[str, Any]
    errors: List[str]
    warnings: List[str]
    metadata: Dict[str, Any]
    confidence: float
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReconstructionResultContract(ResultContract):
    version: str
    timestamp: str
    binary: Dict[str, Any]
    reconstruction: Dict[str, Any]
    quality: Dict[str, Any]
    errors: List[str]
    warnings: List[str]
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class MalwareDetectionResultContract(ResultContract):
    version: str
    timestamp: str
    binary: Dict[str, Any]
    threat_assessment: Dict[str, Any]
    indicators: Dict[str, Any]
    mitre_attacks: List[Any]
    recommendations: List[str]
    errors: List[str]
    warnings: List[str]
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalyzerCapabilitiesContract(ResultContract):
    version: str
    core_features: Dict[str, Any]
    enhanced_modules: Dict[str, Any]
    tools: Dict[str, Any]
    ml_models: Dict[str, Any]
    provenance: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AIBinaryAnalysisContract(ResultContract):
    version: str
    mode: str
    triage: Dict[str, Any]
    reveng_summary: Dict[str, Any] = field(default_factory=dict)
    full_analysis: Dict[str, Any] = field(default_factory=dict)
    translation_hints: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
