"""
REVENG Intermediate Representation (IR) -- v2.

A cross-tool, architecture-agnostic graph IR that is the backbone of the
Verified Recompilation Loop. Every analysis stage produces and consumes IR
nodes with explicit provenance back to binary addresses and confidence scores
that compound through the pipeline.

Backwards-compatible aliases: RENode, REEdge, REProjectIR.
Legacy constant: IR_SCHEMA_VERSION (== SCHEMA_VERSION).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

SCHEMA_VERSION = "2.0.0"

# Backwards-compat constant that existing consumers import.
IR_SCHEMA_VERSION = SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class NodeKind(str, Enum):
    PROGRAM = "program"
    MODULE = "module"
    FUNCTION = "function"
    BASIC_BLOCK = "basic_block"
    INSTRUCTION = "instruction"
    VARIABLE = "variable"
    TYPE = "type"
    STRING = "string"
    CONSTANT = "constant"
    IMPORT = "import"
    EXPORT = "export"
    SECTION = "section"
    # Open-ended: consumers may pass raw strings for domain-specific kinds.


class EdgeKind(str, Enum):
    CALLS = "calls"
    JUMPS_TO = "jumps_to"
    FALLS_THROUGH = "falls_through"
    READS = "reads"
    WRITES = "writes"
    REFERENCES = "references"
    CONTAINS = "contains"
    TYPE_OF = "type_of"
    DATA_FLOW = "data_flow"
    CONTROL_FLOW = "control_flow"


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Provenance:
    """
    Traceability record linking an IR node back to its binary origin.

    All fields are optional so that partial provenance can be recorded
    without requiring a complete picture.
    """

    binary_path: Optional[str] = None
    binary_hash: Optional[str] = None
    virtual_address: Optional[int] = None
    file_offset: Optional[int] = None
    source_tool: Optional[str] = None  # e.g. "ghidra", "binja", "llm4decompile"
    source_version: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Provenance":
        return cls(
            binary_path=data.get("binary_path"),
            binary_hash=data.get("binary_hash"),
            virtual_address=data.get("virtual_address"),
            file_offset=data.get("file_offset"),
            source_tool=data.get("source_tool"),
            source_version=data.get("source_version"),
        )


# ---------------------------------------------------------------------------
# IRNode
# ---------------------------------------------------------------------------


@dataclass
class IRNode:
    """
    A typed vertex in the IR graph.

    The ``node_id`` field is the primary key within an IRProgram.
    ``kind`` is either a NodeKind value or an arbitrary string for domain-
    specific node types that do not yet have a canonical enum member.
    ``confidence`` is a float in [0.0, 1.0] where 1.0 means the analysis
    tool is certain and 0.0 means a speculative guess.
    """

    node_id: str
    kind: str  # Accept str so legacy domain kinds ("domain", "endpoint", ...) work.
    label: str = ""
    provenance: Provenance = field(default_factory=Provenance)
    confidence: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    children: List[str] = field(default_factory=list)  # child node_ids

    def to_dict(self) -> Dict[str, Any]:
        kind_val = self.kind.value if isinstance(self.kind, Enum) else self.kind
        return {
            "node_id": self.node_id,
            "kind": kind_val,
            "label": self.label,
            "provenance": self.provenance.to_dict(),
            "confidence": self.confidence,
            "attributes": self.attributes,
            "children": list(self.children),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IRNode":
        prov_data = data.get("provenance") or {}
        return cls(
            node_id=data["node_id"],
            kind=data["kind"],
            label=data.get("label", ""),
            provenance=Provenance.from_dict(prov_data),
            confidence=float(data.get("confidence", 1.0)),
            attributes=dict(data.get("attributes") or {}),
            children=list(data.get("children") or []),
        )


# ---------------------------------------------------------------------------
# IREdge
# ---------------------------------------------------------------------------


@dataclass
class IREdge:
    """
    A directed, typed edge between two IRNode vertices.

    ``source`` and ``target`` are node_id references. The IRProgram
    validates that both exist when ``add_edge`` is called.
    """

    source: str
    target: str
    kind: str  # Accept str for the same reason as IRNode.kind.
    confidence: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        kind_val = self.kind.value if isinstance(self.kind, Enum) else self.kind
        return {
            "source": self.source,
            "target": self.target,
            "kind": kind_val,
            "confidence": self.confidence,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IREdge":
        return cls(
            source=data["source"],
            target=data["target"],
            kind=data["kind"],
            confidence=float(data.get("confidence", 1.0)),
            attributes=dict(data.get("attributes") or {}),
        )


# ---------------------------------------------------------------------------
# IRProgram
# ---------------------------------------------------------------------------


@dataclass
class IRProgram:
    """
    Top-level IR container for one analyzed target.

    Nodes are stored in an insertion-order dict keyed by node_id.
    Edges are stored as a list in insertion order.

    The ``metadata`` dict is a free-form bag for project-level annotations
    such as project_name, input_path, language, and benchmark scores.
    """

    schema_version: str = SCHEMA_VERSION
    metadata: Dict[str, Any] = field(default_factory=dict)
    _nodes: Dict[str, IRNode] = field(default_factory=dict, repr=False)
    _edges: List[IREdge] = field(default_factory=list, repr=False)

    # ------------------------------------------------------------------
    # Convenience properties so callers can read .nodes / .edges directly.
    # ------------------------------------------------------------------

    @property
    def nodes(self) -> Dict[str, IRNode]:
        return self._nodes

    @property
    def edges(self) -> List[IREdge]:
        return self._edges

    # ------------------------------------------------------------------
    # Mutation helpers
    # ------------------------------------------------------------------

    def add_node(self, node: IRNode) -> None:
        if node.node_id in self._nodes:
            raise ValueError(f"Duplicate node_id: {node.node_id!r}")
        self._nodes[node.node_id] = node

    def add_edge(self, edge: IREdge) -> None:
        if edge.source not in self._nodes:
            raise ValueError(f"Unknown source node: {edge.source!r}")
        if edge.target not in self._nodes:
            raise ValueError(f"Unknown target node: {edge.target!r}")
        self._edges.append(edge)

    # ------------------------------------------------------------------
    # Query helpers
    # ------------------------------------------------------------------

    def nodes_of_kind(self, kind: str) -> Iterator[IRNode]:
        """Yield all nodes whose kind matches *kind* (string or NodeKind)."""
        kind_val = kind.value if isinstance(kind, Enum) else kind
        for node in self._nodes.values():
            node_kind = node.kind.value if isinstance(node.kind, Enum) else node.kind
            if node_kind == kind_val:
                yield node

    def outgoing(self, node_id: str) -> Iterator[IREdge]:
        for edge in self._edges:
            if edge.source == node_id:
                yield edge

    def incoming(self, node_id: str) -> Iterator[IREdge]:
        for edge in self._edges:
            if edge.target == node_id:
                yield edge

    def neighbors(self, node_id: str, kind: Optional[str] = None) -> List[IRNode]:
        """Return target nodes reachable via outgoing edges from *node_id*."""
        out: List[IRNode] = []
        kind_val: Optional[str] = None
        if kind is not None:
            kind_val = kind.value if isinstance(kind, Enum) else kind
        for edge in self._edges:
            if edge.source != node_id:
                continue
            if kind_val is not None:
                edge_kind = edge.kind.value if isinstance(edge.kind, Enum) else edge.kind
                if edge_kind != kind_val:
                    continue
            target_node = self._nodes.get(edge.target)
            if target_node is not None:
                out.append(target_node)
        return out

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "metadata": self.metadata,
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
        }

    def to_json(self, path: Optional[Path] = None, indent: int = 2) -> str:
        payload = json.dumps(self.to_dict(), indent=indent, sort_keys=True)
        if path is not None:
            Path(path).write_text(payload, encoding="utf-8")
        return payload

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IRProgram":
        prog = cls(
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            metadata=dict(data.get("metadata") or {}),
        )
        for node_data in data.get("nodes") or []:
            prog.add_node(IRNode.from_dict(node_data))
        for edge_data in data.get("edges") or []:
            prog._edges.append(IREdge.from_dict(edge_data))
        return prog

    @classmethod
    def from_json(cls, payload_or_path: Any) -> "IRProgram":
        """
        Accept either a JSON string/bytes or a filesystem path (str or Path).

        A value is treated as a path when:
        - It is a Path instance, OR
        - It is a str that does not start with ``{``
        """
        if isinstance(payload_or_path, Path) or (
            isinstance(payload_or_path, str) and not payload_or_path.lstrip().startswith("{")
        ):
            text = Path(payload_or_path).read_text(encoding="utf-8")
        elif isinstance(payload_or_path, bytes):
            text = payload_or_path.decode("utf-8")
        else:
            text = payload_or_path
        return cls.from_dict(json.loads(text))


# ---------------------------------------------------------------------------
# Backwards-compat shim: REProjectIR
#
# The legacy REProjectIR dataclass accepted project_name, input_path, and
# language as top-level positional fields.  We provide a drop-in factory
# function so that keyword-argument call sites continue to work unchanged.
# The returned object is a full IRProgram instance.
# ---------------------------------------------------------------------------


class _REProjectIRCompat(IRProgram):
    """
    Thin compatibility subclass that re-exposes the legacy REProjectIR
    constructor signature:

        REProjectIR(
            schema_version=...,
            project_name=...,
            input_path=...,
            language=...,
            nodes=[...],
            edges=[...],
            metadata={...},
        )

    The project_name, input_path, and language values are folded into the
    ``metadata`` dict.  The ``nodes`` and ``edges`` keyword args accept the
    legacy list-based form (List[IRNode/IREdge]) and are converted to the
    internal indexed structures.

    to_dict() preserves the legacy top-level keys so existing JSON consumers
    see the same shape they expected.
    """

    def __init__(
        self,
        schema_version: str = SCHEMA_VERSION,
        project_name: str = "",
        input_path: str = "",
        language: str = "",
        nodes: Optional[List[IRNode]] = None,
        edges: Optional[List[IREdge]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        meta: Dict[str, Any] = dict(metadata or {})
        if project_name:
            meta.setdefault("project_name", project_name)
        if input_path:
            meta.setdefault("input_path", input_path)
        if language:
            meta.setdefault("language", language)
        super().__init__(schema_version=schema_version, metadata=meta)
        for node in nodes or []:
            self.add_node(node)
        for edge in edges or []:
            self._edges.append(edge)

    # ------------------------------------------------------------------
    # Legacy attribute accessors so code like ``ir.project_name`` works.
    # ------------------------------------------------------------------

    @property
    def project_name(self) -> str:
        return self.metadata.get("project_name", "")

    @property
    def input_path(self) -> str:
        return self.metadata.get("input_path", "")

    @property
    def language(self) -> str:
        return self.metadata.get("language", "")

    def to_dict(self) -> Dict[str, Any]:
        """Preserve the legacy flat schema expected by existing consumers."""
        return {
            "schema_version": self.schema_version,
            "project_name": self.project_name,
            "input_path": self.input_path,
            "language": self.language,
            "nodes": [n.to_dict() for n in self._nodes.values()],
            "edges": [e.to_dict() for e in self._edges],
            "metadata": {
                k: v
                for k, v in self.metadata.items()
                if k not in ("project_name", "input_path", "language")
            },
        }


# ---------------------------------------------------------------------------
# Legacy RENode shim
#
# Old signature: RENode(node_id, kind, label, attributes={})
# New signature:  IRNode(node_id, kind, label="", provenance=..., ...)
#
# The only difference is that ``label`` had no default in the old class.
# IRNode gives it a default of "" which is backwards-compatible for all
# keyword-argument callers.  Alias directly.
# ---------------------------------------------------------------------------

RENode = IRNode
REEdge = IREdge  # type: ignore[assignment]  # same class, alias for clarity
REProjectIR = _REProjectIRCompat
