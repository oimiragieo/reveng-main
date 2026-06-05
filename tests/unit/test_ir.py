"""Unit tests for reveng.ir -- v2 IR data model."""

from __future__ import annotations

import json

import pytest

from reveng.core.ir import (
    IR_SCHEMA_VERSION,
    SCHEMA_VERSION,
    EdgeKind,
    IREdge,
    IRNode,
    IRProgram,
    NodeKind,
    Provenance,
    REEdge,
    RENode,
    REProjectIR,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sample_program() -> IRProgram:
    prog = IRProgram()
    prog.add_node(IRNode(node_id="root", kind="project", label="Root"))
    prog.add_node(IRNode(node_id="fn_main", kind=NodeKind.FUNCTION, label="main"))
    prog.add_node(IRNode(node_id="fn_helper", kind=NodeKind.FUNCTION, label="helper"))
    prog.add_edge(IREdge(source="root", target="fn_main", kind=EdgeKind.CONTAINS))
    prog.add_edge(IREdge(source="root", target="fn_helper", kind=EdgeKind.CONTAINS))
    prog.add_edge(IREdge(source="fn_main", target="fn_helper", kind=EdgeKind.CALLS, confidence=0.9))
    return prog


# ---------------------------------------------------------------------------
# Provenance
# ---------------------------------------------------------------------------


class TestProvenance:
    def test_defaults_are_none(self) -> None:
        prov = Provenance()
        assert prov.binary_path is None
        assert prov.virtual_address is None
        assert prov.source_tool is None

    def test_to_dict_round_trip(self) -> None:
        prov = Provenance(
            binary_path="/bin/target",
            binary_hash="abc123",
            virtual_address=0x1000,
            file_offset=4096,
            source_tool="ghidra",
            source_version="10.3",
        )
        d = prov.to_dict()
        restored = Provenance.from_dict(d)
        assert restored == prov

    def test_partial_provenance_round_trip(self) -> None:
        prov = Provenance(source_tool="binja")
        restored = Provenance.from_dict(prov.to_dict())
        assert restored.source_tool == "binja"
        assert restored.binary_path is None


# ---------------------------------------------------------------------------
# IRNode
# ---------------------------------------------------------------------------


class TestIRNode:
    def test_basic_creation(self) -> None:
        node = IRNode(node_id="n1", kind=NodeKind.FUNCTION, label="foo")
        assert node.node_id == "n1"
        assert node.confidence == 1.0
        assert node.attributes == {}
        assert node.children == []

    def test_confidence_default(self) -> None:
        node = IRNode(node_id="x", kind="custom")
        assert node.confidence == 1.0

    def test_confidence_explicit(self) -> None:
        node = IRNode(node_id="x", kind="custom", confidence=0.42)
        assert node.confidence == 0.42

    def test_to_dict_keys(self) -> None:
        node = IRNode(node_id="n1", kind=NodeKind.FUNCTION, label="foo", confidence=0.8)
        d = node.to_dict()
        assert d["node_id"] == "n1"
        assert d["kind"] == "function"
        assert d["label"] == "foo"
        assert d["confidence"] == 0.8
        assert "provenance" in d
        assert "attributes" in d
        assert "children" in d

    def test_from_dict_round_trip(self) -> None:
        node = IRNode(
            node_id="abc",
            kind=NodeKind.BASIC_BLOCK,
            label="bb0",
            confidence=0.75,
            attributes={"size": 16},
            children=["child1"],
        )
        restored = IRNode.from_dict(node.to_dict())
        assert restored.node_id == "abc"
        assert restored.kind == "basic_block"
        assert restored.label == "bb0"
        assert restored.confidence == 0.75
        assert restored.attributes == {"size": 16}
        assert restored.children == ["child1"]

    def test_raw_string_kind_accepted(self) -> None:
        node = IRNode(node_id="d1", kind="domain", label="CLI")
        assert node.kind == "domain"
        assert node.to_dict()["kind"] == "domain"


# ---------------------------------------------------------------------------
# IREdge
# ---------------------------------------------------------------------------


class TestIREdge:
    def test_basic_creation(self) -> None:
        edge = IREdge(source="a", target="b", kind=EdgeKind.CALLS)
        assert edge.source == "a"
        assert edge.target == "b"
        assert edge.confidence == 1.0

    def test_to_dict(self) -> None:
        edge = IREdge(source="a", target="b", kind=EdgeKind.DATA_FLOW, confidence=0.5)
        d = edge.to_dict()
        assert d["source"] == "a"
        assert d["target"] == "b"
        assert d["kind"] == "data_flow"
        assert d["confidence"] == 0.5

    def test_from_dict_round_trip(self) -> None:
        edge = IREdge(source="x", target="y", kind="depends_on", attributes={"weight": 3})
        restored = IREdge.from_dict(edge.to_dict())
        assert restored.source == "x"
        assert restored.target == "y"
        assert restored.kind == "depends_on"
        assert restored.attributes == {"weight": 3}


# ---------------------------------------------------------------------------
# IRProgram -- mutation
# ---------------------------------------------------------------------------


class TestIRProgramMutation:
    def test_add_node(self) -> None:
        prog = IRProgram()
        node = IRNode(node_id="n1", kind="function")
        prog.add_node(node)
        assert "n1" in prog.nodes

    def test_duplicate_node_raises(self) -> None:
        prog = IRProgram()
        prog.add_node(IRNode(node_id="n1", kind="function"))
        with pytest.raises(ValueError, match="Duplicate node_id"):
            prog.add_node(IRNode(node_id="n1", kind="function"))

    def test_add_edge_validates_source(self) -> None:
        prog = IRProgram()
        prog.add_node(IRNode(node_id="b", kind="function"))
        with pytest.raises(ValueError, match="Unknown source node"):
            prog.add_edge(IREdge(source="missing", target="b", kind="calls"))

    def test_add_edge_validates_target(self) -> None:
        prog = IRProgram()
        prog.add_node(IRNode(node_id="a", kind="function"))
        with pytest.raises(ValueError, match="Unknown target node"):
            prog.add_edge(IREdge(source="a", target="missing", kind="calls"))

    def test_add_edge_valid(self) -> None:
        prog = IRProgram()
        prog.add_node(IRNode(node_id="a", kind="function"))
        prog.add_node(IRNode(node_id="b", kind="function"))
        prog.add_edge(IREdge(source="a", target="b", kind=EdgeKind.CALLS))
        assert len(prog.edges) == 1


# ---------------------------------------------------------------------------
# IRProgram -- query helpers
# ---------------------------------------------------------------------------


class TestIRProgramQueries:
    def test_nodes_of_kind(self) -> None:
        prog = _sample_program()
        fns = list(prog.nodes_of_kind(NodeKind.FUNCTION))
        assert len(fns) == 2
        assert {n.node_id for n in fns} == {"fn_main", "fn_helper"}

    def test_nodes_of_kind_string(self) -> None:
        prog = _sample_program()
        fns = list(prog.nodes_of_kind("function"))
        assert len(fns) == 2

    def test_outgoing(self) -> None:
        prog = _sample_program()
        edges = list(prog.outgoing("root"))
        assert len(edges) == 2
        targets = {e.target for e in edges}
        assert targets == {"fn_main", "fn_helper"}

    def test_incoming(self) -> None:
        prog = _sample_program()
        edges = list(prog.incoming("fn_helper"))
        assert len(edges) == 2  # from root (CONTAINS) and fn_main (CALLS)

    def test_neighbors_no_filter(self) -> None:
        prog = _sample_program()
        neighbors = prog.neighbors("root")
        assert len(neighbors) == 2

    def test_neighbors_kind_filter(self) -> None:
        prog = _sample_program()
        neighbors = prog.neighbors("fn_main", kind=EdgeKind.CALLS)
        assert len(neighbors) == 1
        assert neighbors[0].node_id == "fn_helper"

    def test_neighbors_kind_filter_string(self) -> None:
        prog = _sample_program()
        neighbors = prog.neighbors("fn_main", kind="calls")
        assert len(neighbors) == 1


# ---------------------------------------------------------------------------
# IRProgram -- serialization / JSON round-trip
# ---------------------------------------------------------------------------


class TestIRProgramSerialization:
    def test_schema_version_stamped(self) -> None:
        prog = IRProgram()
        assert prog.schema_version == SCHEMA_VERSION
        assert prog.to_dict()["schema_version"] == SCHEMA_VERSION

    def test_to_json_returns_string(self) -> None:
        prog = _sample_program()
        payload = prog.to_json()
        assert isinstance(payload, str)
        data = json.loads(payload)
        assert data["schema_version"] == SCHEMA_VERSION

    def test_full_json_round_trip(self) -> None:
        prog = _sample_program()
        prog.metadata["author"] = "test"
        restored = IRProgram.from_json(prog.to_json())
        assert restored.schema_version == prog.schema_version
        assert restored.metadata["author"] == "test"
        assert len(restored.nodes) == len(prog.nodes)
        assert len(restored.edges) == len(prog.edges)

    def test_from_json_path(self, tmp_path: "Path") -> None:
        prog = _sample_program()
        out = tmp_path / "ir.json"
        prog.to_json(path=out)
        restored = IRProgram.from_json(out)
        assert len(restored.nodes) == 3

    def test_from_dict(self) -> None:
        prog = _sample_program()
        restored = IRProgram.from_dict(prog.to_dict())
        assert set(restored.nodes.keys()) == {"root", "fn_main", "fn_helper"}


# ---------------------------------------------------------------------------
# Backwards-compat aliases
# ---------------------------------------------------------------------------


class TestBackwardsCompatAliases:
    def test_renode_is_irnode(self) -> None:
        assert RENode is IRNode

    def test_reedge_is_ireedge(self) -> None:
        assert REEdge is IREdge

    def test_reprojectir_is_subclass(self) -> None:
        assert issubclass(REProjectIR, IRProgram)

    def test_ir_schema_version_constant(self) -> None:
        assert IR_SCHEMA_VERSION == SCHEMA_VERSION

    def test_renode_construction_keyword(self) -> None:
        node = RENode(node_id="cli", kind="domain", label="CLI", attributes={"score": 1.0})
        assert node.node_id == "cli"
        assert node.attributes == {"score": 1.0}

    def test_reedge_construction_keyword(self) -> None:
        edge = REEdge(source="cli", target="auth", kind="references", attributes={})
        assert edge.source == "cli"

    def test_reprojectir_keyword_construction(self) -> None:
        nodes = [
            RENode(node_id="cli", kind="domain", label="CLI"),
            RENode(node_id="auth", kind="domain", label="Auth"),
        ]
        edges = [REEdge(source="cli", target="auth", kind="references")]
        ir = REProjectIR(
            schema_version="1.0",
            project_name="sample",
            input_path="sample.js",
            language="javascript",
            nodes=nodes,
            edges=edges,
            metadata={"benchmark": "claude"},
        )
        payload = ir.to_dict()
        assert payload["schema_version"] == "1.0"
        assert payload["project_name"] == "sample"
        assert payload["language"] == "javascript"
        node_ids = {n["node_id"] for n in payload["nodes"]}
        assert "cli" in node_ids
        assert "auth" in node_ids
        assert payload["edges"][0]["source"] == "cli"
        assert payload["metadata"]["benchmark"] == "claude"

    def test_reprojectir_legacy_properties(self) -> None:
        ir = REProjectIR(
            schema_version="1.0",
            project_name="myproj",
            input_path="/bin/target",
            language="c",
        )
        assert ir.project_name == "myproj"
        assert ir.input_path == "/bin/target"
        assert ir.language == "c"

    def test_reprojectir_is_irprogram_instance(self) -> None:
        ir = REProjectIR(schema_version="1.0", project_name="p", input_path="", language="c")
        assert isinstance(ir, IRProgram)


# ---------------------------------------------------------------------------
# Provenance serialization in full round-trip
# ---------------------------------------------------------------------------


class TestProvenanceInIR:
    def test_provenance_survives_json_round_trip(self) -> None:
        prog = IRProgram()
        prov = Provenance(
            binary_path="/usr/bin/ls",
            virtual_address=0x4000,
            source_tool="ghidra",
        )
        prog.add_node(
            IRNode(node_id="fn_foo", kind=NodeKind.FUNCTION, label="foo", provenance=prov)
        )
        restored = IRProgram.from_json(prog.to_json())
        node = restored.nodes["fn_foo"]
        assert node.provenance.binary_path == "/usr/bin/ls"
        assert node.provenance.virtual_address == 0x4000
        assert node.provenance.source_tool == "ghidra"
