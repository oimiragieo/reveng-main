"""Tests for the shared reverse-engineering IR and JS IR export."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from reveng.ir import REEdge, RENode, REProjectIR
from reveng.javascript.bundle_reverse_engineer import JavaScriptBundleReverseEngineer


def test_re_project_ir_serializes_nodes_edges_and_metadata():
    ir = REProjectIR(
        schema_version="1.0",
        project_name="sample",
        input_path="sample.js",
        language="javascript",
        nodes=[
            RENode(node_id="cli", kind="domain", label="CLI", attributes={"score": 1.0}),
            RENode(node_id="auth", kind="domain", label="Auth", attributes={}),
        ],
        edges=[REEdge(source="cli", target="auth", kind="references", attributes={})],
        metadata={"benchmark": "claude"},
    )

    payload = ir.to_dict()

    assert payload["schema_version"] == "1.0"
    assert payload["project_name"] == "sample"
    assert payload["nodes"][0]["node_id"] == "cli"
    assert payload["edges"][0]["source"] == "cli"
    assert payload["metadata"]["benchmark"] == "claude"


def test_js_bundle_workflow_emits_ir_artifact(tmp_path: Path):
    install_root = tmp_path / "claude-code"
    install_root.mkdir(parents=True)
    bundle_path = install_root / "cli.js"
    bundle_path.write_text(
        """
        const authRoute = "claude auth login";
        const mcpRoute = "claude mcp serve";
        const endpoint = "https://api.example.com/mcp";
        const promptLibrary = { review: "/review", auth: "/auth" };
        const flagA = "--allowed-tools";
        function runTool(name, args) { return spawn("bash", args); }
        module.exports = { authRoute, mcpRoute, endpoint, promptLibrary, flagA, runTool };
        """,
        encoding="utf-8",
    )

    result = asyncio.run(
        JavaScriptBundleReverseEngineer().reverse_engineer_bundle(
            str(bundle_path),
            str(tmp_path / "analysis_output"),
            input_root=str(install_root),
        )
    )

    assert result.ir_file is not None
    assert result.ir_file.exists()

    payload = json.loads(result.ir_file.read_text(encoding="utf-8"))
    node_ids = {node["node_id"] for node in payload["nodes"]}

    assert payload["language"] == "javascript"
    assert "cli" in node_ids
    assert "auth" in node_ids
    assert "mcp" in node_ids
