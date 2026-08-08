"""Enterprise MCP knob wiring tests."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest


@pytest.mark.asyncio
async def test_analyze_binary_quick_mode_and_find_vulns(monkeypatch, tmp_path):
    from reveng.agent_sdk.mcp.servers import reveng_enterprise_server as ent
    import reveng.analysis.analyzer as analyzer_mod

    captured: Dict[str, Any] = {}

    class FakeAnalyzer:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def analyze_binary(self):
            return {"binary": {"type": "pe", "architecture": "x86"}}

    monkeypatch.setattr(analyzer_mod, "REVENGAnalyzer", FakeAnalyzer)
    monkeypatch.setattr(
        analyzer_mod, "EnhancedAnalysisFeatures", analyzer_mod.EnhancedAnalysisFeatures
    )

    stub = object.__new__(ent.REVENGEnterpriseServer)
    stub.results_cache = {}
    stub._format_analysis_results = lambda result, path, analysis_id: "formatted"

    resp = await ent.REVENGEnterpriseServer.analyze_binary(
        stub,
        {
            "path": str(tmp_path / "x.bin"),
            "quick_mode": True,
            "enable_ai": False,
            "find_vulnerabilities": True,
        },
    )
    assert captured.get("check_ollama") is False
    assert captured.get("enable_ai") is False
    assert "not_run_use_find_vulnerabilities_tool" in str(resp)


@pytest.mark.asyncio
async def test_decompile_binary_unsupported_knobs(monkeypatch):
    from reveng.agent_sdk.mcp.servers import reveng_enterprise_server as ent

    stub = object.__new__(ent.REVENGEnterpriseServer)
    stub._resolve_binary_argument = lambda args, field_name="binary_path": "/tmp/x.bin"
    stub._coerce_optional_int = lambda v: None
    stub._get_ghidra_engine = lambda timeout_override=None: MagicMock(
        decompile=lambda path: {"functions": []}
    )
    stub._build_decompile_response = lambda path, result: {
        "content": [{"text": "decompiled"}],
        "decompiled_source": "// code",
    }

    resp = await ent.REVENGEnterpriseServer.decompile_binary(
        stub,
        {
            "binary_path": "/tmp/x.bin",
            "use_ai_enhancement": True,
            "reconstruct_types": True,
        },
    )
    text = str(resp)
    assert "use_ai_enhancement requested but unsupported" in text
    assert "reconstruct_types requested but unsupported" in text


def test_quick_mode_schema_description():
    src = Path("src/reveng/agent_sdk/mcp/servers/reveng_enterprise_server.py").read_text(
        encoding="utf-8"
    )
    assert "Skip Ollama preflight check (faster startup; analysis steps unchanged)" in src
    assert "unsupported in this MCP path (ghidra-only)" in src
    assert "90%+ accuracy" not in src.split("decompile_binary")[1].split("recompile_binary")[0]


@pytest.mark.asyncio
async def test_analyze_binary_false_find_vulns_omits_key(monkeypatch, tmp_path):
    from reveng.agent_sdk.mcp.servers import reveng_enterprise_server as ent
    import reveng.analysis.analyzer as analyzer_mod

    captured: Dict[str, Any] = {}

    class FakeAnalyzer:
        def __init__(self, **kwargs):
            captured.update(kwargs)
            assert kwargs.get("enhanced_features").enable_vulnerability_discovery is False

        def analyze_binary(self):
            return {"binary": {"type": "pe", "architecture": "x86"}}

    monkeypatch.setattr(analyzer_mod, "REVENGAnalyzer", FakeAnalyzer)

    stub = object.__new__(ent.REVENGEnterpriseServer)
    stub.results_cache = {}
    stub._format_analysis_results = lambda result, path, analysis_id: "formatted"

    resp = await ent.REVENGEnterpriseServer.analyze_binary(
        stub,
        {
            "path": str(tmp_path / "x.bin"),
            "quick_mode": False,
            "enable_ai": True,
            "find_vulnerabilities": False,
        },
    )
    assert captured.get("check_ollama") is True
    assert captured.get("enable_ai") is True
    assert "not_run_use_find_vulnerabilities_tool" not in str(resp)
    payload = resp.get("payload") or {}
    assert "find_vulnerabilities" not in payload


@pytest.mark.asyncio
async def test_decompile_omitted_knobs_no_unsupported_warning(monkeypatch):
    from reveng.agent_sdk.mcp.servers import reveng_enterprise_server as ent

    stub = object.__new__(ent.REVENGEnterpriseServer)
    stub._resolve_binary_argument = lambda args, field_name="binary_path": "/tmp/x.bin"
    stub._coerce_optional_int = lambda v: None
    stub._get_ghidra_engine = lambda timeout_override=None: MagicMock(
        decompile=lambda path: {"functions": []}
    )
    stub._build_decompile_response = lambda path, result: {
        "content": [{"text": "decompiled"}],
        "decompiled_source": "// code",
    }

    resp = await ent.REVENGEnterpriseServer.decompile_binary(stub, {"binary_path": "/tmp/x.bin"})
    text = str(resp)
    assert "use_ai_enhancement requested but unsupported" not in text
    assert "reconstruct_types requested but unsupported" not in text
