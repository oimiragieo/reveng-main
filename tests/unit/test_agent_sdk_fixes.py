"""Regression tests for agent_sdk bug fixes (Tasks 1.9, 1.10, 1.11).

Covers:
1. ToolError raised with two positional args (tool_name, message) in
   ClaudeSDKClient._execute_tool permission/not-found/pre-hook branches.
2. ToolRegistry.try_get returns None on miss (non-raising), and
   ClaudeSDKClient uses it so a missing tool surfaces a ToolError rather than
   an unhandled registry exception.
3. BinaryAnalysisTool.execute constructs REVENGAnalyzer(binary_path=path) and
   calls analyze_binary (no positional analyze()).
4. SecurityAuditSkill uses ToolResult.content (not the nonexistent .data).
"""

import asyncio
from typing import Any, Dict

import pytest

from reveng.agent_sdk.exceptions import ToolError
from reveng.agent_sdk.tools.base import BaseTool, ToolResult
from reveng.agent_sdk.tools.registry import ToolRegistry


class _DummyTool(BaseTool):
    name = "dummy"
    description = "dummy tool"
    input_schema = {"type": "object", "properties": {}, "required": []}

    async def execute(self, args: Dict[str, Any]) -> ToolResult:
        return ToolResult.success_result("ok")


# --- Task 1.10: ToolRegistry.try_get ---------------------------------------


def test_try_get_returns_none_on_miss():
    registry = ToolRegistry()
    assert registry.try_get("nope") is None


def test_try_get_returns_tool_when_present():
    registry = ToolRegistry()
    tool = _DummyTool()
    registry.register(tool)
    assert registry.try_get("dummy") is tool


def test_get_still_raises_on_miss():
    registry = ToolRegistry()
    with pytest.raises(ToolError):
        registry.get("nope")


# --- Task 1.9: ToolError two-arg construction in client --------------------


def _make_client():
    from reveng.agent_sdk.client import ClaudeSDKClient

    return ClaudeSDKClient(api_key="test-key", enable_cost_tracking=False)


def test_execute_tool_permission_denied_raises_toolerror():
    client = _make_client()

    # Force permission denial.
    client.permission_manager.can_execute = lambda name: False

    with pytest.raises(ToolError) as exc_info:
        asyncio.run(client._execute_tool("dummy", {}))
    assert exc_info.value.tool_name == "dummy"
    assert "Permission denied" in str(exc_info.value)


def test_execute_tool_not_found_raises_toolerror():
    client = _make_client()
    client.permission_manager.can_execute = lambda name: True

    # Tool not registered -> registry miss must surface as ToolError, not the
    # raw registry exception leaking out unhandled.
    with pytest.raises(ToolError) as exc_info:
        asyncio.run(client._execute_tool("missing", {}))
    assert exc_info.value.tool_name == "missing"
    assert "not found" in str(exc_info.value).lower()


def test_get_available_tools_filters_missing_without_raising():
    client = _make_client()
    client.permission_manager.can_execute = lambda name: True

    tool = _DummyTool()
    client.register_tool(tool)

    # "missing" is not registered; should be filtered out silently.
    available = client._get_available_tools(["dummy", "missing"])
    names = [t.name for t in available]
    assert names == ["dummy"]


# --- Task 1.11: BinaryAnalysisTool uses analyze_binary ---------------------


def test_binary_analysis_tool_calls_analyze_binary(monkeypatch):
    from reveng.agent_sdk.tools.reveng import binary_analysis_tool as bat

    calls = {}

    class FakeAnalyzer:
        def __init__(self, binary_path=None, **kwargs):
            calls["binary_path"] = binary_path

        def analyze_binary(self):
            calls["analyze_binary_called"] = True
            return {"file_type": "ELF"}

    import types

    fake_module = types.ModuleType("reveng.analyzer")
    fake_module.REVENGAnalyzer = FakeAnalyzer
    monkeypatch.setitem(
        __import__("sys").modules, "reveng.analyzer", fake_module
    )

    tool = bat.BinaryAnalysisTool()
    result = asyncio.run(tool.execute({"path": "/tmp/sample.bin"}))

    assert result.success is True
    assert calls.get("binary_path") == "/tmp/sample.bin"
    assert calls.get("analyze_binary_called") is True


# --- security_audit uses ToolResult.content (.data does not exist) ---------


def test_security_audit_uses_content_not_data():
    from reveng.agent_sdk.skills.builtin import security_audit

    src = security_audit.__file__
    with open(src, "r", encoding="utf-8") as fh:
        text = fh.read()
    assert "analysis_result.data" not in text
    assert "analysis_result.content" in text


def test_toolresult_has_no_data_attribute():
    # Guard: confirms the bug premise — ToolResult has no .data field.
    tr = ToolResult.success_result("x")
    assert not hasattr(tr, "data")
    assert hasattr(tr, "content")
