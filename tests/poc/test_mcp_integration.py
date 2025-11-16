"""
POC Tests for REVENG MCP Integration
====================================

Proof-of-concept tests to validate MCP server functionality.

Tests:
- MCP server initialization
- Tool registration and discovery
- Tool execution
- Resource providers
- Prompt templates
- Enterprise features (rate limiting, audit logging)

Author: REVENG Development Team
Version: 4.0.0
License: MIT
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

# Add src to path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from reveng.agent_sdk.mcp.server import MCPMessageType, MCPPrompt, MCPResource, MCPServer, MCPTool
from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import (
    AuditLogger,
    RateLimiter,
    REVENGEnterpriseServer,
)


# ==================================================================================
# FIXTURES
# ==================================================================================


@pytest.fixture
def temp_dir():
    """Create temporary directory for tests"""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def audit_logger(temp_dir):
    """Create audit logger for testing"""
    return AuditLogger(log_dir=temp_dir / "audit_logs")


@pytest.fixture
def rate_limiter():
    """Create rate limiter for testing"""
    return RateLimiter(tokens_per_second=10.0, bucket_size=20)


@pytest.fixture
def mcp_server():
    """Create MCP server for testing"""
    return REVENGEnterpriseServer(
        enable_rate_limiting=False,  # Disable for testing
        enable_audit_log=False,  # Disable for testing
    )


@pytest.fixture
def mcp_server_with_features(temp_dir):
    """Create MCP server with enterprise features"""
    server = REVENGEnterpriseServer(enable_rate_limiting=True, enable_audit_log=True)
    # Override audit logger to use temp dir
    server.audit_logger = AuditLogger(log_dir=temp_dir / "audit_logs")
    return server


# ==================================================================================
# TEST: SERVER INITIALIZATION
# ==================================================================================


@pytest.mark.poc
def test_mcp_server_initialization(mcp_server):
    """Test MCP server initializes correctly"""
    assert mcp_server.name == "reveng-enterprise"
    assert mcp_server.version == "4.0.0"
    assert len(mcp_server.tools) > 0
    assert len(mcp_server.resources) > 0
    assert len(mcp_server.prompts) > 0

    print(f"\n✓ Server initialized: {mcp_server.name} v{mcp_server.version}")
    print(f"✓ Registered {len(mcp_server.tools)} tools")
    print(f"✓ Registered {len(mcp_server.resources)} resources")
    print(f"✓ Registered {len(mcp_server.prompts)} prompts")


# ==================================================================================
# TEST: TOOL REGISTRATION
# ==================================================================================


@pytest.mark.poc
def test_tool_registration(mcp_server):
    """Test all expected tools are registered"""
    expected_tools = [
        "analyze_binary",
        "decompile_binary",
        "recompile_binary",
        "diff_binaries",
        "find_vulnerabilities",
        "generate_exploit",
        "classify_malware",
        "deobfuscate_javascript",
        "detect_js_malware",
        "ask_ai_about_binary",
        "ai_code_reconstruction",
        "get_analysis_report",
        "list_recent_analyses",
    ]

    for tool_name in expected_tools:
        assert tool_name in mcp_server.tools, f"Tool {tool_name} not registered"
        tool = mcp_server.tools[tool_name]
        assert tool.name == tool_name
        assert tool.description
        assert tool.input_schema
        assert tool.handler is not None

    print(f"\n✓ All {len(expected_tools)} tools registered correctly")
    for tool_name in expected_tools:
        tool = mcp_server.tools[tool_name]
        print(f"  • {tool_name}: {tool.description[:60]}...")


# ==================================================================================
# TEST: MCP PROTOCOL MESSAGES
# ==================================================================================


@pytest.mark.poc
@pytest.mark.asyncio
async def test_initialize_message(mcp_server):
    """Test MCP initialize message"""
    message = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}

    response = await mcp_server.handle_message(message)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 1
    assert "result" in response
    assert response["result"]["protocolVersion"] == "2024-11-05"
    assert response["result"]["serverInfo"]["name"] == "reveng-enterprise"
    assert response["result"]["serverInfo"]["version"] == "4.0.0"

    print("\n✓ Initialize message handled correctly")
    print(f"  Protocol version: {response['result']['protocolVersion']}")
    print(
        f"  Server: {response['result']['serverInfo']['name']} v{response['result']['serverInfo']['version']}"
    )


@pytest.mark.poc
@pytest.mark.asyncio
async def test_tools_list_message(mcp_server):
    """Test tools/list message"""
    message = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

    response = await mcp_server.handle_message(message)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 2
    assert "result" in response
    assert "tools" in response["result"]
    assert len(response["result"]["tools"]) > 0

    # Verify tool format
    tool = response["result"]["tools"][0]
    assert "name" in tool
    assert "description" in tool
    assert "inputSchema" in tool

    print(f"\n✓ Tools list message handled correctly")
    print(f"  Returned {len(response['result']['tools'])} tools")


@pytest.mark.poc
@pytest.mark.asyncio
async def test_resources_list_message(mcp_server):
    """Test resources/list message"""
    message = {"jsonrpc": "2.0", "id": 3, "method": "resources/list", "params": {}}

    response = await mcp_server.handle_message(message)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 3
    assert "result" in response
    assert "resources" in response["result"]

    print(f"\n✓ Resources list message handled correctly")
    print(f"  Returned {len(response['result']['resources'])} resources")


@pytest.mark.poc
@pytest.mark.asyncio
async def test_prompts_list_message(mcp_server):
    """Test prompts/list message"""
    message = {"jsonrpc": "2.0", "id": 4, "method": "prompts/list", "params": {}}

    response = await mcp_server.handle_message(message)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 4
    assert "result" in response
    assert "prompts" in response["result"]

    print(f"\n✓ Prompts list message handled correctly")
    print(f"  Returned {len(response['result']['prompts'])} prompts")


# ==================================================================================
# TEST: TOOL EXECUTION
# ==================================================================================


@pytest.mark.poc
@pytest.mark.asyncio
async def test_list_recent_analyses_tool(mcp_server):
    """Test list_recent_analyses tool execution"""
    message = {
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "list_recent_analyses", "arguments": {"limit": 5}},
    }

    response = await mcp_server.handle_message(message)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 5
    assert "result" in response
    assert "content" in response["result"]
    assert len(response["result"]["content"]) > 0

    print("\n✓ list_recent_analyses tool executed successfully")
    print(f"  Response: {response['result']['content'][0]['text'][:100]}...")


@pytest.mark.poc
@pytest.mark.asyncio
async def test_tool_execution_error_handling(mcp_server):
    """Test tool execution error handling"""
    message = {
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {"name": "nonexistent_tool", "arguments": {}},
    }

    response = await mcp_server.handle_message(message)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 6
    assert "error" in response
    assert response["error"]["code"] == -32601

    print("\n✓ Tool execution error handling works correctly")
    print(f"  Error message: {response['error']['message']}")


# ==================================================================================
# TEST: ENTERPRISE FEATURES
# ==================================================================================


@pytest.mark.poc
@pytest.mark.asyncio
async def test_rate_limiter(rate_limiter):
    """Test rate limiter functionality"""
    # Should acquire tokens successfully
    for i in range(20):
        result = await rate_limiter.acquire()
        assert result is True

    # Should fail when bucket is empty
    result = await rate_limiter.acquire()
    assert result is False

    print("\n✓ Rate limiter works correctly")
    print("  • Acquired 20 tokens successfully")
    print("  • Correctly rejected when bucket empty")


@pytest.mark.poc
def test_audit_logger(audit_logger, temp_dir):
    """Test audit logging functionality"""
    # Log some events
    audit_logger.log_event(
        event_type="tool_execution",
        tool_name="analyze_binary",
        args={"path": "/test/binary.exe"},
        result="success",
        duration_ms=1234.56,
    )

    audit_logger.log_event(
        event_type="tool_execution",
        tool_name="deobfuscate_javascript",
        args={"code": "console.log('test')"},
        result="error",
        duration_ms=567.89,
        error="Test error",
    )

    # Verify log file exists
    log_files = list((temp_dir / "audit_logs").glob("audit_*.jsonl"))
    assert len(log_files) > 0

    # Verify log contents
    with open(log_files[0], "r") as f:
        lines = f.readlines()
        assert len(lines) == 2

        # Parse first event
        event1 = json.loads(lines[0])
        assert event1["event_type"] == "tool_execution"
        assert event1["tool_name"] == "analyze_binary"
        assert event1["result"] == "success"
        assert event1["duration_ms"] == 1234.56

        # Parse second event
        event2 = json.loads(lines[1])
        assert event2["tool_name"] == "deobfuscate_javascript"
        assert event2["result"] == "error"
        assert event2["error"] == "Test error"

    print("\n✓ Audit logging works correctly")
    print(f"  • Log file created: {log_files[0]}")
    print(f"  • Logged 2 events successfully")


@pytest.mark.poc
@pytest.mark.asyncio
async def test_enterprise_server_with_rate_limiting(mcp_server_with_features):
    """Test MCP server with rate limiting enabled"""
    # This should work (within rate limit)
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "list_recent_analyses", "arguments": {}},
    }

    response = await mcp_server_with_features.handle_message(message)
    assert "result" in response

    print("\n✓ Enterprise server with rate limiting works")


# ==================================================================================
# TEST: RESOURCE READING
# ==================================================================================


@pytest.mark.poc
@pytest.mark.asyncio
async def test_read_resource(mcp_server):
    """Test resource reading"""
    message = {
        "jsonrpc": "2.0",
        "id": 7,
        "method": "resources/read",
        "params": {"uri": "reveng://analyses/recent"},
    }

    response = await mcp_server.handle_message(message)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 7
    assert "result" in response
    assert "contents" in response["result"]

    print("\n✓ Resource reading works correctly")
    print(f"  • Read resource: reveng://analyses/recent")


# ==================================================================================
# TEST: PROMPT TEMPLATES
# ==================================================================================


@pytest.mark.poc
@pytest.mark.asyncio
async def test_get_prompt(mcp_server):
    """Test prompt template retrieval"""
    message = {
        "jsonrpc": "2.0",
        "id": 8,
        "method": "prompts/get",
        "params": {"name": "analyze_malware", "arguments": {"binary_path": "/samples/malware.exe"}},
    }

    response = await mcp_server.handle_message(message)

    assert response["jsonrpc"] == "2.0"
    assert response["id"] == 8
    assert "result" in response
    assert "messages" in response["result"]
    assert len(response["result"]["messages"]) > 0

    print("\n✓ Prompt template retrieval works correctly")
    print(f"  • Retrieved prompt: analyze_malware")
    print(f"  • Messages: {len(response['result']['messages'])}")


# ==================================================================================
# TEST: TOOL SCHEMA VALIDATION
# ==================================================================================


@pytest.mark.poc
def test_tool_schemas(mcp_server):
    """Test all tool schemas are valid"""
    for tool_name, tool in mcp_server.tools.items():
        schema = tool.input_schema

        # Verify schema has required fields
        assert "type" in schema, f"Tool {tool_name} missing schema type"
        assert schema["type"] == "object", f"Tool {tool_name} schema must be object type"
        assert "properties" in schema, f"Tool {tool_name} missing properties"

        # Verify required fields if present
        if "required" in schema:
            assert isinstance(schema["required"], list)
            for required_field in schema["required"]:
                assert (
                    required_field in schema["properties"]
                ), f"Tool {tool_name} requires missing field {required_field}"

    print(f"\n✓ All {len(mcp_server.tools)} tool schemas are valid")


# ==================================================================================
# MAIN
# ==================================================================================

if __name__ == "__main__":
    # Run tests with pytest
    pytest.main([__file__, "-v", "-m", "poc", "--tb=short"])
