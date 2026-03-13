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

import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

# Add src to path
import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import (  # noqa: E402
    AuditLogger,
    RateLimiter,
    REVENGEnterpriseServer,
)
from reveng.malware.memory_forensics import (  # noqa: E402
    MemoryAnalysis,
    MemoryArtifact,
    ProcessInfo,
)
from reveng.tools.diffing.binary_differ import DiffResult, FunctionMatch  # noqa: E402


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
        "scan_yara",
        "analyze_memory_dump",
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

    print("\n✓ Tools list message handled correctly")
    print(f"  Returned {len(response['result']['tools'])} tools")


@pytest.mark.poc
@pytest.mark.asyncio
async def test_tools_list_includes_forensic_tools(mcp_server):
    """Test new forensic tools are listed with schemas."""
    message = {"jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {}}

    response = await mcp_server.handle_message(message)

    tools = {tool["name"]: tool for tool in response["result"]["tools"]}

    assert "scan_yara" in tools
    assert "analyze_memory_dump" in tools
    assert "diff_binaries" in tools
    assert tools["scan_yara"]["inputSchema"]["required"] == ["path", "rules_path"]
    assert tools["analyze_memory_dump"]["inputSchema"]["required"] == ["path"]
    assert tools["diff_binaries"]["inputSchema"]["required"] == ["binary1", "binary2"]


@pytest.mark.poc
@pytest.mark.asyncio
async def test_scan_yara_tool_returns_structured_matches(mcp_server, temp_dir):
    """Test YARA scanning executes backend logic and returns structured JSON."""
    binary_path = temp_dir / "sample.bin"
    binary_path.write_bytes(b"MZ\x90\x00suspicious data")
    rules_path = temp_dir / "sample.yar"
    rules_path.write_text("rule test_rule { condition: true }", encoding="utf-8")

    yara_match = Mock(
        rule_name="test_rule",
        namespace="default",
        tags=["malware"],
        meta={"family": "demo"},
        strings=[(16, "$a", b"suspicious")],
    )
    scanner_instance = Mock()
    scanner_instance.scan_file.return_value = [yara_match]

    with patch(
        "reveng.tools.threat_intel.yara_scanner.YARAScanner", return_value=scanner_instance
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {
                    "name": "scan_yara",
                    "arguments": {"path": str(binary_path), "rules_path": str(rules_path)},
                },
            }
        )

    assert "result" in response
    assert response["result"]["match_count"] == 1
    assert response["result"]["matches"][0]["rule"] == "test_rule"
    assert response["result"]["matches"][0]["meta"]["family"] == "demo"
    assert response["result"]["matches"][0]["strings"][0]["identifier"] == "$a"


@pytest.mark.poc
@pytest.mark.asyncio
async def test_analyze_memory_dump_tool_returns_structured_analysis(mcp_server, temp_dir):
    """Test memory dump analysis executes backend logic and returns structured JSON."""
    dump_path = temp_dir / "sample.dmp"
    dump_path.write_bytes(b"memory-dump")

    analysis = MemoryAnalysis(
        binary_path=str(dump_path),
        analysis_timestamp="2026-03-13T00:00:00Z",
        total_processes=1,
        total_memory_regions=2,
        total_artifacts=1,
        processes=[
            ProcessInfo(
                process_id=101,
                process_name="malware.exe",
                parent_id=1,
                command_line="malware.exe --stealth",
                working_directory="C:/tmp",
            )
        ],
        artifacts=[
            MemoryArtifact(
                artifact_type="shellcode",
                address=4096,
                size=32,
                data=b"\x90" * 8,
                hash_md5="md5",
                hash_sha1="sha1",
                hash_sha256="sha256",
                description="Injected shellcode",
                confidence=0.95,
                threat_level="HIGH",
                anomaly_score=0.91,
                anomaly_threshold=0.68,
                is_anomalous=True,
                anomaly_reasons=["Injected code detected"],
            )
        ],
        risk_score=87.5,
        threat_level="HIGH",
        anomaly_score=0.88,
        anomaly_threshold=0.68,
        anomaly_flags=["Injected code detected"],
    )

    engine_instance = Mock()
    engine_instance.analyze_memory.return_value = analysis

    with patch(
        "reveng.malware.memory_forensics.MemoryForensics", return_value=engine_instance
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": {
                    "name": "analyze_memory_dump",
                    "arguments": {"path": str(dump_path), "output_dir": str(temp_dir / "out")},
                },
            }
        )

    assert "result" in response
    assert response["result"]["analysis"]["threat_level"] == "HIGH"
    assert response["result"]["analysis"]["risk_score"] == 87.5
    assert response["result"]["analysis"]["processes"][0]["process_name"] == "malware.exe"
    assert response["result"]["analysis"]["artifacts"][0]["artifact_type"] == "shellcode"


@pytest.mark.poc
@pytest.mark.asyncio
async def test_diff_binaries_tool_returns_structured_diff(mcp_server, temp_dir):
    """Test binary diffing executes backend logic and returns structured JSON."""
    binary1 = temp_dir / "v1.bin"
    binary2 = temp_dir / "v2.bin"
    binary1.write_bytes(b"AAAA")
    binary2.write_bytes(b"AAAB")

    diff_result = DiffResult(
        binary_v1=str(binary1),
        binary_v2=str(binary2),
        similarity_score=0.75,
        unchanged_functions=["main"],
        modified_functions=[
            FunctionMatch(
                func_v1_name="parse_config",
                func_v2_name="parse_config",
                similarity=0.83,
                match_type="name_match",
                changes=["string constant updated"],
            )
        ],
        new_functions=["handle_forensics"],
        deleted_functions=[],
        total_functions_v1=2,
        total_functions_v2=3,
        match_count=2,
        instruction_changes={"parse_config": {"changed_blocks": 1}},
        string_changes={"added": ["forensics"]},
    )

    differ_instance = Mock()
    differ_instance.diff.return_value = diff_result

    with patch(
        "reveng.tools.diffing.binary_differ.BinaryDiffer", return_value=differ_instance
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 23,
                "method": "tools/call",
                "params": {
                    "name": "diff_binaries",
                    "arguments": {"binary1": str(binary1), "binary2": str(binary2)},
                },
            }
        )

    assert "result" in response
    assert response["result"]["diff"]["similarity_score"] == 0.75
    assert response["result"]["diff"]["modified_functions"][0]["func_v1_name"] == "parse_config"
    assert response["result"]["diff"]["new_functions"] == ["handle_forensics"]


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

    print("\n✓ Resources list message handled correctly")
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

    print("\n✓ Prompts list message handled correctly")
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
    print("  • Logged 2 events successfully")


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
    print("  • Read resource: reveng://analyses/recent")


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
    print("  • Retrieved prompt: analyze_malware")
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
