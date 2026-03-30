"""
Integration Tests for REVENG MCP Integration
====================================

Integration tests that validate MCP server functionality.

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

# Add src to path
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

import pytest

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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tools_list_includes_decompile_binary_schema_and_descriptions(mcp_server):
    """Test tools/list exposes complete schemas for all registered tools."""
    response = await mcp_server.handle_message(
        {"jsonrpc": "2.0", "id": 22, "method": "tools/list", "params": {}}
    )

    tools = response["result"]["tools"]
    assert len(tools) >= 15

    for tool in tools:
        assert tool["name"]
        assert tool["description"].strip()
        assert tool["inputSchema"]["type"] == "object"
        assert "properties" in tool["inputSchema"]

    decompile_tool = {tool["name"]: tool for tool in tools}["decompile_binary"]
    assert decompile_tool["inputSchema"]["required"] == ["binary_path"]
    assert decompile_tool["inputSchema"]["properties"]["binary_path"]["type"] == "string"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_tools_list_includes_recompile_binary_schema(mcp_server):
    """Test recompile_binary exposes the new binary_path/source_code schema."""
    response = await mcp_server.handle_message(
        {"jsonrpc": "2.0", "id": 25, "method": "tools/list", "params": {}}
    )

    recompile_tool = {tool["name"]: tool for tool in response["result"]["tools"]}[
        "recompile_binary"
    ]

    assert recompile_tool["inputSchema"]["required"] == ["binary_path"]
    assert recompile_tool["inputSchema"]["properties"]["binary_path"]["type"] == "string"
    assert recompile_tool["inputSchema"]["properties"]["source_code"]["type"] == "string"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_decompile_binary_tool_returns_structured_json(mcp_server, temp_dir):
    """Test decompile_binary returns structured decompilation details."""
    binary_path = temp_dir / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00")

    function_one = (
        "int add(int a, int b) {\n"
        "    int sum = a + b;\n"
        "    if (sum > 10) {\n"
        "        sum -= 1;\n"
        "    }\n"
        "    return sum;\n"
        "}\n"
    )
    function_two = (
        "int main(void) {\n"
        "    int total = add(20, 22);\n"
        "    if (total > 0) {\n"
        '        puts("hello");\n'
        "    }\n"
        "    return total;\n"
        "}\n"
    )

    mcp_server.ghidra_engine = Mock()
    mcp_server.ghidra_engine.decompile.return_value = {
        "functions": [
            {"name": "add", "entry_point": "0x401000", "source": function_one},
            {"name": "main", "entry_point": "0x401080", "source": function_two},
        ],
        "strings": ["hello", "world"],
        "imports": ["puts", "printf"],
    }

    response = await mcp_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {
                "name": "decompile_binary",
                "arguments": {"binary_path": str(binary_path)},
            },
        }
    )

    result = response["result"]
    assert result["binary_path"] == str(binary_path)
    assert result["status_code"] == 200
    assert len(result["decompiled_functions"]) == 2
    assert result["decompiled_functions"][0]["name"] == "add"
    assert result["strings"] == ["hello", "world"]
    assert result["imports"] == ["puts", "printf"]
    assert len(result["decompiled_source"]) >= 200
    assert "int add(" in result["decompiled_source"]
    assert result["content"][0]["text"].count("int ") >= 2


@pytest.mark.integration
@pytest.mark.asyncio
async def test_decompile_binary_tool_returns_descriptive_error(mcp_server, temp_dir):
    """Test decompile_binary returns a structured error instead of crashing."""
    binary_path = temp_dir / "missing.exe"
    binary_path.write_bytes(b"MZ\x90\x00")

    mcp_server.ghidra_engine = Mock()
    mcp_server.ghidra_engine.decompile.side_effect = RuntimeError("Ghidra backend exploded")

    response = await mcp_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 24,
            "method": "tools/call",
            "params": {
                "name": "decompile_binary",
                "arguments": {"binary_path": str(binary_path)},
            },
        }
    )

    result = response["result"]
    assert result["status_code"] == 500
    assert "Ghidra backend exploded" in result["error"]
    assert "Ghidra backend exploded" in result["content"][0]["text"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_recompile_binary_tool_returns_structured_success(mcp_server, temp_dir):
    """Test recompile_binary returns a real binary artifact path and overlap score."""
    binary_path = temp_dir / "sample.exe"
    rebuilt_binary = temp_dir / "rebuilt.exe"
    source_file = temp_dir / "reconstructed.c"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 2048))
    rebuilt_binary.write_bytes(b"MZ" + (b"\x90" * 2048))
    source_file.write_text("int main(void) { return 0; }\n", encoding="utf-8")

    decompile_result = {
        "decompiled_functions": [
            {
                "name": "main",
                "entry_point": "0x401000",
                "source": "int main(void) { return 0; }",
            }
        ],
        "decompiled_source": "int main(void) { return 0; }\n",
        "strings": [],
        "imports": [],
    }
    compile_report = {
        "status": "success",
        "binary_path": str(rebuilt_binary),
        "final_source_file": str(source_file),
        "attempts": [{"attempt": 1, "stderr": "", "returncode": 0}],
        "total_attempts": 1,
    }
    mock_backend = Mock()
    mock_backend.is_available.return_value = True
    mock_backend.model = "qwen2.5-coder:32b-instruct"

    with (
        patch(
            "reveng.agent_sdk.mcp.servers.reveng_enterprise_server.OllamaRepairEngine",
            return_value=mock_backend,
        ),
        patch(
            "reveng.ai.recompilation_engine.BinaryRecompilationEngine._phase1_decompilation",
            new=AsyncMock(return_value={"functions": [], "imports": [], "strings": []}),
        ),
        patch(
            "reveng.ai.recompilation_engine.BinaryRecompilationEngine._compile_with_feedback_loop",
            new=AsyncMock(return_value=compile_report),
        ),
        patch.object(
            mcp_server,
            "decompile_binary",
            new=AsyncMock(return_value=decompile_result),
        ) as mock_decompile,
        patch.object(
            mcp_server,
            "_calculate_function_overlap",
            new=AsyncMock(return_value=62.5),
        ),
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 26,
                "method": "tools/call",
                "params": {
                    "name": "recompile_binary",
                    "arguments": {"binary_path": str(binary_path)},
                },
            }
        )

    result = response["result"]
    mock_decompile.assert_awaited_once_with(
        {"binary_path": str(binary_path), "_ghidra_timeout": 180}
    )
    assert result["success"] is True
    assert result["output_path"] == str(rebuilt_binary)
    assert Path(result["output_path"]).exists()
    assert result["binary_size"] > 1024
    assert result["magic_bytes"] == "MZ"
    assert result["function_overlap"] == 62.5
    assert result["model"] == mock_backend.model


@pytest.mark.integration
@pytest.mark.asyncio
async def test_recompile_binary_tool_returns_structured_failure(mcp_server, temp_dir):
    """Test recompile_binary returns structured compiler errors when retries are exhausted."""
    binary_path = temp_dir / "sample.exe"
    source_file = temp_dir / "reconstructed.c"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 2048))
    source_file.write_text("int main(void) { broken }\n", encoding="utf-8")

    decompile_result = {
        "decompiled_functions": [
            {
                "name": "main",
                "entry_point": "0x401000",
                "source": "int main(void) { broken }",
            }
        ],
        "decompiled_source": "int main(void) { broken }\n",
        "strings": [],
        "imports": [],
    }
    compile_report = {
        "status": "failed",
        "binary_path": None,
        "final_source_file": str(source_file),
        "attempts": [
            {"attempt": 1, "stderr": "error: expected ';' before '}' token", "returncode": 1},
            {"attempt": 2, "stderr": "error: unknown type name 'broken'", "returncode": 1},
        ],
        "total_attempts": 2,
        "failure_reason": "max_retries_exceeded",
    }
    mock_backend = Mock()
    mock_backend.is_available.return_value = True
    mock_backend.model = "qwen2.5-coder:32b-instruct"

    with (
        patch(
            "reveng.agent_sdk.mcp.servers.reveng_enterprise_server.OllamaRepairEngine",
            return_value=mock_backend,
        ),
        patch(
            "reveng.ai.recompilation_engine.BinaryRecompilationEngine._phase1_decompilation",
            new=AsyncMock(return_value={"functions": [], "imports": [], "strings": []}),
        ),
        patch(
            "reveng.ai.recompilation_engine.BinaryRecompilationEngine._compile_with_feedback_loop",
            new=AsyncMock(return_value=compile_report),
        ),
        patch.object(
            mcp_server,
            "decompile_binary",
            new=AsyncMock(return_value=decompile_result),
        ),
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 27,
                "method": "tools/call",
                "params": {
                    "name": "recompile_binary",
                    "arguments": {"binary_path": str(binary_path)},
                },
            }
        )

    result = response["result"]
    assert result["success"] is False
    assert result["failure_reason"] == "max_retries_exceeded"
    assert len(result["compilation_errors"]) == 2
    assert "expected ';'" in result["compilation_errors"][0]
    assert result["partial_source"] == "int main(void) { broken }\n"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_recompile_binary_tool_skips_decompile_when_source_is_provided(mcp_server, temp_dir):
    """Test recompile_binary does not re-decompile when explicit source_code is supplied."""
    binary_path = temp_dir / "sample.exe"
    rebuilt_binary = temp_dir / "rebuilt.exe"
    source_file = temp_dir / "provided.c"
    provided_source = "int helper(void) { return 7; }\nint main(void) { return helper(); }\n"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 2048))
    rebuilt_binary.write_bytes(b"MZ" + (b"\x90" * 2048))
    source_file.write_text(provided_source, encoding="utf-8")

    compile_report = {
        "status": "success",
        "binary_path": str(rebuilt_binary),
        "final_source_file": str(source_file),
        "attempts": [{"attempt": 1, "stderr": "", "returncode": 0}],
        "total_attempts": 1,
    }
    mock_backend = Mock()
    mock_backend.is_available.return_value = True
    mock_backend.model = "qwen2.5-coder:32b-instruct"

    with (
        patch(
            "reveng.agent_sdk.mcp.servers.reveng_enterprise_server.OllamaRepairEngine",
            return_value=mock_backend,
        ),
        patch(
            "reveng.ai.recompilation_engine.BinaryRecompilationEngine._phase1_decompilation",
            new=AsyncMock(return_value={"functions": [], "imports": [], "strings": []}),
        ),
        patch(
            "reveng.ai.recompilation_engine.BinaryRecompilationEngine._compile_with_feedback_loop",
            new=AsyncMock(return_value=compile_report),
        ),
        patch.object(
            mcp_server,
            "decompile_binary",
            new=AsyncMock(),
        ) as mock_decompile,
        patch.object(
            mcp_server,
            "_calculate_function_overlap",
            new=AsyncMock(return_value=50.0),
        ),
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 28,
                "method": "tools/call",
                "params": {
                    "name": "recompile_binary",
                    "arguments": {
                        "binary_path": str(binary_path),
                        "source_code": provided_source,
                    },
                },
            }
        )

    result = response["result"]
    mock_decompile.assert_not_awaited()
    assert result["success"] is True
    assert result["output_path"] == str(rebuilt_binary)
    assert result["function_overlap"] == 50.0


@pytest.mark.integration
@pytest.mark.asyncio
async def test_ask_ai_about_binary_returns_structured_ollama_answer(mcp_server, temp_dir):
    """Test ask_ai_about_binary decompiles first and returns structured Ollama output."""
    binary_path = temp_dir / "sample.exe"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 512))

    mcp_server.ghidra_engine = Mock()
    mcp_server.ghidra_engine.timeout = 180
    mcp_server.ghidra_engine.fail_fast = False
    mcp_server.ghidra_engine.decompile.return_value = {
        "functions": [
            {
                "name": "main",
                "entry_point": "0x401000",
                "source": (
                    "int main(void) {\n"
                    "    initialize_network();\n"
                    "    send_status();\n"
                    "    return 0;\n"
                    "}\n"
                ),
            }
        ],
        "imports": ["send", "connect"],
        "strings": ["status=ok", "10.0.0.5"],
    }

    mock_query = AsyncMock(
        return_value=(
            "The binary appears to initialize a network routine, prepare a status payload, "
            "and send it outbound before exiting. The imported networking APIs and status "
            "string strongly suggest beaconing or telemetry behavior."
        )
    )

    with patch.object(mcp_server, "_query_ollama_chat", new=mock_query):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 29,
                "method": "tools/call",
                "params": {
                    "name": "ask_ai_about_binary",
                    "arguments": {
                        "binary_path": str(binary_path),
                        "question": "What does this binary do?",
                    },
                },
            }
        )

    result = response["result"]
    assert result["status_code"] == 200
    assert result["binary_path"] == str(binary_path)
    assert result["model"] == mcp_server.ollama_chat_model
    assert result["context_used"] is True
    assert len(result["answer"]) >= 50
    assert "network" in result["answer"].lower()

    query_kwargs = mock_query.await_args.kwargs
    assert "What does this binary do?" in query_kwargs["user_prompt"]
    assert "initialize_network" in query_kwargs["user_prompt"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_ask_ai_about_binary_returns_timeout_error_json(mcp_server, temp_dir):
    """Test ask_ai_about_binary turns Ollama timeouts into structured error JSON."""
    binary_path = temp_dir / "sample.exe"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 512))

    mcp_server.ghidra_engine = Mock()
    mcp_server.ghidra_engine.timeout = 180
    mcp_server.ghidra_engine.fail_fast = False
    mcp_server.ghidra_engine.decompile.return_value = {
        "functions": [
            {"name": "main", "entry_point": "0x401000", "source": "int main(void) { return 0; }"}
        ],
        "imports": [],
        "strings": [],
    }

    with patch.object(
        mcp_server,
        "_query_ollama_chat",
        new=AsyncMock(side_effect=TimeoutError("Ollama request timed out after 90 seconds")),
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 30,
                "method": "tools/call",
                "params": {
                    "name": "ask_ai_about_binary",
                    "arguments": {
                        "binary_path": str(binary_path),
                        "question": "What does this binary do?",
                    },
                },
            }
        )

    result = response["result"]
    assert result["status_code"] == 504
    assert "timed out" in result["error"].lower()
    assert result["model"] == mcp_server.ollama_chat_model


@pytest.mark.integration
@pytest.mark.asyncio
async def test_ask_ai_about_binary_timeout_without_context_returns_safe_fallback(
    mcp_server, temp_dir
):
    """Test timeout fallback does not require decompiled context to return structured JSON."""
    binary_path = temp_dir / "sample.exe"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 512))

    with (
        patch.object(
            mcp_server,
            "decompile_binary",
            new=AsyncMock(return_value={}),
        ),
        patch.object(
            mcp_server,
            "_build_binary_question_context",
            return_value="Binary question context",
        ),
        patch.object(
            mcp_server,
            "_query_ollama_chat",
            new=AsyncMock(side_effect=TimeoutError("Ollama request timed out after 90 seconds")),
        ),
        patch.object(
            mcp_server,
            "_build_timeout_question_fallback",
            side_effect=AssertionError("unexpected context fallback"),
        ),
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 30_1,
                "method": "tools/call",
                "params": {
                    "name": "ask_ai_about_binary",
                    "arguments": {
                        "binary_path": str(binary_path),
                        "question": "What does this binary do?",
                    },
                },
            }
        )

    result = response["result"]
    assert result["status_code"] == 504
    assert result["fallback_used"] is True
    assert "timed out before it could produce an answer" in result["answer"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_ai_code_reconstruction_returns_cfg_aware_structured_code(mcp_server, temp_dir):
    """Test ai_code_reconstruction uses CFG context and returns parsed reconstructed code."""
    binary_path = temp_dir / "sample.exe"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 512))

    mcp_server.ghidra_engine = Mock()
    mcp_server.ghidra_engine.timeout = 180
    mcp_server.ghidra_engine.fail_fast = False
    mcp_server.ghidra_engine.decompile.return_value = {
        "functions": [
            {
                "name": "main",
                "entry_point": "0x401000",
                "source": (
                    "int main(void) {\n"
                    "    int v1 = initialize();\n"
                    "    if (v1 != 0) {\n"
                    "        return process(v1);\n"
                    "    }\n"
                    "    return -1;\n"
                    "}\n"
                ),
            }
        ],
        "imports": ["puts"],
        "strings": ["processing"],
    }

    cfg_context = {
        "payload": {"function_count": 1, "graph_metrics": {"node_count": 7, "edge_count": 8}},
        "context_text": "Function main @ 0x401000: 3 basic blocks\n  Calls: initialize, process",
        "function_count": 1,
        "node_count": 7,
        "edge_count": 8,
    }
    llm_json = json.dumps(
        {
            "reconstructed_code": (
                "int initialize_context(void) {\n"
                "    return 1;\n"
                "}\n\n"
                "int process_request(int initialization_status) {\n"
                "    return initialization_status + 41;\n"
                "}\n\n"
                "int main(void) {\n"
                "    int initialization_status = initialize_context();\n"
                "    if (initialization_status != 0) {\n"
                "        return process_request(initialization_status);\n"
                "    }\n"
                "    return -1;\n"
                "}\n"
            ),
            "improvement_notes": "Renamed temporary variables, split helper logic into named functions, and preserved the original branch structure.",
        }
    )

    mock_query = AsyncMock(return_value=llm_json)
    with (
        patch.object(
            mcp_server,
            "_extract_cfg_context",
            new=AsyncMock(return_value=cfg_context),
        ),
        patch.object(
            mcp_server,
            "_query_ollama_chat",
            new=mock_query,
        ),
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {
                    "name": "ai_code_reconstruction",
                    "arguments": {"binary_path": str(binary_path)},
                },
            }
        )

    result = response["result"]
    assert result["status_code"] == 200
    assert result["cfg_context_used"] is True
    assert result["model"] == mcp_server.ollama_chat_model
    assert len(result["reconstructed_code"]) >= 100
    assert "int main(" in result["reconstructed_code"]
    assert "Renamed temporary variables" in result["improvement_notes"]
    assert result["cfg_summary"] == {"function_count": 1, "node_count": 7, "edge_count": 8}

    query_kwargs = mock_query.await_args.kwargs
    assert "CFG summary:" in query_kwargs["user_prompt"]
    assert "Calls: initialize, process" in query_kwargs["user_prompt"]


@pytest.mark.integration
@pytest.mark.asyncio
async def test_ai_code_reconstruction_returns_timeout_error_json(mcp_server, temp_dir):
    """Test ai_code_reconstruction returns structured timeout details instead of raising."""
    binary_path = temp_dir / "sample.exe"
    binary_path.write_bytes(b"MZ" + (b"\x00" * 512))

    mcp_server.ghidra_engine = Mock()
    mcp_server.ghidra_engine.timeout = 180
    mcp_server.ghidra_engine.fail_fast = False
    mcp_server.ghidra_engine.decompile.return_value = {
        "functions": [
            {"name": "main", "entry_point": "0x401000", "source": "int main(void) { return 0; }"}
        ],
        "imports": [],
        "strings": [],
    }

    with (
        patch.object(
            mcp_server,
            "_extract_cfg_context",
            new=AsyncMock(
                return_value={
                    "payload": {},
                    "context_text": "cfg",
                    "function_count": 1,
                    "node_count": 1,
                    "edge_count": 0,
                }
            ),
        ),
        patch.object(
            mcp_server,
            "_query_ollama_chat",
            new=AsyncMock(side_effect=TimeoutError("Ollama request timed out after 90 seconds")),
        ),
    ):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 32,
                "method": "tools/call",
                "params": {
                    "name": "ai_code_reconstruction",
                    "arguments": {"binary_path": str(binary_path)},
                },
            }
        )

    result = response["result"]
    assert result["status_code"] == 504
    assert "timed out" in result["error"].lower()
    assert result["cfg_context_used"] is False


@pytest.mark.integration
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

    with patch("reveng.tools.threat_intel.yara_scanner.YARAScanner", return_value=scanner_instance):
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


@pytest.mark.integration
@pytest.mark.asyncio
async def test_scan_yara_tool_rejects_non_rule_files(mcp_server, temp_dir):
    """Test scan_yara returns a structured error for invalid rule-file inputs."""
    binary_path = temp_dir / "sample.bin"
    binary_path.write_bytes(b"MZ\x90\x00suspicious data")
    rules_path = temp_dir / "rules.txt"
    rules_path.write_text("not yara", encoding="utf-8")

    response = await mcp_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 21_1,
            "method": "tools/call",
            "params": {
                "name": "scan_yara",
                "arguments": {"path": str(binary_path), "rules_path": str(rules_path)},
            },
        }
    )

    result = response["result"]
    assert result["status"] == "error"
    assert "YARA rules path must be a .yar/.yara file or directory containing rule files" in (
        result["error"]
    )


@pytest.mark.integration
@pytest.mark.asyncio
async def test_classify_malware_tool_returns_structured_result(mcp_server, temp_dir):
    """Test malware classification executes backend logic and returns structured JSON."""
    binary_path = temp_dir / "sample.exe"
    binary_path.write_bytes(b"MZ\x90\x00" + b"\x00" * 128)

    scanner_instance = Mock()
    scanner_instance.classify_file.return_value = {
        "family": "Generic Trojan",
        "confidence": 0.82,
        "matched_rules": ["trojan_process_injection_apis"],
        "indicators": ["Process injection API cluster detected"],
        "yara_matches": [
            {
                "rule": "trojan_process_injection_apis",
                "namespace": "trojan_indicators",
                "tags": ["trojan", "injection"],
                "meta": {"family": "Injection Trojan"},
                "strings": [],
            }
        ],
        "ml_assessment": {
            "score": 0.71,
            "threshold": 0.64,
            "exceeded": True,
            "reasons": ["import table contains many suspicious APIs"],
            "features": {"entropy": 7.1},
        },
        "feature_summary": {"entropy": 7.1, "import_count": 12.0},
    }

    with patch("reveng.security.yara_scanner.YARAScanner", return_value=scanner_instance):
        response = await mcp_server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 22,
                "method": "tools/call",
                "params": {
                    "name": "classify_malware",
                    "arguments": {
                        "path": str(binary_path),
                        "use_ollama_family_naming": False,
                    },
                },
            }
        )

    assert "result" in response
    assert response["result"]["family"] == "Generic Trojan"
    assert response["result"]["confidence"] == 0.82
    assert response["result"]["matched_rules"] == ["trojan_process_injection_apis"]
    assert response["result"]["indicators"] == ["Process injection API cluster detected"]


@pytest.mark.integration
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

    with patch("reveng.malware.memory_forensics.MemoryForensics", return_value=engine_instance):
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


@pytest.mark.integration
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

    with patch("reveng.tools.diffing.binary_differ.BinaryDiffer", return_value=differ_instance):
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


@pytest.mark.integration
@pytest.mark.asyncio
async def test_detect_js_malware_tool_rejects_non_utf8_file(mcp_server, temp_dir):
    """Test detect_js_malware surfaces a clear UTF-8 decoding error contract."""
    sample = temp_dir / "sample.js"
    sample.write_bytes(b"\xff\xfe\x00\x00")

    response = await mcp_server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 23_1,
            "method": "tools/call",
            "params": {
                "name": "detect_js_malware",
                "arguments": {"file_path": str(sample)},
            },
        }
    )

    result = response["result"]
    assert result["status"] == "error"
    assert "Could not decode JavaScript file as UTF-8" in result["error"]


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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


@pytest.mark.integration
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
