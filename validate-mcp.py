#!/usr/bin/env python3
"""
Quick validation script for REVENG MCP Server
==============================================

Tests basic functionality without requiring pytest.
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))


async def test_basic_functionality():
    """Test basic MCP server functionality"""
    print("=" * 70)
    print("REVENG MCP Server Validation")
    print("=" * 70)

    try:
        # Test 1: Import modules
        print("\n[1/5] Testing imports...")
        from reveng.agent_sdk.mcp.servers.reveng_enterprise_server import (
            REVENGEnterpriseServer,
            AuditLogger,
            RateLimiter,
        )
        print("✓ All imports successful")

        # Test 2: Create server instance
        print("\n[2/5] Creating MCP server...")
        server = REVENGEnterpriseServer(
            enable_rate_limiting=False,
            enable_audit_log=False
        )
        print(f"✓ Server created: {server.name} v{server.version}")
        print(f"  - Tools registered: {len(server.tools)}")
        print(f"  - Resources registered: {len(server.resources)}")
        print(f"  - Prompts registered: {len(server.prompts)}")

        # Test 3: Verify tool registration
        print("\n[3/5] Verifying tool registration...")
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

        missing_tools = []
        for tool_name in expected_tools:
            if tool_name not in server.tools:
                missing_tools.append(tool_name)

        if missing_tools:
            print(f"✗ Missing tools: {', '.join(missing_tools)}")
            return False

        print(f"✓ All {len(expected_tools)} expected tools registered")

        # Test 4: Test MCP protocol messages
        print("\n[4/5] Testing MCP protocol messages...")

        # Test initialize message
        init_msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        response = await server.handle_message(init_msg)

        if response.get("jsonrpc") != "2.0" or response.get("id") != 1:
            print("✗ Initialize message failed")
            return False

        print("✓ Initialize message handled correctly")

        # Test tools/list message
        tools_msg = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        response = await server.handle_message(tools_msg)

        if "result" not in response or "tools" not in response["result"]:
            print("✗ Tools list message failed")
            return False

        print(f"✓ Tools list returned {len(response['result']['tools'])} tools")

        # Test 5: Test tool execution
        print("\n[5/5] Testing tool execution...")

        # Test list_recent_analyses tool
        tool_msg = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "list_recent_analyses",
                "arguments": {"limit": 5}
            }
        }
        response = await server.handle_message(tool_msg)

        if "result" not in response or "content" not in response["result"]:
            print("✗ Tool execution failed")
            print(f"Response: {response}")
            return False

        print("✓ Tool execution successful")

        # Test rate limiter
        print("\n[BONUS] Testing rate limiter...")
        rate_limiter = RateLimiter(tokens_per_second=10.0, bucket_size=20)

        # Should succeed 20 times
        for i in range(20):
            result = await rate_limiter.acquire()
            if not result:
                print(f"✗ Rate limiter failed at iteration {i}")
                return False

        # Should fail on 21st attempt
        result = await rate_limiter.acquire()
        if result:
            print("✗ Rate limiter should have rejected request")
            return False

        print("✓ Rate limiter working correctly")

        # Test audit logger
        print("\n[BONUS] Testing audit logger...")
        import tempfile
        with tempfile.TemporaryDirectory() as tmpdir:
            audit_logger = AuditLogger(log_dir=Path(tmpdir) / "audit_logs")
            audit_logger.log_event(
                event_type="test",
                tool_name="test_tool",
                args={"test": "data"},
                result="success",
                duration_ms=123.45
            )

            log_files = list((Path(tmpdir) / "audit_logs").glob("audit_*.jsonl"))
            if len(log_files) == 0:
                print("✗ Audit log file not created")
                return False

            print("✓ Audit logger working correctly")

        print("\n" + "=" * 70)
        print("ALL TESTS PASSED ✓")
        print("=" * 70)
        print("\nREVENG MCP Server is ready for production!")
        return True

    except Exception as e:
        print(f"\n✗ ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    result = asyncio.run(test_basic_functionality())
    sys.exit(0 if result else 1)
