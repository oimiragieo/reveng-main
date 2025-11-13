#!/usr/bin/env python3
"""
REVENG Agent SDK - Comprehensive Demo

This example demonstrates the new agent SDK capabilities including:
- Custom tool creation with @tool decorator
- Integration with existing REVENG features
- Binary analysis via agents
- JavaScript deobfuscation via agents

Prerequisites:
    pip install anthropic  # For Claude API access
    export ANTHROPIC_API_KEY=your-key-here

Author: REVENG Development Team
Version: 1.0.0
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from reveng.agent_sdk import tool, ToolResult
from reveng.agent_sdk.tools import get_tool_registry
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool, JSDeobfuscationTool


# ============================================================================
# Example 1: Simple Custom Tool
# ============================================================================

@tool("greet", "Greet a user by name", {"name": str})
async def greet_user(args):
    """Simple greeting tool."""
    name = args["name"]
    return ToolResult.success_result(f"Hello, {name}! Welcome to REVENG Agent SDK!")


@tool("calculate", "Perform basic calculations", {"a": int, "b": int, "operation": str})
async def calculate(args):
    """Calculator tool demonstrating error handling."""
    a = args["a"]
    b = args["b"]
    operation = args["operation"]

    if operation == "add":
        result = a + b
    elif operation == "subtract":
        result = a - b
    elif operation == "multiply":
        result = a * b
    elif operation == "divide":
        if b == 0:
            return ToolResult.error_result("Cannot divide by zero!")
        result = a / b
    else:
        return ToolResult.error_result(f"Unknown operation: {operation}")

    return ToolResult.success_result(f"{a} {operation} {b} = {result}")


# ============================================================================
# Example 2: Advanced Tool with REVENG Integration
# ============================================================================

@tool(
    "security_audit",
    "Perform comprehensive security audit on a binary",
    {
        "binary_path": str,
        "check_malware": bool,
    }
)
async def security_audit(args):
    """
    Comprehensive security audit tool combining multiple REVENG features.
    """
    binary_path = args["binary_path"]
    check_malware = args.get("check_malware", True)

    try:
        # Use the binary analysis tool
        binary_tool = BinaryAnalysisTool()
        binary_result = await binary_tool.execute({
            "path": binary_path,
            "quick_mode": False
        })

        if not binary_result.success:
            return binary_result

        # Build comprehensive report
        report = [
            "=" * 70,
            "  COMPREHENSIVE SECURITY AUDIT",
            "=" * 70,
            "",
            binary_result.content[0]["text"],
            "",
        ]

        if check_malware:
            report.append("Malware Analysis: Integrated in binary analysis")
            report.append("")

        report.append("Audit complete. Recommendations:")
        report.append("  1. Review all identified vulnerabilities")
        report.append("  2. Apply security patches")
        report.append("  3. Implement input validation")
        report.append("  4. Use modern compiler protections")

        return ToolResult.success_result("\n".join(report))

    except Exception as e:
        return ToolResult.error_result(f"Security audit failed: {str(e)}")


# ============================================================================
# Main Demo
# ============================================================================

async def demo_basic_tools():
    """Demo 1: Basic tool usage."""
    print("=" * 70)
    print("DEMO 1: Basic Tool Usage")
    print("=" * 70)
    print()

    # Test greeting tool
    print("Testing greeting tool...")
    result = await greet_user._tool_instance.execute({"name": "Alice"})
    print(result.content[0]["text"])
    print()

    # Test calculator
    print("Testing calculator tool...")
    result = await calculate._tool_instance.execute({
        "a": 10,
        "b": 5,
        "operation": "multiply"
    })
    print(result.content[0]["text"])
    print()

    # Test error handling
    print("Testing error handling (divide by zero)...")
    result = await calculate._tool_instance.execute({
        "a": 10,
        "b": 0,
        "operation": "divide"
    })
    print(result.content[0]["text"])
    print()


async def demo_reveng_integration():
    """Demo 2: REVENG integration."""
    print("=" * 70)
    print("DEMO 2: REVENG Integration")
    print("=" * 70)
    print()

    # Show available tools
    registry = get_tool_registry()
    print("Available tools:")
    for tool_name in registry.list_tools():
        tool_instance = registry.get(tool_name)
        print(f"  • {tool_name}: {tool_instance.description[:60]}...")
    print()

    # Test JavaScript deobfuscation
    print("Testing JavaScript deobfuscation tool...")
    js_tool = JSDeobfuscationTool()

    obfuscated_code = """
    var _0x1234=['hello','world'];
    function _0x5678(i){return _0x1234[i];}
    console.log(_0x5678(0),_0x5678(1));
    """.strip()

    result = await js_tool.execute({
        "code": obfuscated_code,
        "use_ml": False,  # Skip ML for demo (requires Node.js tools)
        "detect_malware": True
    })

    if result.success:
        print(result.content[0]["text"])
    else:
        print(f"Error: {result.error}")
    print()


async def demo_tool_definitions():
    """Demo 3: Tool definitions (for Claude API)."""
    print("=" * 70)
    print("DEMO 3: Tool Definitions for Claude API")
    print("=" * 70)
    print()

    registry = get_tool_registry()
    definitions = registry.get_definitions()

    print("Tool definitions (Claude API format):")
    print()

    for i, definition in enumerate(definitions[:3], 1):  # Show first 3
        print(f"{i}. {definition['name']}")
        print(f"   Description: {definition['description'][:100]}...")
        print(f"   Required params: {definition['input_schema'].get('required', [])}")
        print()

    print(f"Total: {len(definitions)} tools available")
    print()


async def demo_usage_patterns():
    """Demo 4: Usage patterns."""
    print("=" * 70)
    print("DEMO 4: Usage Patterns")
    print("=" * 70)
    print()

    print("Pattern 1: Simple tool creation")
    print("-" * 70)
    print("""
    from reveng.agent_sdk import tool

    @tool("my_tool", "Description", {"arg": str})
    async def my_tool(args):
        return {"content": [{"type": "text", "text": "Result"}]}
    """)
    print()

    print("Pattern 2: REVENG integration")
    print("-" * 70)
    print("""
    from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool

    tool = BinaryAnalysisTool()
    result = await tool.execute({"path": "binary.exe"})
    """)
    print()

    print("Pattern 3: With Claude API (future)")
    print("-" * 70)
    print("""
    from reveng.agent_sdk import ClaudeSDKClient

    async with ClaudeSDKClient(allowed_tools=["analyze_binary"]) as client:
        async for message in client.query("Analyze malware.exe"):
            print(message)
    """)
    print()


async def main():
    """Run all demos."""
    print()
    print("╔" + "=" * 70 + "╗")
    print("║" + " " * 70 + "║")
    print("║" + "  REVENG Agent SDK - Comprehensive Demo".center(70) + "║")
    print("║" + " " * 70 + "║")
    print("╚" + "=" * 70 + "╝")
    print()

    try:
        # Demo 1: Basic tools
        await demo_basic_tools()

        # Demo 2: REVENG integration
        await demo_reveng_integration()

        # Demo 3: Tool definitions
        await demo_tool_definitions()

        # Demo 4: Usage patterns
        await demo_usage_patterns()

        print("=" * 70)
        print("  Demo Complete!")
        print("=" * 70)
        print()
        print("Next steps:")
        print("  1. Read AGENT_SDK_IMPLEMENTATION_PLAN.md for architecture")
        print("  2. See src/reveng/agent_sdk/ for implementation")
        print("  3. Create your own tools with @tool decorator")
        print("  4. Integrate with Claude API (coming soon)")
        print()

    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
