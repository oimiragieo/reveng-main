"""
REVENG Agent SDK
================

Enterprise-grade agent framework for autonomous binary analysis,
JavaScript deobfuscation, and multi-agent workflows.

Features:
- Tool use (bash, code execution, web search, etc.)
- MCP (Model Context Protocol) support
- Session management with state persistence
- Cost tracking and analytics
- Permission and security controls
- Streaming support for real-time feedback

Example:
    ```python
    from reveng.agent_sdk import ClaudeSDKClient, tool

    # Define custom tool
    @tool("analyze", "Analyze a binary", {"path": str})
    async def analyze(args):
        # Your analysis logic
        return {"content": [{"type": "text", "text": "Analysis result"}]}

    # Create agent
    async with ClaudeSDKClient() as client:
        async for msg in client.query("Analyze malware.exe"):
            print(msg)
    ```

Author: REVENG Development Team
Version: 4.0.0
License: MIT
"""

__version__ = "4.0.0"
__author__ = "REVENG Development Team"

# Core client (Phase 6 - implemented)
# Make client import optional (requires anthropic package)
try:
    from .client import ClaudeSDKClient
    _HAS_CLIENT = True
except ImportError:
    _HAS_CLIENT = False
    ClaudeSDKClient = None

# Exceptions
from .exceptions import (
    AgentSDKError,
    ClientError,
    PermissionError,
    SessionError,
    ToolError,
)
from .tools.base import BaseTool, ToolResult

# Tool framework (Phase 1 & 2 - implemented)
from .tools.decorator import tool

# Types
from .types import (
    CostReport,
    Message,
    MessageType,
    PermissionMode,
    TextBlock,
    ThinkingBlock,
    ToolResultBlock,
    ToolUseBlock,
    UsageMetrics,
)

__all__ = [
    # Client (Phase 6 - implemented)
    "ClaudeSDKClient",
    # Tools (Phase 1 & 2 - implemented)
    "tool",
    "BaseTool",
    "ToolResult",
    # Types (Phase 1 - implemented)
    "Message",
    "MessageType",
    "TextBlock",
    "ThinkingBlock",
    "ToolUseBlock",
    "ToolResultBlock",
    "PermissionMode",
    "CostReport",
    "UsageMetrics",
    # Exceptions (Phase 1 - implemented)
    "AgentSDKError",
    "ClientError",
    "ToolError",
    "SessionError",
    "PermissionError",
]
