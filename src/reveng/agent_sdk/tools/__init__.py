"""
Tool framework for REVENG Agent SDK.

Provides:
- @tool decorator for creating custom tools
- BaseTool class for advanced tool implementation
- Tool registry for managing available tools
- Built-in tools (bash, web_fetch, etc.)
"""

from .base import BaseTool, ToolResult
from .decorator import tool
from .registry import ToolRegistry

# Global tool registry
_global_registry = ToolRegistry()


def get_tool_registry() -> ToolRegistry:
    """Get the global tool registry."""
    return _global_registry


def register_tool(tool_instance: BaseTool):
    """Register a tool with the global registry."""
    _global_registry.register(tool_instance)


def get_tool(name: str) -> BaseTool:
    """Get a tool by name from global registry."""
    return _global_registry.get(name)


__all__ = [
    "BaseTool",
    "ToolResult",
    "tool",
    "ToolRegistry",
    "get_tool_registry",
    "register_tool",
    "get_tool",
]
