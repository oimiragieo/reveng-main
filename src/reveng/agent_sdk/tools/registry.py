"""
Tool registry for managing available tools.
"""

from typing import Dict, List

from ..exceptions import ToolError
from .base import BaseTool


class ToolRegistry:
    """Registry for managing tool instances."""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}

    def register(self, tool: BaseTool):
        """Register a tool."""
        if tool.name in self._tools:
            raise ToolError(tool.name, f"Tool '{tool.name}' already registered")
        self._tools[tool.name] = tool

    def get(self, name: str) -> BaseTool:
        """Get a tool by name."""
        if name not in self._tools:
            raise ToolError(name, f"Tool '{name}' not found in registry")
        return self._tools[name]

    def list_tools(self) -> List[str]:
        """List all registered tool names."""
        return list(self._tools.keys())

    def get_definitions(self) -> List[Dict]:
        """Get all tool definitions for API."""
        return [tool.to_definition() for tool in self._tools.values()]

    def clear(self):
        """Clear all registered tools."""
        self._tools.clear()
