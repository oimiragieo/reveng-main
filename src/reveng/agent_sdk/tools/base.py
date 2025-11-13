"""
Base classes for tools in REVENG Agent SDK.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import asyncio
import time


@dataclass
class ToolResult:
    """Result from tool execution."""

    success: bool
    content: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def success_result(text: str, **metadata) -> "ToolResult":
        """Create a successful result with text content."""
        return ToolResult(
            success=True,
            content=[{"type": "text", "text": text}],
            metadata=metadata,
        )

    @staticmethod
    def error_result(error_message: str, **metadata) -> "ToolResult":
        """Create an error result."""
        return ToolResult(
            success=False,
            error=error_message,
            content=[{"type": "text", "text": f"Error: {error_message}"}],
            metadata=metadata,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format for API."""
        result = {
            "content": self.content,
        }
        if not self.success:
            result["is_error"] = True
        return result


class BaseTool(ABC):
    """
    Base class for all tools.

    Tools must implement:
    - name: Unique tool identifier
    - description: Detailed explanation of what the tool does
    - input_schema: JSON Schema defining expected parameters
    - execute(): Async method that performs the tool's action

    Example:
        ```python
        class MyTool(BaseTool):
            name = "my_tool"
            description = "Does something useful"
            input_schema = {
                "type": "object",
                "properties": {
                    "arg": {"type": "string", "description": "An argument"}
                },
                "required": ["arg"]
            }

            async def execute(self, args: Dict[str, Any]) -> ToolResult:
                # Your logic here
                return ToolResult.success_result(f"Result: {args['arg']}")
        ```
    """

    name: str = ""
    description: str = ""
    input_schema: Dict[str, Any] = {}

    def __init__(self):
        """Initialize the tool."""
        if not self.name:
            raise ValueError(f"{self.__class__.__name__} must define 'name'")
        if not self.description:
            raise ValueError(f"{self.__class__.__name__} must define 'description'")
        if not self.input_schema:
            raise ValueError(f"{self.__class__.__name__} must define 'input_schema'")

    @abstractmethod
    async def execute(self, args: Dict[str, Any]) -> ToolResult:
        """
        Execute the tool with given arguments.

        Args:
            args: Dictionary of arguments matching input_schema

        Returns:
            ToolResult with success/failure and content

        Raises:
            Any exceptions should be caught and returned as error results
        """
        pass

    async def safe_execute(self, args: Dict[str, Any]) -> ToolResult:
        """
        Execute the tool with error handling and timing.

        This wrapper ensures consistent error handling and metrics collection.
        """
        start_time = time.time()
        try:
            # Validate args against schema (basic check)
            if "required" in self.input_schema:
                for required_field in self.input_schema["required"]:
                    if required_field not in args:
                        return ToolResult.error_result(
                            f"Missing required field: {required_field}"
                        )

            # Execute the tool
            result = await self.execute(args)
            result.execution_time = time.time() - start_time
            return result

        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                error=str(e),
                content=[{"type": "text", "text": f"Tool execution failed: {str(e)}"}],
                execution_time=execution_time,
            )

    def to_definition(self) -> Dict[str, Any]:
        """Convert tool to API definition format."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }
