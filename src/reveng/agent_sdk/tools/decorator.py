"""
@tool decorator for creating custom tools easily.

Example:
    ```python
    from reveng.agent_sdk import tool

    @tool("greet", "Greet a user", {"name": str})
    async def greet_user(args):
        name = args["name"]
        return {"content": [{"type": "text", "text": f"Hello, {name}!"}]}
    ```
"""

import inspect
from functools import wraps
from typing import Any, Callable, Dict, Union

from .base import BaseTool, ToolResult


def tool(
    name: str,
    description: str,
    schema: Union[Dict[str, Any], Dict[str, type]],
):
    """
    Decorator to create a tool from a function.

    Args:
        name: Tool name (must match ^[a-zA-Z0-9_-]{1,64}$)
        description: Detailed description of what the tool does
        schema: Either a JSON Schema dict or simple {arg_name: type} dict

    Returns:
        Decorated function that's registered as a tool

    Example:
        ```python
        # Simple type hints
        @tool("calculate", "Add two numbers", {"a": int, "b": int})
        async def calculate(args):
            return ToolResult.success_result(str(args["a"] + args["b"]))

        # Full JSON Schema
        @tool("search", "Search for items", {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "Search query"},
                "limit": {"type": "integer", "default": 10}
            },
            "required": ["query"]
        })
        async def search(args):
            results = perform_search(args["query"], args.get("limit", 10))
            return ToolResult.success_result(results)
        ```
    """

    def decorator(func: Callable):
        # Convert simple schema to JSON Schema if needed
        json_schema = _convert_schema(schema)

        # Create a tool class dynamically
        class DecoratedTool(BaseTool):
            def __init__(self):
                self.name = name
                self.description = description
                self.input_schema = json_schema
                self.func = func
                super().__init__()

            async def execute(self, args: Dict[str, Any]) -> ToolResult:
                # Call the decorated function
                if inspect.iscoroutinefunction(self.func):
                    result = await self.func(args)
                else:
                    result = self.func(args)

                # Handle different return formats
                if isinstance(result, ToolResult):
                    return result
                elif isinstance(result, dict):
                    if "content" in result:
                        return ToolResult(success=True, content=result["content"])
                    else:
                        # Assume it's content
                        return ToolResult.success_result(str(result))
                elif isinstance(result, str):
                    return ToolResult.success_result(result)
                else:
                    return ToolResult.success_result(str(result))

        # Create an instance and register it
        tool_instance = DecoratedTool()

        # Auto-register with global registry
        from . import register_tool

        register_tool(tool_instance)

        # Return the original function (but mark it)
        @wraps(func)
        async def wrapper(*args, **kwargs):
            return await func(*args, **kwargs)

        wrapper._tool_instance = tool_instance
        return wrapper

    return decorator


def _convert_schema(schema: Union[Dict[str, Any], Dict[str, type]]) -> Dict[str, Any]:
    """
    Convert simple {arg: type} schema to JSON Schema format.

    Args:
        schema: Either full JSON Schema or simple type dict

    Returns:
        Full JSON Schema dict
    """
    # If it already has "type": "object", assume it's a full schema
    if isinstance(schema, dict) and schema.get("type") == "object":
        return schema

    # Convert simple type dict to JSON Schema
    properties = {}
    required = []

    for arg_name, arg_type in schema.items():
        if arg_type == str:
            properties[arg_name] = {"type": "string"}
        elif arg_type == int:
            properties[arg_name] = {"type": "integer"}
        elif arg_type == float:
            properties[arg_name] = {"type": "number"}
        elif arg_type == bool:
            properties[arg_name] = {"type": "boolean"}
        elif arg_type == list:
            properties[arg_name] = {"type": "array"}
        elif arg_type == dict:
            properties[arg_name] = {"type": "object"}
        else:
            # Default to string
            properties[arg_name] = {"type": "string"}

        # All fields are required by default
        required.append(arg_name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }
