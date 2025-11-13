"""
MCP Server Implementation
=========================

Base classes for creating MCP servers that extend agent capabilities.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional


class MCPMessageType(Enum):
    """MCP protocol message types"""

    INITIALIZE = "initialize"
    TOOLS_LIST = "tools/list"
    TOOL_CALL = "tools/call"
    RESOURCES_LIST = "resources/list"
    RESOURCE_READ = "resources/read"
    PROMPTS_LIST = "prompts/list"
    PROMPT_GET = "prompts/get"


@dataclass
class MCPTool:
    """MCP tool definition"""

    name: str
    description: str
    input_schema: Dict[str, Any]
    handler: Optional[Callable] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to MCP protocol format"""
        return {
            "name": self.name,
            "description": self.description,
            "inputSchema": self.input_schema,
        }


@dataclass
class MCPResource:
    """MCP resource definition"""

    uri: str
    name: str
    description: str
    mime_type: str = "text/plain"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "uri": self.uri,
            "name": self.name,
            "description": self.description,
            "mimeType": self.mime_type,
        }


@dataclass
class MCPPrompt:
    """MCP prompt template"""

    name: str
    description: str
    arguments: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description, "arguments": self.arguments}


class MCPServer(ABC):
    """
    Base class for MCP servers.

    MCP servers provide tools, resources, and prompts that extend
    agent capabilities through a standardized protocol.

    Example:
        ```python
        class DatabaseMCPServer(MCPServer):
            def __init__(self):
                super().__init__("database-mcp", "1.0.0")
                self.register_tool(MCPTool(
                    name="query_db",
                    description="Execute SQL query",
                    input_schema={"type": "object", "properties": {...}},
                    handler=self.query_db
                ))

            async def query_db(self, args: Dict[str, Any]) -> Dict[str, Any]:
                # Execute query and return results
                return {"rows": [...]}
        ```
    """

    def __init__(self, name: str, version: str = "1.0.0"):
        self.name = name
        self.version = version
        self.tools: Dict[str, MCPTool] = {}
        self.resources: Dict[str, MCPResource] = {}
        self.prompts: Dict[str, MCPPrompt] = {}
        self.transport = None
        self.running = False

    def register_tool(self, tool: MCPTool):
        """Register a tool with this MCP server"""
        self.tools[tool.name] = tool

    def register_resource(self, resource: MCPResource):
        """Register a resource with this MCP server"""
        self.resources[resource.uri] = resource

    def register_prompt(self, prompt: MCPPrompt):
        """Register a prompt template with this MCP server"""
        self.prompts[prompt.name] = prompt

    async def handle_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Handle incoming MCP protocol message"""
        msg_type = message.get("method")
        msg_id = message.get("id")
        params = message.get("params", {})

        try:
            if msg_type == MCPMessageType.INITIALIZE.value:
                return self._create_response(
                    msg_id,
                    {
                        "protocolVersion": "2024-11-05",
                        "serverInfo": {"name": self.name, "version": self.version},
                        "capabilities": {
                            "tools": {"listChanged": True},
                            "resources": {"listChanged": True},
                            "prompts": {"listChanged": True},
                        },
                    },
                )

            elif msg_type == MCPMessageType.TOOLS_LIST.value:
                return self._create_response(
                    msg_id, {"tools": [tool.to_dict() for tool in self.tools.values()]}
                )

            elif msg_type == MCPMessageType.TOOL_CALL.value:
                tool_name = params.get("name")
                arguments = params.get("arguments", {})

                if tool_name not in self.tools:
                    return self._create_error(msg_id, -32601, f"Tool not found: {tool_name}")

                tool = self.tools[tool_name]
                if tool.handler is None:
                    return self._create_error(msg_id, -32603, f"No handler for tool: {tool_name}")

                result = await tool.handler(arguments)
                return self._create_response(msg_id, result)

            elif msg_type == MCPMessageType.RESOURCES_LIST.value:
                return self._create_response(
                    msg_id, {"resources": [res.to_dict() for res in self.resources.values()]}
                )

            elif msg_type == MCPMessageType.RESOURCE_READ.value:
                uri = params.get("uri")
                if uri not in self.resources:
                    return self._create_error(msg_id, -32601, f"Resource not found: {uri}")

                content = await self.read_resource(uri)
                return self._create_response(msg_id, {"contents": [content]})

            elif msg_type == MCPMessageType.PROMPTS_LIST.value:
                return self._create_response(
                    msg_id, {"prompts": [prompt.to_dict() for prompt in self.prompts.values()]}
                )

            elif msg_type == MCPMessageType.PROMPT_GET.value:
                prompt_name = params.get("name")
                if prompt_name not in self.prompts:
                    return self._create_error(msg_id, -32601, f"Prompt not found: {prompt_name}")

                prompt_args = params.get("arguments", {})
                messages = await self.get_prompt(prompt_name, prompt_args)
                return self._create_response(msg_id, {"messages": messages})

            else:
                return self._create_error(msg_id, -32601, f"Method not found: {msg_type}")

        except Exception as e:
            return self._create_error(msg_id, -32603, f"Internal error: {str(e)}")

    def _create_response(self, msg_id: int, result: Any) -> Dict[str, Any]:
        """Create JSON-RPC success response"""
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def _create_error(self, msg_id: int, code: int, message: str) -> Dict[str, Any]:
        """Create JSON-RPC error response"""
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    @abstractmethod
    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource by URI (implement in subclass)"""
        pass

    @abstractmethod
    async def get_prompt(self, name: str, arguments: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Get a prompt with filled arguments (implement in subclass)"""
        pass

    async def start(self, transport):
        """Start the MCP server with given transport"""
        self.transport = transport
        self.running = True
        await transport.start(self)

    async def stop(self):
        """Stop the MCP server"""
        self.running = False
        if self.transport:
            await self.transport.stop()
