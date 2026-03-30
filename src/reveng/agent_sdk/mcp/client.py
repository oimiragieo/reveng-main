"""
MCP Client Implementation
=========================

Client for communicating with MCP servers.
"""

from typing import Any, Dict, List, Optional


class MCPClient:
    """
    Client for communicating with MCP servers.

    Example:
        ```python
        client = MCPClient(transport)
        await client.initialize()

        # List available tools
        tools = await client.list_tools()

        # Call a tool
        result = await client.call_tool("query_db", {"sql": "SELECT * FROM users"})
        ```
    """

    def __init__(self, transport):
        self.transport = transport
        self.next_id = 1
        self.server_info = None
        self.capabilities = None

    def _get_next_id(self) -> int:
        """Get next message ID"""
        msg_id = self.next_id
        self.next_id += 1
        return msg_id

    async def _send_request(
        self, method: str, params: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Send a JSON-RPC request and wait for response"""
        msg_id = self._get_next_id()
        message = {"jsonrpc": "2.0", "id": msg_id, "method": method, "params": params or {}}

        # For in-process transport, use direct call
        if hasattr(self.transport, "call"):
            return await self.transport.call(message)

        # For other transports, send and receive
        await self.transport.send_message(message)
        response = await self.transport.receive_message()

        if "error" in response:
            raise Exception(f"MCP error: {response['error']['message']}")

        return response.get("result", {})

    async def initialize(self) -> Dict[str, Any]:
        """Initialize connection with MCP server"""
        result = await self._send_request(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "clientInfo": {"name": "reveng-agent-sdk", "version": "1.0.0"},
            },
        )

        self.server_info = result.get("serverInfo")
        self.capabilities = result.get("capabilities")

        return result

    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from MCP server"""
        result = await self._send_request("tools/list")
        return result.get("tools", [])

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        """Call a tool on the MCP server"""
        return await self._send_request("tools/call", {"name": name, "arguments": arguments})

    async def list_resources(self) -> List[Dict[str, Any]]:
        """List available resources from MCP server"""
        result = await self._send_request("resources/list")
        return result.get("resources", [])

    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource from the MCP server"""
        result = await self._send_request("resources/read", {"uri": uri})
        return result.get("contents", [])[0] if result.get("contents") else {}

    async def list_prompts(self) -> List[Dict[str, Any]]:
        """List available prompts from MCP server"""
        result = await self._send_request("prompts/list")
        return result.get("prompts", [])

    async def get_prompt(
        self, name: str, arguments: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Get a prompt with filled arguments"""
        result = await self._send_request(
            "prompts/get", {"name": name, "arguments": arguments or {}}
        )
        return result.get("messages", [])

    async def close(self):
        """Close the client connection"""
        await self.transport.stop()
