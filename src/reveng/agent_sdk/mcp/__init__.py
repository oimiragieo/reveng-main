"""
REVENG Agent SDK - Model Context Protocol (MCP)
================================================

MCP enables extending agent capabilities through server-based tools.

Features:
- Multiple transports (stdio, HTTP, in-process)
- Server lifecycle management
- Tool registration and discovery
- Configuration via .mcp.json
- Built-in servers (database, filesystem, cloud)

Example:
    ```python
    from reveng.agent_sdk.mcp import MCPServer, StdioTransport

    class MyMCPServer(MCPServer):
        def __init__(self):
            super().__init__("my-server", "1.0.0")
            self.register_tool(my_tool)

    # Run server
    server = MyMCPServer()
    await server.start(StdioTransport())
    ```
"""

from .client import MCPClient
from .config import MCPConfig, load_mcp_config
from .server import MCPServer, MCPTool
from .transports import HTTPTransport, InProcessTransport, StdioTransport

__all__ = [
    "MCPServer",
    "MCPTool",
    "MCPClient",
    "StdioTransport",
    "HTTPTransport",
    "InProcessTransport",
    "MCPConfig",
    "load_mcp_config",
]
