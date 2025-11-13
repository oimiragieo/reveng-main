"""
MCP Transport Implementations
==============================

Transports for communicating with MCP servers via different channels.
"""

import asyncio
import json
import sys
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

# Optional HTTP transport support
try:
    from aiohttp import web
    _HAS_AIOHTTP = True
except ImportError:
    _HAS_AIOHTTP = False
    web = None


class MCPTransport(ABC):
    """Base class for MCP transports"""

    @abstractmethod
    async def start(self, server):
        """Start the transport"""
        pass

    @abstractmethod
    async def stop(self):
        """Stop the transport"""
        pass

    @abstractmethod
    async def send_message(self, message: Dict[str, Any]):
        """Send a message"""
        pass

    @abstractmethod
    async def receive_message(self) -> Optional[Dict[str, Any]]:
        """Receive a message"""
        pass


class StdioTransport(MCPTransport):
    """
    Stdio transport for MCP.

    Reads JSON-RPC messages from stdin and writes responses to stdout.
    This is the primary transport used by Claude Desktop and CLI tools.

    Example:
        ```python
        transport = StdioTransport()
        await server.start(transport)
        ```
    """

    def __init__(self):
        self.server = None
        self.running = False

    async def start(self, server):
        """Start reading from stdin"""
        self.server = server
        self.running = True

        # Process messages from stdin
        while self.running:
            try:
                line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)

                if not line:
                    break

                message = json.loads(line.strip())
                response = await self.server.handle_message(message)
                await self.send_message(response)

            except json.JSONDecodeError:
                continue
            except Exception as e:
                error_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
                await self.send_message(error_response)

    async def stop(self):
        """Stop the transport"""
        self.running = False

    async def send_message(self, message: Dict[str, Any]):
        """Write JSON-RPC message to stdout"""
        output = json.dumps(message) + "\n"
        sys.stdout.write(output)
        sys.stdout.flush()

    async def receive_message(self) -> Optional[Dict[str, Any]]:
        """Read JSON-RPC message from stdin"""
        line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
        if not line:
            return None
        return json.loads(line.strip())


class HTTPTransport(MCPTransport):
    """
    HTTP transport for MCP.

    Runs an HTTP server that accepts JSON-RPC messages via POST requests.
    Useful for remote MCP servers and web-based integrations.

    Example:
        ```python
        transport = HTTPTransport(host="0.0.0.0", port=8080)
        await server.start(transport)
        ```
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080):
        if not _HAS_AIOHTTP:
            raise ImportError(
                "HTTPTransport requires aiohttp. Install it with: pip install aiohttp>=3.9.0"
            )
        self.host = host
        self.port = port
        self.server = None
        self.app = None
        self.runner = None
        self.site = None

    async def start(self, server):
        """Start HTTP server"""
        self.server = server
        self.app = web.Application()
        self.app.router.add_post("/mcp", self.handle_request)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()

        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()

        print(f"MCP HTTP server listening on {self.host}:{self.port}")

    async def stop(self):
        """Stop HTTP server"""
        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

    async def handle_request(self, request, response=None):
        """Handle incoming HTTP request"""
        try:
            message = await request.json()
            response = await self.server.handle_message(message)
            return web.json_response(response)

        except json.JSONDecodeError:
            return web.json_response(
                {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
                status=400,
            )
        except Exception as e:
            return web.json_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": f"Internal error: {str(e)}"},
                },
                status=500,
            )

    async def send_message(self, message: Dict[str, Any]):
        """Not used in HTTP transport (responses sent via HTTP)"""
        pass

    async def receive_message(self) -> Optional[Dict[str, Any]]:
        """Not used in HTTP transport (messages received via HTTP)"""
        pass


class InProcessTransport(MCPTransport):
    """
    In-process transport for MCP.

    Enables direct communication with MCP servers within the same process.
    Useful for testing and embedded use cases.

    Example:
        ```python
        transport = InProcessTransport()
        await server.start(transport)

        # Send message directly
        response = await transport.call({"method": "tools/list", "id": 1})
        ```
    """

    def __init__(self):
        self.server = None
        self.message_queue = asyncio.Queue()

    async def start(self, server):
        """Initialize the transport"""
        self.server = server

    async def stop(self):
        """Stop the transport"""
        pass

    async def send_message(self, message: Dict[str, Any]):
        """Send message to queue"""
        await self.message_queue.put(message)

    async def receive_message(self) -> Optional[Dict[str, Any]]:
        """Receive message from queue"""
        return await self.message_queue.get()

    async def call(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Make a synchronous call to the server"""
        return await self.server.handle_message(message)
