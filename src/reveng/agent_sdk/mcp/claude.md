# Agent SDK - Model Context Protocol (MCP)

## Overview

The MCP (Model Context Protocol) module implements a standardized protocol for extending agent capabilities through server-based tools, resources, and prompts. MCP enables modular, reusable agent capabilities that can be shared across different clients and environments.

This module provides the infrastructure for creating MCP servers, managing transports, and integrating with external MCP-compatible systems.

**Location:** `/home/user/reveng-main/src/reveng/agent_sdk/mcp/`

**Protocol Version:** 2024-11-05

## Files in This Directory

### `__init__.py` (44 lines)
Public API exports for MCP functionality.

**Exports:**
- `MCPServer`, `MCPTool` - Server and tool abstractions
- `MCPClient` - Client for connecting to MCP servers
- `StdioTransport`, `HTTPTransport`, `InProcessTransport` - Transport layers
- `MCPConfig`, `load_mcp_config` - Configuration management

### `server.py` (224 lines)
Core MCP server implementation with protocol handling.

**Key Classes:**
- `MCPMessageType` - Enum for protocol message types
- `MCPTool` - Tool definition with schema and handler
- `MCPResource` - Resource definition (files, data, etc.)
- `MCPPrompt` - Prompt template definition
- `MCPServer` - Abstract base class for MCP servers

**Protocol Methods:**
- `initialize` - Server handshake
- `tools/list` - List available tools
- `tools/call` - Execute a tool
- `resources/list` - List available resources
- `resources/read` - Read a resource
- `prompts/list` - List available prompts
- `prompts/get` - Get a prompt with arguments

**Example:**
```python
class MyMCPServer(MCPServer):
    def __init__(self):
        super().__init__("my-server", "1.0.0")
        self.register_tool(MCPTool(
            name="my_tool",
            description="Does something useful",
            input_schema={"type": "object", "properties": {...}},
            handler=self.handle_my_tool
        ))

    async def handle_my_tool(self, args):
        return {"result": "success"}
```

### `client.py` (3671 lines)
MCP client for connecting to and communicating with MCP servers.

**Key Classes:**
- `MCPClient` - Client for MCP server communication

**Features:**
- Server discovery and connection
- Tool invocation
- Resource access
- Prompt retrieval
- Transport abstraction

**Methods:**
```python
async def connect(server_config) -> None
async def list_tools() -> List[MCPTool]
async def call_tool(name, args) -> Dict
async def list_resources() -> List[MCPResource]
async def read_resource(uri) -> Any
async def disconnect() -> None
```

### `config.py` (5237 lines)
Configuration management for MCP servers and clients.

**Key Classes:**
- `MCPConfig` - Configuration container

**Features:**
- `.mcp.json` file parsing
- Server endpoint configuration
- Transport configuration
- Authentication settings
- Environment variable expansion

**Configuration Format:**
```json
{
  "mcpServers": {
    "database": {
      "command": "python",
      "args": ["-m", "reveng.agent_sdk.mcp.servers.database"],
      "transport": "stdio"
    },
    "reveng": {
      "command": "python",
      "args": ["-m", "reveng.agent_sdk.mcp.servers.reveng_server"],
      "transport": "stdio"
    }
  }
}
```

### `transports.py` (6496 lines)
Transport layer implementations for MCP communication.

**Key Classes:**
- `StdioTransport` - Standard input/output transport
- `HTTPTransport` - HTTP/HTTPS transport
- `InProcessTransport` - In-process (direct function call) transport

**StdioTransport Features:**
- JSON-RPC over stdio
- Process management
- Stream handling
- Error recovery

**HTTPTransport Features:**
- RESTful API endpoints
- WebSocket support (planned)
- Authentication headers
- TLS/SSL support

**InProcessTransport Features:**
- Direct function calls
- No serialization overhead
- Useful for testing
- Thread-safe

**Usage:**
```python
# Stdio transport (for subprocess servers)
transport = StdioTransport()
await server.start(transport)

# HTTP transport (for remote servers)
transport = HTTPTransport("https://server.example.com")
client = MCPClient()
await client.connect(transport)

# In-process transport (for local servers)
transport = InProcessTransport(my_server)
await client.connect(transport)
```

## Architecture

### MCP Protocol Stack

```
┌─────────────────────────────────────┐
│         Agent SDK Client            │
└─────────────────┬───────────────────┘
                  │
                  ↓
┌─────────────────────────────────────┐
│          MCP Client                 │
│  - Server discovery                 │
│  - Tool invocation                  │
│  - Resource access                  │
└─────────────────┬───────────────────┘
                  │
                  ↓
┌─────────────────────────────────────┐
│         Transport Layer             │
│  - Stdio / HTTP / InProcess         │
│  - JSON-RPC messaging               │
└─────────────────┬───────────────────┘
                  │
                  ↓
┌─────────────────────────────────────┐
│          MCP Server                 │
│  - Protocol handling                │
│  - Tool registration                │
│  - Resource management              │
└─────────────────┬───────────────────┘
                  │
                  ↓
┌─────────────────────────────────────┐
│       Tool Implementations          │
│  - Binary analysis                  │
│  - JS deobfuscation                 │
│  - Database queries                 │
│  - File operations                  │
└─────────────────────────────────────┘
```

### Message Flow

```
Client                                Server
  │                                     │
  │─────── initialize ─────────────────>│
  │<────── capabilities ───────────────│
  │                                     │
  │─────── tools/list ─────────────────>│
  │<────── [tool1, tool2] ─────────────│
  │                                     │
  │─────── tools/call(tool1, args) ───>│
  │                (execute)            │
  │<────── result ─────────────────────│
  │                                     │
```

### Server Lifecycle

```
1. Server Creation
   └─> Register tools/resources/prompts

2. Transport Binding
   └─> Attach transport (stdio/http/in-process)

3. Start
   └─> Begin listening for messages

4. Message Handling
   ├─> Parse JSON-RPC message
   ├─> Route to handler
   ├─> Execute tool/resource/prompt
   └─> Return response

5. Stop
   └─> Clean up and shut down
```

## Key Concepts

### 1. MCP Protocol

MCP is a standardized protocol for agent-server communication:

**JSON-RPC 2.0 Based:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "analyze_binary",
    "arguments": {"path": "/path/to/binary"}
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [{"type": "text", "text": "Analysis complete"}],
    "analysis": {...}
  }
}
```

### 2. Tools

Tools are executable functions exposed via MCP:

```python
MCPTool(
    name="analyze_binary",
    description="Analyze a binary file",
    input_schema={
        "type": "object",
        "properties": {
            "path": {"type": "string"}
        },
        "required": ["path"]
    },
    handler=analyze_binary_handler
)
```

### 3. Resources

Resources are data sources accessible via URI:

```python
MCPResource(
    uri="file:///analysis/report.txt",
    name="Analysis Report",
    description="Latest analysis results",
    mime_type="text/plain"
)
```

### 4. Prompts

Prompts are templates with variable substitution:

```python
MCPPrompt(
    name="analyze_and_report",
    description="Analyze binary and generate report",
    arguments=[
        {"name": "binary_path", "description": "Path to binary", "required": True}
    ]
)
```

### 5. Transports

Transports handle message delivery between client and server:

- **Stdio** - For subprocess-based servers
- **HTTP** - For remote network servers
- **InProcess** - For same-process servers (testing)

## Usage Examples

### Example 1: Creating an MCP Server

```python
from reveng.agent_sdk.mcp import MCPServer, MCPTool, StdioTransport

class DatabaseMCPServer(MCPServer):
    def __init__(self):
        super().__init__("database-mcp", "1.0.0")

        # Register tools
        self.register_tool(MCPTool(
            name="query_db",
            description="Execute SQL query",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "database": {"type": "string"}
                },
                "required": ["query"]
            },
            handler=self.query_db
        ))

    async def query_db(self, args):
        # Execute query
        results = execute_sql(args["query"])
        return {
            "content": [{"type": "text", "text": f"Found {len(results)} rows"}],
            "rows": results
        }

    async def read_resource(self, uri):
        return {"uri": uri, "text": ""}

    async def get_prompt(self, name, arguments):
        return []

# Run server
async def main():
    server = DatabaseMCPServer()
    transport = StdioTransport()
    await server.start(transport)

asyncio.run(main())
```

### Example 2: Using MCP Client

```python
from reveng.agent_sdk.mcp import MCPClient, MCPConfig

async def use_mcp_server():
    # Load configuration
    config = load_mcp_config(".mcp.json")

    # Connect to server
    client = MCPClient()
    await client.connect(config.servers["database"])

    # List available tools
    tools = await client.list_tools()
    print(f"Available tools: {[t.name for t in tools]}")

    # Call a tool
    result = await client.call_tool("query_db", {
        "query": "SELECT * FROM users",
        "database": "main"
    })

    print(result)

    # Disconnect
    await client.disconnect()

await use_mcp_server()
```

### Example 3: Using REVENG MCP Server

```python
from reveng.agent_sdk.mcp.servers import REVENGMCPServer
from reveng.agent_sdk.mcp import StdioTransport

async def analyze_with_mcp():
    # Start REVENG MCP server
    server = REVENGMCPServer()
    transport = StdioTransport()
    await server.start(transport)

    # Server is now running and can handle:
    # - analyze_binary
    # - deobfuscate_js
    # - detect_malware
```

### Example 4: HTTP Transport Server

```python
from reveng.agent_sdk.mcp import MCPServer, HTTPTransport

class RemoteMCPServer(MCPServer):
    def __init__(self):
        super().__init__("remote-server", "1.0.0")
        # ... register tools ...

async def run_http_server():
    server = RemoteMCPServer()
    transport = HTTPTransport(host="0.0.0.0", port=8080)
    await server.start(transport)

await run_http_server()
```

## Configuration

### MCP Configuration File (.mcp.json)

```json
{
  "mcpServers": {
    "reveng": {
      "command": "python",
      "args": ["-m", "reveng.agent_sdk.mcp.servers.reveng_server"],
      "transport": "stdio",
      "env": {
        "LOG_LEVEL": "INFO"
      }
    },
    "database": {
      "command": "python",
      "args": ["-m", "reveng.agent_sdk.mcp.servers.database"],
      "transport": "stdio"
    },
    "remote_server": {
      "url": "https://mcp.example.com",
      "transport": "http",
      "headers": {
        "Authorization": "Bearer ${API_TOKEN}"
      }
    }
  }
}
```

### Loading Configuration

```python
from reveng.agent_sdk.mcp import load_mcp_config

# Load from default location
config = load_mcp_config()

# Load from specific path
config = load_mcp_config("/path/to/.mcp.json")

# Access server configs
reveng_config = config.servers["reveng"]
```

## Testing

### Unit Tests

```python
import pytest
from reveng.agent_sdk.mcp import MCPServer, MCPTool, InProcessTransport

@pytest.mark.asyncio
async def test_mcp_server():
    class TestServer(MCPServer):
        def __init__(self):
            super().__init__("test", "1.0.0")
            self.register_tool(MCPTool(
                name="echo",
                description="Echo input",
                input_schema={"type": "object"},
                handler=lambda args: {"text": str(args)}
            ))

        async def read_resource(self, uri):
            return {}

        async def get_prompt(self, name, arguments):
            return []

    server = TestServer()
    transport = InProcessTransport(server)
    await server.start(transport)

    # Test tool listing
    response = await server.handle_message({
        "id": 1,
        "method": "tools/list",
        "params": {}
    })

    assert len(response["result"]["tools"]) == 1
    assert response["result"]["tools"][0]["name"] == "echo"
```

### Integration Tests

```bash
# Test REVENG MCP server
python -m pytest tests/agent_sdk/mcp/test_reveng_server.py

# Test transports
python -m pytest tests/agent_sdk/mcp/test_transports.py

# Test client
python -m pytest tests/agent_sdk/mcp/test_client.py
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/agent_sdk/` - Parent SDK
- `/home/user/reveng-main/src/reveng/agent_sdk/mcp/servers/` - Built-in MCP servers
- `/home/user/reveng-main/src/reveng/agent_sdk/tools/` - Tool framework

### External REVENG Integration
- `/home/user/reveng-main/src/reveng/analyzer/` - Binary analysis (via REVENG server)
- `/home/user/reveng-main/src/reveng/javascript/` - JS deobfuscation (via REVENG server)

### Third-Party Dependencies
- `asyncio` - Async I/O
- `json` - JSON-RPC serialization
- `aiohttp` - HTTP transport (optional)

## Notes

### MCP Benefits

1. **Modularity** - Tools can be developed and deployed independently
2. **Reusability** - Same server can be used by multiple clients
3. **Scalability** - Servers can run remotely or in containers
4. **Standardization** - Protocol is vendor-neutral and well-documented
5. **Security** - Transport-level encryption and authentication

### Best Practices

1. **Always validate inputs** - Use JSON Schema for input validation
2. **Handle errors gracefully** - Return proper error codes
3. **Use appropriate transports** - Stdio for local, HTTP for remote
4. **Document tools thoroughly** - Detailed descriptions help agents
5. **Version your servers** - Include version in server info

### Common Patterns

**Request-Response:**
```python
# Client sends request
request = {"method": "tools/call", "params": {...}}

# Server processes and responds
response = {"result": {...}}
```

**Error Handling:**
```python
# On error, return error code
{
  "error": {
    "code": -32601,  # Method not found
    "message": "Tool not found: unknown_tool"
  }
}
```

### Security Considerations

1. **Input Validation** - Always validate tool arguments
2. **Sandboxing** - Run tools in isolated environments
3. **Rate Limiting** - Prevent abuse of expensive operations
4. **Authentication** - Use tokens for remote transports
5. **Encryption** - Use TLS for HTTP transport

### Future Enhancements

- [ ] WebSocket transport for bidirectional streaming
- [ ] Built-in authentication and authorization
- [ ] Server-to-server communication
- [ ] Distributed server orchestration
- [ ] Built-in monitoring and metrics
- [ ] Server marketplace for discovering servers
- [ ] Hot reload for server code updates

---

**Status:** Implemented (Phase 3) ✅

**Next Steps:** Add more built-in servers, enhance transports

**Maintainer:** REVENG Development Team
