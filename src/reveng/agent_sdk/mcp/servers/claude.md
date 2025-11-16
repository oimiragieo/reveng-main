# MCP Servers - Built-in Servers

## Overview

This directory contains built-in MCP (Model Context Protocol) servers that extend agent capabilities through standardized interfaces. These servers provide access to databases, filesystems, and REVENG-specific functionality via the MCP protocol.

**Location:** `/home/user/reveng-main/src/reveng/agent_sdk/mcp/servers/`

## Files in This Directory

### `__init__.py` (438 lines)
Module initialization and server exports.

**Exports:**
- `DatabaseMCPServer` - Database query and management server
- `FilesystemMCPServer` - File and directory operations server
- `REVENGMCPServer` - REVENG binary analysis and deobfuscation server

### `reveng_server.py` (250 lines)
REVENG-specific MCP server exposing reverse engineering capabilities.

**Exposed Tools:**
1. **analyze_binary** - Analyze binary files (EXE, DLL, ELF, etc.)
   - Input: `path` (string), `quick_mode` (boolean, optional)
   - Output: File type, architecture, vulnerabilities, decompiled code

2. **deobfuscate_js** - Deobfuscate JavaScript code
   - Input: `code` (string), `use_ml` (boolean), `detect_malware` (boolean)
   - Output: Deobfuscated code, confidence score, obfuscation types, malware analysis

3. **detect_malware** - Detect malware in code or binary
   - Input: `path` (string), `type` (enum: "binary" or "javascript")
   - Output: Threat score, is_malicious flag, indicators

**Key Features:**
- Integration with `reveng.analyzer` for binary analysis
- Integration with `reveng.javascript` for JS deobfuscation
- Async execution to avoid blocking
- Comprehensive error handling
- Malware detection capabilities

**Usage:**
```python
from reveng.agent_sdk.mcp.servers import REVENGMCPServer
from reveng.agent_sdk.mcp import StdioTransport

server = REVENGMCPServer()
transport = StdioTransport()
await server.start(transport)
```

### `database.py` (8273 lines)
Database MCP server for SQL operations.

**Exposed Tools:**
- `query_database` - Execute SQL queries
- `list_tables` - List all tables in database
- `describe_table` - Get table schema
- `execute_transaction` - Execute transactional SQL

**Features:**
- Support for SQLite, PostgreSQL, MySQL
- Connection pooling
- Transaction management
- Query parameterization for security
- Result pagination

**Example:**
```python
from reveng.agent_sdk.mcp.servers import DatabaseMCPServer

server = DatabaseMCPServer(
    connection_string="sqlite:///analysis.db"
)
await server.start(transport)
```

### `filesystem.py` (7958 lines)
Filesystem operations MCP server.

**Exposed Tools:**
- `read_file` - Read file contents
- `write_file` - Write to file
- `list_directory` - List directory contents
- `search_files` - Search for files by pattern
- `get_file_info` - Get file metadata

**Features:**
- Sandboxed file operations
- Path validation and sanitization
- Permission checks
- Binary and text file support
- Recursive directory operations

**Security:**
- Restricts access to allowed directories
- Prevents path traversal attacks
- Validates file permissions
- Limits file sizes

**Example:**
```python
from reveng.agent_sdk.mcp.servers import FilesystemMCPServer

server = FilesystemMCPServer(
    allowed_paths=["/home/user/analysis/"]
)
await server.start(transport)
```

## Architecture

### Server Hierarchy

```
MCPServer (base)
    ├── REVENGMCPServer
    │   ├── Binary analysis
    │   ├── JS deobfuscation
    │   └── Malware detection
    │
    ├── DatabaseMCPServer
    │   ├── SQL queries
    │   ├── Schema inspection
    │   └── Transactions
    │
    └── FilesystemMCPServer
        ├── File I/O
        ├── Directory operations
        └── File search
```

### Integration Flow

```
Agent
  ↓
MCP Client
  ↓
Transport (Stdio/HTTP)
  ↓
MCP Server (REVENG/Database/Filesystem)
  ↓
Backend Service (Analyzer/DB/FS)
  ↓
Result
```

## Key Concepts

### 1. Tool Registration

Each server registers tools during initialization:

```python
class MyMCPServer(MCPServer):
    def __init__(self):
        super().__init__("my-server", "1.0.0")

        self.register_tool(MCPTool(
            name="my_tool",
            description="Tool description",
            input_schema={...},
            handler=self.my_tool_handler
        ))
```

### 2. Async Handlers

All tool handlers are async to prevent blocking:

```python
async def analyze_binary(self, args):
    # Run CPU-intensive work in executor
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, cpu_intensive_work, args)
    return result
```

### 3. Error Handling

Servers return structured errors:

```python
try:
    result = perform_operation(args)
    return {"content": [{"type": "text", "text": result}]}
except Exception as e:
    return {
        "content": [{"type": "text", "text": f"Error: {str(e)}"}],
        "error": str(e)
    }
```

## Usage Examples

### Example 1: Using REVENG Server for Binary Analysis

```python
from reveng.agent_sdk.mcp.servers import REVENGMCPServer
from reveng.agent_sdk.mcp import StdioTransport

async def analyze_malware():
    # Start server
    server = REVENGMCPServer()
    transport = StdioTransport()
    await server.start(transport)

    # Server handles requests like:
    # {
    #   "method": "tools/call",
    #   "params": {
    #     "name": "analyze_binary",
    #     "arguments": {"path": "/path/to/malware.exe"}
    #   }
    # }
```

### Example 2: Using Database Server

```python
from reveng.agent_sdk.mcp.servers import DatabaseMCPServer
from reveng.agent_sdk.mcp import StdioTransport

async def query_results():
    server = DatabaseMCPServer(
        connection_string="postgresql://localhost/analysis"
    )
    transport = StdioTransport()
    await server.start(transport)

    # Handles SQL queries, schema inspection, etc.
```

### Example 3: Using Filesystem Server

```python
from reveng.agent_sdk.mcp.servers import FilesystemMCPServer
from reveng.agent_sdk.mcp import StdioTransport

async def file_operations():
    server = FilesystemMCPServer(
        allowed_paths=[
            "/home/user/analysis/",
            "/tmp/reveng/"
        ]
    )
    transport = StdioTransport()
    await server.start(transport)

    # Handles file read/write, directory listing, etc.
```

### Example 4: Integrating All Servers

```python
from reveng.agent_sdk import ClaudeSDKClient
from reveng.agent_sdk.mcp import load_mcp_config

# Configure all servers in .mcp.json
config = load_mcp_config()

async with ClaudeSDKClient() as client:
    # Client can now use tools from all configured servers
    async for msg in client.query(
        "Analyze malware.exe and store results in database"
    ):
        print(msg.get_text())
```

## Configuration

### .mcp.json Configuration

```json
{
  "mcpServers": {
    "reveng": {
      "command": "python",
      "args": ["-m", "reveng.agent_sdk.mcp.servers.reveng_server"],
      "transport": "stdio"
    },
    "database": {
      "command": "python",
      "args": ["-m", "reveng.agent_sdk.mcp.servers.database"],
      "transport": "stdio",
      "env": {
        "DB_CONNECTION": "sqlite:///analysis.db"
      }
    },
    "filesystem": {
      "command": "python",
      "args": ["-m", "reveng.agent_sdk.mcp.servers.filesystem"],
      "transport": "stdio",
      "env": {
        "ALLOWED_PATHS": "/home/user/analysis/,/tmp/reveng/"
      }
    }
  }
}
```

## Testing

### Testing REVENG Server

```python
import pytest
from reveng.agent_sdk.mcp.servers import REVENGMCPServer

@pytest.mark.asyncio
async def test_reveng_server():
    server = REVENGMCPServer()

    # Test tool listing
    response = await server.handle_message({
        "id": 1,
        "method": "tools/list",
        "params": {}
    })

    tools = response["result"]["tools"]
    assert any(t["name"] == "analyze_binary" for t in tools)
    assert any(t["name"] == "deobfuscate_js" for t in tools)

@pytest.mark.asyncio
async def test_binary_analysis():
    server = REVENGMCPServer()

    response = await server.analyze_binary({
        "path": "/path/to/test.exe",
        "quick_mode": True
    })

    assert "content" in response
    assert len(response["content"]) > 0
```

### Running Server Tests

```bash
# Test all servers
pytest tests/agent_sdk/mcp/servers/

# Test specific server
pytest tests/agent_sdk/mcp/servers/test_reveng_server.py

# Test with coverage
pytest --cov=reveng.agent_sdk.mcp.servers tests/agent_sdk/mcp/servers/
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/agent_sdk/mcp/` - MCP framework
- `/home/user/reveng-main/src/reveng/analyzer/` - Binary analysis (used by REVENG server)
- `/home/user/reveng-main/src/reveng/javascript/` - JS deobfuscation (used by REVENG server)

### External Dependencies
- `asyncio` - Async I/O
- `sqlalchemy` - Database operations (for DatabaseMCPServer)
- `aiofiles` - Async file I/O (for FilesystemMCPServer)

## Notes

### Design Principles

1. **Security First** - All operations are sandboxed and validated
2. **Async Everything** - Non-blocking I/O for better performance
3. **Error Recovery** - Graceful error handling with detailed messages
4. **Extensibility** - Easy to add new tools to existing servers
5. **Modularity** - Servers can run independently or together

### Best Practices

1. **Always validate inputs** - Use JSON Schema for validation
2. **Use executors for CPU work** - Don't block the event loop
3. **Return structured errors** - Include error details in response
4. **Document tools thoroughly** - Help agents understand capabilities
5. **Test extensively** - Unit and integration tests for all tools

### Security Considerations

**REVENG Server:**
- Validates binary paths before analysis
- Sandboxes code execution during deobfuscation
- Limits resource usage (memory, CPU time)

**Database Server:**
- Uses parameterized queries to prevent SQL injection
- Restricts dangerous SQL operations (DROP, DELETE without WHERE)
- Implements connection pooling limits

**Filesystem Server:**
- Validates all paths to prevent traversal attacks
- Restricts operations to allowed directories
- Checks file permissions before operations
- Limits file sizes for read/write

### Future Enhancements

- [ ] Cloud MCP server (S3, Azure Blob, GCS)
- [ ] Network MCP server (port scanning, packet capture)
- [ ] ML MCP server (model inference, training)
- [ ] Collaboration MCP server (multi-agent coordination)
- [ ] Monitoring MCP server (metrics, logging, tracing)
- [ ] Container MCP server (Docker, Kubernetes integration)

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
