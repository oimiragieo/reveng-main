# `claude.md` — `agent_sdk/mcp`

**Repository path:** `src/reveng/agent_sdk/mcp/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `servers/` — [`claude.md`](servers/claude.md)

## Python modules

### `__init__.py`
- **Summary:** REVENG Agent SDK - Model Context Protocol (MCP)

### `client.py`
- **Summary:** MCP Client Implementation
- **Classes:**
  - `MCPClient` — Client for communicating with MCP servers.

### `config.py`
- **Summary:** MCP Configuration Management
- **Classes:**
  - `MCPServerConfig` — Configuration for a single MCP server
  - `MCPConfig` — MCP configuration file format.
- **Functions / coroutines:**
  - `def load_mcp_config()` — Load MCP configuration from file.
  - `def save_mcp_config()` — Save MCP configuration to file.
  - `def _expand_env_vars()` — Recursively expand environment variables in config data

### `server.py`
- **Summary:** MCP Server Implementation
- **Classes:**
  - `MCPMessageType` — MCP protocol message types
  - `MCPTool` — MCP tool definition
  - `MCPResource` — MCP resource definition
  - `MCPPrompt` — MCP prompt template
  - `MCPServer` — Base class for MCP servers.

### `transports.py`
- **Summary:** MCP Transport Implementations
- **Classes:**
  - `MCPTransport` — Base class for MCP transports
  - `StdioTransport` — Stdio transport for MCP.
  - `HTTPTransport` — HTTP transport for MCP.
  - `InProcessTransport` — In-process transport for MCP.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
