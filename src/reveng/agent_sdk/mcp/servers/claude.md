# `claude.md` — `agent_sdk/mcp/servers`

**Repository path:** `src/reveng/agent_sdk/mcp/servers/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Built-in MCP Servers

### `database.py`
- **Summary:** Database MCP Server
- **Classes:**
  - `DatabaseMCPServer` — Database MCP Server.

### `filesystem.py`
- **Summary:** Filesystem MCP Server
- **Classes:**
  - `FilesystemMCPServer` — Filesystem MCP Server.

### `reveng_enterprise_server.py`
- **Summary:** REVENG Enterprise MCP Server
- **Classes:**
  - `AuditLogger` — Enterprise audit logging for MCP operations
  - `RateLimiter` — Simple token bucket rate limiter
  - `OllamaRepairEngine` — Minimal LLM adapter that matches the recompilation engine's expectations.
  - `REVENGEnterpriseServer` — Enterprise-grade REVENG MCP Server.
- **Functions / coroutines:**
  - `async def main()` — Run REVENG Enterprise MCP Server

### `reveng_server.py`
- **Summary:** REVENG MCP Server
- **Classes:**
  - `REVENGMCPServer` — REVENG MCP Server.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
