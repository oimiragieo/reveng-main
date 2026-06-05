# `claude.md` — `integrations/ghidra`

**Repository path:** `src/reveng/integrations/ghidra/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Ghidra integration helpers for REVENG.

### `ghidra_engine.py`
- **Summary:** Ghidra Engine - Client for Ghidra Analysis Server
- **Classes:**
  - `GhidraConnectionError` — Raised when Ghidra Analysis Server is not available.
  - `GhidraEngine` — Client for the Ghidra Analysis Server.
  - `GhidraDataExtractor` — Helper class to extract specific data from Ghidra analysis results.

### `ghidra_http_client.py`
- **Summary:** Ghidra HTTP Client - Base communication layer for Ghidra MCP Server
- **Classes:**
  - `GhidraHTTPClient` — HTTP client for Ghidra MCP server with connection pooling and error handling.

### `ghidra_mcp_connector.py`
- **Summary:** Ghidra MCP Connector
- **Classes:**
  - `GhidraMCPConnector` — Enhanced Ghidra MCP Connector for AI Integration

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
