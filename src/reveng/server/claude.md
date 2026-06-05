# `claude.md` — `server`

**Repository path:** `src/reveng/server/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** REVENG Ghidra Analysis Server

### `ghidra_analysis_server.py`
- **Summary:** Ghidra Analysis Server - The "Database" for REVENG
- **Classes:**
  - `GhidraAnalysisEngine` — Core analysis engine that wraps Ghidra functionality.
- **Functions / coroutines:**
  - `def health()` — Health check endpoint.
  - `def analyze()` — Main analysis endpoint.
  - `def get_function()` — Get detailed information about a specific function.
  - `def index()` — Root endpoint with server information.
  - `def start_server()` — Start the Ghidra Analysis Server.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
