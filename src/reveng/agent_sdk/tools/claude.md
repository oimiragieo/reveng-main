# `claude.md` — `agent_sdk/tools`

**Repository path:** `src/reveng/agent_sdk/tools/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `reveng/` — [`claude.md`](reveng/claude.md)

## Python modules

### `__init__.py`
- **Summary:** Tool framework for REVENG Agent SDK.
- **Functions / coroutines:**
  - `def get_tool_registry()` — Get the global tool registry.
  - `def register_tool()` — Register a tool with the global registry.
  - `def get_tool()` — Get a tool by name from global registry.

### `base.py`
- **Summary:** Base classes for tools in REVENG Agent SDK.
- **Classes:**
  - `ToolResult` — Result from tool execution.
  - `BaseTool` — Base class for all tools.

### `decorator.py`
- **Summary:** @tool decorator for creating custom tools easily.
- **Functions / coroutines:**
  - `def tool()` — Decorator to create a tool from a function.
  - `def _convert_schema()` — Convert simple {arg: type} schema to JSON Schema format.

### `registry.py`
- **Summary:** Tool registry for managing available tools.
- **Classes:**
  - `ToolRegistry` — Registry for managing tool instances.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
