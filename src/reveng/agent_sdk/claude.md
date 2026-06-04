# `claude.md` — `agent_sdk`

**Repository path:** `src/reveng/agent_sdk/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `mcp/` — [`claude.md`](mcp/claude.md)
- `skills/` — [`claude.md`](skills/claude.md)
- `tools/` — [`claude.md`](tools/claude.md)

## Python modules

### `__init__.py`
- **Summary:** REVENG Agent SDK

### `client.py`
- **Summary:** Claude SDK Client
- **Classes:**
  - `ClaudeSDKClient` — Enterprise Claude SDK Client.

### `cost_tracking.py`
- **Summary:** Cost Tracking and Analytics
- **Classes:**
  - `CostTracker` — Track API costs and token usage across sessions.
- **Functions / coroutines:**
  - `def get_global_tracker()` — Get the global cost tracker instance

### `exceptions.py`
- **Summary:** Exception classes for REVENG Agent SDK.
- **Classes:**
  - `AgentSDKError` — Base exception for all agent SDK errors.
  - `ClientError` — Error in SDK client operations.
  - `ToolError` — Error during tool execution.
  - `SessionError` — Error in session management.
  - `PermissionError` — Permission denied for tool/operation.
  - `ValidationError` — Input validation error.
  - `ConfigurationError` — Configuration error.
  - `TimeoutError` — Operation timeout.
  - `RateLimitError` — API rate limit exceeded.

### `permissions.py`
- **Summary:** Permissions and Security System
- **Classes:**
  - `ToolPermission` — Permission configuration for a tool
  - `PermissionManager` — Manage tool permissions and security policies.
- **Functions / coroutines:**
  - `def get_global_manager()` — Get the global permission manager

### `types.py`
- **Summary:** Type definitions for REVENG Agent SDK.
- **Classes:**
  - `MessageType` — Types of messages in agent conversations.
  - `PermissionMode` — Permission modes for tool execution.
  - `TextBlock` — A text content block.
  - `ThinkingBlock` — A thinking/reasoning content block.
  - `ToolUseBlock` — A tool use request block.
  - `ToolResultBlock` — A tool execution result block.
  - `Message` — A message in an agent conversation.
  - `UsageMetrics` — Token usage metrics for cost tracking.
  - `CostReport` — Cost tracking report for a session.
  - `ToolDefinition` — Definition of a tool for Claude.

## Other files in this folder

- `README.md`

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
