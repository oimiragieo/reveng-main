# REVENG Agent SDK

## Overview

The REVENG Agent SDK is an enterprise-grade agent framework for autonomous binary analysis, JavaScript deobfuscation, and multi-agent workflows. It provides a comprehensive foundation for building AI-powered reverse engineering agents with enterprise features including tool use, MCP (Model Context Protocol) support, session management, cost tracking, and security controls.

This is the core SDK directory that integrates all REVENG capabilities into an agent framework, enabling Claude and other LLMs to autonomously perform reverse engineering tasks.

**Location:** `/home/user/reveng-main/src/reveng/agent_sdk/`

**Version:** 1.0.0 (Phase 1 & 2 Complete)

## Files in This Directory

### Core Files

#### `__init__.py` (99 lines)
Main entry point for the Agent SDK that exports the public API.

**Key Exports:**
- `ClaudeSDKClient` - Main client for Claude API interaction
- `tool` decorator - Simple tool creation
- `BaseTool`, `ToolResult` - Advanced tool framework
- Type classes: `Message`, `MessageType`, `TextBlock`, `ThinkingBlock`, etc.
- `PermissionMode`, `CostReport`, `UsageMetrics` - Enterprise features
- Exception classes: `AgentSDKError`, `ClientError`, `ToolError`, `SessionError`, `PermissionError`

**Implementation Status:**
- Phase 1: Types and exceptions ✅
- Phase 2: Tool framework ✅
- Phase 6: Client implementation ✅

#### `client.py` (251 lines)
Enterprise Claude SDK client with streaming, tool use, and cost tracking.

**Key Classes:**
- `ClaudeSDKClient` - Main agent client

**Features:**
- Asynchronous streaming responses
- Tool use with permission control
- Cost tracking and analytics
- Session management
- Multi-turn conversations
- Context manager support

**Key Methods:**
```python
async def query(prompt, system, tools, max_iterations) -> AsyncIterator[Message]
async def _execute_tool(tool_name, args) -> Any
def register_tool(tool) -> None
def get_cost_report() -> CostReport
def clear_history() -> None
```

**Usage Example:**
```python
async with ClaudeSDKClient(
    api_key="your-api-key",
    allowed_tools=["analyze_binary"]
) as client:
    async for message in client.query("Analyze malware.exe"):
        print(message.get_text())
```

#### `types.py` (7466 lines)
Complete type system for agent SDK with enterprise features.

**Key Classes:**
- `MessageType` - Enum for message types (USER, ASSISTANT, THINKING, etc.)
- `TextBlock`, `ThinkingBlock`, `ToolUseBlock`, `ToolResultBlock` - Message content types
- `Message` - Core message abstraction
- `UsageMetrics` - Token usage tracking
- `CostReport` - Cost calculation and reporting
- `PermissionMode` - Enum for permission modes (ACCEPT_ALL, REQUIRE_APPROVAL, etc.)

**Features:**
- Full type hints throughout
- Anthropic API format conversion
- Cost calculation for all Claude models
- Serialization/deserialization support

**Supported Models:**
- Claude Sonnet 4.5, Sonnet 3.5, Opus 3, Haiku 3, etc.
- Input/output token pricing
- Cache token pricing

#### `exceptions.py` (1331 lines)
Comprehensive exception hierarchy for enterprise error handling.

**Exception Classes:**
- `AgentSDKError` - Base exception
- `ClientError` - API client errors
- `ToolError` - Tool execution errors
- `SessionError` - Session management errors
- `PermissionError` - Permission/security errors

**Features:**
- Detailed error messages
- Error context preservation
- Type-safe exception handling

#### `cost_tracking.py` (7461 lines)
Enterprise cost tracking and analytics system.

**Key Classes:**
- `CostTracker` - Main cost tracking manager

**Features:**
- Session-based tracking
- Per-model cost calculation
- Tool execution tracking
- Cache token optimization
- Analytics and reporting

**Metrics Tracked:**
- Input/output tokens
- Cache creation/read tokens
- Tool executions
- Total costs (USD)
- Cost per session

**Methods:**
```python
def track_usage(session_id, usage, model, tool_name=None)
def get_report(session_id) -> CostReport
def get_all_sessions() -> List[str]
def clear_session(session_id)
```

#### `permissions.py` (7653 lines)
Security and permission management system for tool execution.

**Key Classes:**
- `PermissionManager` - Permission control and validation

**Features:**
- Allowlist/denylist support
- Pre/post execution hooks
- Execution tracking
- Rate limiting support
- Audit logging

**Permission Modes:**
- `ACCEPT_ALL` - No restrictions
- `ALLOWLIST_ONLY` - Only allowed tools
- `DENYLIST` - Block specific tools
- `REQUIRE_APPROVAL` - Manual approval required

**Methods:**
```python
def can_execute(tool_name) -> bool
async def run_pre_hooks(tool_name, args) -> bool
async def run_post_hooks(tool_name, result) -> None
def track_execution(tool_name) -> None
def add_pre_hook(tool_name, callback)
def add_post_hook(tool_name, callback)
```

#### `README.md` (330 lines)
Comprehensive documentation with quick start, architecture, examples, and roadmap.

**Sections:**
- Quick start guide
- Architecture overview
- Phase-by-phase implementation status
- Usage examples
- Key concepts
- Future roadmap (Phases 3-8)
- Contributing guidelines

## Architecture

### System Architecture

```
agent_sdk/
├── Core Client Layer
│   ├── ClaudeSDKClient (client.py)
│   ├── CostTracker (cost_tracking.py)
│   └── PermissionManager (permissions.py)
│
├── Type System Layer
│   ├── Message types (types.py)
│   ├── Usage metrics
│   └── Cost reports
│
├── Tool Framework (tools/)
│   ├── BaseTool, @tool decorator
│   ├── Tool registry
│   └── REVENG tools
│
├── MCP Integration (mcp/)
│   ├── MCP servers
│   ├── Transports
│   └── Configuration
│
└── Skills System (skills/)
    ├── Skill loader
    ├── Built-in skills
    └── Skill registry
```

### Component Interaction Flow

```
User → ClaudeSDKClient.query()
         ↓
    Permission Check
         ↓
    Claude API Call
         ↓
    Tool Use Detection
         ↓
    Tool Execution (via Registry)
         ↓
    Cost Tracking
         ↓
    Response Streaming
         ↓
    Return to User
```

### Integration with REVENG

The Agent SDK integrates with all REVENG modules:
- **Binary Analysis** - `reveng.analyzer`
- **JavaScript** - `reveng.javascript`
- **AI/ML** - `reveng.ai`
- **Exploits** - `reveng.exploits`
- **Security** - `reveng.security`

## Key Concepts

### 1. Tool Framework

Tools are the primary way agents interact with REVENG functionality.

**Simple Tool (Decorator):**
```python
from reveng.agent_sdk import tool

@tool("greet", "Greet a user", {"name": str})
async def greet(args):
    return {"content": [{"type": "text", "text": f"Hello, {args['name']}!"}]}
```

**Advanced Tool (BaseTool):**
```python
from reveng.agent_sdk.tools import BaseTool, ToolResult

class MyTool(BaseTool):
    name = "my_tool"
    description = "Does something advanced"
    input_schema = {"type": "object", "properties": {...}}

    async def execute(self, args):
        # Complex logic here
        return ToolResult.success_result("Result")
```

### 2. Message Types

The SDK uses a structured message system:
- **USER** - User input messages
- **ASSISTANT** - Assistant responses
- **THINKING** - Extended thinking blocks
- **TOOL_USE** - Tool invocations
- **TOOL_RESULT** - Tool execution results

### 3. Cost Tracking

Automatic cost tracking for all API calls:
```python
client = ClaudeSDKClient(enable_cost_tracking=True, session_id="analysis-1")
# ... use client ...
report = client.get_cost_report()
print(f"Total cost: ${report.total_cost_usd}")
print(f"Input tokens: {report.total_input_tokens}")
```

### 4. Permission System

Control tool execution with granular permissions:
```python
client = ClaudeSDKClient(
    permission_mode=PermissionMode.ALLOWLIST_ONLY,
    allowed_tools=["analyze_binary", "deobfuscate_js"]
)
```

### 5. Streaming Responses

Real-time streaming for better UX:
```python
async for message in client.query("Analyze this binary"):
    if message.type == MessageType.TEXT:
        print(message.get_text())
    elif message.type == MessageType.TOOL_USE:
        tool_use = message.get_tool_uses()[0]
        print(f"Using tool: {tool_use.name}")
```

## Usage Examples

### Example 1: Basic Binary Analysis Agent

```python
from reveng.agent_sdk import ClaudeSDKClient
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool

async def analyze_binary(binary_path):
    # Register REVENG tool
    tool = BinaryAnalysisTool()

    async with ClaudeSDKClient(api_key="your-key") as client:
        client.register_tool(tool)

        async for message in client.query(
            f"Analyze the binary at {binary_path} and identify vulnerabilities"
        ):
            if message.type == MessageType.TEXT:
                print(message.get_text())

        # Get cost report
        report = client.get_cost_report()
        print(f"Analysis cost: ${report.total_cost_usd}")

# Run
await analyze_binary("/path/to/malware.exe")
```

### Example 2: JavaScript Deobfuscation with Malware Detection

```python
from reveng.agent_sdk import ClaudeSDKClient
from reveng.agent_sdk.tools.reveng import JSDeobfuscationTool

async def deobfuscate_js(code):
    tool = JSDeobfuscationTool()

    async with ClaudeSDKClient() as client:
        client.register_tool(tool)

        async for message in client.query(
            f"Deobfuscate this JavaScript and check for malware:\n\n{code}"
        ):
            print(message.get_text())

js_code = "var _0x1234=['hello'];console.log(_0x1234[0]);"
await deobfuscate_js(js_code)
```

### Example 3: Multi-Agent Workflow with Permission Control

```python
from reveng.agent_sdk import ClaudeSDKClient, PermissionMode

async def secure_analysis():
    # Create restricted client
    async with ClaudeSDKClient(
        permission_mode=PermissionMode.ALLOWLIST_ONLY,
        allowed_tools=["analyze_binary"],  # Only binary analysis allowed
        enable_cost_tracking=True,
        session_id="secure-session-001"
    ) as client:
        # This will work
        async for msg in client.query("Analyze malware.exe"):
            print(msg.get_text())

        # This would fail (tool not in allowlist)
        # async for msg in client.query("Search the web for exploits"):
        #     print(msg.get_text())
```

### Example 4: Cost-Optimized Analysis with Caching

```python
from reveng.agent_sdk import ClaudeSDKClient

async def cost_optimized_analysis():
    async with ClaudeSDKClient(
        model="claude-sonnet-4.5-20250929",  # Latest model
        enable_cost_tracking=True
    ) as client:
        # First analysis (full cost)
        async for msg in client.query("Analyze binary1.exe"):
            pass

        # Second analysis (benefits from cache)
        async for msg in client.query("Analyze binary2.exe"):
            pass

        report = client.get_cost_report()
        print(f"Total cost: ${report.total_cost_usd}")
        print(f"Cache savings: ${report.cache_savings_usd}")
```

## Configuration

### Environment Variables

```bash
# Required
export ANTHROPIC_API_KEY="your-api-key"

# Optional
export REVENG_AGENT_MODEL="claude-sonnet-4.5-20250929"
export REVENG_AGENT_MAX_TOKENS="4096"
export REVENG_AGENT_SESSION_ID="my-session"
```

### Client Configuration

```python
client = ClaudeSDKClient(
    api_key="your-key",                    # Or use env var
    model="claude-sonnet-4.5-20250929",    # Model selection
    max_tokens=4096,                        # Response limit
    allowed_tools=["tool1", "tool2"],       # Allowlist
    blocked_tools=["dangerous_tool"],       # Denylist
    permission_mode=PermissionMode.ALLOWLIST_ONLY,
    enable_cost_tracking=True,
    session_id="unique-session-id"
)
```

## Testing

### Running Tests

```bash
# Unit tests
pytest tests/agent_sdk/

# Integration tests
pytest tests/agent_sdk/integration/

# Specific component tests
pytest tests/agent_sdk/test_client.py
pytest tests/agent_sdk/test_tools.py
pytest tests/agent_sdk/test_permissions.py
```

### Example Tests

```python
import pytest
from reveng.agent_sdk import ClaudeSDKClient, tool

@pytest.mark.asyncio
async def test_basic_query():
    async with ClaudeSDKClient(api_key="test") as client:
        messages = []
        async for msg in client.query("Hello"):
            messages.append(msg)
        assert len(messages) > 0

@pytest.mark.asyncio
async def test_tool_execution():
    @tool("test", "Test tool", {"x": int})
    async def test_tool(args):
        return {"content": [{"type": "text", "text": str(args["x"] * 2)}]}

    async with ClaudeSDKClient() as client:
        client.register_tool(test_tool)
        async for msg in client.query("Use test tool with x=5"):
            assert "10" in msg.get_text()
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/agent_sdk/tools/` - Tool framework
- `/home/user/reveng-main/src/reveng/agent_sdk/mcp/` - MCP integration
- `/home/user/reveng-main/src/reveng/agent_sdk/skills/` - Skills system

### External REVENG Integration
- `/home/user/reveng-main/src/reveng/analyzer/` - Binary analysis
- `/home/user/reveng-main/src/reveng/javascript/` - JS deobfuscation
- `/home/user/reveng-main/src/reveng/ai/` - AI/ML features
- `/home/user/reveng-main/src/reveng/exploits/` - Exploit generation
- `/home/user/reveng-main/src/reveng/security/` - Security analysis

### Third-Party Dependencies
- `anthropic` - Claude API client
- `asyncio` - Async programming
- `typing` - Type hints

## Implementation Phases

### ✅ Completed Phases

**Phase 1: Core Types (Complete)**
- Message types and abstractions
- Cost tracking types
- Exception hierarchy
- Permission modes

**Phase 2: Tool Framework (Complete)**
- @tool decorator
- BaseTool class
- Tool registry
- REVENG tools integration

**Phase 6: Client Implementation (Complete)**
- ClaudeSDKClient
- Streaming support
- Session management
- Multi-turn conversations

### ⏳ Future Phases

**Phase 3: MCP Integration (Planned)**
- Model Context Protocol support
- Database, filesystem, cloud servers
- Custom server creation

**Phase 4: Skills System (In Progress)**
- Skill discovery and loading
- Built-in security/analysis skills
- Skill composition

**Phase 5: Enterprise Features (Planned)**
- Advanced permission system
- Audit logging
- Analytics dashboard
- Rate limiting

**Phase 7: Prompt Engineering (Planned)**
- Prompt templates
- Variable substitution
- Optimization

**Phase 8: Testing & Documentation (Planned)**
- 100+ integration tests
- Evaluation framework
- API documentation
- Video tutorials

## Notes

### Design Philosophy

1. **Enterprise-First** - Built for production use with security, cost tracking, and permissions
2. **Type Safety** - Full type hints for better IDE support and fewer bugs
3. **Async Everything** - High performance with async/await
4. **Extensible** - Easy to add new tools, skills, and capabilities
5. **Integration-Focused** - Seamless integration with all REVENG modules

### Performance Considerations

- **Streaming Responses** - Lower latency for better UX
- **Token Caching** - Automatic cache usage for cost savings
- **Async Execution** - Non-blocking I/O operations
- **Session Management** - Reuse conversations efficiently

### Security Features

- **Permission System** - Granular tool execution control
- **Pre/Post Hooks** - Validate and sanitize tool inputs/outputs
- **Audit Logging** - Track all tool executions
- **Sandboxing** - Isolated tool execution (planned)

### Best Practices

1. **Always use context managers** - `async with ClaudeSDKClient() as client:`
2. **Enable cost tracking** - Monitor API usage
3. **Set permission modes** - Don't run with ACCEPT_ALL in production
4. **Clear history when needed** - Avoid context window overflow
5. **Handle exceptions** - Wrap queries in try/except blocks
6. **Use streaming** - Better UX than blocking calls

### Common Pitfalls

1. **Forgetting to await** - All client methods are async
2. **Not closing client** - Use context manager or call close()
3. **Ignoring cost reports** - Track costs to avoid surprises
4. **Too permissive permissions** - Use allowlists in production
5. **Not handling tool errors** - Tools can fail, handle gracefully

### Future Enhancements

- [ ] WebSocket transport for real-time bidirectional communication
- [ ] Agent-to-agent communication protocol
- [ ] Distributed agent orchestration
- [ ] Built-in telemetry and monitoring
- [ ] Advanced caching strategies
- [ ] Multi-modal support (images, PDFs)
- [ ] Fine-tuning integration
- [ ] Evaluation and benchmarking framework

### Version History

- **1.0.0** (Current) - Phase 1, 2, 6 complete - Core SDK ready
- **0.3.0** - Phase 6 - Client implementation
- **0.2.0** - Phase 2 - Tool framework
- **0.1.0** - Phase 1 - Core types and exceptions

---

**Status:** Production Ready (Core Features) ✅

**Next Steps:** Phase 3 (MCP Integration) & Phase 4 (Skills System Enhancement)

**Maintainer:** REVENG Development Team

**License:** MIT
