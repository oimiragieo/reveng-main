# Agent SDK - Tools Framework

## Overview

The Tools Framework provides the infrastructure for creating, registering, and executing atomic agent tools. Tools are single-purpose operations that agents can use to interact with REVENG capabilities, external systems, and file operations.

**Location:** `/home/user/reveng-main/src/reveng/agent_sdk/tools/`

## Files in This Directory

### `__init__.py` (43 lines)
Public API for the tools framework.

**Exports:**
- `BaseTool`, `ToolResult` - Core tool abstractions
- `tool` decorator - Simple tool creation
- `ToolRegistry` - Tool management
- `get_tool_registry()`, `register_tool()`, `get_tool()` - Helper functions

### `base.py` (4742 lines)
Base classes for tool implementation.

**Key Classes:**

**ToolResult:**
```python
@dataclass
class ToolResult:
    success: bool
    content: List[Dict[str, Any]]  # Anthropic format
    error: Optional[str] = None
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
```

Factory methods:
- `ToolResult.success_result(text, metadata)` - Create success result
- `ToolResult.error_result(error, metadata)` - Create error result

**BaseTool:**
```python
class BaseTool(ABC):
    name: str
    description: str
    input_schema: Dict[str, Any]

    @abstractmethod
    async def execute(self, args: Dict[str, Any]) -> ToolResult:
        pass

    async def safe_execute(self, args: Dict[str, Any]) -> ToolResult:
        # Execute with error handling and timing
        pass

    def to_anthropic_format(self) -> Dict[str, Any]:
        # Convert to Claude API format
        pass
```

### `decorator.py` (4852 lines)
@tool decorator for simple tool creation.

**Features:**
- Simple function-to-tool conversion
- Automatic input schema generation
- Type hint support
- Validation integration
- Registry auto-registration

**Example:**
```python
@tool("greet", "Greet a user", {"name": str})
async def greet(args):
    return {"content": [{"type": "text", "text": f"Hello, {args['name']}!"}]}
```

### `registry.py` (1128 lines)
Central registry for tool management.

**ToolRegistry:**
```python
class ToolRegistry:
    def register(self, tool: BaseTool) -> None
    def get(self, name: str) -> Optional[BaseTool]
    def list_tools(self) -> List[str]
    def get_all_tools(self) -> List[BaseTool]
```

**Features:**
- Thread-safe registration
- Name collision detection
- Tool discovery
- Global and local registries

## Architecture

### Tool Lifecycle

```
1. Definition
   ├─> @tool decorator (simple)
   └─> BaseTool class (advanced)

2. Registration
   └─> ToolRegistry.register(tool)

3. Discovery
   └─> ToolRegistry.get(name)

4. Execution
   ├─> Validate input
   ├─> tool.execute(args)
   └─> Return ToolResult

5. Result Formatting
   └─> to_anthropic_format()
```

### Tool vs Skill

```
Tool (Atomic)               Skill (Composite)
  ↓                              ↓
Single operation             Multi-step workflow
  ↓                              ↓
Direct integration           Orchestrates tools
  ↓                              ↓
Fast execution              Complex logic
```

## Usage Examples

### Example 1: Simple Tool with Decorator

```python
from reveng.agent_sdk.tools import tool

@tool(
    name="calculate",
    description="Add two numbers",
    input_schema={"a": int, "b": int}
)
async def calculate(args):
    result = args["a"] + args["b"]
    return {
        "content": [{"type": "text", "text": str(result)}]
    }

# Tool is automatically registered
# Use via ToolRegistry.get("calculate")
```

### Example 2: Advanced Tool with BaseTool

```python
from reveng.agent_sdk.tools import BaseTool, ToolResult

class AdvancedAnalysisTool(BaseTool):
    name = "advanced_analysis"
    description = "Perform advanced binary analysis"
    input_schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "options": {"type": "object"}
        },
        "required": ["path"]
    }

    async def execute(self, args):
        path = args["path"]
        options = args.get("options", {})

        # Complex analysis logic
        result = await self.perform_analysis(path, options)

        return ToolResult.success_result(
            text=f"Analysis complete: {result}",
            metadata={"path": path, "duration": 10.5}
        )

    async def perform_analysis(self, path, options):
        # Analysis implementation
        return {"findings": [...]}
```

### Example 3: Using Tool Registry

```python
from reveng.agent_sdk.tools import get_tool_registry, register_tool

# Get global registry
registry = get_tool_registry()

# Register tool
my_tool = MyCustomTool()
register_tool(my_tool)

# Get tool by name
tool = registry.get("my_custom_tool")

# List all tools
tools = registry.list_tools()
print(f"Available: {tools}")

# Execute tool
result = await tool.safe_execute({"arg1": "value1"})
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/agent_sdk/` - Parent SDK
- `/home/user/reveng-main/src/reveng/agent_sdk/tools/reveng/` - REVENG-specific tools

### External Integration
- Used by `/home/user/reveng-main/src/reveng/agent_sdk/client.py` - Client tool execution
- Used by `/home/user/reveng-main/src/reveng/agent_sdk/skills/` - Skills use tools

## Notes

**Best Practices:**
1. Keep tools atomic and focused
2. Provide detailed descriptions
3. Validate all inputs
4. Handle errors gracefully
5. Return structured results

**Future Enhancements:**
- [ ] Tool versioning
- [ ] Tool dependencies
- [ ] Tool rate limiting
- [ ] Tool monitoring/metrics

---

**Status:** Phase 2 Complete ✅

**Maintainer:** REVENG Development Team
