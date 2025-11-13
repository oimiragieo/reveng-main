# REVENG Agent SDK

> **Enterprise-ready agent framework for autonomous reverse engineering**

[![Version](https://img.shields.io/badge/version-1.0.0-brightgreen.svg)]()
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)]()
[![Status](https://img.shields.io/badge/status-Phase%201%20Complete-success.svg)]()

---

## 🚀 Quick Start

```python
from reveng.agent_sdk import tool, ToolResult

# Create a custom tool
@tool("greet", "Greet a user", {"name": str})
async def greet(args):
    return ToolResult.success_result(f"Hello, {args['name']}!")

# Use REVENG tools
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool

tool = BinaryAnalysisTool()
result = await tool.execute({"path": "malware.exe"})
print(result.content[0]["text"])
```

---

## 📦 What's Implemented (Phase 1 & 2)

### ✅ Core Framework
- **Types & Exceptions** - Complete type system with enterprise error handling
- **Tool Framework** - @tool decorator, BaseTool class, tool registry
- **REVENG Integration** - Binary analysis and JS deobfuscation tools
- **Cost Tracking Types** - Usage metrics and cost calculation

### ✅ Built-in Tools
- `analyze_binary` - Comprehensive binary analysis
- `deobfuscate_javascript` - JavaScript deobfuscation with malware detection
- Custom tool support via @tool decorator

### ✅ Enterprise Features
- Type hints throughout (Python 3.9+)
- Comprehensive error handling
- Async/await for performance
- Extensible architecture

---

## 🎯 Architecture

```
reveng/agent_sdk/
├── __init__.py           # Public API
├── types.py              # Message types, cost tracking
├── exceptions.py         # Exception hierarchy
│
├── tools/
│   ├── base.py           # BaseTool class
│   ├── decorator.py      # @tool decorator
│   ├── registry.py       # Tool registry
│   └── reveng/           # REVENG-specific tools
│       ├── binary_analysis_tool.py
│       └── js_deobfuscation_tool.py
│
└── README.md             # This file
```

---

## 📚 Usage Examples

### Example 1: Simple Tool

```python
from reveng.agent_sdk import tool

@tool("calculate", "Add two numbers", {"a": int, "b": int})
async def calculate(args):
    result = args["a"] + args["b"]
    return {"content": [{"type": "text", "text": str(result)}]}
```

### Example 2: Binary Analysis

```python
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool

tool = BinaryAnalysisTool()
result = await tool.execute({
    "path": "suspicious.exe",
    "quick_mode": False
})

if result.success:
    print(result.content[0]["text"])
else:
    print(f"Error: {result.error}")
```

### Example 3: JavaScript Deobfuscation

```python
from reveng.agent_sdk.tools.reveng import JSDeobfuscationTool

tool = JSDeobfuscationTool()
result = await tool.execute({
    "code": "var _0x1234=['hello'];console.log(_0x1234[0]);",
    "use_ml": True,
    "detect_malware": True
})

print(result.content[0]["text"])
```

### Example 4: Advanced Custom Tool

```python
from reveng.agent_sdk.tools import BaseTool, ToolResult

class MyAdvancedTool(BaseTool):
    name = "my_tool"
    description = "Does something advanced"
    input_schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"}
        },
        "required": ["query"]
    }

    async def execute(self, args):
        # Your complex logic here
        return ToolResult.success_result("Result")
```

---

## 🎓 Key Concepts

### Tool Definition

Tools require three components:
1. **Name** - Unique identifier (regex: `^[a-zA-Z0-9_-]{1,64}$`)
2. **Description** - Detailed explanation (3-4 sentences minimum)
3. **Input Schema** - JSON Schema or simple type dict

### Tool Results

Tools return `ToolResult` objects:
```python
ToolResult(
    success=True,
    content=[{"type": "text", "text": "Output"}],
    error=None,
    execution_time=0.5,
    metadata={"extra": "info"}
)
```

### Cost Tracking

Cost tracking is built-in:
```python
report = CostReport(session_id="sess_123")
report.add_usage(UsageMetrics(
    input_tokens=100,
    output_tokens=50
))
print(f"Total cost: ${report.total_cost_usd}")
```

---

## 🚧 What's Next (Future Phases)

### Phase 3: MCP Integration
- Model Context Protocol support
- Database MCP servers
- Cloud MCP servers
- Custom MCP server creation

### Phase 4: Skills System
- Reusable agent skills
- Skill marketplace
- Skill templates

### Phase 5: Enterprise Features
- Complete cost tracking
- Permission system (allowlists, denylists)
- Audit logging
- Analytics dashboard

### Phase 6: Claude SDK Client
- ClaudeSDKClient class
- Streaming support
- Session management
- Multi-turn conversations

### Phase 7: Prompt Engineering
- Prompt templates
- Variable substitution
- Prompt optimization
- System prompts library

### Phase 8: Testing & Docs
- 100+ integration tests
- Evaluation framework
- Complete API documentation
- Video tutorials

---

## 📊 Current Status

| Component | Status | Phase |
|-----------|--------|-------|
| **Core Types** | ✅ Complete | Phase 1 |
| **Tool Framework** | ✅ Complete | Phase 2 |
| **REVENG Integration** | ✅ Complete | Phase 2 |
| **Cost Tracking Types** | ✅ Complete | Phase 1 |
| **MCP Support** | ⏳ Planned | Phase 3 |
| **Skills System** | ⏳ Planned | Phase 4 |
| **Claude Client** | ⏳ Planned | Phase 6 |
| **Full Testing** | ⏳ Planned | Phase 7 |

---

## 🔧 Development

### Running Examples

```bash
# Basic demo
python examples/agent_sdk_demo.py

# Binary analysis
python -c "
import asyncio
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool
tool = BinaryAnalysisTool()
asyncio.run(tool.execute({'path': 'test.exe'}))
"
```

### Creating Custom Tools

1. Use `@tool` decorator for simple tools
2. Extend `BaseTool` for advanced tools
3. Register automatically or manually
4. Test with `tool.safe_execute(args)`

### Integration with REVENG

Tools can access all REVENG features:
- `reveng.analyzer` - Binary analysis
- `reveng.javascript` - JS deobfuscation
- `reveng.ai` - AI/ML features
- `reveng.exploits` - Exploit generation

---

## 📖 Documentation

- **[Implementation Plan](../../../AGENT_SDK_IMPLEMENTATION_PLAN.md)** - Complete 8-week roadmap
- **[API Reference](types.py)** - Type definitions
- **[Tool Framework](tools/)** - Tool implementation details
- **[Examples](../../../examples/agent_sdk_demo.py)** - Working examples

---

## 🎉 Benefits

### For Developers
- **Easy Tool Creation** - @tool decorator is simple
- **Type Safety** - Full type hints throughout
- **Error Handling** - Comprehensive exception hierarchy
- **Async Support** - High performance with asyncio

### For Enterprises
- **Cost Tracking** - Built-in usage monitoring
- **Extensibility** - Easy to add new capabilities
- **Integration** - Seamless with existing REVENG
- **Production-Ready** - Enterprise-grade quality

### For Researchers
- **Automation** - Autonomous binary analysis
- **Malware Detection** - Integrated threat detection
- **Multi-Agent** - Future: coordinated agents
- **Reproducibility** - Consistent results

---

## 🤝 Contributing

To extend the agent SDK:

1. **Add New Tool**: Create in `tools/` directory
2. **Add REVENG Integration**: Extend `tools/reveng/`
3. **Add MCP Server**: Coming in Phase 3
4. **Add Skill**: Coming in Phase 4

See `AGENT_SDK_IMPLEMENTATION_PLAN.md` for roadmap.

---

## 📄 License

MIT License - See [LICENSE](../../../LICENSE)

---

## 🎯 Success Stories

Once fully implemented, the agent SDK will enable:
- **Autonomous Binary Analysis** - Agents analyze binaries without human input
- **Multi-Agent Workflows** - Coordinate multiple agents for complex tasks
- **Enterprise Automation** - Scale reverse engineering operations
- **AI-Powered Security** - Intelligent threat detection and response

---

**Status:** Phase 1 & 2 Complete (Foundation Ready) ✅

**Next:** Phase 3 - MCP Integration (See implementation plan)

**Made with ❤️ by the REVENG Development Team**
