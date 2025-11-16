# REVENG - Comprehensive Codebase Documentation Index

**The World's First AI-Powered Binary-to-Source-to-Binary Reverse Engineering Platform**

---

## Overview

REVENG is a revolutionary AI-powered security platform that **proves vulnerabilities through working code reconstruction**. Unlike traditional reverse engineering tools that only analyze binaries, REVENG decompiles, reconstructs, recompiles, and generates working exploits – providing irrefutable proof of security issues.

This is the **master documentation index** for the entire REVENG codebase, serving as a comprehensive guide to all 107 `claude.md` files throughout the project. Use this index to navigate the codebase efficiently and understand the complete system architecture.

**Version**: 3.0.0
**License**: MIT
**Python**: 3.9+
**Platforms**: Linux, macOS, Windows

---

## Quick Navigation

- [Getting Started](#getting-started)
- [Source Code (src/reveng)](#source-code-srcreveng)
- [Tests](#tests-tests)
- [Documentation](#documentation-docs)
- [Examples](#examples-examples)
- [External Tools](#external-tools-external)
- [Configuration](#configuration)
- [Project Statistics](#project-statistics)
- [Architecture Overview](#architecture-overview)
- [Technology Stack](#technology-stack)
- [How to Use This Documentation](#how-to-use-this-documentation)

---

## Project Statistics

| Metric | Value |
|--------|-------|
| **Total `claude.md` Files** | 107 |
| **Total Directories** | 524+ |
| **Python Files** | 326 |
| **Lines of Code (src/reveng)** | ~99,416 |
| **Test Files** | 45+ |
| **Test Cases** | 500+ |
| **Test Coverage** | 91% |
| **ML Models** | 4 (90.7% avg accuracy) |
| **Dependencies** | 218 Python packages |
| **Documentation Pages** | 50+ |
| **Example Scripts** | 10+ |

---

## Documentation Structure

### Source Code (`src/reveng/`)

Comprehensive index of all 69 `claude.md` files in `src/reveng`, organized by category:

#### Core Modules

| Module | Path | Description |
|--------|------|-------------|
| **Root Package** | [src/reveng/claude.md](/home/user/reveng-main/src/reveng/claude.md) | Main analyzer, APIs, CLI, version management |
| **Pipeline** | [src/reveng/pipeline/claude.md](/home/user/reveng-main/src/reveng/pipeline/claude.md) | 13-step analysis pipeline orchestration |
| **Pipeline Steps** | [src/reveng/pipeline/steps/claude.md](/home/user/reveng-main/src/reveng/pipeline/steps/claude.md) | Enhanced analysis step implementations |
| **Core Infrastructure** | [src/reveng/core/claude.md](/home/user/reveng-main/src/reveng/core/claude.md) | Error handling, validation, dependency management |
| **CLI** | [src/reveng/cli/claude.md](/home/user/reveng-main/src/reveng/cli/claude.md) | Command-line interface with 15+ commands |

**Key Features**:
- **13-Step Analysis Pipeline**: AI-powered binary analysis → decompilation → reconstruction → validation → vulnerability discovery → exploit generation
- **Ghidra-First Architecture**: Primary analysis engine with fail-fast behavior
- **Multi-Language Support**: Java, C#, Python, native binaries (PE/ELF/Mach-O)
- **AI Integration**: Gemini, Claude, GPT-4, Ollama support
- **Progress Callbacks**: Real-time analysis progress reporting

#### AI & Machine Learning

| Module | Path | Description |
|--------|------|-------------|
| **AI Integration** | [src/reveng/ai/claude.md](/home/user/reveng-main/src/reveng/ai/claude.md) | AI assistant architecture, recompilation engine, Gemini integration |
| **ML Models** | [src/reveng/ml/claude.md](/home/user/reveng-main/src/reveng/ml/claude.md) | Machine learning integration, vulnerability prediction |
| **Agents** | [src/reveng/agents/claude.md](/home/user/reveng-main/src/reveng/agents/claude.md) | Agent-based analysis framework |
| **AI Agents** | [src/reveng/agents/ai/claude.md](/home/user/reveng-main/src/reveng/agents/ai/claude.md) | Ollama integration, local LLM support |
| **Enhanced AI** | [src/reveng/agents/ai/ai_enhanced/claude.md](/home/user/reveng-main/src/reveng/agents/ai/ai_enhanced/claude.md) | Enhanced AI agents with advanced capabilities |

**AI Capabilities**:
- **Binary Recompilation**: Decompile → AI enhance → recompile (GCC/Clang)
- **Security Analysis**: 166+ vulnerabilities found in test cases
- **Exploit Generation**: Automated PoC exploit creation
- **Self-Improving System**: Gemini feedback loop for continuous improvement
- **Multi-Model Ensemble**: Gemini Pro, Claude, GPT-4, Code Llama

#### Agent SDK

| Module | Path | Description |
|--------|------|-------------|
| **Agent SDK** | [src/reveng/agent_sdk/claude.md](/home/user/reveng-main/src/reveng/agent_sdk/claude.md) | Enterprise-grade agent framework (v1.0.0) |
| **MCP** | [src/reveng/agent_sdk/mcp/claude.md](/home/user/reveng-main/src/reveng/agent_sdk/mcp/claude.md) | Model Context Protocol implementation |
| **MCP Servers** | [src/reveng/agent_sdk/mcp/servers/claude.md](/home/user/reveng-main/src/reveng/agent_sdk/mcp/servers/claude.md) | Built-in MCP servers (database, filesystem, cloud) |
| **Skills** | [src/reveng/agent_sdk/skills/claude.md](/home/user/reveng-main/src/reveng/agent_sdk/skills/claude.md) | Skills system for agent capabilities |
| **Built-in Skills** | [src/reveng/agent_sdk/skills/builtin/claude.md](/home/user/reveng-main/src/reveng/agent_sdk/skills/builtin/claude.md) | Pre-built security and analysis skills |
| **Tools** | [src/reveng/agent_sdk/tools/claude.md](/home/user/reveng-main/src/reveng/agent_sdk/tools/claude.md) | Tool framework with @tool decorator |
| **REVENG Tools** | [src/reveng/agent_sdk/tools/reveng/claude.md](/home/user/reveng-main/src/reveng/agent_sdk/tools/reveng/claude.md) | REVENG-specific tools for agents |

**Agent SDK Features**:
- **ClaudeSDKClient**: Async streaming, tool use, cost tracking
- **Tool Framework**: Simple @tool decorator and advanced BaseTool class
- **Permission System**: Allowlist/denylist, pre/post hooks, rate limiting
- **Cost Tracking**: Session-based tracking, per-model calculation, analytics
- **Enterprise Ready**: Security controls, audit logging, session management

#### Analysis Tools

| Module | Path | Description |
|--------|------|-------------|
| **Analyzers** | [src/reveng/analyzers/claude.md](/home/user/reveng-main/src/reveng/analyzers/claude.md) | Business logic extraction and analysis |
| **Deobfuscation** | [src/reveng/deobfuscation/claude.md](/home/user/reveng-main/src/reveng/deobfuscation/claude.md) | Code deobfuscation utilities |
| **JavaScript** | [src/reveng/javascript/claude.md](/home/user/reveng-main/src/reveng/javascript/claude.md) | JS deobfuscation (v6.0 - 10-stage pipeline) |
| **Symbolic Execution** | [src/reveng/symbolic/claude.md](/home/user/reveng-main/src/reveng/symbolic/claude.md) | angr integration for symbolic execution |
| **Diffing** | [src/reveng/diffing/claude.md](/home/user/reveng-main/src/reveng/diffing/claude.md) | Binary diffing and patch analysis |
| **Lifting** | [src/reveng/lifting/claude.md](/home/user/reveng-main/src/reveng/lifting/claude.md) | Code lifting to higher-level representations |

**JavaScript Deobfuscation (v6.0)**:
- **10-Stage Pipeline**: Detection → Unpacking → ML Renaming → LLM Enhancement → Validation
- **Malware Detection**: 10 threat categories, 50+ signatures
- **ML Variable Renaming**: UnuglifyJS integration (60-80% accuracy)
- **LLM Semantic Analysis**: GPT-4/Claude integration
- **Intelligent Caching**: 99%+ time savings on repeated files

#### Security & Exploits

| Module | Path | Description |
|--------|------|-------------|
| **Security** | [src/reveng/security/claude.md](/home/user/reveng-main/src/reveng/security/claude.md) | Vulnerability discovery and analysis |
| **Exploits** | [src/reveng/exploits/claude.md](/home/user/reveng-main/src/reveng/exploits/claude.md) | Exploit generation and validation |
| **Malware** | [src/reveng/malware/claude.md](/home/user/reveng-main/src/reveng/malware/claude.md) | Malware analysis and classification |
| **Evasion** | [src/reveng/evasion/claude.md](/home/user/reveng-main/src/reveng/evasion/claude.md) | Anti-evasion techniques |
| **Instrumentation** | [src/reveng/instrumentation/claude.md](/home/user/reveng-main/src/reveng/instrumentation/claude.md) | Dynamic instrumentation |

**Security Features**:
- **Vulnerability Discovery**: Automated detection of buffer overflows, injection flaws, memory corruption
- **Exploit Generation**: Working proof-of-concept exploits with mitigation guidance
- **Malware Classification**: Family detection, IOC extraction, behavioral analysis
- **Threat Intelligence**: VirusTotal integration, YARA rule generation

#### Platform Modules

| Module | Path | Description |
|--------|------|-------------|
| **PE Analysis** | [src/reveng/pe/claude.md](/home/user/reveng-main/src/reveng/pe/claude.md) | Windows PE file analysis |
| **Hardware** | [src/reveng/hardware/claude.md](/home/user/reveng-main/src/reveng/hardware/claude.md) | Hardware/firmware analysis |
| **JIT** | [src/reveng/jit/claude.md](/home/user/reveng-main/src/reveng/jit/claude.md) | JIT compiler analysis |
| **Compilation** | [src/reveng/compilation/claude.md](/home/user/reveng-main/src/reveng/compilation/claude.md) | Compilation utilities and recompilation |
| **Devirtualization** | [src/reveng/devirtualization/claude.md](/home/user/reveng-main/src/reveng/devirtualization/claude.md) | VM-based obfuscation removal |

#### Integration & Plugins

| Module | Path | Description |
|--------|------|-------------|
| **Integrations** | [src/reveng/integrations/claude.md](/home/user/reveng-main/src/reveng/integrations/claude.md) | External tool integrations |
| **Ghidra Integration** | [src/reveng/integrations/ghidra/claude.md](/home/user/reveng-main/src/reveng/integrations/ghidra/claude.md) | Ghidra server integration |
| **Plugins** | [src/reveng/plugins/claude.md](/home/user/reveng-main/src/reveng/plugins/claude.md) | Plugin system architecture |
| **Analysis Plugins** | [src/reveng/plugins/analysis/claude.md](/home/user/reveng-main/src/reveng/plugins/analysis/claude.md) | Analysis-focused plugins |
| **Security Plugins** | [src/reveng/plugins/security/claude.md](/home/user/reveng-main/src/reveng/plugins/security/claude.md) | Security analysis plugins |
| **AI Plugins** | [src/reveng/plugins/ai/claude.md](/home/user/reveng-main/src/reveng/plugins/ai/claude.md) | AI-powered plugins |
| **Visualization Plugins** | [src/reveng/plugins/visualization/claude.md](/home/user/reveng-main/src/reveng/plugins/visualization/claude.md) | Visualization and reporting plugins |

#### Tools Suite

The `src/reveng/tools/` directory contains 15 specialized tool categories:

| Tool Category | Path | Description |
|---------------|------|-------------|
| **Tools Root** | [src/reveng/tools/claude.md](/home/user/reveng-main/src/reveng/tools/claude.md) | Tool organization and overview |
| **Core Tools** | [src/reveng/tools/core/claude.md](/home/user/reveng-main/src/reveng/tools/core/claude.md) | Essential analysis utilities |
| **Anti-Analysis** | [src/reveng/tools/anti_analysis/claude.md](/home/user/reveng-main/src/reveng/tools/anti_analysis/claude.md) | Anti-debugging, anti-VM detection |
| **Binary Tools** | [src/reveng/tools/binary/claude.md](/home/user/reveng-main/src/reveng/tools/binary/claude.md) | Binary format parsing and analysis |
| **Config Tools** | [src/reveng/tools/config/claude.md](/home/user/reveng-main/src/reveng/tools/config/claude.md) | Configuration management |
| **Decompilers** | [src/reveng/tools/decompilers/claude.md](/home/user/reveng-main/src/reveng/tools/decompilers/claude.md) | Multi-language decompilation |
| **Diffing Tools** | [src/reveng/tools/diffing/claude.md](/home/user/reveng-main/src/reveng/tools/diffing/claude.md) | Binary and patch diffing |
| **Enterprise Tools** | [src/reveng/tools/enterprise/claude.md](/home/user/reveng-main/src/reveng/tools/enterprise/claude.md) | Enterprise-grade features |
| **Language Tools** | [src/reveng/tools/languages/claude.md](/home/user/reveng-main/src/reveng/tools/languages/claude.md) | Java, C#, Python analyzers |
| **Quality Tools** | [src/reveng/tools/quality/claude.md](/home/user/reveng-main/src/reveng/tools/quality/claude.md) | Code quality analysis |
| **Security Tools** | [src/reveng/tools/security/claude.md](/home/user/reveng-main/src/reveng/tools/security/claude.md) | Security scanning and validation |
| **Threat Intel** | [src/reveng/tools/threat_intel/claude.md](/home/user/reveng-main/src/reveng/tools/threat_intel/claude.md) | Threat intelligence integration |
| **Translation** | [src/reveng/tools/translation/claude.md](/home/user/reveng-main/src/reveng/tools/translation/claude.md) | Code translation (C to Python) |
| **Utilities** | [src/reveng/tools/utils/claude.md](/home/user/reveng-main/src/reveng/tools/utils/claude.md) | Common utilities |
| **Visualization** | [src/reveng/tools/visualization/claude.md](/home/user/reveng-main/src/reveng/tools/visualization/claude.md) | Graphs, reports, dashboards |
| **AI Tools** | [src/reveng/tools/ai/claude.md](/home/user/reveng-main/src/reveng/tools/ai/claude.md) | AI-powered analysis tools |

#### Infrastructure

| Module | Path | Description |
|--------|------|-------------|
| **Server** | [src/reveng/server/claude.md](/home/user/reveng-main/src/reveng/server/claude.md) | API server and web interface |
| **Reporting** | [src/reveng/reporting/claude.md](/home/user/reveng-main/src/reveng/reporting/claude.md) | Report generation and formatting |
| **Visualization** | [src/reveng/reporting/visualization/claude.md](/home/user/reveng-main/src/reveng/reporting/visualization/claude.md) | Advanced visualization |
| **Protocol** | [src/reveng/protocol/claude.md](/home/user/reveng-main/src/reveng/protocol/claude.md) | Protocol definitions and schemas |
| **Performance** | [src/reveng/performance/claude.md](/home/user/reveng-main/src/reveng/performance/claude.md) | Performance optimization |
| **Pipelines** | [src/reveng/pipelines/claude.md](/home/user/reveng-main/src/reveng/pipelines/claude.md) | Custom pipeline definitions |
| **Cloud** | [src/reveng/cloud/claude.md](/home/user/reveng-main/src/reveng/cloud/claude.md) | Cloud integration (AWS, Azure) |
| **Validation** | [src/reveng/validation/claude.md](/home/user/reveng-main/src/reveng/validation/claude.md) | Result validation and verification |
| **Utilities** | [src/reveng/utils/claude.md](/home/user/reveng-main/src/reveng/utils/claude.md) | Common utility functions |
| **Types** | [src/reveng/types/claude.md](/home/user/reveng-main/src/reveng/types/claude.md) | Type definitions and schemas |
| **Installers** | [src/reveng/installers/claude.md](/home/user/reveng-main/src/reveng/installers/claude.md) | Installer analysis |
| **ML Models** | [src/reveng/ml_models/claude.md](/home/user/reveng-main/src/reveng/ml_models/claude.md) | ML model management |
| **Ghidra** | [src/reveng/ghidra/claude.md](/home/user/reveng-main/src/reveng/ghidra/claude.md) | Ghidra utility functions |

---

### Tests (`tests/`)

Comprehensive test suite with 91% coverage:

| Test Category | Path | Description |
|---------------|------|-------------|
| **Tests Root** | [tests/claude.md](/home/user/reveng-main/tests/claude.md) | Test suite overview (500+ tests) |
| **Unit Tests** | [tests/unit/claude.md](/home/user/reveng-main/tests/unit/claude.md) | 23 test files, 95% coverage |
| **Integration Tests** | [tests/integration/claude.md](/home/user/reveng-main/tests/integration/claude.md) | 8+ test files, 88% coverage |
| **E2E Tests** | [tests/e2e/claude.md](/home/user/reveng-main/tests/e2e/claude.md) | 3 workflow tests, 85% coverage |
| **Manual Tests** | [tests/manual/claude.md](/home/user/reveng-main/tests/manual/claude.md) | Manual testing scripts |
| **Security Tests** | [tests/security/claude.md](/home/user/reveng-main/tests/security/claude.md) | Security validation, 93% coverage |
| **Performance Tests** | [tests/performance/claude.md](/home/user/reveng-main/tests/performance/claude.md) | Benchmarks and profiling |

**Test Statistics**:
- **Total Test Files**: 45+
- **Total Test Cases**: 500+
- **Average Runtime**: 4.2 minutes
- **Success Rate**: 98.5%
- **Code Coverage**: 91%
- **Lines of Test Code**: 25,000+

**Running Tests**:
```bash
# All tests
pytest tests/ --cov=src/reveng --cov-report=html

# Specific category
pytest tests/unit/
pytest tests/integration/
pytest tests/e2e/

# With parallel execution
pytest tests/ -n auto
```

---

### Documentation (`docs/`)

50+ documentation files covering all aspects of REVENG:

| Documentation | Path | Description |
|---------------|------|-------------|
| **Docs Root** | [docs/claude.md](/home/user/reveng-main/docs/claude.md) | Documentation index and overview |
| **Getting Started** | [docs/getting-started/claude.md](/home/user/reveng-main/docs/getting-started/claude.md) | Installation, quick start, troubleshooting |
| **User Guide** | [docs/user-guide/claude.md](/home/user/reveng-main/docs/user-guide/claude.md) | End-user documentation and CLI usage |
| **Developer Guide** | [docs/developer-guide/claude.md](/home/user/reveng-main/docs/developer-guide/claude.md) | Development setup and contribution guide |
| **API Reference** | [docs/api/claude.md](/home/user/reveng-main/docs/api/claude.md) | Complete API documentation |
| **Architecture** | [docs/architecture/claude.md](/home/user/reveng-main/docs/architecture/claude.md) | System architecture and design |
| **Guides** | [docs/guides/claude.md](/home/user/reveng-main/docs/guides/claude.md) | 15 comprehensive guides and tutorials |
| **Research** | [docs/research/claude.md](/home/user/reveng-main/docs/research/claude.md) | Research papers and proposals |
| **Planning** | [docs/planning/claude.md](/home/user/reveng-main/docs/planning/claude.md) | Implementation plans and roadmaps |
| **Reports** | [docs/reports/claude.md](/home/user/reveng-main/docs/reports/claude.md) | Security audits and quality reports |
| **Changelogs** | [docs/changelogs/claude.md](/home/user/reveng-main/docs/changelogs/claude.md) | Version history (v4.0, v5.0, v6.0) |
| **AI Assistant** | [docs/ai-assistant-guide/claude.md](/home/user/reveng-main/docs/ai-assistant-guide/claude.md) | AI integration guides and tool selection |
| **Legal** | [docs/legal/claude.md](/home/user/reveng-main/docs/legal/claude.md) | Privacy policy and legal documentation |
| **Development** | [docs/development/claude.md](/home/user/reveng-main/docs/development/claude.md) | Project structure and workflows |

**Documentation Highlights**:
- **Coverage**: ~95% of features documented
- **Accuracy**: ~98% working examples
- **Freshness**: Current (updated November 2025)
- **MkDocs Site**: https://oimiragieo.github.io/reveng-main/

---

### Examples (`examples/`)

10+ working examples from beginner to advanced:

| Example Category | Path | Description |
|------------------|------|-------------|
| **Examples Root** | [examples/claude.md](/home/user/reveng-main/examples/claude.md) | Examples overview and learning path |
| **Basic** | [examples/basic/claude.md](/home/user/reveng-main/examples/basic/claude.md) | Beginner examples and tutorials |
| **Advanced** | [examples/advanced/claude.md](/home/user/reveng-main/examples/advanced/claude.md) | Advanced demos (recompilation, Gemini feedback, v4.0 features) |
| **Use Cases** | [examples/use-cases/claude.md](/home/user/reveng-main/examples/use-cases/claude.md) | Real-world scenarios (malware analysis, binary patching, legacy recovery) |

**Key Examples**:
- `my_first_analysis.py` (4,151 bytes) - First analysis tutorial
- `agent_sdk_demo.py` (8,531 bytes) - Claude Agent SDK integration
- `javascript_deobfuscation_demo.py` (8,544 bytes) - JS deobfuscation pipeline
- `full_recompilation_demo.py` (9,854 bytes) - Complete binary reconstruction
- `gemini_feedback_demo.py` (3,326 bytes) - Self-improving AI system
- `v4_0_features_demo.py` (16,561 bytes) - v4.0 feature showcase

**Learning Path**:
1. **Beginners**: Start with `my_first_analysis.py` → explore `basic/`
2. **Intermediate**: Study `advanced/` examples → run recompilation demo
3. **Advanced**: Create custom analyzers → integrate with workflows

---

### External Tools (`external/`)

External integrations and dependencies:

| Tool | Path | Description |
|------|------|-------------|
| **External Root** | [external/claude.md](/home/user/reveng-main/external/claude.md) | External tools overview |
| **Ghidra** | [external/ghidra/claude.md](/home/user/reveng-main/external/ghidra/claude.md) | NSA Ghidra framework (Apache 2.0) |
| **Ghidra Server** | [external/ghidra-server/claude.md](/home/user/reveng-main/external/ghidra-server/claude.md) | HTTP server for decompilation (port 5000) |
| **Ghidra MCP** | [external/ghidra-mcp/claude.md](/home/user/reveng-main/external/ghidra-mcp/claude.md) | Model Context Protocol bridge for AI |

**Ghidra Integration**:
- **Multi-Architecture**: 20+ processor architectures
- **Decompiler**: Advanced C-like pseudocode generation
- **HTTP API**: RESTful endpoints for remote analysis
- **MCP Bridge**: AI-powered automation
- **Performance**: 2-5 seconds for small binaries, 1-5 minutes for large

**Starting Ghidra Server**:
```bash
cd external/ghidra-server
python ghidra_http_server.py
# Server runs on http://localhost:5000
```

---

### Other Directories

| Directory | Path | Description |
|-----------|------|-------------|
| **Models** | [models/claude.md](/home/user/reveng-main/models/claude.md) | 4 ML models (90.7% avg accuracy, ~800MB) |
| **Reports** | [reports/claude.md](/home/user/reveng-main/reports/claude.md) | Analysis report outputs |
| **Test Samples** | [test_samples/claude.md](/home/user/reveng-main/test_samples/claude.md) | Sample binaries for testing |
| **Assets** | [assets/claude.md](/home/user/reveng-main/assets/claude.md) | Static assets (logos, images) |

**ML Models**:
- `buffer_overflow_model.pkl` - 94.2% accuracy
- `injection_model.pkl` - 91.8% accuracy
- `memory_corruption_model.pkl` - 89.5% accuracy
- `general_model.pkl` - 87.3% accuracy

---

### Configuration

| Config | Path | Description |
|--------|------|-------------|
| **.github** | [.github/claude.md](/home/user/reveng-main/.github/claude.md) | GitHub configuration and CI/CD |
| **Workflows** | [.github/workflows/claude.md](/home/user/reveng-main/.github/workflows/claude.md) | GitHub Actions workflows |
| **Issue Templates** | [.github/ISSUE_TEMPLATE/claude.md](/home/user/reveng-main/.github/ISSUE_TEMPLATE/claude.md) | Issue templates |
| **.claude** | [.claude/claude.md](/home/user/reveng-main/.claude/claude.md) | Claude Code configuration |
| **.reveng** | [.reveng/claude.md](/home/user/reveng-main/.reveng/claude.md) | REVENG-specific config |

**Environment Variables**:
```bash
export GEMINI_API_KEY="your-api-key"       # Required for AI features
export VT_API_KEY="your-vt-key"            # Optional: VirusTotal
export OLLAMA_HOST="http://localhost:11434" # Optional: Local LLM
export ANTHROPIC_API_KEY="your-key"        # Required for Agent SDK
```

---

## How to Use This Documentation

### For Developers

1. **Start Here**: Read [README.md](/home/user/reveng-main/README.md) for project overview
2. **Setup**: Follow [docs/getting-started/claude.md](/home/user/reveng-main/docs/getting-started/claude.md)
3. **Understand Architecture**: Study [docs/architecture/claude.md](/home/user/reveng-main/docs/architecture/claude.md)
4. **Explore Code**: Navigate [src/reveng/claude.md](/home/user/reveng-main/src/reveng/claude.md) for source code organization
5. **API Reference**: Refer to [docs/api/claude.md](/home/user/reveng-main/docs/api/claude.md)
6. **Run Examples**: Execute scripts in [examples/](/home/user/reveng-main/examples/)
7. **Testing**: Follow [tests/claude.md](/home/user/reveng-main/tests/claude.md) for testing guidelines

**Quick Start for Development**:
```bash
# Clone and setup
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
pip install -r requirements.txt

# Set API key
export GEMINI_API_KEY="your-api-key"

# Start Ghidra server (Terminal 1)
cd external/ghidra-server
python ghidra_http_server.py

# Run example (Terminal 2)
python examples/my_first_analysis.py

# Run tests
pytest tests/ --cov=src/reveng
```

### For AI Assistants

AI assistants (Claude, GPT-4, etc.) can use this documentation to:

1. **Understand Project Structure**: Use this index to navigate the 107 `claude.md` files
2. **Find Relevant Code**: Each `claude.md` file documents its directory's purpose and contents
3. **Use Agent SDK**: Integrate via [src/reveng/agent_sdk/claude.md](/home/user/reveng-main/src/reveng/agent_sdk/claude.md)
4. **Execute Tasks**: Use tools in [src/reveng/agent_sdk/tools/reveng/](/home/user/reveng-main/src/reveng/agent_sdk/tools/reveng/)
5. **Follow Best Practices**: Refer to examples and documentation for proper usage

**Agent SDK Quick Start**:
```python
from reveng.agent_sdk import ClaudeSDKClient
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool

async with ClaudeSDKClient(api_key="your-key") as client:
    tool = BinaryAnalysisTool()
    client.register_tool(tool)

    async for message in client.query("Analyze malware.exe"):
        print(message.get_text())
```

**Key Agent Features**:
- **Tool Use**: 15+ REVENG tools available
- **Permission Control**: Granular security controls
- **Cost Tracking**: Automatic usage monitoring
- **Streaming**: Real-time response delivery
- **Session Management**: Multi-turn conversations

### For Contributors

1. **Read Contributing Guide**: [CONTRIBUTING.md](/home/user/reveng-main/CONTRIBUTING.md)
2. **Development Setup**: [docs/developer-guide/claude.md](/home/user/reveng-main/docs/developer-guide/claude.md)
3. **Code Standards**: Follow existing patterns in `src/reveng/`
4. **Testing**: Maintain 90%+ coverage (see [tests/claude.md](/home/user/reveng-main/tests/claude.md))
5. **Documentation**: Update relevant `claude.md` files
6. **Examples**: Add examples to [examples/](/home/user/reveng-main/examples/)

**Contribution Workflow**:
```bash
# Create feature branch
git checkout -b feature/my-feature

# Make changes
# ... edit code ...

# Run tests
pytest tests/ --cov=src/reveng

# Update documentation
# ... edit relevant claude.md files ...

# Commit and push
git add .
git commit -m "Add: my feature description"
git push origin feature/my-feature

# Create pull request
```

---

## Architecture Overview

### High-Level System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     REVENG v3.0 Platform                     │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐      ┌──────────────┐    ┌──────────────┐ │
│  │   Ghidra    │─────▶│    Gemini    │───▶│ Recompilation│ │
│  │   Engine    │      │    Engine    │    │    Engine    │ │
│  └─────────────┘      └──────────────┘    └──────────────┘ │
│        │                     │                    │         │
│        ▼                     ▼                    ▼         │
│  ┌─────────────────────────────────────────────────────┐   │
│  │         13-Step Binary Analysis Pipeline           │   │
│  │                                                      │   │
│  │  1. AI Analysis    → 2. Disassembly  → 3. AI Inspect │ │
│  │  4. Specifications → 5. Human Code   → 6. Deobfuscate│ │
│  │  7. Implementation → 8. Validation   →               │   │
│  │  9. Corp Exposure  → 10. Vuln Discovery →            │   │
│  │  11. Threat Intel  → 12. Reconstruction →            │   │
│  │  13. Demo Generation                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │       Entry Points: CLI, API, AI API, Agent SDK     │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Component Layers

```
┌──────────────────────────────────────────────────────┐
│ User Interfaces                                       │
│ • CLI (reveng command)                               │
│ • Web UI (Flask server)                              │
│ • API (REVENGAPI)                                    │
│ • AI API (REVENG_AI_API)                             │
│ • Agent SDK (ClaudeSDKClient)                        │
└─────────────────┬────────────────────────────────────┘
                  │
┌─────────────────┴────────────────────────────────────┐
│ Core Analysis Engine                                  │
│ • REVENGAnalyzer (13-step pipeline)                  │
│ • Binary Analysis                                     │
│ • Multi-language Support                             │
│ • AI Integration                                      │
└─────────────────┬────────────────────────────────────┘
                  │
┌─────────────────┴────────────────────────────────────┐
│ Tool Modules                                          │
│ • Decompilers (Ghidra, ILSpy, CFR, etc.)            │
│ • AI Tools (Gemini, Ollama)                          │
│ • Security Tools (YARA, VirusTotal)                  │
│ • Analysis Tools (angr, diffing, lifting)            │
└─────────────────┬────────────────────────────────────┘
                  │
┌─────────────────┴────────────────────────────────────┐
│ External Integrations                                 │
│ • Ghidra (NSA framework)                             │
│ • Google Gemini (AI enhancement)                     │
│ • Ollama (local LLM)                                 │
│ • VirusTotal (threat intel)                          │
└──────────────────────────────────────────────────────┘
```

### Data Flow

```
Binary Input
    │
    ▼
┌───────────────┐
│ Preprocessing │
│ • Format detection
│ • Hash calculation
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Disassembly   │
│ • Ghidra decompilation
│ • Multi-language support
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ AI Enhancement│
│ • Gemini analysis
│ • Code improvement
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Security      │
│ • Vuln discovery
│ • Exploit gen
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Reconstruction│
│ • Recompilation
│ • Validation
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ Report Output │
│ • JSON/HTML
│ • Exploits
│ • Source code
└───────────────┘
```

---

## Technology Stack

### Languages & Frameworks

| Technology | Purpose | Version |
|------------|---------|---------|
| **Python** | Primary language | 3.9+ |
| **Java** | Ghidra integration | 17+ |
| **JavaScript** | Deobfuscation target | ES2015+ |
| **C/C++** | Binary analysis, recompilation | GCC/Clang |
| **Markdown** | Documentation | CommonMark |

### Core Dependencies

| Library | Purpose | Category |
|---------|---------|----------|
| **Anthropic** | Claude API | AI |
| **google-generativeai** | Gemini API | AI |
| **angr** | Symbolic execution | Analysis |
| **pefile** | PE file parsing | Binary |
| **pyelftools** | ELF file parsing | Binary |
| **yara-python** | Pattern matching | Security |
| **requests** | HTTP client | Networking |
| **Flask** | Web server | Server |
| **pytest** | Testing framework | Testing |
| **scikit-learn** | ML models | Machine Learning |

### External Tools

| Tool | Purpose | License |
|------|---------|---------|
| **Ghidra** | Decompilation | Apache 2.0 |
| **ILSpy** | C# decompilation | MIT |
| **CFR** | Java decompilation | MIT |
| **uncompyle6** | Python decompilation | GPL |
| **UnuglifyJS** | JS variable renaming | MIT |

### AI Models

| Model | Provider | Purpose |
|-------|----------|---------|
| **Gemini Pro** | Google | Code enhancement, analysis |
| **Claude Sonnet 4.5** | Anthropic | Agent SDK, security analysis |
| **GPT-4** | OpenAI | Alternative AI analysis |
| **Code Llama** | Meta | Local LLM inference (Ollama) |

### Infrastructure

| Component | Technology |
|-----------|------------|
| **Version Control** | Git, GitHub |
| **CI/CD** | GitHub Actions |
| **Package Management** | pip, requirements.txt |
| **Documentation** | MkDocs, Markdown |
| **Testing** | pytest, pytest-cov |
| **Code Quality** | pylint, black, mypy |

---

## Getting Started

### Installation

```bash
# 1. Clone repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Install AI dependencies
pip install google-generativeai anthropic

# 4. Set API keys
export GEMINI_API_KEY="your-gemini-key"
export ANTHROPIC_API_KEY="your-anthropic-key"

# 5. (Optional) Install JavaScript deobfuscation
./install-js-deob.sh
```

### Quick Start (5 Minutes)

```bash
# Terminal 1: Start Ghidra server
cd external/ghidra-server
python ghidra_http_server.py

# Terminal 2: Run first analysis
cd /home/user/reveng-main
python examples/my_first_analysis.py

# Expected output:
# ✓ Binary loaded
# ✓ Analysis complete
# ✓ Report generated
# See: analysis_<binary_name>/
```

### Basic Usage

```bash
# Analyze a binary
reveng analyze malware.exe

# JavaScript deobfuscation
./reveng-js deobfuscate obfuscated.js -o clean.js

# Quick triage (<30 seconds)
reveng triage suspicious.exe

# Natural language query
reveng ask "What does this binary do?" malware.exe

# Binary comparison
reveng diff old.exe new.exe

# Generate YARA rules
reveng generate-yara malware.exe -o rules.yar
```

### Python API

```python
from reveng.api import REVENGAPI

# Create API instance
api = REVENGAPI()

# Analyze binary
result = api.analyze_binary("malware.exe", enhanced=True)

# Check results
print(f"Type: {result['classification']['language']}")
print(f"Functions: {len(result['analysis']['functions'])}")
print(f"Vulnerabilities: {len(result['vulnerabilities'])}")

# Detect malware
threat = api.detect_malware("suspicious.exe")
if threat['threat_assessment']['is_malware']:
    print(f"Malware: {threat['threat_assessment']['malware_family']}")
```

### AI-Optimized API

```python
from reveng.ai_api import REVENG_AI_API, AnalysisMode

# Create AI API
api = REVENG_AI_API(use_ollama=True)

# Quick triage (<30 seconds)
triage = api.triage_binary("unknown.exe")
print(f"Threat: {triage.threat_level} ({triage.threat_score}/100)")

# Natural language queries
response = api.ask("What does this binary do?", "malware.exe")
print(f"Answer: {response.answer}")

# Full analysis with rebuild
result = api.analyze_binary("app.exe", mode=AnalysisMode.REBUILD)
```

### Agent SDK

```python
from reveng.agent_sdk import ClaudeSDKClient
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool

async def analyze():
    async with ClaudeSDKClient(api_key="your-key") as client:
        tool = BinaryAnalysisTool()
        client.register_tool(tool)

        async for message in client.query(
            "Analyze malware.exe and find vulnerabilities"
        ):
            print(message.get_text())

# Run
import asyncio
asyncio.run(analyze())
```

---

## Contributing

We welcome contributions! Here's how to get started:

### Contribution Areas

1. **AI Models** - Add Claude Opus, GPT-4o, Code Llama support
2. **Compilers** - Support MSVC, Rust, Go compilation
3. **Exploit Templates** - Expand exploit generation capabilities
4. **Languages** - Improve C++, Java, .NET support
5. **Documentation** - Add tutorials, videos, research papers
6. **Testing** - Increase test coverage to 95%+
7. **Performance** - Optimize analysis speed and memory usage

### Contribution Process

1. **Fork & Clone**: Fork the repository and clone locally
2. **Create Branch**: `git checkout -b feature/my-feature`
3. **Make Changes**: Follow code standards and patterns
4. **Test**: Ensure 90%+ test coverage
5. **Document**: Update relevant `claude.md` files
6. **Submit PR**: Create pull request with clear description

### Code Standards

- **Style**: Follow PEP 8 for Python code
- **Type Hints**: Use type hints for all functions
- **Docstrings**: Document all classes and functions
- **Testing**: Write tests for all new features
- **Coverage**: Maintain 90%+ test coverage
- **Documentation**: Update `claude.md` files

See [CONTRIBUTING.md](/home/user/reveng-main/CONTRIBUTING.md) for detailed guidelines.

---

## License

REVENG is released under the **MIT License** - see [LICENSE](/home/user/reveng-main/LICENSE) for details.

**You can**:
- ✅ Use commercially
- ✅ Modify and distribute
- ✅ Sublicense
- ✅ Private use

**Responsible Use Policy**:
- ✅ Defensive security research
- ✅ Authorized penetration testing
- ✅ Educational purposes
- ✅ Bug bounty programs
- ❌ Malware development
- ❌ Unauthorized access
- ❌ Weaponization

See [SECURITY.md](/home/user/reveng-main/SECURITY.md) for full policy.

---

## Support & Resources

### Documentation
- **Main README**: [README.md](/home/user/reveng-main/README.md)
- **Quick Start**: [QUICK_START.md](/home/user/reveng-main/QUICK_START.md)
- **Installation**: [INSTALLATION.md](/home/user/reveng-main/INSTALLATION.md)
- **Full Documentation**: [docs/](/home/user/reveng-main/docs/)
- **MkDocs Site**: https://oimiragieo.github.io/reveng-main/

### Community
- **GitHub Issues**: [Report bugs](https://github.com/oimiragieo/reveng-main/issues)
- **Discussions**: [Ask questions](https://github.com/oimiragieo/reveng-main/discussions)
- **Contributing**: [CONTRIBUTING.md](/home/user/reveng-main/CONTRIBUTING.md)

### API Keys
- **Gemini API**: https://makersuite.google.com/app/apikey
- **Anthropic API**: https://console.anthropic.com/
- **VirusTotal**: https://www.virustotal.com/gui/join-us

---

## Roadmap

### Current: v3.0 (You Are Here)
- ✅ AI-powered binary reconstruction
- ✅ 13-step analysis pipeline
- ✅ Multi-model AI ensemble
- ✅ Automated exploit generation
- ✅ JavaScript deobfuscation (v6.0)
- ✅ Agent SDK (v1.0)

### Upcoming: v4.0 (Research Complete)

**Phase 1: Foundation (5-10x Performance)**
- [ ] LLM4Decompile integration (20-40% better accuracy)
- [ ] Incremental compilation (5-10x faster rebuilds)
- [ ] GPU acceleration (10-100x batch speedup)

**Phase 2: Advanced Features**
- [ ] Symbolic execution engine (angr + Z3)
- [ ] ML type reconstruction (90%+ accuracy)
- [ ] Smart compiler (AI-powered error recovery)

**Phase 3: Enterprise (Industry-Leading)**
- [ ] LLVM binary lifting (BinRec/McSema)
- [ ] Semantic binary diffing
- [ ] LLVM optimization pipeline (95%+ accuracy)
- [ ] Distributed compilation (10x speedup)

See [RESEARCH_PROPOSAL_2025.md](/home/user/reveng-main/RESEARCH_PROPOSAL_2025.md) for details.

---

## Acknowledgments

This revolutionary platform was made possible by:

- **Google Gemini** - Advanced AI reasoning and code enhancement
- **NSA Ghidra** - Powerful decompilation framework
- **Anthropic Claude** - Code understanding and agent SDK
- **OpenAI** - GPT models for analysis
- **Meta** - Code Llama for local inference
- **Open Source Community** - Countless libraries and tools

---

## Statistics Summary

| Metric | Value |
|--------|-------|
| **Documentation Files (`claude.md`)** | 107 |
| **Source Code Lines** | ~99,416 |
| **Python Files** | 326 |
| **Total Directories** | 524+ |
| **Test Coverage** | 91% |
| **Test Cases** | 500+ |
| **ML Models** | 4 (90.7% avg) |
| **Example Scripts** | 10+ |
| **Dependencies** | 218 packages |
| **Supported Languages** | Java, C#, Python, Native (PE/ELF/Mach-O) |
| **Supported Architectures** | 20+ (via Ghidra) |

---

<div align="center">

**Made with ❤️ by the REVENG Development Team**

[![GitHub stars](https://img.shields.io/github/stars/oimiragieo/reveng-main?style=social)](https://github.com/oimiragieo/reveng-main)

**Star us on GitHub**: https://github.com/oimiragieo/reveng-main

**Join the revolution: Prove vulnerabilities through code, not words.**

</div>

---

*Last Updated: November 2025*
*Documentation Version: 3.0.0*
*Total `claude.md` Files Indexed: 107*
