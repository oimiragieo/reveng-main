# REVENG Project Structure

## Overview
REVENG follows a modular, package-based structure with clear separation of concerns.

## Root Directory Layout

```
reveng-main/
├── src/reveng/              # Main package source code
│   ├── __init__.py
│   ├── analyzer.py          # Main analysis orchestrator
│   ├── cli.py               # CLI entry point
│   ├── api.py                # REST API
│   ├── ai_api.py             # AI service API
│   ├── version.py
│   │
│   ├── tools/               # Analysis tools (categorized)
│   │   ├── core/            # Core analysis tools
│   │   ├── languages/       # Language-specific analyzers
│   │   ├── ai/              # AI-powered tools
│   │   ├── security/        # Security analysis
│   │   ├── quality/         # Code quality tools
│   │   ├── binary/          # Binary manipulation
│   │   ├── visualization/   # Reporting & visualization
│   │   ├── enterprise/      # Enterprise features
│   │   ├── config/          # Configuration management
│   │   ├── utils/           # Utility functions
│   │   ├── threat_intel/    # Threat intelligence
│   │   ├── diffing/         # Binary diffing
│   │   ├── anti_analysis/   # Anti-analysis detection
│   │   ├── translation/     # Code translation
│   │   └── decompilers/     # Decompiler integrations
│   │
│   ├── web/                 # Web interface backend
│   │   ├── api/            # API routes
│   │   ├── services/       # Business logic
│   │   ├── middleware/     # Express middleware
│   │   ├── models/         # Data models
│   │   ├── static/         # Static assets
│   │   └── templates/      # HTML templates
│   │
│   ├── ghidra/             # Ghidra integration
│   │   └── scripting_engine.py
│   │
│   ├── analyzers/          # Specialized analyzers
│   ├── core/               # Core utilities
│   ├── installers/         # Tool installers
│   ├── malware/            # Malware analysis
│   ├── ml/                 # Machine learning
│   ├── pe/                 # PE file analysis
│   ├── pipeline/           # Analysis pipeline
│   ├── pipelines/          # Pipeline definitions
│   └── plugins/            # Plugin system
│
├── external/               # External tools and dependencies
│   ├── ghidra/            # Ghidra source code
│   ├── ghidra-mcp/        # Ghidra MCP bridge
│   └── README.md          # External tools documentation
│
├── web_interface/          # Web UI (React frontend)
│   ├── client/            # React application
│   ├── scripts/           # Deployment scripts
│   └── kubernetes/        # K8s configs
│
├── docs/                   # Documentation
│   ├── getting-started/
│   ├── user-guide/
│   ├── developer-guide/
│   ├── api/
│   ├── guides/
│   │   └── ghidra-integration.md  # NEW: Ghidra guide
│   ├── reports/           # Project reports
│   └── development/       # Development docs
│
├── tests/                  # Test suite
├── examples/               # Example usage
├── scripts/                # Utility scripts
│   └── ghidra/            # Ghidra automation scripts
├── models/                 # ML models
└── test_samples/           # Test binaries
```

## External Tools

### Ghidra Integration
REVENG includes full Ghidra integration:
- **Location:** `external/ghidra/`
- **Purpose:** Advanced disassembly and decompilation
- **Integration:** `src/reveng/ghidra/scripting_engine.py`
- **Scripts:** `scripts/ghidra/`

### Ghidra MCP Bridge
AI-powered Ghidra automation:
- **Location:** `external/ghidra-mcp/`
- **Purpose:** AI assistant integration with Ghidra
- **Connector:** `src/reveng/tools/config/ghidra_mcp_connector.py`

## Import Paths

### Current (Correct)
```python
from reveng.tools.core.ai_recompiler_converter import AIRecompilerConverter
from reveng.tools.languages.java_bytecode_analyzer import JavaBytecodeAnalyzer
from reveng.tools.security.vulnerability_discovery_engine import VulnerabilityDiscoveryEngine
from reveng.web.services.analysisService import AnalysisService
from reveng.ghidra.scripting_engine import GhidraScriptingEngine
from reveng.tools.config.ghidra_mcp_connector import GhidraMCPConnector
```

### Old (Deprecated)
```python
from tools.core.ai_recompiler_converter import AIRecompilerConverter  # ❌
from web_interface.server.services.analysisService import AnalysisService  # ❌
```

## CLI Commands

### Current
```bash
reveng analyze <binary>              # Analyze binary
reveng analyze --decompiler ghidra   # Use Ghidra decompiler
reveng serve --port 3000             # Start web interface
reveng --help                        # Show help
```

### Deprecated
```bash
python reveng_analyzer.py <binary>  # ❌ Use 'reveng analyze' instead
```

## Key Files

- `src/reveng/analyzer.py` - Main analysis orchestrator
- `src/reveng/cli.py` - CLI interface
- `src/reveng/tools/` - All analysis tools (categorized)
- `src/reveng/web/` - Web backend
- `src/reveng/ghidra/` - Ghidra integration
- `external/ghidra/` - Ghidra source code
- `external/ghidra-mcp/` - MCP bridge

## Configuration

- `pyproject.toml` - Package metadata and tool configs
- `requirements.txt` - Runtime dependencies
- `requirements-dev.txt` - Development dependencies
- `requirements-optional.txt` - Optional features
- `.prettierrc` - JavaScript/TypeScript formatting
- `.gitignore` - Git ignore patterns
