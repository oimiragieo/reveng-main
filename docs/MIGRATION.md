# REVENG Migration Guide

This guide helps you migrate from older versions of REVENG to the new v2.1+ structure.

## 🚨 Breaking Changes

### Command Line Interface

**OLD (Deprecated)**:
```bash
python reveng_analyzer.py <binary_path>
python reveng_analyzer.py --help
```

**NEW (Current)**:
```bash
reveng analyze <binary_path>
reveng --help
```

### Python Imports

**OLD**:
```python
from tools.core.ai_recompiler_converter import AIRcompilerConverter
from tools.languages.java_bytecode_analyzer import JavaBytecodeAnalyzer
from tools.security.vulnerability_discovery_engine import VulnerabilityDiscoveryEngine
```

**NEW**:
```python
from reveng.tools.core.ai_recompiler_converter import AIRcompilerConverter
from reveng.tools.languages.java_bytecode_analyzer import JavaBytecodeAnalyzer
from reveng.tools.security.vulnerability_discovery_engine import VulnerabilityDiscoveryEngine
from reveng.ghidra.scripting_engine import GhidraScriptingEngine
from reveng.tools.config.ghidra_mcp_connector import GhidraMCPConnector
```

### Web Interface

**OLD**:
```python
from web_interface.server.server import start_server
from web_interface.server.services.analysisService import AnalysisService
```

**NEW**:
```python
from reveng.web.server import start_server
from reveng.web.services.analysisService import AnalysisService
```

### Ghidra Integration

**NEW** (Ghidra integration added):
```python
from reveng.ghidra.scripting_engine import GhidraScriptingEngine
from reveng.tools.config.ghidra_mcp_connector import GhidraMCPConnector
```

**CLI with Ghidra**:
```bash
reveng analyze --decompiler ghidra binary.exe
```

## 📦 Package Installation

### Old Installation
```bash
pip install reveng-toolkit
```

### New Installation
```bash
pip install reveng
```

## 🔧 Configuration Changes

### Tool Paths
- **OLD**: Tools scattered across `tools/` and `src/tools/`
- **NEW**: All tools consolidated in `src/reveng/tools/` with categories

### Web Interface
- **OLD**: `web_interface/server/` directory
- **NEW**: `src/reveng/web/` with organized subdirectories

### Documentation
- **OLD**: Multiple documentation directories (`docsapi/`, `docsarchitecture/`, `docsguides/`)
- **NEW**: Single `docs/` hierarchy with clear organization

## 🗂️ Directory Structure Changes

### Old Structure
```
reveng-main/
├── tools/                    # Scattered tools
├── src/tools/               # More scattered tools
├── web_interface/server/    # Web backend
├── docsapi/                 # Empty directory
├── docsarchitecture/        # Empty directory
├── docsguides/             # Empty directory
├── testsfixtures/          # Empty directory
├── testsintegration/       # Empty directory
├── testsunit/              # Empty directory
├── reveng_analyzer.py      # Legacy entry point
└── setup.py                # Redundant with pyproject.toml
```

### New Structure
```
reveng-main/
├── src/reveng/
│   ├── tools/              # Consolidated tools
│   │   ├── core/           # Core analysis tools
│   │   ├── languages/        # Language analyzers
│   │   ├── ai/             # AI/ML tools
│   │   ├── security/       # Security tools
│   │   ├── quality/        # Code quality tools
│   │   ├── binary/         # Binary processing
│   │   ├── visualization/  # Visualization tools
│   │   ├── enterprise/     # Enterprise features
│   │   ├── config/         # Configuration
│   │   ├── utils/          # Utilities
│   │   ├── threat_intel/   # Threat intelligence
│   │   ├── diffing/        # Binary comparison
│   │   ├── anti_analysis/  # Anti-analysis tools
│   │   ├── translation/    # Code translation
│   │   └── decompilers/     # Decompiler integration
│   └── web/                # Web interface backend
│       ├── api/            # REST API routes
│       ├── services/       # Business logic
│       ├── middleware/     # Middleware components
│       └── static/         # Static assets
├── docs/                   # Consolidated documentation
│   ├── getting-started/    # Installation and setup
│   ├── user-guide/         # User documentation
│   ├── developer-guide/    # Developer documentation
│   ├── api/               # API reference
│   ├── deployment/        # Deployment guides
│   └── guides/            # Advanced guides
├── tests/                 # Unified test suite
└── web_interface/client/  # Frontend (unchanged)
```

## 🔄 Migration Steps

### 1. Update Installation
```bash
# Uninstall old version
pip uninstall reveng-toolkit

# Install new version
pip install reveng
```

### 2. Update Import Statements
Search and replace in your code:
- `from tools.` → `from reveng.tools.`
- `from web_interface.server.` → `from reveng.web.`

### 3. Update CLI Usage
Replace all instances of:
- `python reveng_analyzer.py` → `reveng analyze`
- `python reveng_analyzer.py --help` → `reveng --help`

### 4. Update Configuration Files
- Update any configuration files that reference old paths
- Update Docker configurations if using custom builds
- Update CI/CD pipelines with new command structure

## ⚠️ Deprecation Timeline

### v2.1.0 (Current)
- `reveng_analyzer.py` shows deprecation warnings
- Old import paths still work but show warnings
- `setup.py` removed (use `pyproject.toml`)

### v2.2.0 (Planned)
- Old import paths will raise `ImportError`
- `reveng_analyzer.py` will be removed
- Complete migration required

### v3.0.0 (Future)
- All legacy support removed
- New structure only

## 🆘 Troubleshooting

### Import Errors
If you get import errors after migration:
1. Check that you're using the new import paths
2. Verify the package is installed: `pip show reveng`
3. Check Python path includes the package

### CLI Not Found
If `reveng` command is not found:
1. Reinstall the package: `pip install --force-reinstall reveng`
2. Check your PATH includes Python scripts directory
3. Try: `python -m reveng.cli --help`

### Web Interface Issues
If web interface doesn't work:
1. Check that server files are in `src/reveng/web/`
2. Update any hardcoded paths in configuration
3. Restart the web server

## 📞 Support

If you encounter issues during migration:
1. Check this migration guide
2. Review the [Troubleshooting Guide](getting-started/troubleshooting.md)
3. Open an issue on [GitHub](https://github.com/oimiragieo/reveng-main/issues)
4. Check the [Discussions](https://github.com/oimiragieo/reveng-main/discussions)

## ✅ Migration Checklist

- [ ] Updated installation to `reveng` package
- [ ] Updated all import statements
- [ ] Updated CLI commands
- [ ] Updated configuration files
- [ ] Tested basic functionality
- [ ] Tested web interface
- [ ] Updated documentation references
- [ ] Updated CI/CD pipelines
- [ ] Updated Docker configurations

---

*This migration guide will be updated as the project evolves.*
