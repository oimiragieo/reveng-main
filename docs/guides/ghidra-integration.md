# Ghidra Integration Guide

REVENG includes comprehensive Ghidra integration for advanced binary analysis.

## Features

- **Automated Disassembly:** Leverage Ghidra's powerful disassembler
- **MCP Bridge:** AI assistants can control Ghidra programmatically
- **Script Automation:** Run custom Ghidra scripts from REVENG
- **Decompilation:** Access Ghidra's decompiler for C-like output

## Setup

### 1. Install Ghidra
```bash
cd external/ghidra
./gradlew buildGhidra
```

### 2. Configure REVENG
Edit `~/.reveng/config.yaml`:
```yaml
ghidra:
  path: /path/to/external/ghidra
  headless: true
  project_dir: ~/.reveng/ghidra_projects
```

### 3. Install MCP Bridge (Optional)
For AI integration:
```bash
cd external/ghidra-mcp
pip install -r requirements.txt
```

## Usage

### CLI Analysis with Ghidra
```bash
reveng analyze --decompiler ghidra binary.exe
```

### Python API
```python
from reveng.tools.core.optimal_binary_analysis import OptimalBinaryAnalyzer

analyzer = OptimalBinaryAnalyzer()
result = analyzer.analyze_with_ghidra("binary.exe")
```

### MCP Bridge for AI
```python
from reveng.tools.config.ghidra_mcp_connector import GhidraMCPConnector

connector = GhidraMCPConnector()
result = connector.execute_script("analyze_functions.py")
```

## Troubleshooting

See [Troubleshooting Guide](../getting-started/troubleshooting.md#ghidra-integration)
