# External Tools and Dependencies

This directory contains external tools and integrations that enhance REVENG's capabilities.

## Ghidra Integration

### ghidra/
Full Ghidra reverse engineering framework source code.

**Version:** [Check ghidra/README.md]
**Purpose:** Advanced disassembly and decompilation
**Integration:** Used by `src/reveng/tools/core/optimal_binary_analysis.py`

**Setup:**
```bash
cd external/ghidra
./gradlew buildGhidra
```

**Documentation:** See [ghidra/README.md](ghidra/README.md)

### ghidra-mcp/
Ghidra MCP (Model Context Protocol) bridge for AI integration.

**Purpose:** Enables AI assistants to interact with Ghidra programmatically

**Features:**
- Script execution in Ghidra
- Binary analysis automation
- AI-powered reverse engineering workflows

**Setup:**
```bash
cd external/ghidra-mcp
pip install -r requirements.txt
python bridge_mcp_ghidra.py
```

**Documentation:** See [ghidra-mcp/README.md](ghidra-mcp/README.md)

## Integration with REVENG

REVENG integrates with these tools through:
- `src/reveng/ghidra/` - Ghidra scripting engine
- `src/reveng/tools/config/ghidra_mcp_connector.py` - MCP bridge connector
- `scripts/ghidra/` - Ghidra automation scripts

## Adding New External Tools

When adding new external tools:
1. Place in `external/<tool-name>/`
2. Document in this README
3. Update `.gitignore` if needed
4. Create integration code in `src/reveng/integrations/`
