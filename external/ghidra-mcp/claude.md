# Ghidra MCP Bridge Directory

## Overview

The `external/ghidra-mcp/` directory contains the Ghidra Model Context Protocol (MCP) bridge that enables AI assistants like Claude to interact with Ghidra programmatically. This enables AI-powered automated reverse engineering workflows.

**Purpose**: Enable AI assistants to control Ghidra and automate reverse engineering tasks.

**Location**: `/home/user/reveng-main/external/ghidra-mcp/`

## Directory Contents

```
ghidra-mcp/
├── claude.md                  # This file
├── README.md                  # MCP bridge documentation (4,873 bytes)
├── LICENSE                    # License file (11,357 bytes)
├── requirements.txt           # Python dependencies (28 bytes)
├── bridge_mcp_ghidra.py       # Main MCP bridge (10,886 bytes)
├── pom.xml                    # Maven build configuration (5,009 bytes)
│
├── .github/                   # GitHub configuration
│   └── workflows/             # CI/CD workflows
│
├── src/                       # Java source code
│   └── main/                  # Main source
│       └── java/              # Java packages
│
├── lib/                       # Library dependencies
└── images/                    # Documentation images
```

## Key Files

### MCP Bridge Implementation

**bridge_mcp_ghidra.py** (10,886 bytes)
- Model Context Protocol implementation
- Python-Java bridge
- Ghidra script execution
- Analysis automation
- Result extraction

**Features:**
- Execute Ghidra scripts from AI
- Automate binary analysis
- Extract decompilation results
- Generate analysis reports
- Stream results to AI

### Build Configuration

**pom.xml** (5,009 bytes)
- Maven build configuration
- Java dependencies
- Build plugins
- Ghidra integration

## Usage

### Setup

```bash
# Navigate to MCP bridge directory
cd /home/user/reveng-main/external/ghidra-mcp

# Install Python dependencies
pip install -r requirements.txt

# Build Java components (if needed)
mvn clean package
```

### Running the Bridge

```bash
# Start MCP bridge
python bridge_mcp_ghidra.py

# Bridge will enable AI assistants to control Ghidra
```

### AI Integration Example

```python
# AI assistant can now execute Ghidra operations
# Example MCP command from AI:

{
  "command": "analyze_binary",
  "binary_path": "/path/to/binary.exe",
  "options": {
    "decompile": true,
    "find_functions": true,
    "extract_strings": true
  }
}

# Bridge executes analysis and returns results
```

## Architecture

### MCP Bridge Architecture

```
AI Assistant (Claude)
       ↓
Model Context Protocol
       ↓
bridge_mcp_ghidra.py (Python)
       ↓
Java Bridge
       ↓
Ghidra API
       ↓
Binary Analysis Results
```

### Components

1. **MCP Interface**: Handles AI communication
2. **Python Bridge**: Coordinates operations
3. **Java Bridge**: Interfaces with Ghidra
4. **Ghidra API**: Performs actual analysis
5. **Result Formatter**: Formats for AI consumption

## Capabilities

### Supported Operations

- **Binary Analysis**: Analyze binary structure
- **Decompilation**: Decompile functions to C
- **Function Discovery**: Find and list functions
- **String Extraction**: Extract embedded strings
- **Cross-References**: Find code references
- **Control Flow**: Analyze program flow
- **Data Flow**: Track data movement
- **Script Execution**: Run custom Ghidra scripts

### AI-Powered Workflows

The MCP bridge enables AI to:
- Automatically analyze binaries
- Generate analysis reports
- Answer questions about code
- Identify patterns and vulnerabilities
- Create custom analysis scripts
- Automate reverse engineering tasks

## Related Directories

- **external/ghidra/** - Ghidra source code
- **external/ghidra-server/** - HTTP server
- **src/reveng/integrations/ghidra/** - REVENG integration

## Notes

### Model Context Protocol (MCP)

MCP is a protocol that allows AI assistants to interact with external tools and services. The Ghidra MCP bridge implements this protocol to enable AI-powered reverse engineering.

**Benefits:**
- AI can use Ghidra directly
- Automated analysis workflows
- Natural language to Ghidra operations
- Intelligent result interpretation

### Security Considerations

**Important:**
- MCP bridge has powerful capabilities
- Only use with trusted AI assistants
- Restrict file system access
- Monitor executed operations
- Consider running in isolated environment

### Performance

**Resource Usage:**
- Memory: Depends on Ghidra operations
- CPU: Can use multiple cores
- Network: For AI communication

**Speed:**
- Script execution: Near-instant
- Binary analysis: Depends on size
- AI communication: Network latency

### Troubleshooting

**Bridge Won't Start:**
```bash
# Check Python dependencies
pip install -r requirements.txt

# Check Java installation
java -version

# Check Ghidra availability
echo $GHIDRA_INSTALL_DIR
```

**Communication Errors:**
```bash
# Check MCP connection
# Verify AI assistant has MCP access
# Check network connectivity
```

## Future Enhancements

- Enhanced error handling
- More Ghidra operations
- Batch processing support
- Result caching
- Metrics and logging
- Multi-model AI support

---

**Technology**: Python + Java + MCP
**AI Integration**: Claude, GPT-4, others
**License**: Check LICENSE file
**Protocol**: Model Context Protocol (MCP)
