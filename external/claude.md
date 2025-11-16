# External Directory

## Overview

The `external/` directory contains external tools, integrations, and dependencies that enhance REVENG's capabilities. This includes the Ghidra reverse engineering framework, Ghidra MCP bridge for AI integration, and the Ghidra HTTP server for decompilation services.

**Purpose**: House external tools and integrations essential for REVENG's advanced features.

**Location**: `/home/user/reveng-main/external/`

## Directory Contents

```
external/
├── claude.md                  # This file
├── README.md                  # External tools overview (1,421 bytes)
│
├── ghidra/                    # Full Ghidra source code (NSA framework)
│   ├── claude.md
│   ├── GPL/                   # GPL-licensed components
│   ├── Ghidra/                # Main Ghidra source
│   ├── LICENSE                # Apache 2.0 License
│   └── licenses/              # Third-party licenses
│
├── ghidra-server/             # Ghidra HTTP server for REVENG
│   ├── claude.md
│   ├── README.md              # Server documentation
│   ├── ghidra_http_server.py  # Main HTTP server (7,608 bytes)
│   ├── ghidra_http_server_working.py
│   ├── ghidra_http_server_broken_backup.py
│   └── scripts/               # Ghidra automation scripts
│
└── ghidra-mcp/                # Ghidra MCP bridge for AI integration
    ├── claude.md
    ├── README.md              # MCP bridge documentation
    ├── bridge_mcp_ghidra.py   # MCP bridge implementation
    ├── requirements.txt       # Python dependencies
    ├── pom.xml                # Maven build configuration
    ├── src/                   # Java source code
    ├── lib/                   # Library dependencies
    └── .github/               # GitHub configuration
```

## Structure

### Components

#### 1. Ghidra Framework (ghidra/)
- Complete NSA Ghidra source code
- World-class disassembler and decompiler
- Supports multiple architectures (x86, ARM, MIPS, etc.)
- Extensible plugin system
- Apache 2.0 licensed

#### 2. Ghidra HTTP Server (ghidra-server/)
- HTTP wrapper for Ghidra decompilation
- RESTful API for binary analysis
- Used by REVENG for decompilation services
- Enables remote decompilation

#### 3. Ghidra MCP Bridge (ghidra-mcp/)
- Model Context Protocol integration
- Enables AI assistants to control Ghidra
- Automated reverse engineering workflows
- Script execution and analysis

## Key Components

### Ghidra Framework

**Purpose**: Advanced disassembly and decompilation
**Version**: Ghidra 10.x (check ghidra/README.md)
**License**: Apache 2.0

**Capabilities:**
- Multi-architecture support (x86, x64, ARM, MIPS, PowerPC, etc.)
- Advanced decompilation to C-like pseudocode
- Control flow analysis
- Data flow analysis
- Function identification
- Cross-references
- Symbol resolution
- Script automation (Python, Java)

**Integration Points:**
- `src/reveng/integrations/ghidra/ghidra_engine.py` - Python interface
- `external/ghidra-server/` - HTTP API wrapper
- `external/ghidra-mcp/` - AI integration

### Ghidra HTTP Server

**Purpose**: HTTP wrapper for Ghidra decompilation services
**Main File**: `ghidra_http_server.py` (7,608 bytes)

**Features:**
- RESTful API for decompilation
- Binary upload and analysis
- Function listing
- Decompilation results
- JSON response format

**API Endpoints:**
```
POST /analyze - Upload and analyze binary
GET /functions - List discovered functions
GET /decompile/<function> - Decompile specific function
GET /health - Server health check
```

**Usage:**
```bash
# Start server
cd external/ghidra-server
python ghidra_http_server.py

# Server runs on http://localhost:5000
```

### Ghidra MCP Bridge

**Purpose**: Enable AI assistants to interact with Ghidra
**Main File**: `bridge_mcp_ghidra.py` (10,886 bytes)

**Features:**
- MCP (Model Context Protocol) implementation
- Script execution in Ghidra
- Binary analysis automation
- AI-powered reverse engineering

**Capabilities:**
- Execute Ghidra scripts from AI
- Automate analysis workflows
- Extract analysis results
- Generate reports

## Usage

### Setting Up Ghidra

```bash
# Navigate to Ghidra directory
cd /home/user/reveng-main/external/ghidra

# Build Ghidra (if needed)
./gradlew buildGhidra

# Ghidra will be built in Ghidra/build/dist/
```

### Running Ghidra Server

```bash
# Navigate to server directory
cd /home/user/reveng-main/external/ghidra-server

# Start HTTP server
python ghidra_http_server.py

# Server listens on http://localhost:5000
# Access API at http://localhost:5000/analyze
```

### Using Ghidra MCP Bridge

```bash
# Navigate to MCP bridge directory
cd /home/user/reveng-main/external/ghidra-mcp

# Install dependencies
pip install -r requirements.txt

# Run MCP bridge
python bridge_mcp_ghidra.py

# AI assistants can now interact with Ghidra via MCP
```

### Integration with REVENG

```python
# REVENG uses Ghidra through the HTTP server
from reveng.integrations.ghidra.ghidra_engine import GhidraEngine

# Initialize Ghidra engine
ghidra = GhidraEngine(server_url="http://localhost:5000")

# Decompile binary
result = await ghidra.decompile_binary("binary.exe")

# Access decompiled code
print(result.decompiled_code)
```

## Related Directories

### REVENG Integration
- **src/reveng/integrations/ghidra/** - Ghidra integration code
- **examples/advanced/full_recompilation_demo.py** - Uses Ghidra for decompilation
- **tests/manual/test_ghidra_server.py** - Server testing

### Documentation
- **docs/architecture/ghidra-integration.md** - Ghidra integration architecture
- **docs/guides/ghidra-integration.md** - Ghidra integration guide

## Notes

### Ghidra Overview

Ghidra is a sophisticated reverse engineering framework developed by the NSA and released as open source in 2019. It provides world-class binary analysis capabilities comparable to commercial tools like IDA Pro.

**Key Features:**
- **Multi-Architecture**: Supports 20+ processor architectures
- **Decompiler**: Advanced decompilation to C-like pseudocode
- **Collaborative**: Multi-user project support
- **Extensible**: Plugin system for custom analyzers
- **Scripting**: Python and Java scripting support
- **Free**: Apache 2.0 licensed, no cost

### REVENG's Ghidra Integration

REVENG integrates Ghidra in three ways:

1. **Direct Integration**: Use Ghidra libraries directly (when available)
2. **HTTP Server**: RESTful API wrapper for remote access
3. **MCP Bridge**: AI-powered automation via Model Context Protocol

### HTTP Server Architecture

```
┌─────────────────┐
│  REVENG Client  │
└────────┬────────┘
         │ HTTP POST /analyze
         ▼
┌─────────────────┐
│ Ghidra HTTP     │
│ Server          │
│ (Python Flask)  │
└────────┬────────┘
         │ Java Bridge
         ▼
┌─────────────────┐
│ Ghidra Engine   │
│ (Java)          │
└────────┬────────┘
         │
         ▼
    Decompiled Code
```

### Performance Considerations

**Memory Usage:**
- Ghidra requires 2-8GB RAM depending on binary size
- Large binaries (>50MB) may need 16GB+ RAM

**Speed:**
- Small binaries (<1MB): 2-5 seconds
- Medium binaries (1-10MB): 10-30 seconds
- Large binaries (>10MB): 1-5 minutes

**Optimization:**
- Use headless mode for batch processing
- Limit analysis scope when possible
- Cache analysis results
- Run server on dedicated hardware

### Troubleshooting

**Server Won't Start:**
```bash
# Check if port 5000 is in use
lsof -i :5000

# Kill existing process
pkill -f ghidra_http_server

# Restart server
python external/ghidra-server/ghidra_http_server.py
```

**Ghidra Out of Memory:**
```bash
# Increase Java heap size
export GHIDRA_MAX_MEM=8G

# Restart server
python ghidra_http_server.py
```

**Connection Refused:**
```bash
# Verify server is running
curl http://localhost:5000/health

# Check firewall rules
sudo ufw status

# Check Ghidra logs
tail -f external/ghidra-server/logs/server.log
```

### Security Considerations

**Server Deployment:**
- HTTP server is for local use only
- Do NOT expose to internet without authentication
- Consider HTTPS for production
- Implement rate limiting
- Add authentication/authorization

**Binary Analysis Safety:**
- Analyze untrusted binaries in isolated environment
- Use VM or container for malware analysis
- Disable network access for malware samples
- Monitor resource usage

### Future Enhancements

- **Authentication**: Add API key authentication
- **HTTPS Support**: SSL/TLS encryption
- **Caching**: Cache decompilation results
- **Async Processing**: Queue-based async analysis
- **Multi-Server**: Load balancing across servers
- **Metrics**: Prometheus metrics endpoint

---

**Maintained by**: REVENG Development Team
**Ghidra Version**: 10.x (NSA Framework)
**License**: Apache 2.0 (Ghidra), MIT (REVENG integration)
**Server Port**: 5000 (HTTP)
