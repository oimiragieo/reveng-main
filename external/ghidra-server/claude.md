# Ghidra HTTP Server Directory

## Overview

The `external/ghidra-server/` directory contains the Ghidra HTTP server implementation that provides a RESTful API wrapper around Ghidra's decompilation capabilities. This server enables REVENG to perform remote decompilation via HTTP requests.

**Purpose**: Provide HTTP/REST API access to Ghidra decompilation services.

**Location**: `/home/user/reveng-main/external/ghidra-server/`

## Directory Contents

```
ghidra-server/
├── claude.md                              # This file
├── README.md                              # Server documentation (381 bytes)
├── ghidra_http_server.py                  # Main HTTP server (7,608 bytes)
├── ghidra_http_server_working.py          # Working version backup (7,239 bytes)
├── ghidra_http_server_broken_backup.py    # Broken version for reference (2,220 bytes)
└── scripts/                               # Ghidra automation scripts
    └── [Ghidra headless scripts]
```

## Key Files

### Main Server Implementation

**ghidra_http_server.py** (7,608 bytes)
- Flask-based HTTP server
- RESTful API for Ghidra operations
- Binary upload and analysis
- Decompilation endpoints
- JSON response format

**Features:**
- HTTP POST for binary upload
- Decompilation results in JSON
- Function listing
- Health check endpoint
- Error handling and logging

## Usage

### Starting the Server

```bash
# Navigate to server directory
cd /home/user/reveng-main/external/ghidra-server

# Start server
python ghidra_http_server.py

# Server will listen on http://localhost:5000
```

### API Endpoints

```bash
# Health check
curl http://localhost:5000/health

# Analyze binary
curl -X POST -F "binary=@/path/to/binary.exe" \
  http://localhost:5000/analyze

# List functions
curl http://localhost:5000/functions

# Decompile function
curl http://localhost:5000/decompile/<function_address>
```

### Integration with REVENG

```python
# REVENG uses the server via GhidraEngine
from reveng.integrations.ghidra.ghidra_engine import GhidraEngine

ghidra = GhidraEngine(server_url="http://localhost:5000")
result = await ghidra.decompile_binary("binary.exe")
```

## Architecture

### Server Architecture

```
HTTP Request → Flask Server → Ghidra Headless → Analysis → JSON Response
```

**Components:**
1. **Flask Web Server**: Handles HTTP requests
2. **Ghidra Headless**: Runs Ghidra in headless mode
3. **Analysis Scripts**: Automate Ghidra analysis
4. **Response Formatter**: Convert results to JSON

### Workflow

1. Client uploads binary via POST
2. Server saves binary to temp location
3. Ghidra headless analyzes binary
4. Results extracted from Ghidra
5. JSON response returned to client
6. Temp files cleaned up

## Configuration

### Server Configuration

```python
# Default configuration
HOST = "localhost"
PORT = 5000
UPLOAD_FOLDER = "/tmp/ghidra_uploads"
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
GHIDRA_TIMEOUT = 300  # 5 minutes
```

### Environment Variables

```bash
# Optional configuration via environment
export GHIDRA_SERVER_PORT=5000
export GHIDRA_SERVER_HOST=localhost
export GHIDRA_MAX_MEM=8G
```

## Related Directories

- **external/ghidra/** - Ghidra source code
- **external/ghidra-mcp/** - MCP bridge
- **src/reveng/integrations/ghidra/** - Python client
- **tests/manual/test_ghidra_server.py** - Server tests

## Notes

### Performance

**Response Times:**
- Small binaries (<1MB): 2-5 seconds
- Medium binaries (1-10MB): 10-30 seconds
- Large binaries (>10MB): 1-5 minutes

**Resource Usage:**
- Memory: 2-8GB depending on binary size
- CPU: Can use multiple cores
- Disk: Temporary storage for uploads

### Security

**Important Security Notes:**
- Server is for local use only
- No authentication by default
- Do NOT expose to internet without security
- Binaries are temporarily stored on disk
- Consider running in isolated environment

### Troubleshooting

**Server Won't Start:**
```bash
# Check if port is in use
lsof -i :5000

# Kill existing process
pkill -f ghidra_http_server
```

**Out of Memory:**
```bash
# Increase Java heap
export GHIDRA_MAX_MEM=16G
```

**Connection Issues:**
```bash
# Test server health
curl http://localhost:5000/health
```

## Future Enhancements

- Authentication/Authorization
- HTTPS support
- Request queuing
- Result caching
- Metrics and monitoring
- Multi-server load balancing

---

**Technology**: Python Flask + Ghidra
**Port**: 5000 (default)
**Protocol**: HTTP/REST
**Authentication**: None (local use only)
