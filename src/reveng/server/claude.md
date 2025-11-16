# REVENG Server

## Overview

Server module for running REVENG as a service with REST API, WebSocket support, and multi-user capabilities.

**Location:** `/home/user/reveng-main/src/reveng/server/`

## Key Features

### API Server
- REST API
- WebSocket support
- GraphQL (optional)
- Authentication

### Job Management
- Job queue
- Priority scheduling
- Status tracking
- Result retrieval

### Multi-User Support
- User management
- Access control
- Quota management
- Audit logging

## Usage Examples

### Example 1: Start Server

```bash
# Start REVENG server
reveng-server --host 0.0.0.0 --port 8080

# With authentication
reveng-server --auth --db postgresql://localhost/reveng
```

### Example 2: Submit Analysis Job

```python
import requests

response = requests.post(
    "http://localhost:8080/api/analyze",
    json={"binary_path": "/path/to/binary.exe"},
    headers={"Authorization": "Bearer token"}
)

job_id = response.json()["job_id"]

# Check status
status = requests.get(f"http://localhost:8080/api/jobs/{job_id}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/protocol/` - Protocol definitions
- `/home/user/reveng-main/src/reveng/agent_sdk/mcp/` - MCP server

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
