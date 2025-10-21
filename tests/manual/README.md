# Manual Test Scripts

These test scripts require manual setup and cannot be run in automated CI/CD pipelines.

## Prerequisites

### For Ghidra Tests
1. **Ghidra** must be installed (run `python scripts/setup/download_ghidra.py`)
2. **Ghidra MCP Plugin** must be installed and configured
3. **Binary loaded** in Ghidra (e.g., KARP.exe or test binary)
4. **Ghidra MCP Server** running at http://127.0.0.1:8080

### For Server Tests
1. **REVENG Ghidra Analysis Server** running at http://127.0.0.1:1337
2. **Flask dependencies** installed (`pip install flask flask-cors requests`)

## Test Scripts

### test_ghidra_server.py
Tests the REVENG Ghidra Analysis Server integration.

**Usage:**
```bash
# Start Ghidra Analysis Server first
python -m reveng.server.ghidra_analysis_server --port 1337

# In another terminal
python tests/manual/test_ghidra_server.py
```

**What it tests:**
- Server health endpoint
- Binary analysis endpoint
- Function decompilation
- Cross-reference extraction

### test_ghidra_simple.py
Simple connectivity test for Ghidra MCP.

**Usage:**
```bash
# Ensure Ghidra MCP is running
python tests/manual/test_ghidra_simple.py
```

**What it tests:**
- Basic Ghidra MCP connectivity
- Health check endpoint
- Simple decompilation request

### test_server_standalone.py
Standalone server test without Ghidra integration.

**Usage:**
```bash
python tests/manual/test_server_standalone.py
```

**What it tests:**
- Server starts correctly
- Endpoints respond
- Error handling

## Running Manual Tests

### Quick Test All
```bash
# Ensure all prerequisites are running, then:
for test in tests/manual/test_*.py; do
    echo "Running $test..."
    python "$test"
done
```

### Individual Tests
```bash
python tests/manual/test_ghidra_server.py
python tests/manual/test_ghidra_simple.py
python tests/manual/test_server_standalone.py
```

## Troubleshooting

### "Connection refused" errors
- Ensure Ghidra MCP Server is running (check http://127.0.0.1:8080/health)
- Ensure REVENG Analysis Server is running (check http://127.0.0.1:1337/health)
- Verify firewall settings allow localhost connections

### "Module not found" errors
```bash
pip install -r requirements.txt
pip install flask flask-cors requests
```

### Ghidra MCP not responding
1. Open Ghidra application
2. Load a binary (File → Import File)
3. Open CodeBrowser tool
4. Enable GhidraMCP plugin (File → Configure → Miscellaneous)
5. Verify plugin started (check Ghidra console for "GhidraMCP server started")

## Adding New Manual Tests

When adding new manual tests:

1. **Name clearly:** `test_<feature>_manual.py`
2. **Document prerequisites** in docstring
3. **Provide clear error messages** when prerequisites not met
4. **Update this README** with usage instructions

Example:
```python
#!/usr/bin/env python3
"""
Test Feature X

Prerequisites:
- Service Y running on port Z
- Environment variable FOO set

Usage:
    python tests/manual/test_feature_x.py
"""

def main():
    # Check prerequisites
    if not check_service_running():
        print("ERROR: Service Y not running. Start with: ...")
        sys.exit(1)

    # Run tests
    ...
```

## Integration with CI/CD

These tests are **excluded** from CI/CD pipelines due to manual setup requirements.

For automated testing, see:
- `tests/unit/` - Fast, isolated unit tests
- `tests/integration/` - Automated integration tests
- `tests/e2e/` - End-to-end tests with mocked dependencies
