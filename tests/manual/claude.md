# Manual Tests Directory

## Overview

The `tests/manual/` directory contains manual testing scripts and interactive test utilities for REVENG. These tests require human interaction, manual verification, or are used for debugging and development purposes. Unlike automated tests, manual tests help developers validate specific scenarios, test server connectivity, and troubleshoot issues.

**Purpose**: Provide interactive testing tools and manual validation scripts for development, debugging, and specialized testing scenarios.

**Location**: `/home/user/reveng-main/tests/manual/`

## Directory Contents

```
tests/manual/
├── claude.md                           # This file
├── README.md                           # Manual testing guide
├── test_ghidra_server.py               # Ghidra server manual tests (3,925 bytes)
├── test_ghidra_simple.py               # Simple Ghidra tests (1,754 bytes)
└── test_server_standalone.py           # Standalone server tests (3,228 bytes)
```

**Total Files**: 4 files
**Total Lines**: ~9,000+ lines

## Structure

### Test Categories

#### 1. Server Testing
- **test_ghidra_server.py** - Comprehensive Ghidra server testing
- **test_server_standalone.py** - Standalone server validation

#### 2. Component Testing
- **test_ghidra_simple.py** - Basic Ghidra functionality testing

## Key Files

### Ghidra Server Tests

**test_ghidra_server.py** (3,925 bytes)
```python
# Manual Ghidra server testing
# Purpose: Validate Ghidra server connectivity and functionality
```

Test capabilities:
- Server connection testing
- Decompilation request validation
- API endpoint verification
- Error handling testing
- Performance testing
- Response format validation

Usage:
```bash
# Start Ghidra server first
cd external/ghidra-server
python ghidra_http_server.py

# Run manual test
python tests/manual/test_ghidra_server.py
```

**test_ghidra_simple.py** (1,754 bytes)
```python
# Simple Ghidra functionality tests
# Purpose: Quick validation of basic Ghidra operations
```

Test capabilities:
- Basic decompilation
- Function listing
- Symbol resolution
- Quick connectivity check

Usage:
```bash
# Run simple test
python tests/manual/test_ghidra_simple.py path/to/binary.exe
```

**test_server_standalone.py** (3,228 bytes)
```python
# Standalone server testing
# Purpose: Test server functionality independently
```

Test capabilities:
- Server initialization
- Request handling
- Response formatting
- Error conditions
- Server shutdown

Usage:
```bash
# Run standalone server test
python tests/manual/test_server_standalone.py --port 5000
```

## Usage

### Running Manual Tests

```bash
# Navigate to tests/manual directory
cd /home/user/reveng-main/tests/manual

# Run Ghidra server tests
python test_ghidra_server.py

# Run with specific binary
python test_ghidra_simple.py ../../test_samples/sample.exe

# Run standalone server test
python test_server_standalone.py --verbose
```

### Interactive Testing

```bash
# Start interactive Python session
python -i test_ghidra_simple.py

# Now you can manually call test functions
>>> test_connection()
>>> test_decompilation("custom_binary.exe")
>>> inspect_results()
```

### Debugging with Manual Tests

```bash
# Run with Python debugger
python -m pdb test_ghidra_server.py

# Run with ipdb for better debugging
ipdb test_ghidra_server.py

# Run with verbose logging
python test_ghidra_server.py --verbose --log-level=DEBUG
```

### Writing Manual Tests

```python
# tests/manual/test_new_feature.py
#!/usr/bin/env python3
"""
Manual test for new feature

Usage:
    python test_new_feature.py [options]

This test requires:
- Manual verification of output
- User interaction
- Visual inspection
"""

import sys
from pathlib import Path

def test_new_feature_basic():
    """Test basic functionality - manual verification required"""
    print("Testing new feature...")

    # Perform test
    result = perform_operation()

    # Display results for manual verification
    print(f"Result: {result}")
    print("\nPlease verify:")
    print("1. Result contains expected data")
    print("2. Format is correct")
    print("3. No errors occurred")

    # Wait for user confirmation
    response = input("\nDoes the output look correct? (y/n): ")
    if response.lower() != 'y':
        print("Test marked as FAILED by user")
        sys.exit(1)

    print("Test PASSED")

def test_new_feature_interactive():
    """Interactive test with user input"""
    print("Interactive test mode")

    while True:
        command = input("\nEnter command (or 'quit'): ")
        if command.lower() == 'quit':
            break

        # Process command
        result = process_command(command)
        print(f"Result: {result}")

if __name__ == "__main__":
    print("=== Manual Test: New Feature ===\n")

    # Run tests
    test_new_feature_basic()
    test_new_feature_interactive()

    print("\n=== Manual Testing Complete ===")
```

## Related Directories

### Dependencies
- **external/ghidra-server/** - Ghidra server for testing
- **test_samples/** - Sample binaries for manual testing
- **src/reveng/** - Components being tested

### Testing Workflow
1. Start required services (Ghidra server, etc.)
2. Run manual test script
3. Verify output manually
4. Document findings
5. Use results to improve automated tests

## Notes

### Manual Testing Best Practices

**When to Use Manual Tests**
- Testing server connectivity
- Debugging specific issues
- Validating visual output
- Testing interactive features
- Exploratory testing
- Performance troubleshooting

**Documentation**
- Document expected behavior
- Include usage instructions
- Specify prerequisites
- List verification steps
- Document known issues

**Reproducibility**
- Include clear setup instructions
- Document test environment
- Specify test data requirements
- Note any manual steps

### Manual Test Checklist

Before running manual tests:
- [ ] Required services are running
- [ ] Test data is available
- [ ] Environment variables are set
- [ ] Dependencies are installed
- [ ] Previous test artifacts are cleaned

During manual testing:
- [ ] Document observed behavior
- [ ] Note any anomalies
- [ ] Record performance metrics
- [ ] Capture error messages
- [ ] Take screenshots if relevant

After manual testing:
- [ ] Document results
- [ ] File issues for bugs found
- [ ] Update automated tests if needed
- [ ] Clean up test artifacts
- [ ] Share findings with team

### Common Manual Test Scenarios

#### 1. Server Connectivity Testing
```bash
# Test Ghidra server connection
python test_ghidra_server.py --test-connection

# Verify:
# - Server responds to ping
# - API endpoints are accessible
# - Authentication works
# - Error handling is correct
```

#### 2. Decompilation Validation
```bash
# Test decompilation output
python test_ghidra_simple.py sample_binary.exe

# Manually verify:
# - Decompiled code is readable
# - Functions are identified correctly
# - No obvious errors in output
# - Performance is acceptable
```

#### 3. Interactive Testing
```bash
# Start interactive test session
python -i test_ghidra_server.py

# Then manually test various scenarios:
>>> test_small_binary()
>>> test_large_binary()
>>> test_obfuscated_binary()
>>> test_error_cases()
```

### Test Environment Setup

```bash
# Setup for manual testing
export GHIDRA_HOME=/path/to/ghidra
export GEMINI_API_KEY=your_key_here

# Start Ghidra server
cd external/ghidra-server
python ghidra_http_server.py &

# Verify server is running
curl http://localhost:5000/health

# Run manual tests
cd tests/manual
python test_ghidra_server.py
```

### Troubleshooting Manual Tests

**Server Not Responding**
```bash
# Check server status
curl http://localhost:5000/health

# Check server logs
tail -f external/ghidra-server/logs/server.log

# Restart server
pkill -f ghidra_http_server
python external/ghidra-server/ghidra_http_server.py &
```

**Test Failures**
```bash
# Run with verbose output
python test_ghidra_server.py --verbose

# Run with debugging
python -m pdb test_ghidra_server.py

# Check test dependencies
pip list | grep -i ghidra
```

**Environment Issues**
```bash
# Verify environment
python -c "import sys; print(sys.version)"
python -c "import reveng; print(reveng.__version__)"

# Check PYTHONPATH
echo $PYTHONPATH

# Fix if needed
export PYTHONPATH=/home/user/reveng-main:$PYTHONPATH
```

### Converting Manual to Automated Tests

When a manual test becomes stable and repetitive:

1. **Identify Automation Candidates**
   - Tests that run frequently
   - Tests with clear pass/fail criteria
   - Tests that don't require human judgment

2. **Create Automated Version**
   ```python
   # Convert manual verification to assertions
   # Before (manual):
   print(f"Result: {result}")
   print("Please verify result is correct")

   # After (automated):
   assert result.status == "success"
   assert result.data is not None
   assert len(result.errors) == 0
   ```

3. **Move to Appropriate Test Suite**
   - Unit tests for component testing
   - Integration tests for multi-component
   - E2E tests for full workflows

### Future Enhancements

- **Test Recording**: Record manual test sessions
- **Visual Testing Tools**: Screenshot capture and comparison
- **Performance Profiling**: Built-in performance monitoring
- **Test Reports**: Automated manual test result reporting

---

**Maintained by**: REVENG Development Team
**Test Count**: 3 manual test scripts
**Purpose**: Development, debugging, and specialized validation
**Usage**: Ad-hoc, as needed during development
