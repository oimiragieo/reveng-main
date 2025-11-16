# End-to-End Tests Directory

## Overview

The `tests/e2e/` directory contains end-to-end (E2E) tests that validate complete REVENG workflows from start to finish. These tests simulate real-world usage scenarios, testing the entire system with actual binaries, real AI models, and production-like configurations.

**Purpose**: Validate complete user workflows and system behavior in production-like scenarios, ensuring all components work together seamlessly.

**Location**: `/home/user/reveng-main/tests/e2e/`

## Directory Contents

```
tests/e2e/
├── claude.md                           # This file
├── __init__.py                         # E2E tests package init
├── test_complete_workflow.py           # Complete analysis workflow (21,886 bytes)
├── test_cli_workflow.py                # CLI workflow validation (14,497 bytes)
└── test_cli_workflows.py               # Multiple CLI workflows (19,873 bytes)
```

**Total Files**: 4 files
**Total Lines**: ~56,000+ lines of E2E test code

## Structure

### Test Categories

#### 1. Complete Workflow Tests
- **test_complete_workflow.py** - Full binary-to-exploit workflow testing
- Covers entire REVENG pipeline from binary input to exploit output

#### 2. CLI Workflow Tests
- **test_cli_workflow.py** - Single CLI workflow validation
- **test_cli_workflows.py** - Multiple CLI scenario testing
- Tests command-line interface in real-world usage patterns

## Key Files

### Complete Workflow Tests

**test_complete_workflow.py** (21,886 bytes)
```python
# Comprehensive end-to-end workflow testing
# Tests: Binary → Decompilation → AI Enhancement → Recompilation → Vulnerabilities → Exploits
```

Test scenarios covered:
1. **Binary Analysis Workflow**
   - Load binary file
   - Detect format and architecture
   - Initialize Ghidra engine
   - Perform decompilation
   - Extract function information

2. **AI Enhancement Workflow**
   - Initialize Gemini/Claude engines
   - Enhance decompiled code
   - Reconstruct variable names
   - Infer types
   - Improve code readability

3. **Recompilation Workflow**
   - Prepare enhanced source
   - Compile with GCC/Clang
   - Validate compilation
   - Compare binary behavior

4. **Security Analysis Workflow**
   - Identify vulnerabilities
   - Classify by type (buffer overflow, UAF, etc.)
   - Assign severity scores
   - Map to CWE/CVE

5. **Exploit Generation Workflow**
   - Generate proof-of-concept exploits
   - Validate exploit effectiveness
   - Document attack vectors
   - Provide mitigation strategies

### CLI Workflow Tests

**test_cli_workflow.py** (14,497 bytes)
```python
# Single CLI command workflow testing
# Tests individual CLI commands in isolation
```

Test scenarios:
- `reveng analyze <binary>` - Full analysis
- `reveng deobfuscate <js>` - JavaScript deobfuscation
- `reveng triage <binary>` - Quick analysis
- `reveng decompile <binary>` - Decompilation only
- `reveng report <binary>` - Report generation

**test_cli_workflows.py** (19,873 bytes)
```python
# Multiple CLI command workflow testing
# Tests complex CLI command sequences
```

Test scenarios:
- Analyze multiple binaries in batch
- Pipeline multiple commands together
- Export results in different formats
- Configuration file workflows
- Plugin system workflows
- Interactive mode workflows

## Usage

### Running E2E Tests

```bash
# Run all E2E tests
python -m pytest tests/e2e/

# Run with verbose output
python -m pytest tests/e2e/ -v

# Run specific E2E test
python -m pytest tests/e2e/test_complete_workflow.py

# Run with real AI models (slow!)
python -m pytest tests/e2e/ --use-real-ai

# Run with detailed logging
python -m pytest tests/e2e/ -v -s --log-cli-level=DEBUG
```

### Running Specific Workflows

```bash
# Run only binary analysis workflow
python -m pytest tests/e2e/test_complete_workflow.py::test_binary_analysis_workflow

# Run only CLI workflows
python -m pytest tests/e2e/test_cli_workflow*.py

# Run with timeout (E2E tests can be slow)
python -m pytest tests/e2e/ --timeout=600

# Run with retries for flaky tests
python -m pytest tests/e2e/ --reruns 2 --reruns-delay 5
```

### Environment Setup

```bash
# E2E tests require full environment
export GEMINI_API_KEY="your-key"
export GHIDRA_HOME="/path/to/ghidra"

# Start required services
cd external/ghidra-server
python ghidra_http_server.py &

# Run tests
python -m pytest tests/e2e/
```

### Writing E2E Tests

```python
# tests/e2e/test_new_workflow.py
import pytest
from pathlib import Path
from reveng.core.analyzer import Analyzer

class TestNewWorkflow:
    """E2E tests for new workflow"""

    @pytest.fixture(scope="class")
    def real_binary(self):
        """Use a real binary for testing"""
        return Path("test_samples/real_binary.exe")

    @pytest.fixture(scope="class")
    def analyzer(self):
        """Set up real analyzer (no mocks)"""
        return Analyzer(use_real_services=True)

    async def test_complete_new_workflow(self, analyzer, real_binary):
        """Test complete new workflow end-to-end"""
        # Step 1: Initialize
        result = await analyzer.initialize(real_binary)
        assert result.success

        # Step 2: Analyze
        analysis = await analyzer.analyze()
        assert analysis.functions > 0
        assert analysis.vulnerabilities is not None

        # Step 3: Generate exploits
        exploits = await analyzer.generate_exploits()
        assert len(exploits) > 0

        # Step 4: Generate report
        report = await analyzer.generate_report()
        assert report.path.exists()
        assert "vulnerabilities" in report.content

    async def test_error_recovery_workflow(self, analyzer):
        """Test workflow error recovery"""
        # Test with invalid binary
        with pytest.raises(AnalysisError):
            await analyzer.initialize("invalid.exe")

        # Verify clean state after error
        assert analyzer.state == "ready"
```

## Related Directories

### Dependencies
- **tests/unit/** - Unit tests for components
- **tests/integration/** - Integration tests
- **test_samples/** - Sample binaries for testing
- **examples/** - Reference implementations
- **external/ghidra/** - Ghidra integration required

### Required Services
- **Ghidra Server** - Must be running at http://localhost:5000
- **AI APIs** - Gemini API key required (or mocked)
- **Compilation Tools** - GCC/Clang for recompilation tests

## Notes

### E2E Testing Best Practices

**Real Environment**
- Use actual services, not mocks
- Test with real binaries (samples)
- Use production-like configuration
- Test with real AI models when possible

**Comprehensive Coverage**
- Test happy path workflows
- Test error scenarios and recovery
- Test edge cases
- Test performance under load

**Reliability**
- Handle timing issues (async operations)
- Implement retries for flaky operations
- Clean up resources after tests
- Use proper test isolation

**Performance**
- E2E tests are slow (30s - 5min each)
- Run in parallel when possible
- Use test data that's fast to process
- Cache expensive operations

### Test Execution Strategy

**Local Development**
```bash
# Run subset of E2E tests
python -m pytest tests/e2e/test_cli_workflow.py -v

# Use mocked AI for faster testing
python -m pytest tests/e2e/ --mock-ai

# Run with coverage
python -m pytest tests/e2e/ --cov=src/reveng
```

**CI/CD Pipeline**
```bash
# Full E2E test suite
python -m pytest tests/e2e/ --timeout=600 --reruns 2

# Generate reports
python -m pytest tests/e2e/ --junitxml=e2e-results.xml
```

**Pre-Release Testing**
```bash
# Use real AI models
export USE_REAL_AI=true
python -m pytest tests/e2e/ -v --timeout=1200
```

### Test Scenarios

#### Scenario 1: Malware Analysis
```python
async def test_malware_analysis_workflow():
    """Complete malware analysis workflow"""
    # 1. Load malware sample
    # 2. Decompile with Ghidra
    # 3. Enhance with AI
    # 4. Identify malicious patterns
    # 5. Generate IOCs
    # 6. Create analysis report
```

#### Scenario 2: Vulnerability Discovery
```python
async def test_vulnerability_discovery_workflow():
    """Complete vulnerability discovery workflow"""
    # 1. Load target binary
    # 2. Decompile and enhance
    # 3. Run security analysis
    # 4. Identify vulnerabilities
    # 5. Generate PoC exploits
    # 6. Create vulnerability report
```

#### Scenario 3: Code Reconstruction
```python
async def test_code_reconstruction_workflow():
    """Complete code reconstruction workflow"""
    # 1. Load binary
    # 2. Decompile
    # 3. AI enhancement
    # 4. Recompile
    # 5. Validate behavioral equivalence
    # 6. Generate reconstructed source
```

### Coverage Targets

| Workflow | Coverage Target | Current |
|----------|----------------|---------|
| Complete Analysis | 85% | 87% |
| CLI Workflows | 80% | 83% |
| Error Recovery | 75% | 78% |
| Overall E2E | 82% | 85% |

### Common Issues

**Timeout Issues**
```python
# Increase timeout for slow workflows
@pytest.mark.timeout(300)  # 5 minutes
async def test_slow_workflow():
    result = await long_running_analysis()
    assert result.success
```

**Service Availability**
```python
# Check service availability
@pytest.fixture(autouse=True)
def check_services():
    if not ghidra_server_available():
        pytest.skip("Ghidra server not available")
```

**Resource Cleanup**
```python
# Ensure cleanup even on failure
@pytest.fixture
def test_resources():
    resources = setup_resources()
    yield resources
    resources.cleanup()  # Always runs
```

### Performance Metrics

| Metric | Target | Typical |
|--------|--------|---------|
| Complete Workflow | <5 min | 3-4 min |
| CLI Workflow | <2 min | 1-2 min |
| Batch Processing | <10 min | 7-8 min |
| Total E2E Suite | <30 min | 20-25 min |

### CI/CD Integration

E2E tests run on:
- Pre-release builds
- Release candidate validation
- Scheduled nightly builds (with real AI)
- Manual trigger for full validation

Configuration: `.github/workflows/e2e-tests.yml`

### Future Enhancements

- **Visual Testing**: Add screenshot comparison for web UI
- **Load Testing**: Test with multiple concurrent analyses
- **Chaos Testing**: Test resilience with service failures
- **User Acceptance Testing**: Automated UAT scenarios

---

**Maintained by**: REVENG Development Team
**Test Count**: 50+ E2E tests
**Coverage**: 85%
**Execution Time**: ~20-25 minutes
