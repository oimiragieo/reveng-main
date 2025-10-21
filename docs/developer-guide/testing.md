# REVENG Testing Guide

Comprehensive guide for running and writing tests in the REVENG project.

---

## Test Suite Structure

```
tests/
├── unit/           # Fast, isolated component tests
├── integration/    # Component interaction tests
├── e2e/           # End-to-end workflow tests
├── performance/    # Benchmarking and load tests
├── security/       # Security-specific tests
├── manual/         # Tests requiring manual setup
├── fixtures/       # Test data and mocks
└── conftest.py     # PyTest configuration
```

---

## Running Tests

### Quick Start

```bash
# Run all tests
pytest

# Run specific test category
pytest tests/unit/
pytest tests/integration/
pytest tests/e2e/

# Run with coverage
pytest --cov=src/reveng --cov-report=html

# Run in parallel (faster)
pytest -n auto

# Verbose output
pytest -v

# Stop on first failure
pytest -x
```

### Test Categories

#### Unit Tests (Fast)
```bash
pytest tests/unit/ -v

# Specific module
pytest tests/unit/test_analyzer.py

# Specific test
pytest tests/unit/test_analyzer.py::test_binary_detection
```

**Characteristics:**
- ⚡ Fast (<1s each)
- 🔒 Isolated (no external dependencies)
- 🎯 Focused (single function/class)

#### Integration Tests
```bash
pytest tests/integration/ -v

# May require external tools
pytest tests/integration/test_ghidra_integration.py
```

**Characteristics:**
- ⏱️ Slower (1-10s each)
- 🔗 Tests component interactions
- 🛠️ May require tools (Ghidra, etc.)

#### End-to-End Tests
```bash
pytest tests/e2e/ -v --slow

# Full analysis workflow
pytest tests/e2e/test_complete_analysis.py
```

**Characteristics:**
- 🐢 Slow (10s-60s each)
- 🌐 Full system tests
- 📁 Uses real binaries

#### Performance Tests
```bash
pytest tests/performance/ --benchmark

# Generate benchmark report
pytest tests/performance/ --benchmark-autosave
```

**Characteristics:**
- 📊 Measures speed and memory
- 📈 Tracks performance over time
- ⚖️ Ensures efficiency

#### Security Tests
```bash
pytest tests/security/ -v

# Check for known vulnerabilities
pytest tests/security/test_input_validation.py
```

**Characteristics:**
- 🔐 Security-focused
- 🚨 Tests attack scenarios
- ✅ Validates sanitization

#### Manual Tests
```bash
# Requires setup (see tests/manual/README.md)
python tests/manual/test_ghidra_server.py
```

**Characteristics:**
- 🖐️ Requires human setup
- 🔧 External dependencies
- 📝 Documented in tests/manual/README.md

---

## Test Coverage

### Viewing Coverage

```bash
# Generate HTML coverage report
pytest --cov=src/reveng --cov-report=html

# Open in browser
# Windows:
start htmlcov/index.html

# Linux/macOS:
open htmlcov/index.html
```

### Coverage Goals

| Component | Target | Current |
|-----------|--------|---------|
| Core Analyzer | >90% | ~85% |
| AI Integration | >80% | ~75% |
| Tools | >70% | ~65% |
| Web Interface | >80% | ~70% |
| **Overall** | **>80%** | **~75%** |

---

## Writing Tests

### Test Structure

```python
# tests/unit/test_example.py

import pytest
from reveng.analyzer import REVENGAnalyzer

class TestREVENGAnalyzer:
    """Test suite for REVENGAnalyzer."""

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = REVENGAnalyzer("test.exe")
        assert analyzer.binary_path == "test.exe"

    def test_language_detection(self, sample_binary):
        """Test language detection with fixture."""
        analyzer = REVENGAnalyzer(sample_binary)
        lang = analyzer.detect_language()
        assert lang in ["java", "csharp", "python", "native"]

    @pytest.mark.slow
    def test_full_analysis(self, large_binary):
        """Test complete analysis (slow)."""
        analyzer = REVENGAnalyzer(large_binary)
        result = analyzer.analyze_binary()
        assert result["status"] == "success"
```

### Using Fixtures

```python
# tests/conftest.py

import pytest
from pathlib import Path

@pytest.fixture
def sample_binary(tmp_path):
    """Provide a small test binary."""
    binary = tmp_path / "test.exe"
    binary.write_bytes(b"MZ\x90\x00...")  # Minimal PE header
    return str(binary)

@pytest.fixture
def mock_ghidra_server(mocker):
    """Mock Ghidra server responses."""
    mock = mocker.patch("reveng.tools.config.ghidra_engine.GhidraEngine")
    mock.return_value.analyze.return_value = {
        "functions": [],
        "strings": []
    }
    return mock
```

### Test Markers

```python
# Mark slow tests
@pytest.mark.slow
def test_large_binary_analysis():
    pass

# Mark tests requiring specific tools
@pytest.mark.requires_ghidra
def test_ghidra_decompilation():
    pass

# Mark security tests
@pytest.mark.security
def test_input_sanitization():
    pass

# Skip if condition not met
@pytest.mark.skipif(not has_ghidra(), reason="Ghidra not installed")
def test_ghidra_features():
    pass
```

Run specific markers:
```bash
pytest -m slow          # Only slow tests
pytest -m "not slow"    # Skip slow tests
pytest -m security      # Only security tests
```

---

## Continuous Integration

### GitHub Actions

Tests run automatically on:
- Every push
- Every pull request
- Daily (scheduled)

```yaml
# .github/workflows/test.yml
name: Test Suite
on: [push, pull_request]
jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python: ['3.11', '3.12']
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
      - run: pip install -e .[dev]
      - run: pytest --cov --cov-report=xml
      - uses: codecov/codecov-action@v3
```

---

## Debugging Failed Tests

### Common Issues

#### "Module not found"
```bash
# Ensure package installed in dev mode
pip install -e .

# Or with dev dependencies
pip install -e .[dev]
```

#### "Fixture not found"
```bash
# Check conftest.py is in tests/ directory
# Ensure pytest discovers fixtures correctly
pytest --fixtures  # List all fixtures
```

#### "Test hangs/times out"
```bash
# Set timeout for slow tests
pytest --timeout=60  # Kill tests after 60s
```

#### "Binary not found"
```bash
# Download test binaries
python scripts/setup/download_test_samples.py

# Or use fixtures to generate test data
```

---

## Test Data

### Sample Binaries

```bash
# Download official test samples
git lfs pull  # If using Git LFS

# Or generate minimal test binaries
python tests/fixtures/generate_test_binaries.py
```

### Mocking External Services

```python
# Mock Ghidra
@pytest.fixture
def mock_ghidra(mocker):
    return mocker.patch("reveng.ghidra.GhidraEngine")

# Mock AI API
@pytest.fixture
def mock_openai(mocker):
    return mocker.patch("openai.ChatCompletion.create")
```

---

## Best Practices

### ✅ DO

- Write tests for all new features
- Use descriptive test names
- Test edge cases and error conditions
- Keep tests independent
- Use fixtures for setup
- Mock external dependencies
- Run tests before committing

### ❌ DON'T

- Depend on external services in unit tests
- Hard-code file paths
- Leave print statements in tests
- Ignore failing tests
- Test implementation details
- Share state between tests

---

## Performance Testing

### Benchmarking

```python
def test_analysis_performance(benchmark):
    """Benchmark analysis speed."""
    analyzer = REVENGAnalyzer("small.exe")
    result = benchmark(analyzer.analyze_binary)
    assert result["status"] == "success"
```

```bash
# Run benchmarks
pytest tests/performance/ --benchmark-only

# Compare to baseline
pytest --benchmark-compare=0001
```

---

## Test Coverage Reports

### CI/CD Integration

Coverage automatically uploaded to:
- **Codecov:** https://codecov.io/gh/oimiragieo/reveng-main
- **GitHub Actions:** Check/Annotations tab

### Local Reports

```bash
# Terminal summary
pytest --cov=src/reveng

# HTML report
pytest --cov=src/reveng --cov-report=html
open htmlcov/index.html

# XML (for CI)
pytest --cov=src/reveng --cov-report=xml
```

---

## Adding New Tests

### Checklist

- [ ] Test file in correct directory
- [ ] Follows naming convention (`test_*.py`)
- [ ] Has descriptive docstrings
- [ ] Uses appropriate fixtures
- [ ] Marked correctly (slow, security, etc.)
- [ ] Passes locally
- [ ] Documented if complex

### Example PR

```bash
# Create feature branch
git checkout -b feature/new-analyzer

# Write feature + tests
touch src/reveng/new_feature.py
touch tests/unit/test_new_feature.py

# Run tests
pytest tests/unit/test_new_feature.py -v

# Commit
git add .
git commit -m "feat: Add new feature with tests"

# Push and create PR
git push origin feature/new-analyzer
```

---

## Resources

- **PyTest Documentation:** https://docs.pytest.org/
- **Coverage.py:** https://coverage.readthedocs.io/
- **pytest-mock:** https://pytest-mock.readthedocs.io/
- **Testing Best Practices:** See CONTRIBUTING.md

---

## Getting Help

- **Failing tests?** Check [Troubleshooting](#debugging-failed-tests)
- **Questions?** Ask in [Discussions](https://github.com/oimiragieo/reveng-main/discussions)
- **Bug in tests?** [Open an issue](https://github.com/oimiragieo/reveng-main/issues)

---

**Happy Testing! 🧪**
