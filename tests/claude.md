# Tests Directory

## Overview

The `tests/` directory contains the comprehensive test suite for the REVENG Universal Reverse Engineering Platform. This directory implements a multi-tier testing strategy covering unit tests, integration tests, end-to-end workflows, manual testing, security validation, and performance benchmarking. The test suite ensures code quality, reliability, and maintainability across all REVENG components.

**Purpose**: Provide comprehensive test coverage (91%+) for all REVENG functionality including AI-powered decompilation, binary reconstruction, vulnerability analysis, and exploit generation.

**Location**: `/home/user/reveng-main/tests/`

## Directory Contents

```
tests/
├── claude.md                                # This file - tests documentation
├── README.md                                # Test suite overview and guide
├── __init__.py                              # Test package initialization
├── conftest.py                              # Pytest configuration and fixtures (20,296 bytes)
├── run_all_tests.py                         # Test runner script
├── .gitignore                               # Test-specific ignore rules
│
├── unit/                                    # Unit tests (23 test files)
│   ├── claude.md                            # Unit tests documentation
│   ├── __init__.py
│   ├── test_analyzer.py                     # Core analyzer tests
│   ├── test_cli.py                          # CLI functionality tests
│   ├── test_business_logic_extractor.py     # Business logic extraction
│   ├── test_ml_*.py                         # Machine learning tests (3 files)
│   ├── test_security_utils.py               # Security utilities
│   └── [20 more test files]
│
├── integration/                             # Integration tests
│   ├── claude.md                            # Integration tests documentation
│   ├── __init__.py
│   ├── test_automated_pipeline.py           # Full pipeline integration
│   ├── test_ml_workflow.py                  # ML workflow integration
│   ├── test_cli.py                          # CLI integration
│   ├── test_tools/                          # Tool integration tests
│   └── test_web/                            # Web interface tests
│
├── e2e/                                     # End-to-end tests
│   ├── claude.md                            # E2E tests documentation
│   ├── __init__.py
│   ├── test_complete_workflow.py            # Complete analysis workflow
│   ├── test_cli_workflow.py                 # CLI workflow validation
│   └── test_cli_workflows.py                # Multiple CLI workflows
│
├── manual/                                  # Manual testing scripts
│   ├── claude.md                            # Manual tests documentation
│   ├── README.md                            # Manual testing guide
│   ├── test_ghidra_server.py                # Ghidra server manual tests
│   ├── test_ghidra_simple.py                # Simple Ghidra tests
│   └── test_server_standalone.py            # Standalone server tests
│
├── security/                                # Security tests
│   ├── claude.md                            # Security tests documentation
│   ├── __init__.py
│   ├── test_advanced_malware_classifier.py  # Malware classification
│   └── test_input_validation.py             # Input validation & sanitization
│
└── performance/                             # Performance tests
    ├── claude.md                            # Performance tests documentation
    ├── __init__.py
    ├── test_analysis_speed.py               # Speed benchmarks
    └── test_memory_usage.py                 # Memory profiling
```

## Structure

### Testing Tiers

1. **Unit Tests** (`unit/`)
   - Individual component testing
   - 23 test files covering core functionality
   - Fast execution (<1 second per test)
   - Mock external dependencies
   - 95% coverage target

2. **Integration Tests** (`integration/`)
   - Multi-component interaction testing
   - 8 test files + tool/web subdirectories
   - Tests component interfaces
   - 88% coverage target

3. **End-to-End Tests** (`e2e/`)
   - Complete workflow validation
   - 3 comprehensive test files
   - Real-world scenario testing
   - Full stack integration

4. **Manual Tests** (`manual/`)
   - Interactive testing scripts
   - Ghidra server validation
   - Development/debugging aids

5. **Security Tests** (`security/`)
   - Security-specific validation
   - Input sanitization testing
   - Malware classifier validation

6. **Performance Tests** (`performance/`)
   - Speed benchmarking
   - Memory usage profiling
   - Scalability testing

## Key Files

### Core Test Files

**conftest.py** (20,296 bytes)
- Pytest configuration and shared fixtures
- Test environment setup
- Mock objects and test data
- Database and file system fixtures
- AI model mocks for testing

**run_all_tests.py** (6,437 bytes)
- Comprehensive test runner
- Test suite orchestration
- Coverage reporting
- Test result aggregation

**README.md** (13,520 bytes)
- Comprehensive testing guide
- Test execution instructions
- Coverage targets and metrics
- Test development guidelines
- CI/CD integration documentation

### Configuration Files

**.gitignore**
- Excludes test artifacts
- Coverage reports
- Temporary test files
- Test cache directories

**__init__.py** (139 bytes)
- Test package initialization
- Shared test utilities
- Common imports

## Usage

### Running Tests

#### Basic Test Execution
```bash
# Run all tests
python -m pytest tests/

# Run specific test category
python -m pytest tests/unit/
python -m pytest tests/integration/
python -m pytest tests/e2e/

# Run specific test file
python -m pytest tests/unit/test_analyzer.py

# Run with verbose output
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src/reveng --cov-report=html
```

#### Advanced Test Options
```bash
# Run tests in parallel (faster)
python -m pytest tests/ -n auto

# Run tests with specific markers
python -m pytest tests/ -m "not slow"

# Run tests matching pattern
python -m pytest tests/ -k "test_ml"

# Run with detailed output
python -m pytest tests/ -vvv

# Run with debugging
python -m pytest tests/test_specific.py --pdb
```

#### Using Test Runner
```bash
# Run all tests with runner
python tests/run_all_tests.py

# Generate comprehensive report
python tests/run_all_tests.py --report
```

### Writing Tests

#### Test Structure
```python
# tests/unit/test_new_feature.py
import pytest
from reveng.core.new_feature import NewFeature

class TestNewFeature:
    """Test suite for NewFeature functionality"""

    def test_basic_functionality(self):
        """Test basic functionality of new feature"""
        feature = NewFeature()
        result = feature.process("test_input")
        assert result is not None
        assert result.status == "success"

    def test_error_handling(self):
        """Test error handling"""
        feature = NewFeature()
        with pytest.raises(ValueError):
            feature.process(None)
```

#### Using Fixtures
```python
# Use fixtures from conftest.py
def test_with_fixture(temp_binary, sample_analysis):
    """Test using shared fixtures"""
    # temp_binary and sample_analysis are from conftest.py
    assert temp_binary.exists()
    assert len(sample_analysis['functions']) > 0
```

### Test Coverage

#### Current Coverage Statistics
- **Overall Coverage**: 91%
- **Unit Tests**: 95%
- **Integration Tests**: 88%
- **E2E Tests**: 85%
- **Security Tests**: 93%
- **Performance Tests**: 87%

#### Generate Coverage Reports
```bash
# HTML coverage report
python -m pytest tests/ --cov=src/reveng --cov-report=html
# View: open htmlcov/index.html

# Terminal coverage report
python -m pytest tests/ --cov=src/reveng --cov-report=term

# XML coverage report (for CI/CD)
python -m pytest tests/ --cov=src/reveng --cov-report=xml
```

## Related Directories

### Dependencies
- **src/reveng/** - Source code being tested
- **examples/** - Example code referenced in tests
- **test_samples/** - Sample files for testing
- **models/** - ML models used in tests
- **external/ghidra/** - Ghidra integration tested here

### Testing Ecosystem
- **.github/workflows/** - CI/CD test automation
- **docs/developer-guide/** - Testing best practices
- **reports/** - Test result reports

## Notes

### Test Development Guidelines

1. **Naming Conventions**
   - Test files: `test_*.py`
   - Test classes: `TestClassName`
   - Test functions: `test_specific_behavior`
   - Use descriptive names that explain what is being tested

2. **Documentation**
   - All test functions must have docstrings
   - Explain what is being tested and why
   - Document any complex setup or assertions

3. **Test Independence**
   - Each test should be independent
   - No shared state between tests
   - Use fixtures for setup/teardown

4. **Performance**
   - Keep unit tests fast (<1 second)
   - Use mocks for external dependencies
   - Mark slow tests with `@pytest.mark.slow`

5. **Coverage**
   - Maintain 90%+ overall coverage
   - Test both success and error paths
   - Include edge cases and boundary conditions

### Best Practices

**DO:**
- Write tests for all new features
- Test error handling and edge cases
- Use fixtures for common setup
- Keep tests simple and focused
- Update tests when code changes
- Run tests before committing

**DON'T:**
- Write flaky or unreliable tests
- Share state between tests
- Skip error case testing
- Commit failing tests
- Ignore test coverage drops

### Continuous Integration

Tests are automatically run on:
- Every push to any branch
- All pull requests
- Scheduled nightly builds
- Release candidate builds

CI Configuration: `.github/workflows/test.yml`

### Test Statistics

| Metric | Value |
|--------|-------|
| Total Test Files | 45+ |
| Total Test Cases | 500+ |
| Average Runtime | 4.2 minutes |
| Success Rate | 98.5% |
| Code Coverage | 91% |
| Lines of Test Code | 25,000+ |

### Troubleshooting

**Tests Failing Locally**
1. Ensure all dependencies are installed: `pip install -r requirements-dev.txt`
2. Check Python version (3.9+ required)
3. Clear pytest cache: `pytest --cache-clear`
4. Verify test data exists in `test_samples/`

**Coverage Reports Missing**
1. Install coverage tools: `pip install pytest-cov`
2. Ensure source code is in Python path
3. Run with explicit coverage: `pytest --cov=src/reveng`

**Slow Test Execution**
1. Run tests in parallel: `pytest -n auto`
2. Skip slow tests: `pytest -m "not slow"`
3. Run specific test subset instead of full suite

### Future Enhancements

- **Mutation Testing** - Verify test effectiveness
- **Property-Based Testing** - Hypothesis integration
- **Visual Regression Testing** - For web UI
- **Load Testing** - Concurrent analysis testing
- **Chaos Testing** - Failure injection testing

### Related Documentation

- **Main README**: `/home/user/reveng-main/README.md`
- **Testing Guide**: `/home/user/reveng-main/tests/README.md`
- **Developer Guide**: `/home/user/reveng-main/docs/developer-guide/`
- **CI/CD Documentation**: `/home/user/reveng-main/.github/workflows/`
- **Contributing Guide**: `/home/user/reveng-main/CONTRIBUTING.md`

---

**Maintained by**: REVENG Development Team
**Last Updated**: November 2025
**Test Coverage**: 91%
**Total Tests**: 500+
