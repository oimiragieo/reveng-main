# REVENG Test Fixtures

This directory contains test fixtures and sample data for the REVENG test suite.

## Directory Structure

- `binaries/` - Sample binary files for testing
- `expected_outputs/` - Expected output files for comparison
- `mock_data/` - Mock data for testing

## Usage

These fixtures are automatically loaded by the test suite using pytest fixtures defined in `conftest.py`.

## Adding New Fixtures

When adding new test fixtures:

1. Place binary files in `binaries/`
2. Place expected outputs in `expected_outputs/`
3. Place mock data in `mock_data/`
4. Update the corresponding test files to use the new fixtures

## File Naming Convention

- Binary files: `test_<type>_<size>.<ext>` (e.g., `test_java_small.jar`)
- Expected outputs: `expected_<test_name>.json`
- Mock data: `mock_<component>.json`
