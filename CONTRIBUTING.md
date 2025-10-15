# Contributing to REVENG

Thank you for your interest in contributing to REVENG! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)

## Code of Conduct

This project adheres to the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold this code.

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- Basic understanding of reverse engineering concepts
- Familiarity with binary analysis tools (Ghidra, IDA Pro, etc.)

### Development Setup

1. **Fork and Clone**
   ```bash
   git clone https://github.com/your-username/reveng-main.git
   cd reveng-main
   ```

2. **Install Dependencies**
   ```bash
   # Core dependencies
   pip install -r requirements.txt
   
   # Development dependencies
   pip install -r requirements-dev.txt
   
   # Java analysis (optional)
   pip install -r requirements-java.txt
   ```

3. **Verify Installation**
   ```bash
   python reveng_analyzer.py --help
   python -m pytest tests/
   ```

## How to Contribute

### Types of Contributions

We welcome several types of contributions:

- **Bug Reports**: Report issues and unexpected behavior
- **Feature Requests**: Suggest new functionality
- **Code Contributions**: Fix bugs, implement features, improve performance
- **Documentation**: Improve guides, add examples, fix typos
- **Testing**: Add test cases, improve test coverage
- **Examples**: Create usage examples and tutorials

### Contribution Workflow

1. **Create an Issue** (for significant changes)
   - Describe the problem or feature request
   - Check if it's already been reported
   - Use appropriate issue templates

2. **Fork the Repository**
   - Create a fork on GitHub
   - Clone your fork locally

3. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number
   ```

4. **Make Your Changes**
   - Write clean, well-documented code
   - Follow the code style guidelines
   - Add tests for new functionality
   - Update documentation as needed

5. **Test Your Changes**
   ```bash
   # Run linting
   python scripts/lint_codebase.py
   
   # Run tests
   python -m pytest tests/
   
   # Test specific functionality
   python reveng_analyzer.py test_samples/sample.exe
   ```

6. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add: brief description of changes"
   ```

7. **Push and Create Pull Request**
   ```bash
   git push origin feature/your-feature-name
   ```
   Then create a pull request on GitHub.

## Code Style Guidelines

### Python Code

- **Formatting**: Use `black` with line length 100
- **Import Sorting**: Use `isort` with black profile
- **Linting**: Use `pylint` (see `pyproject.toml` for configuration)
- **Type Hints**: Use type hints for function parameters and return values
- **Docstrings**: Use Google-style docstrings for all public functions

```python
def analyze_binary(binary_path: str, options: Dict[str, Any]) -> AnalysisResult:
    """
    Analyze a binary file using the REVENG pipeline.
    
    Args:
        binary_path: Path to the binary file to analyze
        options: Configuration options for the analysis
        
    Returns:
        AnalysisResult containing the analysis findings
        
    Raises:
        FileNotFoundError: If the binary file doesn't exist
        AnalysisError: If the analysis fails
    """
    # Implementation here
    pass
```

### File Organization

- **Tools**: Place new analysis tools in `tools/` directory
- **Tests**: Place tests in `tests/` directory with descriptive names
- **Documentation**: Update relevant documentation files
- **Examples**: Add examples to `examples/` directory

### Naming Conventions

- **Files**: Use snake_case for Python files
- **Classes**: Use PascalCase for class names
- **Functions/Variables**: Use snake_case
- **Constants**: Use UPPER_SNAKE_CASE

## Testing Requirements

### Test Coverage

- **New Features**: Must include unit tests
- **Bug Fixes**: Must include regression tests
- **Tools**: Each tool should have corresponding tests
- **Coverage**: Maintain >80% test coverage

### Test Structure

```python
# tests/test_new_feature.py
import pytest
from tools.new_feature import NewFeature

class TestNewFeature:
    def test_basic_functionality(self):
        """Test basic functionality of new feature."""
        feature = NewFeature()
        result = feature.process("test_input")
        assert result is not None
        
    def test_edge_cases(self):
        """Test edge cases and error conditions."""
        feature = NewFeature()
        with pytest.raises(ValueError):
            feature.process(None)
```

### Running Tests

```bash
# Run all tests
python -m pytest tests/

# Run specific test file
python -m pytest tests/test_specific.py

# Run with coverage
python -m pytest tests/ --cov=tools --cov-report=html

# Run linting
python scripts/lint_codebase.py
```

## Pull Request Process

### Before Submitting

- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Documentation updated
- [ ] No sensitive data included
- [ ] Commit messages are clear and descriptive

### PR Template

When creating a pull request, please include:

1. **Description**: What changes were made and why
2. **Type**: Bug fix, feature, documentation, etc.
3. **Testing**: How the changes were tested
4. **Breaking Changes**: Any breaking changes and migration steps
5. **Related Issues**: Link to related issues

### Review Process

1. **Automated Checks**: CI/CD pipeline runs tests and linting
2. **Code Review**: Maintainers review code quality and functionality
3. **Testing**: Changes are tested in different environments
4. **Approval**: At least one maintainer approval required

## Issue Reporting

### Bug Reports

When reporting bugs, please include:

- **Environment**: OS, Python version, REVENG version
- **Steps to Reproduce**: Clear, minimal steps
- **Expected Behavior**: What should happen
- **Actual Behavior**: What actually happens
- **Logs**: Relevant log files or error messages
- **Sample Files**: If applicable, provide sample binaries (sanitized)

### Feature Requests

For feature requests, please include:

- **Use Case**: Why is this feature needed?
- **Proposed Solution**: How should it work?
- **Alternatives**: Other approaches considered
- **Additional Context**: Any other relevant information

## Development Areas

### High Priority

- **Multi-Language Support**: Improve Java, C#, Python analysis
- **AI Integration**: Enhance AI-powered analysis features
- **Performance**: Optimize analysis speed and memory usage
- **Documentation**: Improve user guides and examples

### Tool Categories

- **Core Analysis**: `ai_recompiler_converter.py`, `optimal_binary_analysis.py`
- **Multi-Language**: `java_bytecode_analyzer.py`, `csharp_il_analyzer.py`
- **AI Enhancement**: `ai_analyzer_enhanced.py`, `ollama_analyzer.py`
- **Code Quality**: `code_formatter.py`, `type_inference_engine.py`
- **Binary Operations**: `binary_reassembler_v2.py`, `binary_validator.py`

## Getting Help

- **Documentation**: Check `docs/` directory for comprehensive guides
- **Issues**: Search existing issues before creating new ones
- **Discussions**: Use GitHub Discussions for questions and ideas
- **Discord**: Join our community Discord (if available)

## Recognition

Contributors will be recognized in:
- CONTRIBUTORS.md file
- Release notes
- Project documentation

Thank you for contributing to REVENG! 🚀
