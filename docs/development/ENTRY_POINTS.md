# REVENG Entry Points Documentation

## Overview

This document describes the entry point strategy for REVENG v3.0.0 and the deprecation of legacy entry points.

## Current Entry Points (v3.0.0)

### 1. Primary CLI Entry Point
- **File**: `reveng.py` (root directory)
- **Command**: `reveng`
- **Description**: Main command-line interface
- **Usage**: `python reveng.py <command> [options]` or `reveng <command> [options]`

### 2. Module Entry Point
- **File**: `src/reveng/__main__.py`
- **Command**: `python -m reveng`
- **Description**: Python module execution
- **Usage**: `python -m reveng <command> [options]`

### 3. Package Script Entry Point
- **File**: Defined in `pyproject.toml`
- **Command**: `reveng` (after installation)
- **Description**: Installed package command
- **Usage**: `reveng <command> [options]`

## Deprecated Entry Points

### ❌ reveng_analyzer.py (REMOVED in v3.0.0)
- **Status**: Deprecated and removed
- **Reason**: Redundant with modern `reveng.py`
- **Migration**: Use `reveng` command instead
- **Deprecation Date**: v3.0.0 (2025-01-15)

## Entry Point Strategy

### Design Principles
1. **Single Source of Truth**: `reveng.py` is the primary CLI
2. **Multiple Access Methods**: Support different usage patterns
3. **Backward Compatibility**: Maintain existing workflows where possible
4. **Clean Architecture**: Remove redundant entry points

### Implementation Details

#### CLI Structure
```bash
# Primary usage (recommended)
reveng <command> [options]

# Alternative usage patterns
python reveng.py <command> [options]
python -m reveng <command> [options]
```

#### Command Categories
- **Analysis**: `reveng analyze <binary>`
- **Hex Editor**: `reveng hex <binary>`
- **PE Analysis**: `reveng pe <binary>`
- **Ghidra Integration**: `reveng ghidra <command>`
- **Pipeline**: `reveng pipeline <config>`
- **Malware Analysis**: `reveng malware <binary>`
- **ML Operations**: `reveng ml <command>`
- **Setup**: `reveng setup`
- **Configuration**: `reveng config`
- **Plugins**: `reveng plugin <command>`
- **Web Interface**: `reveng serve`

## Migration Guide

### For Users
- **Old**: `python reveng_analyzer.py analyze binary.exe`
- **New**: `reveng analyze binary.exe`

### For Developers
- **Old**: `from reveng_analyzer import REVENGAnalyzer`
- **New**: `from reveng import REVENGAnalyzer`

### For CI/CD
- **Old**: `python reveng_analyzer.py --help`
- **New**: `reveng --help`

## Verification

### Test Entry Points
```bash
# Test primary CLI
reveng --help

# Test module execution
python -m reveng --help

# Test script execution
python reveng.py --help
```

### Verify Deprecation
```bash
# This should fail (file removed)
python reveng_analyzer.py --help
# Expected: FileNotFoundError
```

## Future Considerations

### Planned Enhancements
1. **Plugin System**: Extensible command structure
2. **API Gateway**: RESTful API for web interface
3. **Batch Processing**: Multi-binary analysis commands
4. **Configuration Management**: Centralized settings

### Backward Compatibility
- **v2.x**: Legacy entry points supported with deprecation warnings
- **v3.0.0**: Legacy entry points removed
- **v3.1+**: Enhanced entry point system

## Troubleshooting

### Common Issues
1. **Command not found**: Ensure REVENG is installed
2. **Permission denied**: Check file permissions
3. **Import errors**: Verify Python path and dependencies

### Debug Commands
```bash
# Check installation
pip show reveng

# Verify entry points
python -c "import reveng; print(reveng.__version__)"

# Test CLI
reveng --version
```

## References
- [CLI Implementation](src/reveng/cli.py)
- [Package Configuration](pyproject.toml)
- [Module Structure](src/reveng/__init__.py)
