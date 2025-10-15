# REVENG Scripts

This directory contains utility scripts for REVENG setup, maintenance, and development.

## 📋 Scripts Overview

### Setup Scripts (`setup/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| `bootstrap_windows.bat` | Windows setup automation | `scripts\setup\bootstrap_windows.bat` |
| `bootstrap_linux.sh` | Linux setup automation | `bash scripts/setup/bootstrap_linux.sh` |
| `setup_java_analysis.py` | Java analysis setup | `python scripts/setup/setup_java_analysis.py` |
| `verify_installation.py` | Installation verification | `python scripts/setup/verify_installation.py` |

### Development Scripts (`development/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| `lint_codebase.py` | Code quality checking | `python scripts/development/lint_codebase.py` |
| `lint_codebase.bat` | Windows linting wrapper | `scripts\development\lint_codebase.bat` |

### Testing Scripts (`testing/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| `run_enhanced_tests.py` | Enhanced test suite | `python scripts/testing/run_enhanced_tests.py` |
| `run_examples.py` | Example execution | `python scripts/testing/run_examples.py` |

### Deployment Scripts (`deployment/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| `deploy_enhanced_analysis.py` | Enhanced analysis deployment | `python scripts/deployment/deploy_enhanced_analysis.py` |

### Maintenance Scripts (`maintenance/`)

| Script | Purpose | Usage |
|--------|---------|-------|
| `cleanup_legacy.py` | Legacy file cleanup | `python scripts/maintenance/cleanup_legacy.py` |
| `clean_outputs.py` | Output cleanup | `python scripts/maintenance/clean_outputs.py` |
| `generate_docs.py` | Documentation generation | `python scripts/maintenance/generate_docs.py` |

## 🚀 Quick Start

### Automated Setup (Recommended)

**Windows:**
```cmd
scripts\setup\bootstrap_windows.bat
```

**Linux/macOS:**
```bash
bash scripts/setup/bootstrap_linux.sh
```

### Manual Setup

1. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt
   ```

2. **Setup Java Analysis (Optional)**
   ```bash
   python scripts/setup/setup_java_analysis.py
   ```

3. **Verify Installation**
   ```bash
   python scripts/development/lint_codebase.py
   python -m pytest tests/
   ```

## 📝 Script Details

### bootstrap_windows.bat

Automated Windows setup script that:
- Checks Python installation
- Installs pip dependencies
- Sets up development environment
- Verifies installation

**Requirements:**
- Windows 10/11
- Python 3.11+ in PATH
- Internet connection

### bootstrap_linux.sh

Automated Linux setup script that:
- Updates package manager
- Installs system dependencies
- Sets up Python environment
- Installs REVENG dependencies

**Requirements:**
- Ubuntu 20.04+ or similar
- sudo access
- Internet connection

### setup_java_analysis.py

Sets up Java bytecode analysis capabilities:
- Downloads Java decompilers (CFR, Fernflower, Procyon)
- Configures Java analysis tools
- Sets up Maven/Gradle integration

**Usage:**
```bash
python scripts/setup_java_analysis.py
```

**Options:**
- `--decompilers`: Specify which decompilers to install
- `--output-dir`: Custom output directory
- `--force`: Force reinstall existing tools

### lint_codebase.py

Comprehensive code quality checking:
- Runs pylint on all Python files
- Checks code formatting (black)
- Validates import sorting (isort)
- Reports code quality metrics

**Usage:**
```bash
python scripts/lint_codebase.py
```

**Options:**
- `--fix`: Auto-fix formatting issues
- `--strict`: Use strict linting rules
- `--exclude`: Exclude specific files/directories

### run_enhanced_tests.py

Enhanced test suite with additional checks:
- Unit tests
- Integration tests
- Performance tests
- Security tests

**Usage:**
```bash
python scripts/run_enhanced_tests.py
```

**Options:**
- `--coverage`: Generate coverage report
- `--performance`: Run performance tests
- `--security`: Run security tests

### deploy_enhanced_analysis.py

Deploys enhanced analysis capabilities:
- Sets up AI models
- Configures analysis pipelines
- Deploys web interface
- Sets up monitoring

**Usage:**
```bash
python scripts/deploy_enhanced_analysis.py
```

**Options:**
- `--environment`: Target environment (dev/staging/prod)
- `--models`: Deploy specific AI models
- `--web-interface`: Deploy web interface

### cleanup_legacy.py

Cleans up legacy files and directories:
- Removes deprecated files
- Archives old analysis outputs
- Cleans up temporary files
- Updates project structure

**Usage:**
```bash
python scripts/cleanup_legacy.py
```

**Options:**
- `--dry-run`: Show what would be cleaned
- `--archive`: Archive instead of delete
- `--force`: Skip confirmation prompts

## 🔧 Development Workflow

### Daily Development

1. **Start Development Session**
   ```bash
   # Check code quality
   python scripts/lint_codebase.py
   
   # Run tests
   python -m pytest tests/
   ```

2. **Make Changes**
   - Edit code
   - Add tests
   - Update documentation

3. **Before Committing**
   ```bash
   # Fix formatting
   python scripts/lint_codebase.py --fix
   
   # Run full test suite
   python scripts/run_enhanced_tests.py
   ```

### Weekly Maintenance

1. **Cleanup Legacy Files**
   ```bash
   python scripts/cleanup_legacy.py --dry-run
   python scripts/cleanup_legacy.py
   ```

2. **Update Dependencies**
   ```bash
   pip install -r requirements.txt --upgrade
   pip install -r requirements-dev.txt --upgrade
   ```

3. **Deploy Updates**
   ```bash
   python scripts/deploy_enhanced_analysis.py --environment staging
   ```

## 🐛 Troubleshooting

### Common Issues

**Script Permission Denied (Linux/macOS):**
```bash
chmod +x scripts/*.sh
```

**Python Not Found (Windows):**
- Ensure Python is in PATH
- Use full path: `C:\Python311\python.exe scripts/lint_codebase.py`

**Dependencies Missing:**
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

**Java Analysis Setup Fails:**
```bash
# Check Java installation
java -version
javac -version

# Manual setup
python scripts/setup_java_analysis.py --verbose
```

### Getting Help

- **Script Issues**: Check script output for error messages
- **Dependencies**: Verify all requirements are installed
- **Permissions**: Ensure proper file permissions
- **Documentation**: See main [docs/](../docs/) directory

## 📊 Script Metrics

| Script | Lines | Complexity | Dependencies |
|--------|-------|------------|--------------|
| `bootstrap_windows.bat` | 45 | Low | Windows, Python |
| `bootstrap_linux.sh` | 38 | Low | Linux, Python |
| `setup_java_analysis.py` | 156 | Medium | requests, pathlib |
| `lint_codebase.py` | 89 | Medium | pylint, black, isort |
| `run_enhanced_tests.py` | 134 | Medium | pytest, coverage |
| `deploy_enhanced_analysis.py` | 201 | High | docker, kubernetes |
| `cleanup_legacy.py` | 67 | Low | pathlib, shutil |

## 🔄 Script Lifecycle

### Adding New Scripts

1. **Create Script**
   - Follow naming convention: `action_purpose.py`
   - Add proper docstrings
   - Include error handling

2. **Add to README**
   - Update this file
   - Add usage examples
   - Document options

3. **Test Script**
   - Test on different platforms
   - Verify error handling
   - Check output format

4. **Update Dependencies**
   - Add to requirements if needed
   - Update setup scripts

### Maintaining Scripts

- **Regular Updates**: Keep scripts current with project changes
- **Error Handling**: Improve error messages and recovery
- **Performance**: Optimize for large codebases
- **Documentation**: Keep examples and usage current

## 📚 Related Documentation

- **[Main README](../README.md)** - Project overview
- **[Developer Guide](../docs/DEVELOPER_GUIDE.md)** - Development workflows
- **[User Guide](../docs/USER_GUIDE.md)** - Usage documentation
- **[Contributing Guide](../CONTRIBUTING.md)** - Contribution guidelines

---

**Last Updated**: January 2025  
**Maintainer**: REVENG Development Team
