# REVENG Installation Guide

Complete installation instructions for the REVENG Universal Reverse Engineering Platform.

## Prerequisites

### Required Software

#### Python 3.9 or Higher
```bash
# Check Python version
python --version  # Should be 3.9+ (3.11+ recommended)

# Install Python (if needed)
# Windows: Download from python.org
# Linux: sudo apt install python3.9  # or python3.11
# macOS: brew install python@3.9     # or python@3.11
```

**Note:** Python 3.9+ is the minimum requirement, but Python 3.11+ is recommended for best performance.

#### System Requirements
- **RAM:** 4GB minimum (8GB+ recommended)
- **Disk:** 2GB free space (excluding Ghidra)
- **OS:** Windows 10+, Linux (Ubuntu 20.04+), macOS 11+

### Optional but Recommended

#### Java Development Kit 17+ (for Ghidra)
```bash
# Check Java version
java -version  # Should be 17+

# Install JDK
# Windows: Download from https://adoptium.net/
# Linux: sudo apt install openjdk-17-jdk
# macOS: brew install openjdk@17
```

## Installation Methods

### Method 1: From Source (Recommended) ✅

**Current installation method - PyPI package coming soon**

```bash
# Clone repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main

# Quick install (automated)
./install-reveng.sh

# OR manual install
pip install -e .

# Verify installation
reveng --version  # Should show: REVENG v4.0.0
```

**Note:** PyPI package (`pip install reveng`) is not yet published. Install from source for now.

### Method 2: Development Mode 🔧

**For contributors and developers**

```bash
# Clone repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Verify installation
reveng --version
python -m pytest  # Run tests
```

### Method 3: Docker 🐳 (Coming Soon)

**For containerized deployment**

```bash
# Docker images are planned for future release
# Check back soon or follow: https://github.com/oimiragieo/reveng-main/issues
```

**Status:** Docker images will be available in v4.1.0

## External Dependencies

### Ghidra (Required for Advanced Analysis)

Ghidra is the professional-grade disassembly engine that powers REVENG's advanced analysis.

#### Automated Download (Recommended)

```bash
# Download and install Ghidra automatically
python scripts/setup/download_ghidra.py

# This will:
# 1. Download Ghidra from official NSA GitHub
# 2. Verify SHA256 checksum
# 3. Extract to external/ghidra/
# 4. Set up environment variables
```

#### Manual Download

If you prefer manual installation:

1. **Download Ghidra**
   - Visit: https://github.com/NationalSecurityAgency/ghidra/releases
   - Download: `ghidra_11.2.1_PUBLIC_*.zip` (or latest)

2. **Extract Ghidra**
   ```bash
   # Windows
   unzip ghidra_11.2.1_PUBLIC_*.zip -d C:\ghidra
   
   # Linux/macOS
   unzip ghidra_11.2.1_PUBLIC_*.zip -d /opt/ghidra
   ```

3. **Set Environment Variable**
   ```bash
   # Windows (PowerShell)
   $env:GHIDRA_INSTALL_DIR="C:\ghidra\ghidra_11.2.1_PUBLIC"
   
   # Linux/macOS (bash)
   export GHIDRA_INSTALL_DIR="/opt/ghidra/ghidra_11.2.1_PUBLIC"
   
   # Make permanent (add to ~/.bashrc or ~/.zshrc)
   echo 'export GHIDRA_INSTALL_DIR="/opt/ghidra/ghidra_11.2.1_PUBLIC"' >> ~/.bashrc
   ```

### AI Providers (Optional)

#### Ollama (Local LLM) 🤖

For privacy-focused AI analysis without API costs:

```bash
# Install Ollama
# Windows/macOS: Download from https://ollama.ai
# Linux: curl https://ollama.ai/install.sh | sh

# Start Ollama service
ollama serve

# Pull a model (e.g., llama3)
ollama pull llama3

# Verify
curl http://localhost:11434/api/version
```

#### Claude API 🧠

For advanced AI-powered analysis:

```bash
# Set API key
export ANTHROPIC_API_KEY="your-api-key-here"

# Make permanent
echo 'export ANTHROPIC_API_KEY="your-key"' >> ~/.bashrc
```

#### OpenAI API

```bash
# Set API key
export OPENAI_API_KEY="your-api-key-here"

# Make permanent
echo 'export OPENAI_API_KEY="your-key"' >> ~/.bashrc
```

## Platform-Specific Setup

### Windows

#### Prerequisites
```powershell
# Install Visual Studio Build Tools (for binary reconstruction)
# Download from: https://visualstudio.microsoft.com/downloads/

# OR install MinGW-w64
choco install mingw
```

#### Verify Installation
```powershell
python --version
reveng --version
java -version  # If using Ghidra
```

### Linux (Ubuntu/Debian)

#### Prerequisites
```bash
# Install build tools
sudo apt update
sudo apt install -y gcc g++ clang build-essential python3-dev

# Install optional tools
sudo apt install -y clang-format cppcheck
```

#### Verify Installation
```bash
python3 --version
reveng --version
which gcc clang
```

### macOS

#### Prerequisites
```bash
# Install Xcode Command Line Tools
xcode-select --install

# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install tools
brew install python@3.11 clang-format cppcheck
```

#### Verify Installation
```bash
python3 --version
reveng --version
which clang
```

## Verification & Testing

### Quick Health Check

```bash
# Comprehensive dependency check
reveng doctor

# Should output:
# ✓ Python 3.11+ installed
# ✓ Core dependencies available
# ✓ Ghidra detected (if installed)
# ✓ AI providers configured (if setup)
```

### Test Analysis

```bash
# Download test binary (if available)
curl -O https://github.com/oimiragieo/reveng-main/raw/main/test_samples/HelloWorld.class

# Run basic analysis
reveng analyze HelloWorld.class

# Should produce:
# - analysis_HelloWorld/ directory
# - Decompiled code
# - Analysis report
```

## Troubleshooting

### Common Issues

#### "reveng: command not found"

**Solution:**
```bash
# Ensure pip installed to correct location
pip show reveng-toolkit

# Add Python scripts to PATH
# Windows: Add C:\Users\<user>\AppData\Local\Programs\Python\Python311\Scripts
# Linux/macOS: Add ~/.local/bin to PATH
export PATH="$HOME/.local/bin:$PATH"
```

#### "Ghidra not found"

**Solution:**
```bash
# Check environment variable
echo $GHIDRA_INSTALL_DIR

# If empty, run setup again
python scripts/setup/download_ghidra.py

# Or set manually
export GHIDRA_INSTALL_DIR="/path/to/ghidra/ghidra_11.2.1_PUBLIC"
```

#### "Module not found" errors

**Solution:**
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt

# If using virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

#### Permission errors on Linux/macOS

**Solution:**
```bash
# Use user install (no sudo)
pip install --user reveng-toolkit

# Or use virtual environment (recommended)
python -m venv venv
source venv/bin/activate
pip install reveng-toolkit
```

## Next Steps

✅ **Installation complete!** Now you can:

1. **[Quick Start Guide](QUICK_START.md)** - Analyze your first binary in 5 minutes
2. **[User Guide](../user-guide/USER_GUIDE.md)** - Learn CLI, Web UI, and Python API
3. **[Examples](../../examples/)** - See real-world analysis workflows

## Getting Help

- **Documentation:** [docs/](../)
- **Troubleshooting:** [troubleshooting.md](troubleshooting.md)
- **Issues:** https://github.com/oimiragieo/reveng-main/issues
- **Discussions:** https://github.com/oimiragieo/reveng-main/discussions

---

**Installation successful?** Give us a ⭐ on [GitHub](https://github.com/oimiragieo/reveng-main)!
