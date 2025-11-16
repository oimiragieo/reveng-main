# Getting Started with REVENG

A step-by-step guide to installing and using REVENG for the first time.

**Time to complete:** 10-15 minutes
**Version:** 4.0.0

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Verification](#verification)
4. [Your First Analysis](#your-first-analysis)
5. [Next Steps](#next-steps)
6. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, ensure you have:

### Required
- **Python 3.9 or higher**
  ```bash
  python3 --version
  # Should show: Python 3.9.x or higher
  ```
- **pip** (Python package manager)
  ```bash
  pip --version
  ```
- **Git** (to clone the repository)
  ```bash
  git --version
  ```

### Optional (for advanced features)
- **Ghidra 11.0+** - For advanced binary decompilation
- **Java 21+** - Required for Ghidra
- **Node.js 18+** - For JavaScript deobfuscation
- **GCC/Clang** - For binary recompilation

---

## Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
```

### Step 2: Run the Installer (Recommended)

```bash
./install-reveng.sh
```

This script will:
- Install Python dependencies
- Set up the `reveng` command
- Install JavaScript deobfuscation tools
- Verify the installation

**Installation time:** ~2-3 minutes

### Step 3: Manual Installation (Alternative)

If the automated installer doesn't work:

```bash
# Install dependencies
pip install -r requirements.txt

# Install REVENG
pip install -e .

# Verify installation
reveng --version
```

---

## Verification

After installation, verify everything works:

### 1. Check Version

```bash
reveng --version
```

**Expected output:**
```
REVENG v4.0.0 (Production/Stable)
```

❌ If you see v3.0.0, the installation didn't complete correctly. Try: `pip install -e . --force-reinstall`

### 2. Check CLI Access

```bash
reveng --help
```

You should see a list of available commands.

### 3. Test Core Modules

```bash
python3 -c "from reveng.analyzer import REVENGAnalyzer; print('✓ Core modules OK')"
```

**Expected output:**
```
✓ Core modules OK
```

---

## Your First Analysis

Let's analyze a binary file step by step.

### Option A: Quick Start (No Setup Required)

```bash
# Analyze any binary on your system
reveng analyze /bin/ls

# Or on Windows
reveng analyze C:\Windows\System32\notepad.exe
```

**What happens:**
1. REVENG detects the binary format (ELF, PE, etc.)
2. Performs static analysis
3. Identifies security issues
4. Generates a report

**Time:** 5-30 seconds depending on binary size

### Option B: With Sample Binary

If you don't have a binary handy:

```bash
# Create a simple test program
cat > test.c << 'EOF'
#include <stdio.h>
int main() {
    printf("Hello from REVENG!\n");
    return 0;
}
EOF

# Compile it
gcc test.c -o test

# Analyze it
reveng analyze ./test
```

### Understanding the Output

The analysis report includes:

```
Analysis Results for: test
=========================

Binary Information:
  Format: ELF 64-bit LSB executable
  Architecture: x86-64
  Entry Point: 0x401000

Security Analysis:
  NX Enabled: Yes
  PIE Enabled: No
  Stack Canary: Yes

Vulnerabilities: 0 found

Imports:
  - printf@libc.so.6

Functions: 3
  - main
  - _start
  - __libc_start_main
```

---

## Next Steps

### 1. Try Different Commands

```bash
# Quick threat triage
reveng triage <binary>

# Natural language interface
reveng ask "What does this binary do?" <binary>

# Interactive AI analysis
reveng ai <binary>

# Start web interface
reveng serve
```

### 2. Set Up AI Features (Optional)

For AI-enhanced analysis:

```bash
# Get a free API key from Google AI Studio
# https://makersuite.google.com/app/apikey

# Set the environment variable
export GEMINI_API_KEY="your-key-here"

# Add to your .bashrc or .zshrc to make it permanent
echo 'export GEMINI_API_KEY="your-key-here"' >> ~/.bashrc
```

Now try:
```bash
reveng analyze --enhanced <binary>
```

### 3. Install Ghidra (Optional)

For advanced decompilation:

1. Download Ghidra from https://ghidra-sre.org/
2. Extract to `external/ghidra/`
3. Start the server:
   ```bash
   cd external/ghidra-server
   pip install flask flask-cors
   python ghidra_http_server.py
   ```
4. Verify:
   ```bash
   curl http://localhost:13370/health
   ```

### 4. Explore Examples

```bash
# List available examples
ls examples/

# Try JavaScript deobfuscation
python examples/javascript_deobfuscation_demo.py

# Advanced features (requires Ghidra)
python examples/advanced/full_recompilation_demo.py
```

### 5. Read the Documentation

- **[CLI Reference](CLI_REFERENCE.md)** - All commands and options
- **[User Guide](docs/user-guide/)** - Detailed usage guides
- **[MCP Integration](docs/mcp/README.md)** - AI agent integration
- **[API Reference](docs/api/API_REFERENCE.md)** - Python API

---

## Troubleshooting

### Command Not Found

**Problem:** `reveng: command not found`

**Solution:**
```bash
# Verify installation
pip show reveng

# If not installed
pip install -e .

# Check PATH
which reveng
```

### Wrong Version

**Problem:** `reveng --version` shows v3.0.0 instead of v4.0.0

**Solution:**
```bash
# Reinstall
pip install -e . --force-reinstall

# Verify
reveng --version
```

### Import Errors

**Problem:** `ModuleNotFoundError: No module named 'reveng'`

**Solution:**
```bash
# Make sure you're in the project directory
cd /path/to/reveng-main

# Check Python path
python3 -c "import sys; print('\n'.join(sys.path))"

# Reinstall
pip install -e .
```

### Analysis Fails

**Problem:** `Error analyzing binary`

**Solutions:**
```bash
# Check file exists
ls -la <binary>

# Check file permissions
chmod +r <binary>

# Run with verbose output
reveng analyze --verbose <binary>

# Check file type
file <binary>
```

### Ghidra Not Working

**Problem:** `Ghidra server not responding`

**Solutions:**
```bash
# Check if server is running
curl http://localhost:13370/health

# Start the server
cd external/ghidra-server
python ghidra_http_server.py

# Check port is not in use
netstat -an | grep 13370
```

### API Errors

**Problem:** `API authentication failed`

**Solutions:**
```bash
# Check API key is set
echo $GEMINI_API_KEY

# Set it temporarily
export GEMINI_API_KEY="your-key"

# Or use config file
cat > ~/.reveng/config.yaml << EOF
ai:
  api_keys:
    gemini: "your-key"
EOF
```

---

## Common Questions

### Do I need API keys?

**No**, for basic analysis. API keys are only required for:
- `reveng analyze --enhanced`
- `reveng ask`
- `reveng ai`

### Do I need Ghidra?

**No**, for most features. Ghidra is optional and provides:
- Advanced decompilation
- Deeper code analysis
- Binary reconstruction

### Can I use REVENG offline?

**Yes**, core features work offline. You can also use local AI with Ollama:

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama2

# Use with REVENG
reveng analyze --ai-provider ollama <binary>
```

### Is REVENG safe to use?

Yes! REVENG:
- Analyzes binaries in a sandboxed environment
- Never executes malware
- Respects privacy (no telemetry)
- Open source (MIT license)

### Where are results saved?

Default locations:
- `./analysis_<binary_name>/` - Analysis results
- `~/.reveng/` - Configuration
- `./reveng_analyzer.log` - Log file

Change with:
```bash
reveng analyze --output-dir custom_dir <binary>
```

---

## Getting Help

### Documentation

- **[CLI Reference](CLI_REFERENCE.md)** - Command reference
- **[Installation Guide](INSTALLATION.md)** - Detailed setup
- **[User Guide](docs/user-guide/)** - How-to guides
- **[API Docs](docs/api/)** - Python API

### Community

- **Issues:** https://github.com/oimiragieo/reveng-main/issues
- **Discussions:** https://github.com/oimiragieo/reveng-main/discussions
- **Email:** contact@reveng-project.org

### Quick Links

- [FAQ](docs/FAQ.md)
- [Troubleshooting Guide](docs/getting-started/troubleshooting.md)
- [Security Policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

---

## What's Next?

Now that you have REVENG working:

1. **Learn the CLI**
   - Try all commands: `analyze`, `triage`, `ask`, `ai`, `serve`
   - Read [CLI_REFERENCE.md](CLI_REFERENCE.md)

2. **Explore Advanced Features**
   - Set up Ghidra for decompilation
   - Enable AI analysis
   - Try JavaScript deobfuscation

3. **Use the Web Interface**
   ```bash
   reveng serve
   # Open http://localhost:3000
   ```

4. **Automate Your Workflow**
   - Write scripts using the Python API
   - Integrate with CI/CD
   - Batch process binaries

5. **Contribute**
   - Report bugs
   - Suggest features
   - Submit pull requests

---

**Congratulations!** You're now ready to use REVENG for binary analysis.

Happy reverse engineering! 🔓

---

*Last updated: November 16, 2025 - v4.0.0*
