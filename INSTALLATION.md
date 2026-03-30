# REVENG v4.0.0 - Installation Quick Reference

> 📘 **For the Complete Installation Guide:** This is a quick reference. For the most up-to-date, comprehensive installation instructions, see **[docs/getting-started/installation.md](docs/getting-started/installation.md)**.
>
> **Quick links:**
> - **Complete Guide:** [`docs/getting-started/installation.md`](docs/getting-started/installation.md)
> - **Quick Start (2 min):** [`QUICK_START.md`](QUICK_START.md)
> - **Getting Started:** [`GETTING_STARTED.md`](GETTING_STARTED.md)

**Goal**: Full platform functionality with MCP, GPU acceleration, and advanced features

This quick reference provides installation essentials. For detailed troubleshooting, advanced configuration, and platform-specific instructions, see the complete guide linked above.

---

## Quick Start (Automated Setup)

```bash
# Clone the repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main

# Run automated installer
./install-reveng.sh

# Verify installation
reveng --version
# Should show: REVENG v4.0.0 (Production/Stable)

# Optional: Start Ghidra server (in separate terminal)
cd external/ghidra-server
pip install flask flask-cors
python ghidra_http_server.py

# Run your first analysis
reveng analyze path/to/binary.exe
```

**Expected Result**: Full REVENG functionality including binary analysis, decompilation, and optional features like Ghidra integration and MCP server

---

## System Requirements

### Required
- **Python**: 3.9 or higher
- **pip**: Python package manager
- **Git**: Version control system
- **Disk Space**: ~500MB for dependencies

### Optional (for advanced features)
- **Ghidra**: NSA's binary analysis tool (~400MB download)
- **Java**: 21 or higher (required for Ghidra)
- **Node.js**: 18+ (for JavaScript deobfuscation)
- **C Compiler**: gcc, clang, or MSVC (~200MB-1GB depending on choice)

---

## Step-by-Step Installation

### 1. Install Python Dependencies

```bash
# Install core Python packages
pip install -r requirements.txt

# Install REVENG package
pip install -e .

# Verify installation
reveng --version
```

#### Windows First-Run Setup

For Windows users, REVENG now includes a first-run setup script that installs Python dependencies, validates the bundled Ghidra distribution, starts the local Ghidra HTTP server, checks Ollama/compiler availability, and runs a smoke test:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup_first_run.ps1
```

Useful flags:

```powershell
# Verification only (skip package installation)
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup_first_run.ps1 -VerifyOnly

# Skip the smoke test if you only want environment prep
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\setup_first_run.ps1 -SkipSmokeTest
```

### 2. Install Ghidra (Optional - for Advanced Binary Disassembly)

**Why**: Enables comprehensive binary disassembly and decompilation with Ghidra integration
**Impact**: Access to advanced decompilation features and AI-enhanced analysis

#### Option A: Automated Installation
```bash
python setup_dependencies.py --ghidra-only
```

#### Option B: Manual Installation

1. **Download Ghidra**:
   - Visit: https://ghidra-sre.org/
   - Download: Ghidra 11.0.1 or later
   - Size: ~400MB

2. **Extract Ghidra**:
   ```bash
   # Extract to external/ghidra/
   unzip ghidra_11.0.1_PUBLIC_20240130.zip
   mv ghidra_11.0.1_PUBLIC external/ghidra
   ```

3. **Verify Java**:
   ```bash
   java -version
   # Should be Java 21 or higher
   ```

4. **Start Ghidra Server**:
   ```bash
   cd external/ghidra-server
   pip install flask
   python ghidra_http_server.py
   ```

5. **Test Ghidra Server**:
   ```bash
   curl http://localhost:13370/health
   # Should return: {"status": "healthy"}
   ```

   **Note**: The default port is 13370. If you need to use a different port, set it in your configuration.

### 3. Install C Compiler (Optional - for Binary Reconstruction)

**Why**: Enables binary recompilation and reconstruction features
**Impact**: Access to full binary-to-source-to-binary pipeline

#### Windows

**Option A: MinGW (Recommended)**
```bash
# Via Chocolatey
choco install mingw -y

# Or download manually
# https://github.com/niXman/mingw-builds-binaries/releases
# Extract to C:\mingw64
# Add C:\mingw64\bin to PATH
```

**Option B: Visual Studio Build Tools**
```bash
# Download from Microsoft
# https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2022
# Install "Desktop development with C++" workload
```

**Option C: LLVM/Clang**
```bash
choco install llvm -y
```

**Verify Installation**:
```bash
gcc --version
# OR
clang --version
# OR
cl
```

#### Linux

```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install build-essential -y

# RedHat/CentOS
sudo yum groupinstall "Development Tools" -y

# Arch
sudo pacman -S base-devel

# Verify
gcc --version
```

#### macOS

```bash
# Install Xcode Command Line Tools
xcode-select --install

# Verify
clang --version
```

### 4. Set Up AI Features (Optional)

```bash
# Option 1: Google Gemini (recommended, free tier available)
export GEMINI_API_KEY="your-api-key-here"
# Get from: https://makersuite.google.com/app/apikey

# Option 2: OpenAI GPT-4 (optional)
pip install openai
export OPENAI_API_KEY="sk-your-key-here"

# Option 3: Anthropic Claude (optional)
export ANTHROPIC_API_KEY="sk-ant-your-key-here"

# Option 4: Local LLM with Ollama (free, offline)
# Download from https://ollama.ai/
ollama pull llama2
ollama pull codellama
```

### 5. Verify Complete Installation

```bash
# Verify REVENG installation
reveng --version

# Check Python imports
python3 -c "from reveng.analyzer import REVENGAnalyzer; print('✓ Core modules OK')"

# Optional: Install verification script
./verify-installation.sh
```

**Expected Output**:
```
REVENG v4.0.0 (Production/Stable)
✓ Core modules OK
```

---

## Testing Installation

### Test 1: Basic Analysis (Core Features)

```bash
reveng analyze path/to/binary.exe
```

**Expected**: Basic analysis succeeds with core features:
- Binary format detection
- Static analysis
- Basic security checks
- Output report generation

### Test 2: With Ghidra Integration

**Terminal 1** (Start Ghidra server):
```bash
cd external/ghidra-server
python ghidra_http_server.py
```

**Terminal 2** (Run enhanced analysis):
```bash
reveng analyze --enhanced path/to/binary.exe
```

**Expected**: Enhanced analysis with:
- Ghidra decompilation
- Advanced code analysis
- Type reconstruction
- Comprehensive vulnerability detection

### Test 3: MCP Server (v4.0 Feature)

Test the new Model Context Protocol integration:

```bash
# Start MCP server
./reveng-mcp-server

# In another terminal, validate MCP
./validate-mcp.py
```

**Expected**: MCP server starts successfully and responds to health checks

### Test 4: JavaScript Deobfuscation

```bash
# Install JavaScript tools
./install-js-deob.sh

# Test deobfuscation
./reveng-js deobfuscate path/to/obfuscated.js -o clean.js
```

**Expected**: Successfully deobfuscates JavaScript files

---

## Troubleshooting

### Issue: "Ghidra Analysis Server returned status 426"

**Cause**: Ghidra server not running
**Fix**:
```bash
cd external/ghidra-server
python ghidra_http_server.py
```

### Issue: "No compatible toolchain found for X86_64"

**Cause**: C compiler not installed
**Fix**: Install gcc, clang, or MSVC (see Step 3 above)

### Issue: "API authentication failed"

**Cause**: AI API keys not configured
**Fix**:
```bash
# Set your API key(s)
export GEMINI_API_KEY="your-key-here"
# Or for local LLM with Ollama
ollama serve &
ollama pull llama2
```

### Issue: "Java not found" (for Ghidra)

**Cause**: Java not installed or not in PATH
**Fix**:
```bash
# Download Java 21 from https://adoptium.net/
# Verify installation
java -version
```

### Issue: "ModuleNotFoundError: No module named 'flask'"

**Cause**: Flask not installed
**Fix**:
```bash
pip install flask flask-cors
```

---

## Configuration Files

### Optional: VirusTotal API Key

For enhanced threat intelligence (Step 11):

1. Get API key from https://www.virustotal.com/
2. Create config file:
   ```bash
   mkdir -p ~/.reveng
   cat > ~/.reveng/config.yaml << EOF
   virustotal:
     api_key: YOUR_API_KEY_HERE
   EOF
   ```

### Optional: Custom Ghidra Port

Default port is 13370. To change:

```bash
# Start server on custom port
PORT=8080 python ghidra_http_server.py

# Update REVENG config
# Edit src/reveng/integrations/ghidra/ghidra_http_client.py
# Change: base_url: str = "http://127.0.0.1:13370"
# To:     base_url: str = "http://127.0.0.1:8080"
```

---

## Directory Structure After Installation

```
reveng/
├── external/
│   ├── ghidra/              # Ghidra installation
│   │   ├── ghidraRun
│   │   ├── support/
│   │   └── ...
│   ├── ghidra-server/       # HTTP server wrapper
│   │   ├── ghidra_http_server.py
│   │   └── README.md
│   └── mingw64/             # MinGW (Windows only)
│       └── bin/
│           └── gcc.exe
├── src/                     # REVENG source code
├── docs/                    # Documentation
├── examples/                # Example binaries
├── tests/                   # Test suite
├── setup_dependencies.py    # Automated setup script
├── requirements.txt         # Python dependencies
└── INSTALLATION.md          # This file
```

---

## Dependency Summary

| Dependency | Purpose | Size | Required | Feature Impact |
|------------|---------|------|----------|----------------|
| Python 3.9+ | Core runtime | ~50MB | ✅ Required | Core functionality |
| pip packages | Python libraries | ~200MB | ✅ Required | Core functionality |
| Gemini API | AI analysis | 0MB | ⚠️ Recommended | AI-enhanced analysis |
| Java 21 | Ghidra runtime | ~200MB | ⚠️ For Ghidra | Advanced decompilation |
| Ghidra | Disassembly | ~400MB | ⚠️ Recommended | Advanced decompilation |
| Node.js | JS deobfuscation | ~50MB | ⚠️ Optional | JavaScript analysis |
| C Compiler | Recompilation | ~200MB-1GB | ⚠️ Optional | Binary reconstruction |

**Total**: ~500MB (minimal) to ~2GB (complete setup)

---

## Performance Benchmarks

| Configuration | Feature Coverage | Analysis Time |
|---------------|------------------|---------------|
| Minimal (Core only) | Basic analysis | ~5 seconds |
| + Gemini/AI | AI-enhanced analysis | ~10 seconds |
| + Ghidra | Advanced decompilation | ~15 seconds |
| Complete (All features) | Full pipeline | ~20-30 seconds |

---

## Automated CI/CD Setup

For continuous integration:

```yaml
# .github/workflows/test.yml
name: REVENG Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Set up Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          ./install-reveng.sh

      - name: Run tests
        run: |
          pytest tests/ -v

      - name: Test CLI
        run: |
          reveng --version
          reveng analyze test_samples/simple_binary
```

---

## Next Steps After Installation

1. **Run Test Analysis**: `reveng analyze test_samples/simple_binary`
2. **Review Documentation**: See [GETTING_STARTED.md](GETTING_STARTED.md)
3. **Try Examples**: Run `python examples/my_first_analysis.py`
4. **Explore CLI**: Check [CLI_REFERENCE.md](CLI_REFERENCE.md)
5. **Join Community**: https://github.com/oimiragieo/reveng-main

---

## Getting Help

- **Quick Start**: [QUICK_START.md](QUICK_START.md)
- **Full Installation Guide**: [docs/getting-started/installation.md](docs/getting-started/installation.md)
- **CLI Reference**: [CLI_REFERENCE.md](CLI_REFERENCE.md)
- **Issues**: https://github.com/oimiragieo/reveng-main/issues
- **Documentation**: [docs/](docs/)

---

**Installation Complete!** You're ready to start reverse engineering with REVENG v4.0.0.
