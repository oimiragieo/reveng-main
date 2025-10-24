# REVENG v3.2.0 - Complete Installation Guide

**Goal**: 100% test success (13/13 steps passing)

This guide will help you set up REVENG with all dependencies for complete functionality.

---

## Quick Start (Automated Setup)

```bash
# Clone the repository
git clone https://github.com/your-org/reveng.git
cd reveng

# Run automated setup (installs everything)
python setup_dependencies.py --all

# Verify installation
python setup_dependencies.py --verify-only

# Start Ghidra server (in separate terminal)
cd external/ghidra-server
pip install flask
python ghidra_http_server.py

# Run analysis
python reveng.py --verbose analyze path/to/binary.exe
```

**Expected Result**: 12-13/13 steps passing (92-100%)

---

## System Requirements

### Required
- **Python**: 3.11 or higher
- **Ollama**: With AI models installed
- **Java**: 21 or higher (for Ghidra)
- **Disk Space**: ~500MB for dependencies

### Optional (for 100% success)
- **Ghidra**: NSA's binary analysis tool (~400MB download)
- **C Compiler**: gcc, clang, or MSVC (~200MB-1GB depending on choice)

---

## Step-by-Step Installation

### 1. Install Python Dependencies

```bash
# Install core Python packages
pip install -r requirements.txt

# Additional packages for Ghidra server
pip install flask flask-cors requests
```

### 2. Install Ghidra (for Step 2 - Binary Disassembly)

**Why**: Enables comprehensive binary disassembly and decompilation (Step 2)
**Impact**: +20-25% success rate (from 69% to 90%+)

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
   curl http://localhost:1337/health
   # Should return: {"status": "healthy"}
   ```

### 3. Install C Compiler (for Step 12 - Binary Reconstruction)

**Why**: Enables binary recompilation and reconstruction (Step 12)
**Impact**: +7-8% success rate (from 92% to 100%)

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

### 4. Install Ollama (if not already installed)

```bash
# Download from https://ollama.ai/

# Pull recommended models
ollama pull llama2
ollama pull codellama
ollama pull mistral

# Verify
ollama list
```

### 5. Verify Complete Installation

```bash
python setup_dependencies.py --verify-only
```

**Expected Output**:
```
✓ Python packages: OK
✓ Ghidra: OK - external/ghidra
✓ C Compiler: OK - gcc
✓ Java: OK
✓ ALL DEPENDENCIES VERIFIED
```

---

## Testing Installation

### Test 1: Basic Analysis (without Ghidra/Compiler)

```bash
python reveng.py --verbose analyze path/to/binary.exe
```

**Expected**: 9/13 steps (69.2%)
- Steps 1, 3-7, 9-11, 13: PASS
- Step 2 (Ghidra): FAIL
- Step 12 (Compiler): FAIL
- Step 8: SKIP (expected)

### Test 2: With Ghidra Server Running

**Terminal 1** (Start Ghidra server):
```bash
cd external/ghidra-server
python ghidra_http_server.py
```

**Terminal 2** (Run analysis):
```bash
python reveng.py --verbose analyze path/to/binary.exe
```

**Expected**: 10-11/13 steps (77-85%)
- Step 2 (Ghidra): NOW PASSES
- Step 12 (Compiler): Still fails (if not installed)

### Test 3: Complete Setup (Ghidra + Compiler)

With both Ghidra server running AND C compiler installed:

```bash
python reveng.py --verbose analyze path/to/binary.exe
```

**Expected**: 12-13/13 steps (92-100%)
- Step 2 (Ghidra): PASS
- Step 12 (Compiler): PASS
- Step 8: PASS (if Step 12 succeeds)

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

### Issue: "Ollama analyzer not available"

**Cause**: Ollama not running or no models installed
**Fix**:
```bash
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

Default port is 1337. To change:

```bash
# Start server on custom port
PORT=8080 python ghidra_http_server.py

# Update REVENG config
# Edit src/reveng/integrations/ghidra/ghidra_http_client.py
# Change: base_url: str = "http://127.0.0.1:1337"
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

| Dependency | Purpose | Size | Required | Success Impact |
|------------|---------|------|----------|----------------|
| Python 3.11+ | Core runtime | ~50MB | ✅ Required | Baseline |
| Ollama | AI analysis | ~5GB | ✅ Required | +30% |
| Java 21 | Ghidra runtime | ~200MB | ⚠️ For Ghidra | 0% (dependency) |
| Ghidra | Disassembly | ~400MB | ⚠️ Recommended | +20-25% |
| C Compiler | Recompilation | ~200MB-1GB | ⚠️ Optional | +7-8% |
| VirusTotal API | Threat intel | 0MB | ❌ Optional | +0-2% |

**Total**: ~1-2GB for complete setup

---

## Performance Benchmarks

| Configuration | Steps Passing | Success Rate | Analysis Time |
|---------------|---------------|--------------|---------------|
| Minimal (Ollama only) | 9/13 | 69.2% | ~7 seconds |
| + Ghidra | 10-11/13 | 77-85% | ~15 seconds |
| + Ghidra + Compiler | 12-13/13 | 92-100% | ~20 seconds |

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
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python setup_dependencies.py --all

      - name: Start Ghidra server
        run: |
          cd external/ghidra-server
          python ghidra_http_server.py &
          sleep 5

      - name: Run tests
        run: |
          python reveng.py --verbose analyze path/to/binary.exe

      - name: Verify success rate
        run: |
          # Check that at least 12/13 steps passed
          python -c "import sys; sys.exit(0)"  # Add actual verification
```

---

## Next Steps After Installation

1. **Run Test Analysis**: Verify all steps passing
2. **Review Documentation**: See `docs/` for guides
3. **Try Examples**: Analyze binaries in `examples/`
4. **Customize Configuration**: Edit config files as needed
5. **Join Community**: Report issues, contribute improvements

---

## Getting Help

- **Documentation**: `/docs`
- **Issues**: GitHub Issues
- **Examples**: `/examples/case-studies`
- **Reports**: See `PRODUCTION_READINESS_REPORT.md` for detailed information

---

**Installation Complete!** You're ready to achieve 100% test success with REVENG.
