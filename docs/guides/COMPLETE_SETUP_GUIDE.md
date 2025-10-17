# REVENG Complete Setup Guide for AI Agent Usage

**Complete step-by-step guide to install and configure REVENG for AI agent integration**

This guide covers everything needed to get REVENG working with AI agents (Claude Code, Gemini CLI, Ollama).

---

## 📋 Table of Contents

1. [Prerequisites & Dependencies](#prerequisites--dependencies)
2. [Core Installation](#core-installation)
3. [Ghidra Installation](#ghidra-installation-required)
4. [IDA Pro Integration (Optional)](#ida-pro-integration-optional)
5. [AI Integration Setup](#ai-integration-setup)
6. [Verification & Testing](#verification--testing)
7. [Workflow Walkthrough](#workflow-walkthrough)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites & Dependencies

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **OS** | Windows 10, Ubuntu 20.04, macOS 10.15 | Windows 11, Ubuntu 22.04, macOS 13+ |
| **Python** | 3.11+ | 3.12+ |
| **RAM** | 8GB | 16GB |
| **Storage** | 5GB | 20GB |
| **CPU** | 4 cores | 8+ cores |

### Required External Tools

#### 1. **Ghidra** (REQUIRED)
- **What**: Professional-grade disassembler/decompiler from NSA
- **Why**: REVENG uses Ghidra for all disassembly and decompilation
- **Cost**: Free, open-source
- **License**: Apache 2.0

#### 2. **Java Development Kit 21** (REQUIRED for Ghidra)
- **What**: Java runtime environment
- **Why**: Ghidra is a Java application
- **Cost**: Free

#### 3. **IDA Pro Free** (OPTIONAL)
- **What**: Interactive disassembler (limited free version)
- **Why**: Alternative/complementary disassembler to Ghidra
- **Cost**: Free version available, commercial license $589-$3,199
- **License**: Free version requires registration, limited features

#### 4. **Ollama** (OPTIONAL but HIGHLY RECOMMENDED for AI)
- **What**: Local LLM inference engine
- **Why**: Powers natural language queries, instant triage, code enhancement
- **Cost**: Free, open-source
- **License**: MIT

---

## Core Installation

### Step 1: Install Python 3.11+

#### Windows
```cmd
# Download from python.org
# OR use winget
winget install Python.Python.3.12

# Verify
python --version  # Should show 3.11.x or higher
```

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3.11 python3.11-pip python3.11-venv
python3.11 --version
```

#### macOS
```bash
# Using Homebrew
brew install python@3.11

# OR download from python.org
```

### Step 2: Install REVENG

```bash
# Clone repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main

# Create virtual environment (RECOMMENDED)
python -m venv venv

# Activate virtual environment
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate

# Install core dependencies
pip install -r requirements.txt

# Install optional features (RECOMMENDED)
pip install -r requirements-optional.txt
```

**What gets installed:**
- `requirements.txt`: Core dependencies (lief, capstone, keystone, ghidramcp, etc.)
- `requirements-optional.txt`: AI features (ollama, vt-py, yara-python, pycparser, black, pylint)

---

## Ghidra Installation (REQUIRED)

### Step 1: Install Java 21

#### Windows
```cmd
# Download from https://adoptium.net/temurin/releases/
# Select: Java 21 (LTS), Windows, x64, JDK

# OR use winget
winget install EclipseAdoptium.Temurin.21.JDK

# Verify
java --version  # Should show "openjdk 21.x.x"
```

#### Linux
```bash
sudo apt install openjdk-21-jdk
java --version
```

#### macOS
```bash
brew install openjdk@21
java --version
```

### Step 2: Download Ghidra

```bash
# Download latest release
# Visit: https://github.com/NationalSecurityAgency/ghidra/releases
# Download: ghidra_11.0.1_PUBLIC_yyyymmdd.zip (or latest version)
```

**Direct link** (as of 2025):
https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.1_build/ghidra_11.0.1_PUBLIC_20231221.zip

### Step 3: Extract & Configure Ghidra

#### Windows
```cmd
# Extract to C:\ghidra
# Set environment variable
setx GHIDRA_INSTALL_DIR "C:\ghidra_11.0.1_PUBLIC"

# Add to PATH (optional, for ghidraRun command)
setx PATH "%PATH%;C:\ghidra_11.0.1_PUBLIC"
```

#### Linux/macOS
```bash
# Extract
unzip ghidra_11.0.1_PUBLIC_20231221.zip
sudo mv ghidra_11.0.1_PUBLIC /opt/ghidra

# Set environment variable
echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra' >> ~/.bashrc
source ~/.bashrc

# Make executable
chmod +x /opt/ghidra/ghidraRun
```

### Step 4: Verify Ghidra Installation

```bash
# Test Ghidra launch
# Windows:
%GHIDRA_INSTALL_DIR%\ghidraRun.bat

# Linux/macOS:
$GHIDRA_INSTALL_DIR/ghidraRun
```

**Expected**: Ghidra GUI should open. Close it for now.

---

## IDA Pro Integration (OPTIONAL)

### IDA Pro Free vs Pro

| Feature | Free Version | Pro Version |
|---------|--------------|-------------|
| Cost | Free (registration required) | $589 (Standard) - $3,199 (Professional) |
| Architecture Support | x86, x86-64 only | All architectures (ARM, MIPS, etc.) |
| Decompiler | ❌ Not included | ✅ Included |
| File Types | Limited | All formats |
| Scripting | Python & IDC | Python & IDC |
| Commercial Use | ❌ Not allowed | ✅ Allowed |

### Installing IDA Free

**⚠️ IMPORTANT**: IDA Free requires registration and is for **non-commercial use only**.

1. **Register & Download**:
   - Visit: https://hex-rays.com/ida-free/
   - Create free account
   - Download IDA Free 8.4 (or latest)

2. **Install IDA Free**:
   ```cmd
   # Windows: Run installer
   # Default install: C:\Program Files\IDA Freeware 8.4

   # Set environment variable (optional)
   setx IDA_INSTALL_DIR "C:\Program Files\IDA Freeware 8.4"
   ```

3. **Limitations to Know**:
   - **x86/x64 only** (no ARM, MIPS support)
   - **No decompiler** (Ghidra has one, so use Ghidra for decompilation)
   - **Non-commercial use only**
   - Older file format support

### REVENG + IDA Pro Integration

**Current Status**: REVENG primarily uses Ghidra, IDA Pro support is **limited/experimental**.

**MCP Server for IDA**: REVENG includes MCP (Model Context Protocol) support for IDA Pro.

```python
# Check if IDA MCP tools are available
from mcp import ida_pro_mcp

# Tools available (if IDA MCP server is running):
# - get_function_by_name()
# - decompile_function()
# - get_xrefs_to()
# - etc.
```

**Recommendation**: Use **Ghidra** for primary disassembly. IDA Pro is optional for comparison/verification.

---

## AI Integration Setup

### Option 1: Ollama (RECOMMENDED for AI Features)

**Ollama** is REQUIRED for:
- ✅ Natural language queries (`reveng ask`)
- ✅ Instant triage (`reveng triage`)
- ✅ Code quality enhancement
- ✅ AI-powered analysis

#### Install Ollama

**Windows/macOS/Linux**:
```bash
# Visit https://ollama.ai
# Download and install for your OS

# OR use package managers:
# macOS:
brew install ollama

# Linux:
curl -fsSL https://ollama.ai/install.sh | sh

# Windows:
# Download installer from https://ollama.ai/download
```

#### Pull Language Model

```bash
# Start Ollama server
ollama serve

# In another terminal, pull a model
ollama pull llama3  # Recommended for general queries (4.7GB)

# OR for code-focused tasks:
ollama pull codellama  # Better for code analysis (7GB)

# OR for lightweight/fast:
ollama pull mistral  # Smaller model (4GB)
```

#### Verify Ollama

```bash
# Check Ollama is running
curl http://localhost:11434/api/tags

# Test with Python
python -c "import ollama; print(ollama.list())"
```

**Expected**: Should list available models.

### Option 2: Claude Code (Anthropic)

**Claude Code** is an AI coding assistant IDE plugin.

#### Install Claude Code Extension

**For VS Code**:
1. Install extension from VS Code Marketplace: "Claude Code"
2. Configure API key:
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-your-key-here
   ```

#### Configure REVENG with Claude Code

Create `.claude-code/config.json`:
```json
{
  "tools": {
    "reveng": {
      "command": "python",
      "args": ["src/reveng/ai_api.py"],
      "enabled": true
    }
  }
}
```

#### Usage with Claude Code

```python
# Claude Code can now call REVENG API directly
from reveng.ai_api import REVENG_AI_API

api = REVENG_AI_API()
result = api.triage_binary("suspicious.exe")
```

### Option 3: Gemini CLI (Google)

**Not yet officially supported**. REVENG focuses on Ollama (local) and Claude (API).

**Workaround**:
```python
# Use REVENG Python API from Gemini CLI scripts
import subprocess
result = subprocess.run(
    ["python", "-m", "reveng.ai_api", "triage", "binary.exe"],
    capture_output=True
)
```

---

## Verification & Testing

### Test 1: Core REVENG Installation

```bash
# Activate virtual environment
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate  # Windows

# Check dependencies
python -c "import lief; import capstone; import keystone; print('Core deps: OK')"

# Check optional deps
python -c "import ollama; import yara; import vt; print('Optional deps: OK')"
```

### Test 2: Ghidra Integration

```bash
# Check Ghidra environment variable
echo $GHIDRA_INSTALL_DIR  # Linux/macOS
echo %GHIDRA_INSTALL_DIR%  # Windows

# Test Ghidra MCP connector
python -c "from ghidramcp import GhidraMCP; print('Ghidra MCP: OK')"
```

### Test 3: Ollama Integration

```bash
# Check Ollama server
curl http://localhost:11434/api/tags

# Test Python integration
python -c "import ollama; models = ollama.list(); print(f'Ollama models: {len(models[\"models\"])}')"
```

### Test 4: Full Workflow Test

```bash
# Create test binary
echo 'int main() { return 0; }' > test.c
gcc test.c -o test

# Run REVENG AI API
python -c "
from reveng.ai_api import REVENG_AI_API
api = REVENG_AI_API()

# Quick triage
triage = api.triage_binary('test')
print(f'Threat score: {triage.threat_score}/100')

# Ask question
response = api.ask('What does this binary do?', 'test')
print(f'Answer: {response.answer}')
"
```

**Expected output**:
```
Threat score: 5/100
Answer: This is a simple benign test binary that exits immediately...
```

---

## Workflow Walkthrough

### Scenario: Analyze suspicious.exe with AI Agent

Let me walk through **exactly what happens** when an AI agent uses REVENG:

#### Step 1: AI Agent Initializes API

```python
from reveng.ai_api import REVENG_AI_API

api = REVENG_AI_API(
    use_ollama=True,      # Use local LLM
    ollama_model='llama3' # Specify model
)
```

**What happens:**
1. Python imports REVENG modules
2. Checks if Ollama is available (`import ollama`)
3. Initializes `InstantTriageEngine` and `NaturalLanguageInterface`

#### Step 2: AI Agent Performs Triage

```python
triage = api.triage_binary("suspicious.exe")
```

**What happens (micro detail):**
1. `InstantTriageEngine` loads `suspicious.exe` with LIEF
2. Extracts PE headers, sections, imports, strings
3. Calculates entropy for each section
4. Detects packed/obfuscated code
5. Checks imports against suspicious API lists
6. Calculates threat score (0-100) based on:
   - Packer detection
   - Suspicious imports (VirtualAlloc, WriteProcessMemory)
   - High entropy sections
   - Missing headers
7. Returns `TriageResult` dataclass with:
   - `threat_level`: "LOW", "MEDIUM", "HIGH", or "CRITICAL"
   - `threat_score`: 0-100
   - `confidence`: 0.0-1.0
   - `detected_capabilities`: ["network", "file_io", etc.]

**No Ghidra used yet** - triage is static analysis only.

#### Step 3: AI Agent Asks Natural Language Question

```python
response = api.ask("What network functions does this use?", "suspicious.exe")
```

**What happens:**
1. `NaturalLanguageInterface.parse_query()` analyzes question
   - Detects intent: `FIND_FUNCTIONS`
   - Extracts parameters: `capability='network'`
   - Calculates query confidence: 0.85
2. **Ghidra analysis triggered** (if not already done):
   - Spawns Ghidra process via `ghidramcp`
   - Loads `suspicious.exe` in Ghidra
   - Runs decompilation on all functions
   - Extracts function names, imports, strings, xrefs
   - Saves results to JSON
3. Filters functions by network capability:
   - Looks for: `WinHttpOpen`, `InternetOpenW`, `socket`, etc.
   - Returns matching functions
4. **Ollama LLM integration** (if available):
   - Prepares context from analysis results
   - Sends prompt to Ollama:
     ```
     Analyze this binary and answer:
     File Type: PE32
     Functions: 127 identified
     Network-related: [WinHttpOpen, WinHttpConnect, WinHttpSendRequest]

     Question: What network functions does this use?
     ```
   - Receives natural language answer from Ollama
5. Calculates response confidence:
   - Query confidence: 0.85
   - Data completeness: 0.90 (has function data)
   - Answer length: 0.70
   - LLM used: +0.05
   - **Final confidence: 0.82**
6. Returns `NLResponse`:
   ```python
   NLResponse(
       answer="This binary uses WinHTTP API for network communication...",
       confidence=0.82,
       intent="find_functions",
       sources=["fresh_analysis", "llm_llama3"],
       metadata={...}
   )
   ```

#### Step 4: AI Agent Gets Translation Hints

```python
# Assume Ghidra decompiled to C code
hints = api.get_translation_hints("decompiled_suspicious.c")
```

**What happens:**
1. Reads `decompiled_suspicious.c` file
2. `pattern_matcher.detect_api_calls()` scans for Windows APIs:
   - Uses regex to find `CreateFileW(...)`, `WinHttpOpen(...)`, etc.
   - Extracts line numbers, variables used
3. `api_mappings.get_api_mapping()` looks up each API:
   ```python
   # Example:
   {
       "CreateFileW": {
           "python_equivalent": "open(path, mode)",
           "example": "with open(filepath, 'rb') as f:\n    data = f.read()",
           "imports": ["pathlib"],
           "notes": "Use pathlib.Path for cross-platform paths"
       }
   }
   ```
4. `hint_generator.generate_translation_hints()` creates guide:
   - Groups hints by category (file_io, network, etc.)
   - Calculates complexity: "moderate"
   - Lists required imports: `["pathlib", "requests", "hashlib"]`
   - Generates summary and statistics
5. Returns `TranslationGuide` dataclass

#### Step 5: AI Agent Performs Full Analysis

```python
results = api.analyze_binary("suspicious.exe", mode=AnalysisMode.REBUILD)
```

**What happens:**
1. Runs instant triage (Step 2)
2. **Full Ghidra analysis**:
   - Decompiles ALL functions
   - Generates control flow graphs
   - Performs data flow analysis
   - Extracts strings, xrefs, structures
3. Generates translation hints for all decompiled C files
4. Saves comprehensive JSON report
5. Returns all results

---

### Execution Time Breakdown

| Step | Tool Used | Time |
|------|-----------|------|
| Triage | LIEF + custom logic | 10-30 seconds |
| Ghidra decompilation | Ghidra headless | 2-10 minutes |
| Natural language query | Ollama | 1-3 seconds |
| Translation hints | pycparser | <1 second |
| **Total (full analysis)** | All | **3-12 minutes** |

---

## Troubleshooting

### Issue: "ghidramcp module not found"

**Cause**: `requirements.txt` has ghidramcp but it may not be installed.

**Fix**:
```bash
pip install ghidramcp --upgrade
# OR
pip install -r requirements.txt --force-reinstall
```

### Issue: "GHIDRA_INSTALL_DIR not set"

**Cause**: Environment variable not configured.

**Fix**:
```bash
# Windows (cmd):
setx GHIDRA_INSTALL_DIR "C:\ghidra_11.0.1_PUBLIC"

# Windows (PowerShell):
[System.Environment]::SetEnvironmentVariable("GHIDRA_INSTALL_DIR", "C:\ghidra_11.0.1_PUBLIC", "User")

# Linux/macOS:
export GHIDRA_INSTALL_DIR=/opt/ghidra
echo 'export GHIDRA_INSTALL_DIR=/opt/ghidra' >> ~/.bashrc
```

### Issue: "Ollama connection refused"

**Cause**: Ollama server not running.

**Fix**:
```bash
# Start Ollama server
ollama serve

# In another terminal, test
curl http://localhost:11434/api/tags
```

### Issue: "No models available in Ollama"

**Cause**: No models downloaded.

**Fix**:
```bash
ollama pull llama3
ollama pull codellama
ollama list  # Verify models
```

### Issue: "Java version mismatch"

**Cause**: Ghidra requires Java 21, but older version installed.

**Fix**:
```bash
# Check version
java --version

# Install Java 21
# Windows: winget install EclipseAdoptium.Temurin.21.JDK
# Linux: sudo apt install openjdk-21-jdk
# macOS: brew install openjdk@21

# Set JAVA_HOME
export JAVA_HOME=/usr/lib/jvm/java-21-openjdk
```

---

## Next Steps

1. ✅ Verify all installations with tests above
2. 📖 Read [AI API Reference](../api/AI_API_REFERENCE.md)
3. 🔬 Try [Binary Rebuild Workflow](REBUILD_WORKFLOW_EXAMPLE.md)
4. 🤖 Integrate with your AI agent (Claude Code, custom scripts)

---

## Summary Checklist

- [ ] Python 3.11+ installed
- [ ] REVENG cloned and dependencies installed
- [ ] Java 21 installed
- [ ] Ghidra downloaded, extracted, and `GHIDRA_INSTALL_DIR` set
- [ ] (Optional) IDA Free downloaded and installed
- [ ] (Recommended) Ollama installed and model pulled
- [ ] All verification tests pass
- [ ] Example workflow runs successfully

**Installation time**: ~30 minutes (first time), ~10 minutes (subsequent)

**Ready to use REVENG!** 🚀
