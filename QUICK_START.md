# REVENG Quick Start Guide

Get REVENG running in **2 minutes** and start analyzing binaries immediately.

---

## ⚡ Installation (One Command!)

```bash
# 1. Clone repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main

# 2. Run installer (installs EVERYTHING)
./install-reveng.sh

# That's it! 🎉
```

The installer handles:
- ✅ Python dependencies
- ✅ REVENG package (`reveng` command)
- ✅ JavaScript deobfuscation module
- ✅ Verification

**Installation time: ~2 minutes**

---

## 🚀 First Steps

### 1. Analyze a Binary (Python/Java/Native)

```bash
# Analyze any binary
reveng analyze /path/to/binary.exe

# With AI enhancement (requires API keys)
reveng analyze --enhanced malware.jar

# Triage mode (quick 30-second analysis)
reveng triage suspicious.dll
```

### 2. Deobfuscate JavaScript

```bash
# Basic deobfuscation (free)
./reveng-js deobfuscate obfuscated.js -o clean.js

# With ML variable renaming
./reveng-js deobfuscate obfuscated.js --ml -o clean.js

# Analyze for malware
./reveng-js analyze suspicious.js
```

### 3. Run Example Demos

```bash
# JavaScript deobfuscation demo
python examples/javascript_deobfuscation_demo.py

# Interactive analysis (requires Ghidra - see Optional Setup)
python examples/advanced/full_recompilation_demo.py
```

---

## 📊 What Can REVENG Do?

### Binary Analysis
- **Decompilation** - Ghidra integration for native binaries
- **AI Enhancement** - Gemini/Claude/GPT-4 code improvement
- **Vulnerability Discovery** - Automatic security analysis
- **Exploit Generation** - Working PoC exploits
- **Recompilation** - Binary → Source → Binary reconstruction

### JavaScript Reverse Engineering
- **Deobfuscation** - 10-stage pipeline (webcrack, UnuglifyJS, Babel)
- **Malware Detection** - 10 threat categories, 50+ signatures
- **ML Variable Renaming** - 60-80% accuracy
- **LLM Enhancement** - GPT-4/Claude integration (optional)

### Languages Supported
- ✅ **Native**: C/C++ binaries (.exe, .dll, .so, .dylib)
- ✅ **Java**: JAR, WAR, EAR files
- ✅ **C#**: .NET assemblies
- ✅ **Python**: Compiled .pyc files
- ✅ **JavaScript**: Obfuscated/minified code

---

## 🎯 Common Use Cases

### Security Research
```bash
# Analyze malware sample
reveng triage malware.exe

# Deobfuscate malicious JavaScript
./reveng-js analyze --json report.json malware.js
```

### Vulnerability Discovery
```bash
# Find vulnerabilities with AI
reveng analyze --enhanced vulnerable.dll
```

### Reverse Engineering
```bash
# Analyze closed-source software
reveng analyze proprietary.jar
```

### Code Quality
```bash
# Analyze and improve decompiled code
reveng enhance-code decompiled.c
```

---

## 🔧 Optional Setup (Advanced Features)

### For Ghidra Integration (Binary Disassembly)

**Why?** Enables comprehensive binary disassembly and decompilation.

1. **Download Ghidra**:
   - Visit: https://ghidra-sre.org/
   - Download: Ghidra 11.0+ (~400MB)

2. **Extract and Run Server**:
   ```bash
   # Extract to external/ghidra/
   unzip ghidra_*.zip
   mv ghidra_*_PUBLIC external/ghidra

   # Start Ghidra server (in separate terminal)
   cd external/ghidra-server
   pip install flask flask-cors
   python ghidra_http_server.py
   ```

3. **Verify**:
   ```bash
   curl http://localhost:13370/health
   # Should return: {"status": "healthy"}
   ```

   **Note**: The Ghidra server runs on port 13370 by default.

### For AI Features

```bash
# Gemini (Google)
export GEMINI_API_KEY="your-key-here"
# Get from: https://makersuite.google.com/app/apikey

# OpenAI (GPT-4)
export OPENAI_API_KEY="sk-your-key-here"
# Get from: https://platform.openai.com/api-keys

# Anthropic (Claude)
export ANTHROPIC_API_KEY="sk-ant-your-key-here"
# Get from: https://console.anthropic.com/

# Local LLM (Ollama - free!)
# Install from: https://ollama.ai/
ollama pull llama2  # Or other models
```

---

## 💡 Tips

### JavaScript Deobfuscation
```bash
# Use cache for faster repeated analysis
./reveng-js deobfuscate file.js  # First time: 10s
./reveng-js deobfuscate file.js  # Cache hit: <100ms

# Check what obfuscation was used
./reveng-js detect obfuscated.js

# View cache stats
./reveng-js cache --stats
```

### Binary Analysis
```bash
# Quick triage (no AI needed)
reveng triage unknown.exe

# Full analysis with AI
reveng analyze --enhanced unknown.exe

# Generate YARA rule
reveng generate-yara malware.exe
```

---

## 🆘 Troubleshooting

### `reveng: command not found`

```bash
# Make sure you ran the installer
./install-reveng.sh

# Or install manually
pip install -e .
```

### `./reveng-js: command not found`

```bash
# Make it executable
chmod +x reveng-js

# Or run with python
python reveng-js deobfuscate file.js
```

### Import errors

```bash
# Make sure you're in the project root
cd /path/to/reveng-main

# Reinstall
pip install -e . --force-reinstall
```

### Node.js tools not found (JavaScript deobfuscation)

```bash
# Install Node.js dependencies
npm install -g webcrack prettier unuglify-js

# Or run the JS installer again
./install-js-deob.sh
```

---

## 📚 Next Steps

### Learn More
- **[Full Documentation](docs/)** - Complete guides
- **[JavaScript README](src/reveng/javascript/README.md)** - JS deobfuscation details
- **[Installation Guide](INSTALLATION.md)** - Advanced setup options
- **[API Reference](docs/api/API_REFERENCE.md)** - Python API docs

### Try Examples
```bash
# List all examples
ls examples/

# JavaScript demos
python examples/javascript_deobfuscation_demo.py

# Advanced features (requires Ghidra)
python examples/advanced/full_recompilation_demo.py
python examples/advanced/gemini_feedback_demo.py
python examples/advanced/v4_0_features_demo.py
```

### Get Help
- **GitHub Issues**: https://github.com/oimiragieo/reveng-main/issues
- **Discussions**: https://github.com/oimiragieo/reveng-main/discussions
- **Documentation**: [docs/](docs/)

---

## 🎉 You're Ready!

```bash
# Analyze your first binary
reveng analyze /path/to/binary

# Deobfuscate JavaScript
./reveng-js deobfuscate obfuscated.js

# View all options
reveng --help
./reveng-js --help
```

**Happy reverse engineering!** 🔓

---

*For the complete feature list, see [README.md](README.md)*
*For advanced setup, see [INSTALLATION.md](INSTALLATION.md)*
