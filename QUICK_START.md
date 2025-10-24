# REVENG Quick Start Guide

Get REVENG running in **5 minutes** and see the revolutionary recompilation in action.

## ⚡ Quick Installation

```bash
# 1. Clone repository
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install Gemini AI (optional but recommended)
pip install google-generativeai

# 4. Set API key
export GEMINI_API_KEY="your-api-key-here"  # Get from https://makersuite.google.com/app/apikey
```

## 🚀 Start Ghidra Server

```bash
# Terminal 1: Start Ghidra analysis server
cd external/ghidra-server
python ghidra_http_server.py

# You should see:
# ============================================================
# Ghidra HTTP Analysis Server
# ============================================================
# Server: http://0.0.0.0:13370
# ============================================================
```

## 🎯 Run Your First Analysis

### Option 1: Complete Recompilation Pipeline (Recommended)

```bash
# Terminal 2: Run full recompilation
cd reveng-main
python examples/advanced/full_recompilation_demo.py

# This will:
# ✅ Decompile binary with Ghidra
# ✅ Enhance code with Gemini AI
# ✅ Recompile to working executable
# ✅ Find security vulnerabilities
# ✅ Generate working exploits
```

### Option 2: Python API

```python
# Terminal 2: Python interactive mode
python

>>> import asyncio
>>> from reveng.integrations.ghidra.ghidra_engine import GhidraEngine
>>> from reveng.ai.gemini_engine import GeminiEngine
>>> from reveng.ai.recompilation_engine import BinaryRecompilationEngine

# Initialize engines
>>> ghidra = GhidraEngine()
>>> gemini = GeminiEngine()
>>> recomp = BinaryRecompilationEngine(ghidra, gemini)

# Run analysis
>>> results = asyncio.run(
...     recomp.full_reconstruction_pipeline("path/to/binary.exe")
... )

# View results
>>> print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
>>> print(f"Exploits: {len(results['exploits'])}")
```

### Option 3: Gemini Feedback Loop

```bash
# Terminal 2: Run self-improvement loop
python examples/advanced/gemini_feedback_demo.py

# Gemini will:
# 🤖 Analyze REVENG codebase
# 🤖 Find bugs and suggest fixes
# 🤖 Recommend performance improvements
# 🤖 Propose new features
```

## 📊 Example Output

```
================================================================================
REVENG REVOLUTIONARY RECOMPILATION PIPELINE
Binary → Source → Compiled → Exploits
================================================================================

[Step 1/7] Initializing recompilation engine...
  ✅ Engine initialized

[Step 2/7] Running full reconstruction pipeline...
  ✅ Ghidra decompilation complete (2,431 functions)
  ✅ AI enhancement complete
  ✅ Compilation successful

[Step 3/7] Generated Source Files:
  ✅ C: demo_output/reconstructed.c
     Size: 45,231 bytes, Lines: 1,203
  ✅ PYTHON: demo_output/reconstructed.py
     Size: 38,492 bytes, Lines: 987

[Step 4/7] Compiled Binaries:
  ✅ c_gcc: demo_output/reconstructed_gcc
     Size: 24,576 bytes
  ✅ c_clang: demo_output/reconstructed_clang
     Size: 28,672 bytes

[Step 5/7] Behavioral Validation:
  Similarity Score: 87.3%

[Step 6/7] Security Vulnerabilities Discovered:
  🔴 CRITICAL: 3 vulnerabilities
  🟡 HIGH: 5 vulnerabilities
  🟢 MEDIUM: 2 vulnerabilities

  Top Vulnerabilities:
  1. BUFFER_OVERFLOW
     Severity: critical
     CWE: CWE-120
     Location: line 142
     Description: strcpy used without bounds checking

[Step 7/7] Proof-of-Concept Exploits Generated:
  Exploit #1: Buffer overflow in user_input()
  Language: python
  ✅ Saved to: demo_output/exploit_1.py

================================================================================
RECONSTRUCTION COMPLETE
================================================================================
```

## 🎓 Next Steps

### 1. Analyze Your Own Binaries

```bash
# Edit the demo script
nano examples/advanced/full_recompilation_demo.py

# Change this line:
BINARY_PATH = "your_binary.exe"  # Your binary here

# Run
python examples/advanced/full_recompilation_demo.py
```

### 2. Ask Questions About Binaries

```python
from reveng.ai.gemini_engine import GeminiEngine

engine = GeminiEngine()

answer = await engine.ask_question(
    question="What does this binary do? Is it malicious?",
    context={
        'functions': analysis_data['functions'],
        'strings': analysis_data['strings']
    }
)

print(answer['answer'])
```

### 3. Generate Custom Exploits

```python
# Find vulnerabilities
vulns = await gemini.analyze_security(source_code)

# Generate exploit for first vulnerability
exploit = await gemini.generate_exploit(vulns[0], source_code)

print(exploit['exploit_code'])  # Working Python exploit!
```

### 4. Run Continuous Feedback

```bash
# Let Gemini improve REVENG continuously
python -c "
from reveng.ai.gemini_feedback_loop import run_feedback_loop_sync
run_feedback_loop_sync(
    interval_minutes=5,
    iterations=10  # Run 10 iterations
)
"
```

## 🔧 Troubleshooting

### Issue: Ghidra server not connecting

```bash
# Check if server is running
curl http://127.0.0.1:13370/health

# Should return: {"status": "healthy", ...}

# If not, start it:
cd external/ghidra-server
python ghidra_http_server.py
```

### Issue: Gemini API not working

```bash
# Check API key is set
echo $GEMINI_API_KEY

# If empty, set it:
export GEMINI_API_KEY="your-key-here"

# Verify it works:
python -c "
from reveng.ai.gemini_engine import GeminiEngine
e = GeminiEngine()
print('Gemini available:', e.is_available())
"
```

### Issue: Compilation fails

```bash
# Install GCC/Clang
# Ubuntu/Debian:
sudo apt-get install gcc clang

# macOS:
brew install gcc llvm

# Windows:
# Install MinGW or use WSL
```

## 📚 Full Documentation

- **Architecture**: [WORLD_CLASS_SECURITY_ARCHITECTURE.md](WORLD_CLASS_SECURITY_ARCHITECTURE.md)
- **Features**: [REVOLUTIONARY_FEATURES.md](REVOLUTIONARY_FEATURES.md)
- **API Reference**: [docs/api/](docs/api/)
- **Examples**: [examples/advanced/](examples/advanced/)

## 💡 Pro Tips

1. **Use Gemini for best results**: Gemini provides superior code reconstruction
2. **Start with small binaries**: Test on simple programs first
3. **Check logs**: `reveng_analyzer.log` has detailed debugging info
4. **Save API costs**: Cache Ghidra results, reuse for multiple analyses
5. **Batch processing**: Analyze multiple binaries in parallel

## 🎯 Example Workflow

```bash
# 1. Start Ghidra server (Terminal 1)
cd external/ghidra-server && python ghidra_http_server.py

# 2. Analyze binary (Terminal 2)
python examples/advanced/full_recompilation_demo.py

# 3. While analyzing, start feedback loop (Terminal 3)
python examples/advanced/gemini_feedback_demo.py

# 4. Review results
cat demo_output/RECONSTRUCTION_REPORT.md
cat gemini_feedback/feedback_iteration_001.md
```

## 🆘 Need Help?

- **Documentation**: Check [docs/](docs/) folder
- **Issues**: [GitHub Issues](https://github.com/oimiragieo/reveng-main/issues)
- **Discussions**: [GitHub Discussions](https://github.com/oimiragieo/reveng-main/discussions)

---

**🚀 You're ready! Start proving vulnerabilities through code reconstruction.**
