# REVENG Frequently Asked Questions (FAQ)

**Last Updated:** November 16, 2025
**Version:** 4.0.0

---

## Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Getting Started](#getting-started)
3. [Features & Capabilities](#features--capabilities)
4. [Troubleshooting](#troubleshooting)
5. [AI Integration](#ai-integration)
6. [Advanced Usage](#advanced-usage)
7. [Contributing](#contributing)

---

## Installation & Setup

### Q: Do I need to install anything from PyPI?
**A:** No, not yet. REVENG is currently installed from source:
```bash
git clone https://github.com/oimiragieo/reveng-main.git
cd reveng-main
./install-reveng.sh  # Automated
# OR
pip install -e .     # Manual
```
A PyPI package is planned for v4.1.0.

---

### Q: What Python version do I need?
**A:** Python 3.9+ is required. Python 3.11+ is recommended for best performance.

```bash
# Check your version
python --version

# Should show: Python 3.9.x or higher
```

---

### Q: Do I need Ghidra to use REVENG?
**A:** It depends on your use case:

**NO Ghidra needed for:**
- Basic binary analysis
- JavaScript deobfuscation
- File type detection
- Triage analysis
- String extraction

**YES Ghidra needed for:**
- Advanced decompilation
- Binary reconstruction
- Function analysis
- Control flow graphs
- Full recompilation pipeline

---

### Q: How do I install Ghidra?
**A:** Follow these steps:

1. **Download Ghidra**
   - Visit: https://ghidra-sre.org/
   - Download latest version (11.0+)

2. **Extract to project**
   ```bash
   unzip ghidra_*.zip
   mv ghidra_*_PUBLIC external/ghidra
   ```

3. **Verify Java** (required for Ghidra)
   ```bash
   java -version  # Should be 17+
   ```

4. **Start Ghidra server** (optional)
   ```bash
   cd external/ghidra-server
   pip install flask flask-cors
   python ghidra_http_server.py
   ```

See: [docs/getting-started/installation.md](getting-started/installation.md)

---

### Q: Installation fails with "command not found". What do I do?
**A:** Try these steps:

```bash
# 1. Make sure you're in the project root
cd /path/to/reveng-main

# 2. Reinstall
pip install -e . --force-reinstall

# 3. Check if reveng command exists
which reveng

# 4. If still not found, try:
python3 -m reveng --version

# 5. Add to PATH (if needed)
export PATH="$PATH:$HOME/.local/bin"
```

Still stuck? See: [docs/getting-started/troubleshooting.md](getting-started/troubleshooting.md)

---

## Getting Started

### Q: Where should I start as a new user?
**A:** Follow this path:

1. **Read** [START_HERE.md](../START_HERE.md) (5 min)
2. **Install** `./install-reveng.sh` (2 min)
3. **Run** `python examples/my_first_analysis.py` (2 min)
4. **Try** `reveng analyze /bin/ls` (1 min)
5. **Explore** [QUICK_START.md](../QUICK_START.md) (10 min)

**Total:** ~20 minutes to your first analysis

---

### Q: What file types does REVENG support?
**A:** REVENG supports these formats:

| Language | File Types | Status |
|----------|-----------|---------|
| **Native** | `.exe`, `.dll`, `.so`, `.dylib`, `.elf` | ✅ Full Support |
| **Java** | `.jar`, `.war`, `.ear`, `.class` | ✅ Full Support |
| **C#/.NET** | `.dll`, `.exe` (managed) | ✅ Full Support |
| **Python** | `.pyc`, `.pyo` | ✅ Full Support |
| **JavaScript** | `.js` (obfuscated/minified) | ✅ Full Support |

---

### Q: Can I analyze malware safely?
**A:** Yes! REVENG analyzes binaries **statically** - it never executes them.

**Safety features:**
- Static analysis only (no execution)
- Sandboxed decompilation
- Safe string extraction
- No network connections from analyzed files

**Best practices:**
- Analyze in a VM (recommended for unknown malware)
- Use offline mode for sensitive samples
- Never execute files you're analyzing
- Review reports before sharing

See: [SECURITY.md](../SECURITY.md)

---

### Q: How long does analysis take?
**A:** Depends on binary size:

| Binary Size | Analysis Time | Mode |
|------------|---------------|------|
| < 1 MB | 4-8 seconds | Standard |
| 1-10 MB | 15-30 seconds | Standard |
| 10-100 MB | 60-180 seconds | Standard |
| Any size | < 30 seconds | Triage mode |

**With AI enhancement:** Add 10-30 seconds

**Tip:** Use `reveng triage` for quick 30-second assessments!

---

## Features & Capabilities

### Q: Do I need API keys to use REVENG?
**A:** No for basic features, yes for AI features.

**No API keys needed:**
- Basic binary analysis
- JavaScript deobfuscation (ML only)
- File type detection
- Triage analysis
- String/import extraction

**API keys optional (for AI features):**
- `GEMINI_API_KEY` - Google Gemini (free tier available)
- `OPENAI_API_KEY` - OpenAI GPT models (paid)
- `ANTHROPIC_API_KEY` - Claude models (paid)

**Free alternative:**
Install Ollama for local AI (no API keys needed):
```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama2
reveng analyze --ai-provider ollama binary.exe
```

---

### Q: What's the difference between `analyze` and `triage`?
**A:**

**`reveng analyze`** - Comprehensive analysis (1-5 minutes)
- Full decompilation
- Security analysis
- AI enhancement (optional)
- Detailed report
- Use for: Deep dive analysis

**`reveng triage`** - Quick assessment (< 30 seconds)
- Basic metadata
- Threat indicators
- Quick categorization
- Use for: Incident response, bulk scanning

**Example:**
```bash
# Quick triage first
reveng triage suspicious.exe

# If interesting, do full analysis
reveng analyze --enhanced suspicious.exe
```

---

### Q: Can REVENG generate exploits?
**A:** Yes, for educational and authorized testing purposes only.

**Capabilities:**
- Automatic vulnerability detection
- PoC exploit generation
- Buffer overflow exploits
- Format string exploits
- Use-after-free demos

**Usage:**
```bash
reveng analyze --find-vulnerabilities --generate-exploits binary.exe
```

**Important:** Only use on:
- Your own software
- Authorized penetration tests
- CTF competitions
- Educational purposes

See responsible use policy: [SECURITY.md](../SECURITY.md)

---

### Q: Does REVENG work offline?
**A:** Yes! Core features work completely offline.

**Offline capabilities:**
- All binary analysis
- JavaScript deobfuscation (without LLM)
- Malware detection
- String extraction
- Local AI with Ollama

**Online-only features:**
- Cloud AI (Gemini, GPT-4, Claude)
- VirusTotal integration
- MCP server (if remote)

---

## Troubleshooting

### Q: I get "ModuleNotFoundError: No module named 'reveng'"
**A:** This means REVENG isn't installed or Python can't find it.

**Solution 1 - Reinstall:**
```bash
cd /path/to/reveng-main
pip install -e . --force-reinstall
```

**Solution 2 - Check Python path:**
```bash
python3 -c "import sys; print('\n'.join(sys.path))"
# Should include /path/to/reveng-main/src
```

**Solution 3 - Use absolute imports:**
```bash
cd /path/to/reveng-main
python3 -m reveng analyze binary.exe
```

---

### Q: Analysis fails with "Ghidra not found"
**A:** Ghidra is optional but needed for some features.

**Quick fix - Skip Ghidra:**
```bash
reveng analyze --no-ghidra binary.exe
```

**Or install Ghidra:**
See "How do I install Ghidra?" above

---

### Q: JavaScript deobfuscation doesn't work
**A:** Check if Node.js tools are installed:

```bash
# Check Node.js
node --version  # Should be 18+

# Install JS tools
npm install -g webcrack prettier

# OR run installer again
./install-js-deob.sh

# Test
./reveng-js deobfuscate examples/test-samples/obfuscated-simple.js
```

---

### Q: Where are analysis results saved?
**A:** Default locations:

```
./analysis_<binary_name>/     # Analysis output
  ├── source_code/             # Decompiled code
  ├── reports/                 # JSON/HTML reports
  └── metadata.json            # Analysis metadata

~/.reveng/                     # Configuration
  ├── config.yaml              # User config
  └── cache/                   # Analysis cache

./reveng_analyzer.log          # Debug log
```

**Change output location:**
```bash
reveng analyze --output-dir /custom/path binary.exe
```

---

### Q: How do I enable debug logging?
**A:**

```bash
# Method 1: Environment variable
export REVENG_LOG_LEVEL=DEBUG
reveng analyze binary.exe

# Method 2: CLI flag
reveng analyze --verbose binary.exe

# Method 3: Config file
cat > ~/.reveng/config.yaml << EOF
logging:
  level: DEBUG
  file: reveng_debug.log
EOF
```

**View logs:**
```bash
tail -f reveng_analyzer.log
# OR
tail -f reveng_debug.log
```

---

## AI Integration

### Q: How do I use REVENG with Claude Desktop?
**A:** Follow these steps:

1. **Install REVENG** (if not already)
   ```bash
   cd /path/to/reveng-main
   ./install-reveng.sh
   ```

2. **Get API keys**
   ```bash
   export GEMINI_API_KEY="your-key-here"
   ```

3. **Configure Claude Desktop**
   Edit `~/.config/claude/mcp.json`:
   ```json
   {
     "mcpServers": {
       "reveng": {
         "command": "/path/to/reveng-main/reveng-mcp-server",
         "env": {
           "GEMINI_API_KEY": "your-key"
         }
       }
     }
   }
   ```

4. **Restart Claude Desktop**

5. **Use naturally:**
   - "Analyze this binary: /path/to/suspicious.exe"
   - "Deobfuscate this JavaScript file"
   - "Find vulnerabilities in this binary"

See: [docs/mcp/README.md](mcp/README.md)

---

### Q: What MCP tools are available?
**A:** REVENG provides 15+ specialized tools:

**Binary Analysis:**
- `analyze_binary` - Comprehensive analysis
- `decompile_binary` - Source code extraction
- `recompile_binary` - Binary reconstruction
- `diff_binaries` - Version comparison

**Security:**
- `find_vulnerabilities` - Vuln detection
- `generate_exploit` - PoC generation
- `classify_malware` - Malware categorization

**JavaScript:**
- `deobfuscate_javascript` - JS deobfuscation
- `detect_js_malware` - Malware detection

See full list: [docs/mcp/README.md](mcp/README.md)

---

### Q: Can I use local AI instead of cloud APIs?
**A:** Yes! Use Ollama for free local AI.

**Setup:**
```bash
# 1. Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# 2. Pull a model
ollama pull llama2        # or llama3, codellama, etc.

# 3. Start Ollama (auto-starts as service)
ollama serve

# 4. Use with REVENG
reveng analyze --ai-provider ollama --ai-model llama2 binary.exe
```

**Benefits:**
- No API costs
- Complete privacy
- Works offline
- Fast (with GPU)

---

## Advanced Usage

### Q: How do I batch process multiple binaries?
**A:**

**Method 1 - Shell loop:**
```bash
for file in /path/to/binaries/*.exe; do
    reveng analyze "$file" --output-dir "results/$(basename $file)"
done
```

**Method 2 - Python script:**
```python
from reveng.analyzer import REVENGAnalyzer
from pathlib import Path

for binary in Path("/path/to/binaries").glob("*.exe"):
    analyzer = REVENGAnalyzer(str(binary))
    results = analyzer.analyze_binary()
    print(f"Analyzed: {binary.name}")
```

**Method 3 - Triage bulk mode:**
```bash
reveng triage --bulk /path/to/binaries/*.exe
```

---

### Q: Can I customize the analysis pipeline?
**A:** Yes! Use the Python API:

```python
from reveng.analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures

# Create custom features
features = EnhancedAnalysisFeatures()
features.enable_vulnerability_discovery = True
features.enable_exploit_generation = False  # Skip this
features.timeout_seconds = 600

# Run analysis
analyzer = REVENGAnalyzer("binary.exe", features=features)
results = analyzer.analyze_binary()
```

See: [docs/api/API_REFERENCE.md](api/API_REFERENCE.md)

---

### Q: How do I contribute to REVENG?
**A:** We welcome contributions!

**Quick start:**
```bash
# 1. Fork repository on GitHub
# 2. Clone your fork
git clone https://github.com/YOUR-USERNAME/reveng-main.git
cd reveng-main

# 3. Create branch
git checkout -b feature/my-improvement

# 4. Make changes, add tests
# 5. Run tests
python -m pytest

# 6. Submit pull request
```

See: [CONTRIBUTING.md](../CONTRIBUTING.md)

---

## Contributing

### Q: Where can I get help?
**A:** Multiple support channels:

**Documentation:**
- [START_HERE.md](../START_HERE.md) - Navigation guide
- [QUICK_START.md](../QUICK_START.md) - Quick setup
- [docs/](.) - Full documentation

**Community:**
- GitHub Issues: https://github.com/oimiragieo/reveng-main/issues
- GitHub Discussions: https://github.com/oimiragieo/reveng-main/discussions

**Security Issues:**
- See [SECURITY.md](../SECURITY.md) for responsible disclosure

---

### Q: Is REVENG production-ready?
**A:** Yes! Version 4.0.0 is production/stable.

**Production use:**
- 91% test coverage
- 122,000+ lines of code
- Extensively tested
- Active development
- Used in real-world scenarios

**Use cases:**
- Security research teams
- Malware analysis labs
- CTF competitions
- Educational institutions
- Vulnerability research

---

### Q: Can I use REVENG commercially?
**A:** Yes! REVENG is MIT licensed.

**You can:**
- ✅ Use commercially
- ✅ Modify and distribute
- ✅ Sublicense
- ✅ Private use

**You must:**
- Include original license
- Include copyright notice

See: [LICENSE](../LICENSE)

---

## Still Have Questions?

### Not finding your answer?

1. **Search documentation:**
   ```bash
   cd /path/to/reveng-main
   grep -r "your question" docs/
   ```

2. **Check GitHub Issues:**
   - https://github.com/oimiragieo/reveng-main/issues
   - Someone may have asked already!

3. **Ask in Discussions:**
   - https://github.com/oimiragieo/reveng-main/discussions
   - Community and maintainers can help

4. **Open an issue:**
   - For bugs: Use bug template
   - For features: Use feature request template
   - For questions: Use discussion instead

---

**Last Updated:** November 16, 2025
**Maintainers:** REVENG Development Team
**License:** MIT
