# REVENG Project Overview

## What is REVENG?

REVENG (Reverse Engineering) is a **Universal Reverse Engineering Platform** - the only open-source tool that provides a complete **disassemble-modify-reassemble workflow** for any binary.

## Key Value Propositions

### 🎯 Unique Capabilities
- **Only open-source tool** with full binary reconstruction
- **Multi-language support**: Java, C#, Python, Native binaries
- **AI-powered analysis** with evidence-backed insights
- **Professional-grade** built on Ghidra
- **Enterprise features**: Audit trails, plugins, GPU acceleration

### 🔧 What You Can Do
- **Reverse engineer any binary** (malware analysis, security research)
- **Modify binary behavior** (patching, adding features, removing restrictions)
- **Understand obfuscated code** (ProGuard, ConfuserEx, PyArmor, etc.)
- **Generate human-readable source** from binaries
- **Validate reconstructed binaries** with checksum/smoke tests
- **Full enterprise deployment** with web interface

## Supported Formats

| Language | File Types | Status | Decompilers |
|----------|-----------|--------|-------------|
| **Java** | .jar, .class, .war, .ear | ✅ Complete | CFR, Fernflower, Procyon |
| **C#** | .exe, .dll (.NET) | ✅ Complete | ILSpy, ildasm |
| **Python** | .pyc, .pyo | ✅ Complete | uncompyle6, decompyle3, pycdc |
| **Native** | .exe, .dll, .so, .elf | ✅ Complete | Ghidra, GhidraMCP |

## Architecture Overview

### 8-Step Analysis Pipeline
1. **AI-Powered Analysis** - Confidence scoring, evidence-backed claims
2. **Complete Disassembly** - 100+ functions via Ghidra or language-specific tools
3. **AI Inspection** - Deep analysis with extra thinking
4. **Specification Library** - 7 comprehensive documentation files
5. **Human-Readable Conversion** - Clean C/Java/C# code generation
6. **Deobfuscation** - 6 domain-specific modules
7. **Implementation** - Missing feature generation
8. **Binary Validation** - Checksum and behavioral validation

### Tool Ecosystem (66+ Tools)
- **Core Analysis** (8 tools) - Fundamental binary analysis
- **Multi-Language** (6 tools) - Java, C#, Python analysis
- **AI Enhancement** (5 tools) - AI-powered analysis
- **Code Quality** (4 tools) - Formatting, validation
- **Binary Operations** (5 tools) - Binary manipulation
- **Visualization** (3 tools) - Interactive graphs
- **Enterprise** (4 tools) - Audit, plugins, monitoring
- **ML/Security** (8 tools) - Malware classification, vulnerability detection
- **Configuration** (4 tools) - Configuration management
- **Utilities** (19 tools) - Supporting functions

## Target Audiences

### 🔐 Security Researchers
- Malware analysis and reverse engineering
- Vulnerability research and exploitation
- Binary patching and modification
- Obfuscation detection and deobfuscation

### 🤖 AI Coding Assistants
- Code analysis and understanding
- Tool development and enhancement
- Documentation generation
- Automated testing and validation

### 🏢 Enterprise Teams
- Legacy code recovery and modernization
- Security auditing and compliance
- Binary analysis at scale
- Team collaboration with web interface

### 🎓 Students & Educators
- Learning reverse engineering concepts
- Understanding binary formats
- Hands-on security education
- Research and academic projects

## Key Differentiators

### vs IDA Pro
- ✅ Open source (vs $$$$)
- ✅ AI-powered analysis (vs plugins)
- ✅ Binary reassembly (vs disassembly only)
- ✅ Multi-language support (vs native focus)

### vs Ghidra
- ✅ AI integration (vs manual analysis)
- ✅ Binary reassembly (vs analysis only)
- ✅ Web interface (vs desktop only)
- ✅ Enterprise features (vs basic)

### vs Binary Ninja
- ✅ Open source (vs $$$)
- ✅ AI-powered (vs manual)
- ✅ Binary reassembly (vs analysis only)
- ✅ Multi-language (vs native focus)

## Technical Stack

### Core Technologies
- **Python 3.11+** - Main language
- **Ghidra** - Professional disassembly engine
- **GhidraMCP** - Model Context Protocol integration
- **LIEF** - Binary manipulation library
- **Keystone** - Multi-architecture assembler
- **Capstone** - Multi-architecture disassembler

### AI Integration
- **Ollama** - Local LLM (recommended)
- **Anthropic Claude** - API integration
- **OpenAI GPT** - API integration
- **Evidence-based analysis** - Confidence scoring

### Web Interface
- **React** - Frontend framework
- **Express.js** - Backend API
- **WebSocket** - Real-time updates
- **Docker** - Containerized deployment
- **Kubernetes** - Production orchestration

## Use Cases

### 1. Security Research
```bash
# Analyze malware sample
python reveng_analyzer.py suspicious.exe
# Review in SPECS/security.md
# Modify behavior in human_readable_code/
# Reassemble for testing
python tools/binary_reassembler_v2.py --original suspicious.exe --source human_readable_code/ --output patched.exe
```

### 2. Legacy Code Recovery
```bash
# Understand proprietary protocol
python reveng_analyzer.py client.exe
# Check SPECS/api.md for API calls
# Check src_optimal_analysis_client/network/ for protocol code
```

### 3. Binary Modification
```bash
# Full disassemble-modify-reassemble workflow
python reveng_analyzer.py app.exe
python tools/code_formatter.py human_readable_code/
python tools/type_inference_engine.py --functions analysis_app/functions.json --output types.h
# Edit code in human_readable_code/
# Reassemble
python tools/binary_reassembler_v2.py --original app.exe --source human_readable_code/ --output modified.exe
```

## Project Status

### ✅ Production Ready
- Core analysis pipeline
- Multi-language support
- AI integration
- Binary reconstruction
- Web interface
- Enterprise features

### 🚧 In Development
- Enhanced AI models
- Additional language support
- Performance optimizations
- Advanced visualization

### 📋 Planned
- Mobile app support
- Cloud deployment
- Advanced obfuscation handling
- Community plugins

## Getting Started

### Quick Start (5 minutes)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Analyze a binary
python reveng_analyzer.py binary.exe

# 3. View results
# - analysis_binary/           # JSON reports
# - human_readable_code/       # Cleaned C code
# - deobfuscated_app/          # Domain-organized modules
```

### For AI Assistants
- Start with [AI Assistant Guide](../docs/guides/AI_ASSISTANT_GUIDE.md)
- Check [Tool Categories](../tools/README.md)
- See [Common Tasks](common-tasks.md)

### For Developers
- See [Developer Guide](../docs/DEVELOPER_GUIDE.md)
- Check [Project Structure](../docs/development/PROJECT_STRUCTURE.md)
- Review [Architecture](../docs/architecture/ARCHITECTURE.md)

---

**REVENG** - The universal reverse engineering platform for the modern era.
