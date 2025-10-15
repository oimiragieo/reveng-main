# REVENG Quick Start Guide

Get up and running with REVENG in **5 minutes**!

---

## Prerequisites

- **Python 3.8+**
- **Java 21 (64-bit)** - Required for Ghidra
- **Ghidra** - Installed at C:\ghidra (Windows) or /opt/ghidra (Linux)

---

## 5-Minute Setup

### 1. Install Python Dependencies

```bash
cd c:/dev/projects/droid-main
pip install -r requirements.txt
```

### 2. Start GhidraMCP Server

```bash
# Server should run at http://localhost:13337/mcp
```

### 3. Configure REVENG

Edit `.reveng/config.yaml` with your preferred settings.

### 4. Run Your First Analysis

```bash
# Analyze a binary (auto-detects language)
python reveng_analyzer.py path/to/binary.exe
```

---

## Language-Specific Quick Starts

### Java Bytecode Analysis

```bash
python reveng_analyzer.py application.jar
```

**Java features**:
- Multi-decompiler validation (CFR, Fernflower, Procyon)
- Obfuscation detection (ProGuard, Allatori)
- Project reconstruction (Maven/Gradle)
- AI-powered deobfuscation

### C# .NET Analysis

```bash
python reveng_analyzer.py application.exe
```

**C# features**:
- IL disassembly with ildasm
- C# decompilation with ILSpy
- Obfuscation detection (ConfuserEx, .NET Reactor)

### Python Bytecode Analysis

```bash
python reveng_analyzer.py module.pyc
```

**Python features**:
- Python 2.7 - 3.12 support
- Multi-decompiler (uncompyle6, decompyle3, pycdc)
- Obfuscation detection (PyArmor, Nuitka)

### Native Binary Analysis

```bash
python reveng_analyzer.py application.exe
```

**Native features**:
- Full Ghidra integration (16 MCP features)
- Multi-architecture support
- Call graph analysis

---

## Ollama Setup

Enable AI-powered analysis with Ollama:

### 1. Install Ollama

```bash
# Windows: Download from https://ollama.ai
# Linux: curl -fsSL https://ollama.ai/install.sh | sh
# macOS: brew install ollama
```

### 2. Pull a Model

```bash
ollama pull phi              # Fast, 3.8GB
ollama pull codellama        # Better quality, 3.8GB
ollama pull deepseek-coder   # Best quality, 6.7GB
```

### 3. Configure REVENG

Edit `.reveng/config.yaml` to enable Ollama provider.

### 4. Test AI Analysis

```bash
ollama serve
python reveng_analyzer.py binary.exe
```

---

## Troubleshooting

### Binary not detected
Specify full path or check file extension.

### GhidraMCP connection failed
Ensure server is running on port 13337.

### Java not found
Install Java 21 (64-bit) and add to PATH.

### Ollama connection refused
Start Ollama server with `ollama serve`.

---

**Ready for advanced usage?** → Continue to [User Guide](USER_GUIDE.md)
