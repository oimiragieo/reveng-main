# REVENG User Guide

Complete documentation for using REVENG Universal Binary Analysis System.

## Overview

REVENG is a universal reverse engineering platform supporting 4 languages:
- **Java** (.jar, .class)
- **C#** (.exe, .dll .NET assemblies)
- **Python** (.pyc, .pyo bytecode)
- **Native** (.exe, .dll, .so, .elf binaries)

### Key Capabilities

- Multi-decompiler validation
- Obfuscation detection and removal
- Project reconstruction
- AI-powered analysis
- Enterprise audit trails
- Interactive visualizations

## Installation

See [Quick Start Guide](QUICK_START.md) for setup instructions.

```bash
pip install -r requirements.txt
```

## Configuration

Configuration file: `.reveng/config.yaml`

Key settings:
- AI provider (Ollama, Anthropic, OpenAI)
- Ghidra MCP URL
- Analysis parameters
- Output formats

## Java Bytecode Analysis

```bash
python reveng_analyzer.py application.jar
```

**Features**:
- Multi-decompiler support (CFR, Fernflower, Procyon)
- Obfuscation detection (ProGuard, Allatori)
- Project reconstruction (Maven/Gradle)
- Advanced deobfuscation

**Output**: `java_analysis/` with decompiled sources and reconstructed project

## C# .NET Analysis

```bash
python reveng_analyzer.py application.exe
```

**Features**:
- IL disassembly (ildasm)
- C# decompilation (ILSpy)
- Obfuscation detection (ConfuserEx, .NET Reactor)
- .csproj generation

**Output**: `csharp_analysis/` with IL and C# sources

## Python Bytecode Analysis

```bash
python reveng_analyzer.py module.pyc
```

**Features**:
- Python 2.7-3.12 support
- Multi-decompiler (uncompyle6, decompyle3, pycdc)
- Obfuscation detection (PyArmor, Nuitka)

**Output**: `python_analysis/` with decompiled Python source

## Native Binary Analysis

```bash
python reveng_analyzer.py application.exe
```

**Features**:
- Full Ghidra integration (16 MCP features)
- Multi-architecture support
- Call graph analysis
- Crypto pattern detection

**Output**: `src_optimal_analysis_*/` with comprehensive disassembly

## AI-Powered Analysis

### Ollama Integration

```bash
ollama pull qwen2.5-coder:14b
```

**Models**:
- **phi** (3.8GB) - Fast, good quality
- **codellama** (3.8GB) - Better quality
- **deepseek-coder** (6.7GB) - Best quality
- **qwen2.5-coder:14b** (8.5GB) - Production recommended

**Benefits**:
- Intelligent function naming
- Security vulnerability detection
- Obfuscation pattern recognition
- Natural language descriptions

## Advanced Features

### Visualizations

Interactive call graphs and dependency diagrams:
- HTML interactive (vis.js)
- PNG static (Graphviz)
- JSON data export

### Audit Trails

Enterprise-grade logging in `analysis_*/audit_logs/`:
- SOC 2 / ISO 27001 compliant
- Session tracking
- Security event logging

### Plugin System

Extensible architecture for custom analyzers:

```bash
python tools/plugin_system.py generate my_analyzer
```

### GPU Acceleration

Automatic CUDA/OpenCL/Metal detection for:
- String pattern matching
- Hash cracking
- Similarity analysis

## Output Reference

Main output file: `analysis_*/universal_analysis_report.json`

Contains complete analysis results including:
- Binary metadata
- File type detection
- Disassembly results
- Obfuscation analysis
- Security findings

## Troubleshooting

Common issues and solutions:

**Binary not detected**: Specify full path or check extension

**GhidraMCP fails**: Ensure server running on port 13337

**Java not found**: Install Java 21 (64-bit)

**Ollama timeout**: Use faster model (phi) or increase timeout

For more issues, see [Quick Start Troubleshooting](QUICK_START.md#troubleshooting)

---

See also:
- [Developer Guide](DEVELOPER_GUIDE.md) - Architecture details
- [Implementation Guide](IMPLEMENTATION.md) - Feature history
