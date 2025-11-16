# Directory: src/reveng/tools

## Overview
This directory contains a comprehensive suite of reverse engineering tools organized into specialized subdirectories. It provides implementations for binary analysis, language-specific analyzers, threat intelligence, anti-analysis detection, diffing, and various utility tools.

## Subdirectories

### ai/
AI-enhanced analysis tools including Ollama integration and code enhancement

### anti_analysis/
- `packer_detector.py`: Detect packed/obfuscated binaries
- `universal_unpacker.py`: Unpack common packers (UPX, etc.)

### binary/
Binary manipulation and validation tools

### config/
Configuration management and tool setup

### core/
Core analysis tools (AI recompiler, source inspector, etc.)

### decompilers/
Integration with various decompilers

### diffing/
- `binary_differ.py`: Compare two binary versions
- `patch_analyzer.py`: Analyze security patches for vulnerabilities

### enterprise/
Enterprise features (audit trail, etc.)

### languages/
Language-specific analyzers:
- `language_detector.py`: Detect binary language/format
- `java_bytecode_analyzer.py`: Java .class and .jar analysis
- `csharp_il_analyzer.py`: C# IL analysis
- `python_bytecode_analyzer.py`: Python .pyc analysis
- `java_deobfuscator_advanced.py`: Java code deobfuscation
- `java_project_reconstructor.py`: Reconstruct Java projects

### quality/
Code quality tools:
- `compilation_tester.py`: Test if decompiled code compiles

### security/
Security analysis utilities

### threat_intel/
Threat intelligence tools:
- `virustotal_connector.py`: VirusTotal API integration
- `yara_generator.py`: Generate YARA rules from binaries
- `yara_scanner.py`: Scan with YARA rules

### translation/
Code translation utilities (C to Python, etc.)

### utils/
General utilities

### visualization/
Analysis visualization tools

## Key Files

### hex_editor.py
- **Purpose**: Hex-level binary analysis
- **Key Classes**: `HexEditor`
- **Key Functions**: Entropy analysis, pattern matching, embedded file detection

## Architecture

```
┌─────────────────────────────────────┐
│   Tools Layer                       │
├─────────────────────────────────────┤
│ Specialized analysis tools          │
│ organized by function               │
└──────────────┬──────────────────────┘
               │
    ┌──────────┴──────────────────────┐
    │                                 │
┌───┴───────────┐           ┌─────────┴────────┐
│  Language     │           │  Threat Intel    │
│  Analyzers    │           │  Integration     │
└───────────────┘           └──────────────────┘
```

## Key Concepts

### Tool Organization
Tools are organized by function:
- **Language-specific**: Java, C#, Python analysis
- **Security**: Vulnerability and threat detection
- **Anti-analysis**: Packer detection and unpacking
- **Comparison**: Binary diffing and patch analysis
- **Quality**: Compilation testing

### Multi-Language Support
Supports analysis of:
- Java bytecode (.jar, .class)
- C# IL (.dll, .exe)
- Python bytecode (.pyc)
- Native binaries (PE, ELF, Mach-O)

## Usage Examples

### Language Detection
```python
from reveng.tools.languages.language_detector import LanguageDetector

detector = LanguageDetector()
file_type = detector.detect("unknown_binary")
print(f"Language: {file_type.language}")
print(f"Format: {file_type.format}")
print(f"Confidence: {file_type.confidence}")
```

### Binary Diffing
```python
from reveng.tools.diffing.binary_differ import BinaryDiffer

differ = BinaryDiffer()
result = differ.diff("v1.exe", "v2.exe", deep_analysis=True)
print(f"Similarity: {result.similarity_score}")
print(f"Modified functions: {len(result.modified_functions)}")
```

### VirusTotal Lookup
```python
from reveng.tools.threat_intel.virustotal_connector import VirusTotalConnector

vt = VirusTotalConnector(api_key="YOUR_KEY")
result = vt.lookup_hash(sha256_hash)
print(f"Detections: {result.detections}/{result.total_engines}")
```

## Related Modules

### Used By
- `src/reveng/analyzer.py`: Uses tools for analysis steps
- `src/reveng/pipeline/`: Pipeline uses tools
- `src/reveng/cli.py`: CLI exposes tool functions

## Notes

### Tool Categories
1. **Analysis**: Core analysis functionality
2. **Integration**: External service connectors
3. **Utilities**: Helper functions
4. **Quality**: Validation and testing

### Best Practices
1. Check tool availability before use
2. Handle errors gracefully
3. Cache results when appropriate
4. Use language detector for routing
5. Validate tool outputs
