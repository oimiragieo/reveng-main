# Tools - Core

## Overview

Core tools provide fundamental binary analysis, deobfuscation, and binary manipulation capabilities. These are the essential tools that form the foundation of REVENG's analysis pipeline.

**Location:** `/home/user/reveng-main/src/reveng/tools/core/`

## Files in This Directory

### `__init__.py` (627 lines)
Module initialization and exports.

### `optimal_binary_analysis.py` (33395 lines)
Comprehensive binary analysis tool with optimal analysis strategies.

**Features:**
- Multi-architecture support (x86, x64, ARM, MIPS)
- Control flow graph generation
- Function identification and analysis
- Cross-reference analysis
- Symbol resolution
- Import/export analysis

### `binary_reassembler_v2.py` (52589 lines)
Advanced binary reassembly and reconstruction tool.

**Features:**
- Binary disassembly and reassembly
- Code relocation and patching
- Section manipulation
- Import table reconstruction
- Entry point modification

### `deobfuscation_tool.py` (19875 lines)
General-purpose code deobfuscation tool.

**Features:**
- Control flow flattening removal
- String deobfuscation
- Constant unfolding
- Dead code elimination
- Opaque predicate removal

### `implementation_tool.py` (29553 lines)
Tool implementation utilities and base classes.

### `ai_recompiler_converter.py` (34700 lines)
AI-powered binary to source code conversion.

**Features:**
- Assembly to C/C++ conversion
- AI-enhanced code reconstruction
- Type inference
- Variable naming
- Comment generation

### `ai_source_inspector.py` (28910 lines)
AI-powered source code analysis and inspection.

**Features:**
- Code pattern recognition
- Vulnerability detection
- Code quality assessment
- Semantic analysis

### `binary_validator.py` (12784 lines)
Binary file validation and verification tool.

**Features:**
- Format validation
- Integrity checking
- Signature verification
- Checksum validation

### `human_readable_converter_fixed.py` (16962 lines)
Convert binary analysis results to human-readable formats.

**Features:**
- Assembly to pseudocode
- Annotation generation
- Report formatting

## Usage Examples

### Example 1: Binary Analysis

```python
from reveng.tools.core import optimal_binary_analysis

analyzer = optimal_binary_analysis.OptimalBinaryAnalyzer()
result = analyzer.analyze("/path/to/binary.exe")

print(f"Functions found: {len(result['functions'])}")
print(f"Architecture: {result['architecture']}")
```

### Example 2: Binary Deobfuscation

```python
from reveng.tools.core import deobfuscation_tool

deobfuscator = deobfuscation_tool.Deobfuscator()
result = deobfuscator.deobfuscate("/path/to/obfuscated.exe")

print(f"Obfuscation techniques removed: {result['techniques_removed']}")
```

### Example 3: AI-Powered Recompilation

```python
from reveng.tools.core import ai_recompiler_converter

recompiler = ai_recompiler_converter.AIRecompiler()
source_code = recompiler.convert_to_source("/path/to/binary.exe")

with open("output.c", "w") as f:
    f.write(source_code)
```

## Related Modules

- `/home/user/reveng-main/src/reveng/analyzer/` - Main analyzer
- `/home/user/reveng-main/src/reveng/deobfuscation/` - Advanced deobfuscation
- `/home/user/reveng-main/src/reveng/ai/` - AI utilities

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
