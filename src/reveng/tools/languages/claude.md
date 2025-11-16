# Tools - Languages

## Overview

Multi-language support tools for analyzing binaries compiled from various programming languages and detecting language-specific patterns.

**Location:** `/home/user/reveng-main/src/reveng/tools/languages/`

**File Count:** 7 Python files

## Key Capabilities

### Language Detection
- Detect source language (C, C++, Rust, Go, etc.)
- Identify compiler and version
- Detect build flags

### Language-Specific Analysis
- C/C++ analysis
- Rust binary analysis
- Go binary analysis
- .NET/Java bytecode analysis
- Python compiled bytecode

### Runtime Detection
- Detect runtime libraries
- Identify language frameworks
- Detect standard library usage

## Usage Examples

### Example 1: Detect Programming Language

```python
from reveng.tools.languages import LanguageDetector

detector = LanguageDetector()
result = detector.detect("/path/to/binary.exe")

print(f"Language: {result['language']}")
print(f"Compiler: {result['compiler']}")
print(f"Confidence: {result['confidence']}")
```

### Example 2: Language-Specific Analysis

```python
from reveng.tools.languages import CppAnalyzer

analyzer = CppAnalyzer()
result = analyzer.analyze("/path/to/cpp_binary.exe")

print(f"C++ features: {result['cpp_features']}")
print(f"STL usage: {result['stl_usage']}")
print(f"Exception handling: {result['has_exceptions']}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/analyzers/` - General analyzers
- `/home/user/reveng-main/src/reveng/lifting/` - Code lifting

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
