# REVENG Compilation

## Overview

Compilation and recompilation utilities for translating between different code representations, compiling lifted code, and generating executable binaries from analysis results.

**Location:** `/home/user/reveng-main/src/reveng/compilation/`

## Key Features

### Code Compilation
- C/C++ compilation
- LLVM IR compilation
- Assembly to binary
- Cross-compilation

### Recompilation
- Binary to source to binary
- Architecture translation
- Optimization passes
- ABI adaptation

### Build System Integration
- Make/CMake integration
- Custom build scripts
- Dependency management
- Multi-platform builds

## Usage Examples

### Example 1: Compile Lifted Code

```python
from reveng.compilation import Compiler

compiler = Compiler()
binary = compiler.compile(
    source_code=lifted_code,
    language="c",
    output="/path/to/recompiled.exe"
)

print(f"Compiled successfully: {binary}")
```

### Example 2: Cross-Compile

```python
from reveng.compilation import CrossCompiler

compiler = CrossCompiler()
result = compiler.compile(
    source="/path/to/code.c",
    target_arch="arm64",
    output="/path/to/arm_binary"
)
```

## Related Modules

- `/home/user/reveng-main/src/reveng/lifting/` - Code lifting
- `/home/user/reveng-main/src/reveng/tools/translation/` - Translation tools

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
