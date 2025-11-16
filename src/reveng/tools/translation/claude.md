# Tools - Translation

## Overview

Binary translation and code conversion tools for translating between different binary formats, architectures, and intermediate representations.

**Location:** `/home/user/reveng-main/src/reveng/tools/translation/`

**File Count:** 4 Python files

## Key Capabilities

### Architecture Translation
- x86 to ARM translation
- x64 to x86 translation
- MIPS to x86 translation
- Cross-architecture emulation

### Format Translation
- PE to ELF conversion
- ELF to PE conversion
- Mach-O conversion
- LLVM IR generation

### Code Translation
- Assembly to C
- Binary to LLVM IR
- Binary to WebAssembly
- Bytecode translation

## Usage Examples

### Example 1: Translate Architecture

```python
from reveng.tools.translation import ArchitectureTranslator

translator = ArchitectureTranslator()
result = translator.translate(
    binary="/path/to/x86.exe",
    target_arch="arm64"
)

print(f"Translated binary: {result['output_path']}")
print(f"Instructions translated: {result['instruction_count']}")
```

### Example 2: Generate LLVM IR

```python
from reveng.tools.translation import LLVMTranslator

translator = LLVMTranslator()
llvm_ir = translator.to_llvm_ir("/path/to/binary.exe")

with open("output.ll", "w") as f:
    f.write(llvm_ir)
```

## Related Modules

- `/home/user/reveng-main/src/reveng/lifting/` - Code lifting
- `/home/user/reveng-main/src/reveng/compilation/` - Compilation utilities

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
