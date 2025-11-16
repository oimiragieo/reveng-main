# Tools - Decompilers

## Overview

Decompiler integration and management tools, providing interfaces to various decompilation engines including Ghidra, IDA, Binary Ninja, and custom decompilers.

**Location:** `/home/user/reveng-main/src/reveng/tools/decompilers/`

**File Count:** 2 Python files

## Key Capabilities

### Decompiler Integration
- Ghidra headless decompiler
- IDA Pro integration
- Binary Ninja integration
- Custom REVENG decompiler

### Decompilation Management
- Batch decompilation
- Result caching
- Output formatting
- Error handling

## Usage Examples

### Example 1: Decompile with Ghidra

```python
from reveng.tools.decompilers import GhidraDecompiler

decompiler = GhidraDecompiler()
result = decompiler.decompile("/path/to/binary.exe")

for function_name, code in result['functions'].items():
    print(f"Function: {function_name}")
    print(code)
```

### Example 2: Batch Decompilation

```python
from reveng.tools.decompilers import BatchDecompiler

batch = BatchDecompiler(engine="ghidra")
results = batch.decompile_directory("/path/to/binaries/")

for binary, result in results.items():
    print(f"{binary}: {len(result['functions'])} functions")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/integrations/ghidra/` - Ghidra integration
- `/home/user/reveng-main/src/reveng/lifting/` - Code lifting

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
