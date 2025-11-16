# REVENG Ghidra Integration

## Overview

Ghidra integration module providing programmatic access to Ghidra's decompilation and analysis capabilities.

**Location:** `/home/user/reveng-main/src/reveng/ghidra/`

## Key Features

### Ghidra Integration
- Headless analysis
- Script execution
- Project management
- API access

### Decompilation
- Function decompilation
- Type recovery
- Symbol resolution
- Cross-references

### Analysis
- Disassembly
- Function analysis
- String analysis
- Data type analysis

## Usage Examples

### Example 1: Decompile with Ghidra

```python
from reveng.ghidra import GhidraDecompiler

decompiler = GhidraDecompiler()
result = decompiler.decompile("/path/to/binary.exe")

for func_name, code in result['functions'].items():
    print(f"Function: {func_name}")
    print(code)
```

## Related Modules

- `/home/user/reveng-main/src/reveng/integrations/ghidra/` - Ghidra integration
- `/home/user/reveng-main/src/reveng/tools/decompilers/` - Decompiler tools

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
