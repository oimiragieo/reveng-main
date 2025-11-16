# REVENG Devirtualization

## Overview

VM-based obfuscation removal module for analyzing and devirtualizing code protected by virtual machine obfuscators like VMProtect, Themida, and custom VM engines.

**Location:** `/home/user/reveng-main/src/reveng/devirtualization/`

## Key Features

### VM Detection
- VM architecture detection
- Handler identification
- Context structure analysis
- Dispatcher analysis

### VM Analysis
- Bytecode extraction
- Handler analysis
- Control flow reconstruction
- Data flow analysis

### Devirtualization
- Bytecode to assembly translation
- Code reconstruction
- Optimization
- Simplification

## Usage Examples

### Example 1: Detect VM Protection

```python
from reveng.devirtualization import VMDetector

detector = VMDetector()
result = detector.detect("/path/to/protected.exe")

if result['is_virtualized']:
    print(f"VM Type: {result['vm_type']}")
    print(f"Virtualized functions: {len(result['vm_functions'])}")
```

### Example 2: Devirtualize Code

```python
from reveng.devirtualization import Devirtualizer

devm = Devirtualizer()
result = devm.devirtualize(
    binary="/path/to/protected.exe",
    function_address=0x401000
)

print(f"Original code:\n{result['devirtualized_code']}")
print(f"Confidence: {result['confidence']}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/deobfuscation/` - General deobfuscation
- `/home/user/reveng-main/src/reveng/tools/anti_analysis/` - Anti-analysis tools

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
