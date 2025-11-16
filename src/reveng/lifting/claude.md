# REVENG Lifting

## Overview

Code lifting module for translating low-level assembly and binary code to higher-level intermediate representations and source code.

**Location:** `/home/user/reveng-main/src/reveng/lifting/`

## Key Features

### Intermediate Representations
- LLVM IR generation
- REIL (Reverse Engineering Intermediate Language)
- VEX IR
- Custom IR formats

### Code Translation
- Assembly to C
- Assembly to pseudocode
- Binary to LLVM
- Cross-architecture translation

### Optimization
- IR optimization passes
- Dead code elimination
- Constant propagation
- Loop optimization

## Usage Examples

### Example 1: Lift to LLVM IR

```python
from reveng.lifting import LLVMLifter

lifter = LLVMLifter()
ir_code = lifter.lift("/path/to/binary.exe")

with open("output.ll", "w") as f:
    f.write(ir_code)
```

### Example 2: Lift to Pseudocode

```python
from reveng.lifting import PseudocodeLifter

lifter = PseudocodeLifter()
pseudocode = lifter.lift_function(
    binary="/path/to/binary.exe",
    function_address=0x401000
)

print(pseudocode)
```

## Related Modules

- `/home/user/reveng-main/src/reveng/compilation/` - Compilation utilities
- `/home/user/reveng-main/src/reveng/tools/translation/` - Translation tools

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
