# REVENG Types

## Overview

Type definitions, data classes, and type hints for the REVENG framework providing strong typing throughout the codebase.

**Location:** `/home/user/reveng-main/src/reveng/types/`

## Key Components

### Data Classes
- Analysis results
- Binary metadata
- Function information
- Instruction data
- Configuration types

### Type Aliases
- Path types
- Address types
- Size types
- Architecture enums

### Protocols
- Analyzer protocol
- Plugin protocol
- Tool protocol
- Decompiler protocol

## Usage Examples

### Example 1: Analysis Result Types

```python
from reveng.types import AnalysisResult, FunctionInfo

result = AnalysisResult(
    binary_path="/path/to/binary.exe",
    architecture="x86_64",
    functions=[
        FunctionInfo(name="main", address=0x401000, size=150)
    ]
)
```

### Example 2: Type Hints

```python
from reveng.types import BinaryPath, Address

def analyze_function(binary: BinaryPath, address: Address) -> FunctionInfo:
    # Implementation
    pass
```

## Related Modules

- `/home/user/reveng-main/src/reveng/core/` - Core functionality
- `/home/user/reveng-main/src/reveng/utils/` - Utilities

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
