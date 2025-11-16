# REVENG Utils

## Overview

Common utility functions and helper classes used across the REVENG framework.

**Location:** `/home/user/reveng-main/src/reveng/utils/`

## Key Utilities

### File Utilities
- File I/O operations
- Path manipulation
- Temporary file management
- Archive handling

### String Utilities
- String extraction
- Pattern matching
- Encoding conversion
- String normalization

### Data Utilities
- Data serialization
- Format conversion
- Compression
- Hashing

### System Utilities
- Process execution
- Environment detection
- Platform detection
- Resource management

## Usage Examples

### Example 1: File Operations

```python
from reveng.utils import file_utils

# Read binary file
data = file_utils.read_binary("/path/to/file")

# Calculate hash
hash_value = file_utils.calculate_sha256("/path/to/file")
```

### Example 2: String Extraction

```python
from reveng.utils import string_utils

# Extract strings from binary
strings = string_utils.extract_strings("/path/to/binary.exe")

for s in strings:
    print(f"{s.offset:08x}: {s.value}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/core/` - Core functionality
- `/home/user/reveng-main/src/reveng/types/` - Type definitions
- `/home/user/reveng-main/src/reveng/tools/utils/` - Tool utilities

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
