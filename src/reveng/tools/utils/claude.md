# Tools - Utils

## Overview

Utility tools providing helper functions, data structures, and common functionality used across REVENG.

**Location:** `/home/user/reveng-main/src/reveng/tools/utils/`

**File Count:** 19 Python files

## Key Utilities

### File Operations
- File I/O utilities
- Path manipulation
- Temporary file management
- Archive handling

### Data Processing
- Data parsing
- Format conversion
- Encoding/decoding
- Compression/decompression

### String Utilities
- String extraction
- Pattern matching
- Unicode handling
- String normalization

### Crypto Utilities
- Hash calculation
- Checksum verification
- Encryption/decryption helpers
- Certificate handling

### System Utilities
- Process management
- Command execution
- Environment handling
- Platform detection

## Usage Examples

### Example 1: Extract Strings

```python
from reveng.tools.utils import string_extractor

extractor = string_extractor.StringExtractor()
strings = extractor.extract("/path/to/binary.exe")

for s in strings:
    print(f"{s['offset']:08x}: {s['value']}")
```

### Example 2: Calculate Hashes

```python
from reveng.tools.utils import hash_utils

hashes = hash_utils.calculate_all("/path/to/file.exe")

print(f"MD5: {hashes['md5']}")
print(f"SHA1: {hashes['sha1']}")
print(f"SHA256: {hashes['sha256']}")
```

### Example 3: Archive Extraction

```python
from reveng.tools.utils import archive_utils

archive_utils.extract_all(
    archive="/path/to/samples.zip",
    output_dir="/path/to/extracted/"
)
```

## Related Modules

- `/home/user/reveng-main/src/reveng/utils/` - Core utilities
- `/home/user/reveng-main/src/reveng/types/` - Type definitions

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
