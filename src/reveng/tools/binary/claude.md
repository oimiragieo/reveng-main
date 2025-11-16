# Tools - Binary

## Overview

Binary manipulation and analysis tools for reading, writing, and modifying binary files at a low level.

**Location:** `/home/user/reveng-main/src/reveng/tools/binary/`

**File Count:** 6 Python files

## Key Capabilities

### Binary Reading
- Parse binary file formats
- Extract sections and segments
- Read headers and metadata

### Binary Writing
- Create new binaries
- Modify existing binaries
- Inject code and data

### Binary Analysis
- Calculate checksums
- Analyze entropy
- Detect anomalies

## Usage Examples

### Example 1: Read Binary Metadata

```python
from reveng.tools.binary import BinaryReader

reader = BinaryReader("/path/to/binary.exe")
headers = reader.read_headers()
sections = reader.read_sections()

print(f"Entry Point: {headers['entry_point']}")
print(f"Sections: {len(sections)}")
```

### Example 2: Modify Binary

```python
from reveng.tools.binary import BinaryWriter

writer = BinaryWriter("/path/to/binary.exe")
writer.patch_bytes(offset=0x1000, data=b"\x90\x90\x90")
writer.save("/path/to/modified.exe")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/pe/` - PE-specific binary tools
- `/home/user/reveng-main/src/reveng/utils/` - General utilities

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
