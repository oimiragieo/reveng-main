# REVENG Diffing

## Overview

Binary diffing and comparison module for identifying differences between binary versions, analyzing patches, and detecting malware variants.

**Location:** `/home/user/reveng-main/src/reveng/diffing/`

## Key Features

### Binary Comparison
- Byte-level diffing
- Function-level diffing
- Structural comparison
- Semantic diffing

### Patch Analysis
- Security patch detection
- Bug fix identification
- Feature change detection
- Version comparison

### Variant Detection
- Malware variant analysis
- Code reuse detection
- Similarity scoring
- Family grouping

## Usage Examples

### Example 1: Compare Binaries

```python
from reveng.diffing import BinaryDiffer

differ = BinaryDiffer()
diff = differ.compare(
    binary1="/path/to/v1.exe",
    binary2="/path/to/v2.exe"
)

print(f"Modified functions: {len(diff['modified_functions'])}")
print(f"New functions: {len(diff['new_functions'])}")
print(f"Removed functions: {len(diff['removed_functions'])}")
```

### Example 2: Analyze Patch

```python
from reveng.diffing import PatchAnalyzer

analyzer = PatchAnalyzer()
patches = analyzer.analyze(
    original="/path/to/vulnerable.exe",
    patched="/path/to/patched.exe"
)

for patch in patches:
    print(f"Address: {patch['address']}")
    print(f"Type: {patch['type']}")
    print(f"Security fix: {patch['is_security']}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/tools/diffing/` - Diffing tools
- `/home/user/reveng-main/src/reveng/malware/` - Malware analysis

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
