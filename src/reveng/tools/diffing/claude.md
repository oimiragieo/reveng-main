# Tools - Diffing

## Overview

Binary diffing and comparison tools for identifying changes between binary versions, patch analysis, and variant detection.

**Location:** `/home/user/reveng-main/src/reveng/tools/diffing/`

**File Count:** 3 Python files

## Key Capabilities

### Binary Diffing
- Byte-level comparison
- Function-level diffing
- Structural comparison
- Patch identification

### Diff Analysis
- Change detection
- Security patch analysis
- Malware variant detection
- Code evolution tracking

### Diff Visualization
- Side-by-side comparison
- Highlighted changes
- Diff reports

## Usage Examples

### Example 1: Compare Binaries

```python
from reveng.tools.diffing import BinaryDiffer

differ = BinaryDiffer()
diff_result = differ.compare(
    original="/path/to/v1.exe",
    modified="/path/to/v2.exe"
)

print(f"Changes: {diff_result['change_count']}")
print(f"Modified functions: {len(diff_result['modified_functions'])}")
```

### Example 2: Patch Analysis

```python
from reveng.tools.diffing import PatchAnalyzer

analyzer = PatchAnalyzer()
patches = analyzer.analyze_patch(
    original="/path/to/vulnerable.exe",
    patched="/path/to/patched.exe"
)

for patch in patches:
    print(f"Location: {patch['address']}")
    print(f"Type: {patch['patch_type']}")
    print(f"Security relevant: {patch['is_security_fix']}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/diffing/` - Core diffing functionality
- `/home/user/reveng-main/src/reveng/malware/` - Variant detection

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
