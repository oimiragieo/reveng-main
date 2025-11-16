# Tools - Anti-Analysis

## Overview

Anti-analysis tools detect and bypass anti-debugging, anti-VM, and packer protections commonly used in malware and protected software.

**Location:** `/home/user/reveng-main/src/reveng/tools/anti_analysis/`

## Files in This Directory

### `__init__.py` (219 lines)
Module initialization.

### `packer_detector.py` (7661 lines)
Detects executable packers and protectors.

**Detected Packers:**
- UPX
- ASPack
- PECompact
- Themida
- VMProtect
- And 50+ more

**Features:**
- Signature-based detection
- Heuristic analysis
- Entropy analysis
- Section analysis

### `universal_unpacker.py` (13519 lines)
Universal unpacking tool for packed executables.

**Features:**
- Automatic packer detection
- Memory dumping
- Import reconstruction
- OEP (Original Entry Point) detection
- Multi-stage unpacking

## Usage Examples

### Example 1: Detect Packer

```python
from reveng.tools.anti_analysis import packer_detector

detector = packer_detector.PackerDetector()
result = detector.detect("/path/to/packed.exe")

if result['is_packed']:
    print(f"Packer: {result['packer_name']}")
    print(f"Confidence: {result['confidence']}")
```

### Example 2: Unpack Binary

```python
from reveng.tools.anti_analysis import universal_unpacker

unpacker = universal_unpacker.UniversalUnpacker()
result = unpacker.unpack("/path/to/packed.exe", output="/path/to/unpacked.exe")

if result['success']:
    print(f"Unpacked to: {result['output_path']}")
    print(f"OEP: {result['original_entry_point']}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/evasion/` - Anti-evasion techniques
- `/home/user/reveng-main/src/reveng/security/` - Security analysis

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
