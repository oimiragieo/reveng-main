# REVENG Anti-Evasion

## Overview

Anti-evasion module for detecting and bypassing anti-analysis, anti-debugging, and anti-VM techniques used by malware and protected software.

**Location:** `/home/user/reveng-main/src/reveng/evasion/`

## Key Features

### Evasion Detection
- Anti-debugging detection
- Anti-VM detection
- Anti-emulation detection
- Sandbox detection

### Evasion Bypass
- Debugger hiding
- VM artifact removal
- Timing manipulation
- API hooking

### Protection Analysis
- Code protection detection
- Integrity checks
- Environmental checks
- Trigger analysis

## Usage Examples

### Example 1: Detect Evasion Techniques

```python
from reveng.evasion import EvasionDetector

detector = EvasionDetector()
evasions = detector.detect("/path/to/binary.exe")

for evasion in evasions:
    print(f"Type: {evasion['type']}")
    print(f"Technique: {evasion['technique']}")
    print(f"Location: {evasion['address']}")
```

### Example 2: Bypass Anti-Debugging

```python
from reveng.evasion import AntiDebugBypass

bypass = AntiDebugBypass()
bypass.enable()

# Now debugging is hidden from target
# Analyze with debugger
```

## Related Modules

- `/home/user/reveng-main/src/reveng/tools/anti_analysis/` - Anti-analysis tools
- `/home/user/reveng-main/src/reveng/security/` - Security analysis

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
