# REVENG Deobfuscation

## Overview

Advanced deobfuscation module for removing obfuscation from binaries and code, including control flow flattening, string encryption, and code virtualization.

**Location:** `/home/user/reveng-main/src/reveng/deobfuscation/`

## Key Features

### Control Flow Deobfuscation
- Control flow flattening removal
- Opaque predicate removal
- Jump table resolution
- Indirect call resolution

### String Deobfuscation
- Encrypted string decryption
- Stack string reconstruction
- XOR string decoding
- Custom encoding detection

### Code Deobfuscation
- Dead code elimination
- Constant folding
- Expression simplification
- Code normalization

### Advanced Techniques
- VM-based obfuscation removal
- Packer unpacking
- Code virtualization reversal

## Usage Examples

### Example 1: Deobfuscate Binary

```python
from reveng.deobfuscation import Deobfuscator

deob = Deobfuscator()
result = deob.deobfuscate("/path/to/obfuscated.exe")

print(f"Techniques removed: {result['techniques']}")
print(f"Clarity improvement: {result['clarity_score']}")
```

### Example 2: String Deobfuscation

```python
from reveng.deobfuscation import StringDeobfuscator

str_deob = StringDeobfuscator()
strings = str_deob.extract_strings("/path/to/binary.exe")

for s in strings:
    print(f"Decrypted: {s['value']}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/tools/core/` - Core deobfuscation tools
- `/home/user/reveng-main/src/reveng/devirtualization/` - VM deobfuscation
- `/home/user/reveng-main/src/reveng/tools/anti_analysis/` - Anti-analysis evasion

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
