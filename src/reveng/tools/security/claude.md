# Tools - Security

## Overview

Security analysis tools for vulnerability detection, exploit analysis, and security assessment of binaries.

**Location:** `/home/user/reveng-main/src/reveng/tools/security/`

**File Count:** 1 Python file

## Key Capabilities

### Vulnerability Detection
- Buffer overflow detection
- Format string vulnerabilities
- Use-after-free detection
- Integer overflow detection

### Security Features
- ASLR detection
- DEP/NX detection
- Stack canary detection
- CFG/CET detection

### Exploit Analysis
- ROP gadget finding
- Shellcode detection
- Exploit mitigation bypass analysis

## Usage Examples

### Example 1: Security Scan

```python
from reveng.tools.security import SecurityScanner

scanner = SecurityScanner()
result = scanner.scan("/path/to/binary.exe")

print(f"Vulnerabilities: {len(result['vulnerabilities'])}")
print(f"Security features: {result['security_features']}")
print(f"Risk score: {result['risk_score']}/100")
```

### Example 2: Check Security Mitigations

```python
from reveng.tools.security import MitigationChecker

checker = MitigationChecker()
mitigations = checker.check("/path/to/binary.exe")

print(f"ASLR: {mitigations['aslr']}")
print(f"DEP: {mitigations['dep']}")
print(f"Stack Canary: {mitigations['stack_canary']}")
print(f"CFG: {mitigations['cfg']}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/security/` - Core security functionality
- `/home/user/reveng-main/src/reveng/exploits/` - Exploit generation

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
