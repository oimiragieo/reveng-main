# REVENG Installers

## Overview

Installer analysis module for analyzing setup programs, MSI packages, and installation scripts.

**Location:** `/home/user/reveng-main/src/reveng/installers/`

## Key Features

### Installer Types
- MSI packages
- NSIS installers
- InstallShield
- InnoSetup
- Custom installers

### Installation Analysis
- File extraction
- Registry changes
- Service installation
- Startup items
- Persistence mechanisms

### Security Analysis
- Bundled software detection
- Privilege escalation
- Unwanted software
- Backdoor detection

## Usage Examples

### Example 1: Analyze Installer

```python
from reveng.installers import InstallerAnalyzer

analyzer = InstallerAnalyzer()
result = analyzer.analyze("/path/to/setup.exe")

print(f"Installer type: {result['type']}")
print(f"Files to install: {len(result['files'])}")
print(f"Registry changes: {len(result['registry_changes'])}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/pe/` - PE analysis

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
