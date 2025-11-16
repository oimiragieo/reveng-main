# Agent SDK - REVENG Tools

## Overview

REVENG-specific tools that provide direct integration with REVENG's binary analysis and JavaScript deobfuscation capabilities. These tools expose core REVENG functionality to the agent framework.

**Location:** `/home/user/reveng-main/src/reveng/agent_sdk/tools/reveng/`

## Files in This Directory

### `__init__.py` (478 lines)
Exports REVENG tools.

**Exports:**
- `BinaryAnalysisTool` - Binary analysis and decompilation
- `JSDeobfuscationTool` - JavaScript deobfuscation

### `binary_analysis_tool.py` (3880 lines)
Binary analysis tool integrating with REVENG analyzer.

**BinaryAnalysisTool:**
- **Name:** `analyze_binary`
- **Purpose:** Analyze binary files (EXE, DLL, ELF, etc.)
- **Input:** `path` (string), `quick_mode` (boolean, optional)
- **Output:** File type, architecture, vulnerabilities, decompiled code

**Features:**
- Automatic file type detection
- Architecture identification
- Vulnerability scanning
- Decompilation
- Symbol extraction
- Control flow analysis

### `js_deobfuscation_tool.py` (4684 lines)
JavaScript deobfuscation tool.

**JSDeobfuscationTool:**
- **Name:** `deobfuscate_javascript`
- **Purpose:** Deobfuscate JavaScript code
- **Input:** `code` (string), `use_ml` (boolean), `detect_malware` (boolean)
- **Output:** Deobfuscated code, confidence score, obfuscation types, malware analysis

**Features:**
- Multiple deobfuscation techniques
- ML-based identifier renaming
- Malware detection integration
- Confidence scoring
- Obfuscation type identification

## Usage Examples

### Example 1: Binary Analysis

```python
from reveng.agent_sdk.tools.reveng import BinaryAnalysisTool

async def analyze():
    tool = BinaryAnalysisTool()

    result = await tool.execute({
        "path": "/path/to/malware.exe",
        "quick_mode": False
    })

    if result.success:
        print(result.content[0]["text"])
```

### Example 2: JS Deobfuscation

```python
from reveng.agent_sdk.tools.reveng import JSDeobfuscationTool

async def deobfuscate():
    tool = JSDeobfuscationTool()

    result = await tool.execute({
        "code": "var _0x1234=['hello'];",
        "use_ml": True,
        "detect_malware": True
    })

    if result.success:
        print(result.content[0]["text"])
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/analyzer/` - Binary analysis backend
- `/home/user/reveng-main/src/reveng/javascript/` - JS deobfuscation backend

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
