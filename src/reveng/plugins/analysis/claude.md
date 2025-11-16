# Plugins - Analysis

## Overview

Analysis plugins extend REVENG's core analysis capabilities with specialized analysis for specific file formats and binary types. These plugins implement the `AnalysisPlugin` interface and provide deep insights into binary structure, behavior, and characteristics.

**Location:** `/home/user/reveng-main/src/reveng/plugins/analysis/`

## Files in This Directory

### `pe_analyzer_plugin.py` (8437 lines)
Portable Executable (PE) file analysis plugin.

**PEAnalyzerPlugin:**
- **Category:** CORE_ANALYSIS
- **Priority:** HIGH
- **Dependencies:** `pefile` library

**Features:**
- PE header analysis (PE32/PE32+)
- Section analysis
- Import/Export table parsing
- Resource extraction
- Certificate verification
- Characteristics analysis

**Analysis Output:**
- File type and architecture
- Entry point and image base
- Section information (name, virtual address, size, characteristics)
- Imported DLLs and functions
- Exported functions
- Resources (icons, strings, version info)
- Digital signatures

**Usage:**
```python
from reveng.plugins.analysis import PEAnalyzerPlugin

plugin = PEAnalyzerPlugin()
context = PluginContext(binary_path="/path/to/app.exe")
result = plugin.analyze(context)

print(f"PE Type: {result['pe_type']}")
print(f"Entry Point: {result['entry_point']}")
print(f"Imports: {len(result['imports'])} DLLs")
```

## Architecture

### Plugin Lifecycle

```
1. Registration
   └─> Plugin discovered and loaded

2. Initialization
   ├─> Check dependencies (pefile)
   ├─> Validate requirements
   └─> Setup internal state

3. Analysis
   ├─> Load binary file
   ├─> Parse PE structure
   ├─> Extract metadata
   ├─> Analyze sections
   ├─> Parse imports/exports
   └─> Return results

4. Cleanup
   └─> Release resources
```

### Integration with Core

```
REVENG Core Analyzer
  ↓
Plugin Manager
  ↓
Analysis Plugins
  ├─> PEAnalyzerPlugin
  ├─> ELFAnalyzerPlugin (future)
  └─> MachOAnalyzerPlugin (future)
```

## Key Concepts

### 1. Plugin Metadata

All analysis plugins provide comprehensive metadata:

```python
PluginMetadata(
    name="pe_analyzer",
    version="1.0.0",
    description="Analyzes PE files...",
    category=PluginCategory.CORE_ANALYSIS,
    priority=PluginPriority.HIGH,
    dependencies=[],
    requirements=["pefile"],
    tags=["pe", "windows", "executable"]
)
```

### 2. Context-Based Analysis

Plugins receive context with analysis parameters:

```python
context = PluginContext(
    binary_path="/path/to/binary",
    output_dir="/path/to/output",
    options={"deep_analysis": True}
)
```

### 3. Structured Results

Plugins return structured analysis results:

```python
{
    "pe_type": "PE32",
    "architecture": "x86",
    "sections": [...],
    "imports": [...],
    "exports": [...],
    "resources": [...]
}
```

## Usage Examples

### Example 1: Basic PE Analysis

```python
from reveng.plugins.analysis import PEAnalyzerPlugin
from reveng.plugins.base import PluginContext

# Initialize plugin
plugin = PEAnalyzerPlugin()
context = PluginContext(binary_path="malware.exe")

if plugin.initialize(context):
    # Perform analysis
    result = plugin.analyze(context)

    # Access results
    print(f"Machine: {result['machine']}")
    print(f"Subsystem: {result['subsystem']}")
    print(f"Sections: {len(result['sections'])}")
```

### Example 2: Deep Import Analysis

```python
result = plugin.analyze(context)

# Analyze imports
for dll_name, functions in result['imports'].items():
    print(f"\nDLL: {dll_name}")
    for func in functions[:5]:
        print(f"  - {func}")

# Check for suspicious imports
suspicious = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread"]
for func in suspicious:
    for dll, funcs in result['imports'].items():
        if func in funcs:
            print(f"⚠️ Suspicious: {dll}.{func}")
```

### Example 3: Resource Extraction

```python
result = plugin.analyze(context)

# Extract resources
resources = result['resources']
for res in resources:
    if res['type'] == 'RT_ICON':
        print(f"Icon: {res['name']}, Size: {res['size']}")
    elif res['type'] == 'RT_STRING':
        print(f"String: {res['data']}")
```

## Configuration

### Plugin Configuration

```python
# Configure via plugin context
context = PluginContext(
    binary_path="app.exe",
    options={
        "parse_resources": True,
        "extract_strings": True,
        "verify_signatures": True,
        "deep_imports": True
    }
)
```

### Dependencies

Install required dependencies:

```bash
pip install pefile
```

## Testing

### Unit Tests

```python
import pytest
from reveng.plugins.analysis import PEAnalyzerPlugin
from reveng.plugins.base import PluginContext

def test_pe_analyzer():
    plugin = PEAnalyzerPlugin()
    context = PluginContext(binary_path="test.exe")

    assert plugin.initialize(context)

    result = plugin.analyze(context)
    assert "pe_type" in result
    assert "sections" in result
    assert len(result["sections"]) > 0
```

### Running Tests

```bash
pytest tests/plugins/analysis/test_pe_analyzer.py
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/plugins/` - Plugin framework
- `/home/user/reveng-main/src/reveng/core/` - Core functionality

### External Dependencies
- `pefile` - PE file parsing library

## Notes

**Best Practices:**
1. Always validate binary file exists before analysis
2. Handle malformed PE files gracefully
3. Limit resource extraction to avoid DoS
4. Validate all user inputs

**Security Considerations:**
- PE files can contain malicious resources
- Limit memory usage during analysis
- Sandbox resource extraction
- Validate digital signatures

**Future Enhancements:**
- [ ] ELF file analysis plugin
- [ ] Mach-O file analysis plugin
- [ ] Archive analysis (ZIP, RAR, etc.)
- [ ] Document analysis (PDF, Office)
- [ ] Mobile app analysis (APK, IPA)

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
