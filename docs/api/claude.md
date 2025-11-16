# API Documentation

## Overview

The `docs/api/` directory contains API reference documentation for REVENG's Python API and AI/ML integration APIs. This includes function signatures, parameters, return values, and usage examples.

**Purpose**: Provide complete API reference for programmatic use of REVENG.

**Location**: `/home/user/reveng-main/docs/api/`

## Directory Contents

```
api/
├── claude.md                  # This file
├── API_REFERENCE.md           # Core API reference (13,292 bytes)
├── AI_API_REFERENCE.md        # AI/ML API reference (12,580 bytes)
└── output-schema.json         # Output schema definition (6,008 bytes)
```

## Key Files

**API_REFERENCE.md** - Core API documentation including:
- Core analyzer API
- Binary analysis functions
- Decompilation interfaces
- Recompilation APIs
- Security analysis functions
- Report generation

**AI_API_REFERENCE.md** - AI/ML API documentation including:
- Gemini engine API
- Claude integration API
- ML model interfaces
- Code enhancement functions
- Vulnerability detection
- Exploit generation

**output-schema.json** - JSON schema defining:
- Analysis output format
- Report structure
- Vulnerability schema
- Exploit schema
- Metadata format

## Usage

### For Python Developers

```python
# Import REVENG API
from reveng.core.analyzer import Analyzer
from reveng.ai.gemini_engine import GeminiEngine

# Initialize analyzer
analyzer = Analyzer()

# Analyze binary
result = analyzer.analyze("binary.exe")

# Access results
print(result.vulnerabilities)
print(result.exploits)
```

### For API Integration

```python
# Use AI enhancement API
from reveng.ai.gemini_engine import GeminiEngine

engine = GeminiEngine(api_key="your-key")
enhanced_code = await engine.enhance_code(decompiled_code)
```

## Related Documentation
- `docs/guides/` - Integration guides and tutorials
- `examples/` - Code examples
- `src/reveng/` - Source code with docstrings

---

**Target Audience**: Python developers, integrators
**API Stability**: Stable (v3.0+)
