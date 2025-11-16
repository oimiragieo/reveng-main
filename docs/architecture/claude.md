# Architecture Documentation

## Overview

The `docs/architecture/` directory contains detailed architecture documentation for REVENG, including system design, component interaction, pipeline architecture, and integration patterns.

**Purpose**: Document the technical architecture and design of REVENG.

**Location**: `/home/user/reveng-main/docs/architecture/`

## Directory Contents

```
architecture/
├── claude.md                  # This file
├── overview.md                # Architecture overview (2,085 bytes)
├── pipeline.md                # Pipeline architecture (2,007 bytes)
├── package-map.md             # Package structure (1,555 bytes)
└── ghidra-integration.md      # Ghidra integration (9,691 bytes)
```

## Key Files

**overview.md** - High-level architecture overview including:
- System components
- Component relationships
- Data flow
- Technology stack

**pipeline.md** - Analysis pipeline architecture:
- Pipeline stages
- Data transformations
- Error handling
- State management

**package-map.md** - Code organization:
- Package structure
- Module hierarchy
- Dependencies
- Import patterns

**ghidra-integration.md** - Ghidra integration architecture:
- Server architecture
- HTTP API design
- Request/response flow
- Error handling
- Performance considerations

## Usage

### For Architects
- Study `overview.md` for system design
- Reference `pipeline.md` for workflow design
- Use `package-map.md` for code organization

### For Developers
- Understand component interaction
- Learn integration patterns
- Follow architectural guidelines

## Related Documentation
- `docs/developer-guide/ARCHITECTURE.md` - Detailed architecture
- `docs/guides/pipeline-development.md` - Pipeline development
- `docs/development/PROJECT_STRUCTURE.md` - Project structure

---

**Target Audience**: Architects, senior developers
**Scope**: System-level design and architecture
