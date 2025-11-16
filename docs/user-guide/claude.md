# User Guide Documentation

## Overview

The `docs/user-guide/` directory contains comprehensive documentation for end users of REVENG. This includes detailed usage instructions, CLI command references, and best practices for common workflows.

**Purpose**: Guide users through all REVENG features and capabilities.

**Location**: `/home/user/reveng-main/docs/user-guide/`

## Directory Contents

```
user-guide/
├── claude.md                  # This file
├── USER_GUIDE.md              # Comprehensive user guide (3,740 bytes)
└── cli-usage.md               # CLI command reference (7,368 bytes)
```

## Key Files

**USER_GUIDE.md** - Complete user guide covering all features, workflows, and use cases for REVENG.

**cli-usage.md** - Detailed CLI command reference with examples for all commands, options, and flags.

## Usage

### For End Users
1. Read `USER_GUIDE.md` for feature overview
2. Reference `cli-usage.md` for command syntax
3. Follow examples for common tasks

### Common Commands Reference
```bash
# Analyze binary
reveng analyze binary.exe

# Deobfuscate JavaScript
reveng deobfuscate script.js

# Quick triage
reveng triage suspicious.exe

# Generate report
reveng report binary.exe --format pdf
```

## Related Documentation
- `docs/guides/` - Detailed tutorials and guides
- `docs/api/API_REFERENCE.md` - API documentation
- `examples/` - Code examples and demos

---

**Target Audience**: End users, security researchers
**Skill Level**: Beginner to Advanced
