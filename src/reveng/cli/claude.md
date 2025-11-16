# REVENG CLI

## Overview

Command-line interface for REVENG providing interactive and batch analysis capabilities with a powerful CLI framework.

**Location:** `/home/user/reveng-main/src/reveng/cli/`

## Key Features

### Interactive Mode
- REPL interface
- Tab completion
- Command history
- Syntax highlighting

### Batch Mode
- Script execution
- Batch processing
- Automation support
- Pipeline integration

### Commands
- Analysis commands
- Configuration commands
- Export commands
- Plugin management

## Usage Examples

### Example 1: Interactive Analysis

```bash
# Start interactive mode
reveng --interactive

# Analyze binary
> analyze /path/to/binary.exe

# View results
> show functions
> show imports
```

### Example 2: Batch Processing

```bash
# Batch analyze directory
reveng batch /path/to/binaries/ --output /path/to/results/

# Run script
reveng script analysis.reveng
```

## Related Modules

- `/home/user/reveng-main/src/reveng/` - Main analyzer

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
