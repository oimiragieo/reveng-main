# Directory: src/reveng/integrations

## Overview
This directory contains integration modules for external reverse engineering tools and services. The primary integration is with Ghidra, providing a comprehensive interface to Ghidra's analysis capabilities.

## Files in This Directory

### __init__.py
- **Purpose**: Package initialization
- **Dependencies**: None

## Architecture

```
┌─────────────────────────────────────┐
│   Integrations Layer                │
├─────────────────────────────────────┤
│ • External tool connectors          │
│ • Protocol adapters                 │
│ • Data format converters            │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────┐
       │  ghidra/       │
       │  Ghidra        │
       │  Integration   │
       └────────────────┘
```

## Key Concepts

### Integration Philosophy
- Provide unified interfaces to external tools
- Abstract tool-specific details
- Handle connection management
- Convert data formats
- Provide error recovery

### Supported Integrations
- **Ghidra**: Primary RE tool integration (see ghidra/ subdirectory)
- Future: IDA Pro, Binary Ninja, Radare2, angr

## Related Modules

### Subdirectories
- `src/reveng/integrations/ghidra/`: Ghidra integration (see separate claude.md)

### Used By
- `src/reveng/analyzer.py`: Uses integrations for analysis
- `src/reveng/tools/*`: Tools use integrations

## Notes

### Design Patterns
- Factory pattern for tool selection
- Adapter pattern for API normalization
- Strategy pattern for tool-specific behavior

### Best Practices
1. Check tool availability before using
2. Handle connection failures gracefully
3. Validate tool versions
4. Cache tool results when possible
5. Provide fallbacks when tools unavailable
