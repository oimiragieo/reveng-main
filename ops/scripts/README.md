# REVENG Scripts Directory

This directory contains automation scripts for various reverse engineering tools.

## Structure

- `ghidra/` - Ghidra Python and Java scripts for automated analysis
- `ida/` - IDA Pro Python scripts for automated analysis

## Ghidra Scripts

Ghidra scripts are organized by functionality:

- `extract_functions.py` - Extract all function signatures
- `find_xrefs.py` - Find cross-references
- `decompile_all.py` - Batch decompile all functions
- `extract_strings.py` - Advanced string extraction
- `analyze_imports.py` - Import table analysis
- `find_crypto.py` - Cryptographic constant detection
- `extract_data_types.py` - Data type recovery

## IDA Scripts

IDA Pro scripts for advanced analysis:

- Similar structure to Ghidra scripts
- IDA-specific API usage
- Database manipulation scripts

## Usage

Scripts can be executed through the REVENG CLI:

```bash
# Run Ghidra script
reveng ghidra analyze binary.exe --script scripts/ghidra/extract_functions.py

# Run IDA script
reveng ida analyze binary.exe --script scripts/ida/analyze_imports.py
```

## Script Development

When creating new scripts:

1. Follow the tool's API conventions
2. Include proper error handling
3. Output results in JSON format when possible
4. Document script parameters and usage
5. Test scripts with various binary types
