# Test Samples Directory

## Overview

The `test_samples/` directory contains sample files used for testing REVENG functionality. These include benign test binaries, code samples, and files used in examples and automated tests.

**Purpose**: Provide sample files for testing, examples, and tutorials.

**Location**: `/home/user/reveng-main/test_samples/`

## Directory Contents

```
test_samples/
├── claude.md                  # This file
├── README.md                  # Test samples documentation (4,433 bytes)
├── HelloWorld.java            # Simple Java test file (953 bytes)
└── ObfuscatedExample.java     # Obfuscated Java sample (859 bytes)
```

## Sample Files

### Java Samples

**HelloWorld.java** (953 bytes)
- Simple "Hello World" Java program
- Used for basic Java analysis testing
- Clean, unobfuscated code
- Good for learning examples

**ObfuscatedExample.java** (859 bytes)
- Intentionally obfuscated Java code
- Tests deobfuscation capabilities
- Example of code obfuscation techniques
- Used in obfuscation/deobfuscation examples

## Usage

### Using in Tests

```python
# Use test samples in unit tests
test_binary = "test_samples/HelloWorld.java"
result = analyzer.analyze(test_binary)
```

### Using in Examples

```bash
# Run examples with test samples
python examples/basic/02_java_analysis.py test_samples/HelloWorld.java

# Deobfuscation example
python examples/javascript_deobfuscation_demo.py test_samples/ObfuscatedExample.java
```

### Adding New Samples

```bash
# Add new test sample
cp /path/to/sample.exe test_samples/

# Document in README.md
echo "## sample.exe - Description" >> test_samples/README.md

# Ensure it's safe (no real malware!)
```

## Related Directories

- **tests/** - Automated tests using these samples
- **examples/** - Example scripts using samples
- **docs/** - Documentation referencing samples

## Notes

### Safety

**Important:**
- Only safe, benign samples
- No real malware
- EICAR test file OK for AV testing
- Synthetic samples only

### Sample Types

**Included:**
- Simple programs (Hello World, etc.)
- Obfuscated code examples
- Test binaries for specific features
- Educational samples

**Not Included:**
- Real malware
- Proprietary software
- Copyrighted binaries
- Large binaries (>10MB)

### Contributing Samples

When adding samples:
1. Ensure they're safe and legal
2. Document purpose in README.md
3. Keep file sizes reasonable
4. Include source code when possible
5. Add appropriate license info

---

**Purpose**: Test and example samples
**Size**: Small files only (<1MB preferred)
**Safety**: Benign samples only
**License**: Public domain or permissive
