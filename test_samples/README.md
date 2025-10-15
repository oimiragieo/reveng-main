# REVENG Test Samples

This directory contains sample files for testing REVENG functionality.

## 📁 Sample Files

### Java Samples
- **`HelloWorld.java`** - Simple Java program for basic testing
- **`ObfuscatedExample.java`** - Obfuscated Java code for advanced testing

### Binary Samples (Not Included)
- **Windows PE executables** - `.exe` files for Windows testing
- **Linux ELF binaries** - ELF files for Linux testing
- **Java JAR files** - Compiled Java applications
- **C# assemblies** - .NET executables

## 🧪 Testing Usage

### Basic Testing
```bash
# Test with Java sample
python reveng_analyzer.py test_samples/HelloWorld.java

# Test with obfuscated sample
python reveng_analyzer.py test_samples/ObfuscatedExample.java
```

### Advanced Testing
```bash
# Test with enhanced analysis
python reveng_analyzer.py test_samples/HelloWorld.java --enhanced

# Test with specific modules
python reveng_analyzer.py test_samples/HelloWorld.java --corporate-exposure --vulnerability-discovery
```

## 📊 Expected Results

### HelloWorld.java
- **Language Detection**: Java
- **Analysis Time**: < 30 seconds
- **Functions Found**: 1 (main method)
- **Complexity**: Low
- **Obfuscation**: None

### ObfuscatedExample.java
- **Language Detection**: Java
- **Analysis Time**: < 60 seconds
- **Functions Found**: Multiple
- **Complexity**: Medium
- **Obfuscation**: Present

## 🔧 Adding Test Samples

### Java Samples
1. Create `.java` file in this directory
2. Ensure it compiles: `javac filename.java`
3. Test with REVENG: `python reveng_analyzer.py filename.java`

### Binary Samples
1. **Windows**: Create `.exe` files (not included in repo)
2. **Linux**: Create ELF binaries (not included in repo)
3. **Java**: Create `.jar` files (not included in repo)
4. **C#**: Create `.exe` files (not included in repo)

### Sample Requirements
- **Size**: Keep samples under 10MB
- **Content**: Use simple, non-malicious code
- **Format**: Use standard file formats
- **Documentation**: Add description in this README

## 🚨 Security Notice

**Important**: Only include safe, non-malicious test samples in this repository. Do not include:
- Malware samples
- Proprietary software
- Copyrighted binaries
- Large files (>10MB)

## 📝 Sample Descriptions

### HelloWorld.java
Simple Java program that prints "Hello, World!" to the console. Used for basic functionality testing.

**Features**:
- Single main method
- Console output
- No external dependencies
- Minimal complexity

### ObfuscatedExample.java
Java program with obfuscated code to test deobfuscation capabilities.

**Features**:
- Obfuscated variable names
- Complex control flow
- Multiple methods
- String obfuscation

## 🔍 Analysis Results

### Expected Analysis Output
```
REVENG Analysis Results
======================

Binary: test_samples/HelloWorld.java
Language: Java
Format: Source Code
Confidence: 0.95

Analysis Steps:
✅ Step 1: AI Analysis
✅ Step 2: Language Detection
✅ Step 3: Code Processing
✅ Step 4: Source Generation
✅ Step 5: Validation

Results:
- Functions: 1
- Lines of Code: 5
- Complexity: Low
- Obfuscation: None
```

## 🧪 Test Automation

### Running All Tests
```bash
# Run all sample tests
python -m pytest tests/test_samples.py -v

# Run specific sample test
python -m pytest tests/test_samples.py::TestJavaSamples::test_hello_world -v
```

### Continuous Integration
```bash
# Test samples in CI
python scripts/test_samples.py --all

# Test specific sample
python scripts/test_samples.py --sample HelloWorld.java
```

## 📚 Related Documentation

- **[Main README](../README.md)** - Project overview
- **[User Guide](../docs/USER_GUIDE.md)** - Usage instructions
- **[Developer Guide](../docs/DEVELOPER_GUIDE.md)** - Development workflows
- **[Test Suite](../tests/README.md)** - Testing documentation

## 🤝 Contributing Samples

### Adding New Samples
1. **Create Sample File** - Add to appropriate directory
2. **Update README** - Document the sample
3. **Test Sample** - Verify it works with REVENG
4. **Add Tests** - Create test cases
5. **Submit PR** - Follow contribution guidelines

### Sample Guidelines
- **Size**: Keep under 10MB
- **Content**: Safe, non-malicious code only
- **Format**: Use standard file formats
- **Documentation**: Include description and expected results
- **Testing**: Add automated tests for the sample

---

**Test Samples Directory** - Safe, documented samples for REVENG testing
