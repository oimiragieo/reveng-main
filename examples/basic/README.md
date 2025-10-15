# Basic Examples

This directory contains basic examples demonstrating fundamental REVENG usage.

## 📁 Examples

### 01_simple_analysis.py
**Purpose**: Basic binary analysis demonstration

**Features**:
- Simple binary analysis
- Basic report generation
- Error handling

**Usage**:
```bash
python examples/basic/01_simple_analysis.py binary.exe
```

### 02_java_analysis.py
**Purpose**: Java bytecode analysis

**Features**:
- Java JAR file analysis
- Bytecode decompilation
- Source code generation

**Usage**:
```bash
python examples/basic/02_java_analysis.py app.jar
```

### 03_csharp_analysis.py
**Purpose**: C# .NET analysis

**Features**:
- .NET assembly analysis
- IL code decompilation
- C# source generation

**Usage**:
```bash
python examples/basic/03_csharp_analysis.py app.exe
```

### 04_python_analysis.py
**Purpose**: Python bytecode analysis

**Features**:
- Python bytecode analysis
- Source code reconstruction
- Import analysis

**Usage**:
```bash
python examples/basic/04_python_analysis.py script.pyc
```

### 05_native_analysis.py
**Purpose**: Native binary analysis

**Features**:
- PE/ELF/Mach-O analysis
- Disassembly
- C source generation

**Usage**:
```bash
python examples/basic/05_native_analysis.py binary.exe
```

## 🚀 Quick Start

1. **Install REVENG**: Follow the [Installation Guide](../../INSTALLATION.md)
2. **Prepare samples**: Ensure test samples are available
3. **Run examples**: Start with `01_simple_analysis.py`

## 📊 Expected Results

Each example generates:
- **Analysis Report**: JSON format with analysis results
- **Source Code**: Human-readable source files
- **Validation**: Binary validation results
- **Documentation**: Generated documentation

## 🔧 Customization

### Modify Analysis Parameters

```python
# examples/basic/custom_analysis.py
from reveng_analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures

# Configure enhanced features
features = EnhancedAnalysisFeatures()
features.enable_corporate_exposure = True
features.enable_vulnerability_discovery = True

# Create analyzer with custom configuration
analyzer = REVENGAnalyzer(
    binary_path="binary.exe",
    enhanced_features=features,
    timeout=600  # 10 minutes
)

# Run analysis
success = analyzer.analyze_binary()
```

### Custom Output Formats

```python
# Generate different output formats
analyzer = REVENGAnalyzer("binary.exe")
analyzer.analyze_binary()

# Export results
analyzer.export_results("results.json", format="json")
analyzer.export_results("report.html", format="html")
analyzer.export_results("summary.txt", format="text")
```

## 🧪 Testing

### Run All Basic Examples

```bash
# Run all basic examples
python scripts/run_examples.py --basic

# Run specific example
python examples/basic/01_simple_analysis.py --help
```

### Test with Sample Files

```bash
# Test with Java sample
python examples/basic/02_java_analysis.py test_samples/HelloWorld.java

# Test with C# sample
python examples/basic/03_csharp_analysis.py test_samples/app.exe
```

## 📚 Learning Path

### Step 1: Basic Analysis
1. Run `01_simple_analysis.py`
2. Understand the analysis process
3. Examine generated reports

### Step 2: Language-Specific Analysis
1. Try `02_java_analysis.py` with Java samples
2. Try `03_csharp_analysis.py` with .NET samples
3. Compare different language outputs

### Step 3: Advanced Features
1. Enable enhanced analysis features
2. Customize analysis parameters
3. Experiment with different binary types

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**:
   ```bash
   # Ensure REVENG is in Python path
   export PYTHONPATH=$PYTHONPATH:$(pwd)
   ```

2. **Missing Dependencies**:
   ```bash
   # Install required packages
   pip install -r requirements.txt
   ```

3. **Analysis Failures**:
   ```bash
   # Check toolchain
   python tools/check_toolchain.py --fix
   ```

### Debug Mode

```bash
# Run with debug output
python examples/basic/01_simple_analysis.py --debug

# Enable verbose logging
python examples/basic/02_java_analysis.py --verbose
```

## 📖 Related Documentation

- **[Main Examples README](../README.md)** - All examples overview
- **[Installation Guide](../../INSTALLATION.md)** - Setup instructions
- **[User Guide](../../docs/USER_GUIDE.md)** - Usage documentation
- **[API Reference](../../API_REFERENCE.md)** - Python API

---

**Basic Examples** - Learn the fundamentals of REVENG usage
