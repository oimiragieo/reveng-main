# REVENG Examples

This directory contains examples demonstrating REVENG's capabilities, from beginner-friendly tutorials to advanced features.

## 📁 Current Directory Structure

```
examples/
├── README.md                           # This file
├── my_first_analysis.py                # ✅ Start here! Simplest example
├── javascript_deobfuscation_demo.py    # ✅ JavaScript features demo
├── agent_sdk_demo.py                   # ✅ Agent SDK usage
├── basic/                              # Basic examples for beginners
│   ├── 01_simple_analysis.py           # ✅ NEW! Basic binary analysis
│   ├── README.md                       # ✅ Getting started guide
│   └── claude.md                       # AI context
├── advanced/                           # Advanced feature demonstrations
│   ├── full_recompilation_demo.py      # ✅ Complete recompilation pipeline
│   ├── gemini_feedback_demo.py         # ✅ Self-improving feedback loop
│   ├── v4_0_features_demo.py           # ✅ v4.0 enterprise features
│   ├── README.md                       # Advanced examples guide
│   └── claude.md                       # AI context
├── test-samples/                       # Sample files for testing
│   ├── obfuscated-simple.js            # ✅ Test JavaScript file
│   ├── obfuscated-eval.js              # ✅ Eval-based obfuscation
│   ├── obfuscated-strings.js           # ✅ String obfuscation
│   └── README.md                       # Sample file descriptions
└── use-cases/                          # Real-world use case examples
```

**Note:** More examples are planned for future releases. See [Contributing](#contributing) to help add examples!

## 🚀 Quick Start

### For Complete Beginners (Start Here!)

```bash
# 1. Your very first analysis (2 minutes)
python examples/my_first_analysis.py

# 2. Simple binary analysis (5 minutes)
python examples/basic/01_simple_analysis.py /bin/ls

# 3. JavaScript deobfuscation (5 minutes)
python examples/javascript_deobfuscation_demo.py
```

### Advanced Examples

```bash
# Full recompilation pipeline (requires Ghidra)
python examples/advanced/full_recompilation_demo.py

# Self-improving AI feedback loop
python examples/advanced/gemini_feedback_demo.py

# v4.0 Enterprise features
python examples/advanced/v4_0_features_demo.py
```

## 📚 Available Examples

### ✅ Ready to Use

| Example | Description | Time | Requirements |
|---------|-------------|------|--------------|
| **my_first_analysis.py** | Absolute beginner introduction | 2 min | None |
| **basic/01_simple_analysis.py** | Basic binary analysis | 5 min | None |
| **javascript_deobfuscation_demo.py** | JS deobfuscation features | 5 min | Node.js (optional) |
| **agent_sdk_demo.py** | Agent SDK usage | 10 min | None |
| **advanced/full_recompilation_demo.py** | Complete pipeline | 30 min | Ghidra, API keys |
| **advanced/gemini_feedback_demo.py** | Self-improving AI | 15 min | Gemini API key |
| **advanced/v4_0_features_demo.py** | Enterprise features | 20 min | API keys |

### 🚧 Coming Soon

These examples are referenced in older docs but not yet implemented:

- Java bytecode analysis
- C#/.NET analysis
- Python bytecode analysis
- Custom analyzer creation
- Plugin development
- Batch processing

**Want to help?** See [Contributing](#contributing) below!

## 🧪 Running Examples

### Prerequisites

1. **Install REVENG**: Follow the [Installation Guide](../INSTALLATION.md)
2. **Prepare samples**: Ensure test samples are available
3. **Set up environment**: Configure AI services if needed

### Basic Usage

```bash
# Run all basic examples
python scripts/run_examples.py --basic

# Run all advanced examples
python scripts/run_examples.py --advanced

# Run analysis template
python scripts/run_examples.py --template

# Run all examples
python scripts/run_examples.py
```

### Individual Examples

```bash
# Run specific example
python examples/basic/01_simple_analysis.py

# Run with custom binary
python examples/basic/02_java_analysis.py /path/to/binary.jar

# Run with options
python examples/advanced/01_custom_analyzer.py --verbose --output results/
```

## 📊 Expected Outputs

### Analysis Results

Each example generates:
- **Source Code**: Human-readable source files
- **Analysis Reports**: JSON/HTML reports
- **Validation Results**: Binary validation reports
- **Documentation**: Generated documentation

### Output Structure

```
analysis_output/
├── source_code/                 # Generated source files
│   ├── main.c
│   ├── functions.c
│   └── headers.h
├── reports/                     # Analysis reports
│   ├── analysis_report.json
│   ├── vulnerability_report.html
│   └── summary.txt
├── validation/                  # Validation results
│   ├── checksum_comparison.txt
│   ├── section_analysis.txt
│   └── smoke_test_results.txt
└── documentation/               # Generated docs
    ├── api_documentation.md
    └── user_guide.md
```

## 🔧 Customization

### Creating Custom Examples

1. **Copy Template**:
   ```bash
   cp examples/analysis_template.py examples/my_custom_analysis.py
   ```

2. **Modify Template**:
   ```python
   # Customize analysis parameters
   analyzer = REVENGAnalyzer(binary_path, enhanced_features=my_features)
   
   # Add custom processing
   def custom_processing(self):
       # Your custom logic here
       pass
   ```

3. **Test Example**:
   ```bash
   python examples/my_custom_analysis.py test_binary.exe
   ```

### Example Configuration

```python
# examples/config.py
ANALYSIS_CONFIG = {
    'timeout': 300,
    'max_functions': 1000,
    'enable_ai': True,
    'ai_provider': 'ollama',
    'output_format': 'json',
    'verbose': True
}

ENHANCED_FEATURES = {
    'corporate_exposure': True,
    'vulnerability_discovery': True,
    'threat_intelligence': False,
    'binary_reconstruction': True,
    'demonstration_generation': False
}
```

## 📈 Performance Tips

### Optimization

1. **Use appropriate timeouts**:
   ```python
   analyzer = REVENGAnalyzer(binary_path, timeout=600)  # 10 minutes
   ```

2. **Limit analysis scope**:
   ```python
   features = EnhancedAnalysisFeatures()
   features.enable_corporate_exposure = False  # Skip if not needed
   ```

3. **Use batch processing**:
   ```python
   # Process multiple files efficiently
   for binary in binary_list:
       analyzer = REVENGAnalyzer(binary)
       analyzer.analyze_binary()
   ```

### Resource Management

- **Memory**: Large binaries may require 8GB+ RAM
- **CPU**: Multi-threading available for batch processing
- **Storage**: Analysis outputs can be 10x original file size
- **Network**: AI services require internet connection

## 🐛 Troubleshooting

### Common Issues

1. **Import Errors**:
   ```bash
   # Ensure REVENG is in Python path
   export PYTHONPATH=$PYTHONPATH:/path/to/reveng
   ```

2. **Missing Dependencies**:
   ```bash
   # Install missing packages
   pip install -r requirements.txt
   ```

3. **Analysis Failures**:
   ```bash
   # Check toolchain
   python tools/check_toolchain.py --fix
   ```

4. **Permission Errors**:
   ```bash
   # Fix file permissions
   chmod +x examples/*.py
   ```

### Debug Mode

```bash
# Run with debug output
python examples/basic/01_simple_analysis.py --debug

# Enable verbose logging
python examples/advanced/01_custom_analyzer.py --verbose

# Check analysis steps
python examples/basic/02_java_analysis.py --step-by-step
```

## 📚 Learning Path

### Beginner
1. Start with `basic/01_simple_analysis.py`
2. Try `basic/02_java_analysis.py` with sample files
3. Explore `basic/03_csharp_analysis.py`
4. Read the generated reports

### Intermediate
1. Study `advanced/01_custom_analyzer.py`
2. Try `advanced/03_batch_processing.py`
3. Experiment with different binary types
4. Customize analysis parameters

### Advanced
1. Develop custom analyzers
2. Create plugins for specific use cases
3. Integrate with enterprise systems
4. Contribute back to the project

## 🤝 Contributing Examples

### Adding New Examples

1. **Create Example File**:
   ```bash
   touch examples/basic/06_new_analysis.py
   ```

2. **Follow Template**:
   ```python
   #!/usr/bin/env python3
   """
   New Analysis Example
   ===================
   
   Description of what this example demonstrates.
   """

   from reveng.analyzer import REVENGAnalyzer
   
   def main():
       # Your example code here
       pass
   
   if __name__ == "__main__":
       main()
   ```

3. **Add Documentation**:
   - Update this README
   - Add docstring to example
   - Include usage instructions

4. **Test Example**:
   ```bash
   python examples/basic/06_new_analysis.py --help
   python examples/basic/06_new_analysis.py test_sample.exe
   ```

### Example Standards

- **Documentation**: Clear docstrings and comments
- **Error Handling**: Graceful failure with helpful messages
- **Configuration**: Use command-line arguments
- **Output**: Generate useful analysis results
- **Testing**: Include test cases

## 📖 Related Documentation

- **[Main README](../README.md)** - Project overview
- **[Installation Guide](../INSTALLATION.md)** - Setup instructions
- **[User Guide](../docs/USER_GUIDE.md)** - Usage documentation
- **[API Reference](../API_REFERENCE.md)** - Python API
- **[Architecture](../ARCHITECTURE.md)** - System design

## 🆘 Support

### Getting Help

- **GitHub Issues**: Report bugs and request features
- **Discussions**: Ask questions and share ideas
- **Documentation**: Check the comprehensive guides
- **Examples**: Study the provided examples

### Community

- **Contributors**: Join the development team
- **Examples**: Share your custom examples
- **Feedback**: Help improve the project
- **Testing**: Test with different binary types

---

**REVENG Examples** - Learn, experiment, and master reverse engineering with REVENG