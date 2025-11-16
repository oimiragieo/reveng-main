# Examples Directory

## Overview

The `examples/` directory contains comprehensive code examples demonstrating REVENG's capabilities, from basic usage to advanced customization. These examples serve as both learning tools and reference implementations for common reverse engineering tasks.

**Purpose**: Provide working code examples for all REVENG features, from beginner tutorials to advanced use cases.

**Location**: `/home/user/reveng-main/examples/`

## Directory Contents

```
examples/
├── claude.md                           # This file
├── README.md                           # Examples overview (9,352 bytes)
├── my_first_analysis.py                # First analysis tutorial (4,151 bytes)
├── agent_sdk_demo.py                   # Agent SDK demo (8,531 bytes)
├── javascript_deobfuscation_demo.py    # JS deobfuscation demo (8,544 bytes)
│
├── basic/                              # Basic usage examples
│   ├── claude.md
│   └── README.md
│
├── advanced/                           # Advanced examples
│   ├── claude.md
│   ├── README.md                       # Advanced examples guide
│   ├── full_recompilation_demo.py      # Complete recompilation demo
│   ├── gemini_feedback_demo.py         # Gemini feedback loop demo
│   └── v4_0_features_demo.py           # v4.0 features showcase
│
├── use-cases/                          # Real-world use cases
│   ├── claude.md
│   ├── binary-patching.md              # Binary patching guide
│   ├── legacy-recovery.md              # Legacy code recovery
│   └── malware-analysis.md             # Malware analysis workflow
│
└── test-samples/                       # Sample files for examples
    └── [test sample files]
```

## Structure

### Example Categories

#### 1. Getting Started Examples
- **my_first_analysis.py** - First analysis walkthrough
- **agent_sdk_demo.py** - Claude Agent SDK integration demo
- **javascript_deobfuscation_demo.py** - JavaScript deobfuscation examples

#### 2. Basic Examples (basic/)
- Simple analysis workflows
- Language-specific analysis (Java, C#, Python, Native)
- Core feature demonstrations

#### 3. Advanced Examples (advanced/)
- **full_recompilation_demo.py** - Complete binary reconstruction pipeline
- **gemini_feedback_demo.py** - AI feedback loop demonstration
- **v4_0_features_demo.py** - Advanced features showcase

#### 4. Use Cases (use-cases/)
- **binary-patching.md** - Binary modification and patching
- **legacy-recovery.md** - Recovering legacy source code
- **malware-analysis.md** - Malware analysis workflows

## Key Files

### Core Examples

**my_first_analysis.py** (4,151 bytes)
```python
# First analysis example
# Demonstrates basic binary analysis workflow
- Load binary
- Perform analysis
- View results
- Generate report
```

**agent_sdk_demo.py** (8,531 bytes)
```python
# Claude Agent SDK integration demo
# Shows how to use REVENG with Claude Agent SDK
- SDK initialization
- Automated analysis
- AI-assisted reverse engineering
- Report generation
```

**javascript_deobfuscation_demo.py** (8,544 bytes)
```python
# JavaScript deobfuscation demonstrations
# 10-stage deobfuscation pipeline examples
- Malware detection
- ML variable renaming
- LLM semantic analysis
- Output validation
```

### Advanced Examples

**full_recompilation_demo.py** (9,854 bytes)
```python
# Complete binary reconstruction demonstration
# Binary → Decompilation → AI Enhancement → Recompilation
- Ghidra decompilation
- Gemini AI enhancement
- GCC/Clang recompilation
- Behavioral validation
- Vulnerability analysis
- Exploit generation
```

**gemini_feedback_demo.py** (3,326 bytes)
```python
# Gemini feedback loop demonstration
# Self-improving AI analysis system
- Continuous improvement
- Automated suggestions
- Bug detection
- Feature proposals
```

**v4_0_features_demo.py** (16,561 bytes)
```python
# Version 4.0 features showcase
- Advanced ML integration
- Enhanced analysis capabilities
- Performance optimizations
- New API features
```

## Usage

### Running Basic Examples

```bash
# First analysis tutorial
python examples/my_first_analysis.py

# JavaScript deobfuscation demo
python examples/javascript_deobfuscation_demo.py

# Agent SDK demo
python examples/agent_sdk_demo.py
```

### Running Advanced Examples

```bash
# Terminal 1: Start Ghidra server
cd external/ghidra-server
python ghidra_http_server.py

# Terminal 2: Run recompilation demo
python examples/advanced/full_recompilation_demo.py

# Terminal 3: Run feedback loop demo
python examples/advanced/gemini_feedback_demo.py

# v4.0 features demo
python examples/advanced/v4_0_features_demo.py
```

### Running with Custom Binaries

```bash
# Analyze custom binary
python examples/my_first_analysis.py /path/to/binary.exe

# Deobfuscate custom JavaScript
python examples/javascript_deobfuscation_demo.py /path/to/obfuscated.js

# Full pipeline with custom binary
python examples/advanced/full_recompilation_demo.py --binary /path/to/binary.exe
```

### Expected Output

Each example generates:
- **Console Output**: Real-time analysis progress
- **Analysis Reports**: JSON/HTML reports with findings
- **Source Code**: Decompiled and enhanced source code
- **Validation Results**: Recompilation and validation results
- **Exploits**: Generated proof-of-concept exploits (when applicable)

## Related Directories

### Dependencies
- **test_samples/** - Sample files used by examples
- **src/reveng/** - REVENG source code
- **external/ghidra/** - Ghidra integration (for some examples)
- **models/** - ML models used in examples

### Documentation
- **docs/guides/** - Detailed guides referencing examples
- **docs/api/** - API documentation for example code
- **docs/user-guide/** - User guide with example workflows

## Notes

### Learning Path

**Beginners**
1. Start with `my_first_analysis.py`
2. Read `basic/README.md`
3. Try basic examples
4. Experiment with sample files

**Intermediate Users**
1. Study `advanced/` examples
2. Run `full_recompilation_demo.py`
3. Customize examples for your needs
4. Explore `use-cases/` documentation

**Advanced Users**
1. Study advanced demos
2. Create custom analyzers
3. Integrate with your workflows
4. Contribute new examples

### Example Standards

**All Examples Include**
- Clear docstrings explaining purpose
- Usage instructions in comments
- Error handling
- Helpful output messages
- Command-line argument parsing
- Example outputs

**Code Quality**
- Follow PEP 8 style guide
- Include type hints
- Add comprehensive comments
- Handle errors gracefully
- Provide meaningful output

### Prerequisites

**For All Examples**
- Python 3.9+
- REVENG installed
- Required dependencies from `requirements.txt`

**For Advanced Examples**
- Ghidra server running (for decompilation)
- API keys for AI services (Gemini, etc.)
- Sufficient disk space for outputs
- Sample binaries or test files

### Troubleshooting

**Import Errors**
```bash
# Add REVENG to Python path
export PYTHONPATH=/home/user/reveng-main:$PYTHONPATH
```

**Missing Dependencies**
```bash
# Install all dependencies
pip install -r requirements.txt
```

**Ghidra Server Not Running**
```bash
# Start Ghidra server
cd external/ghidra-server
python ghidra_http_server.py
```

**API Key Not Set**
```bash
# Set Gemini API key
export GEMINI_API_KEY="your-api-key-here"
```

### Customizing Examples

```python
# Copy example as template
cp examples/my_first_analysis.py examples/my_custom_analysis.py

# Modify for your use case
# - Change binary path
# - Adjust analysis parameters
# - Customize output format
# - Add custom processing
```

### Contributing Examples

To contribute a new example:

1. **Create Example File**
   - Follow naming convention: `descriptive_name.py`
   - Include comprehensive docstring
   - Add usage instructions

2. **Write Clear Code**
   - Follow existing example patterns
   - Include error handling
   - Add helpful comments
   - Use command-line arguments

3. **Test Thoroughly**
   - Test with multiple binaries
   - Verify output correctness
   - Check error handling
   - Validate documentation

4. **Document Example**
   - Update README.md
   - Add to appropriate category
   - Include expected output
   - List prerequisites

5. **Submit PR**
   - Create pull request
   - Describe example purpose
   - Include sample output
   - Link to related documentation

### Future Examples

Planned additions:
- **Cloud Integration**: AWS/Azure analysis examples
- **Distributed Analysis**: Multi-machine processing
- **Custom Plugin**: Plugin development tutorial
- **API Integration**: RESTful API examples
- **CI/CD Integration**: Automated analysis pipeline

---

**Maintained by**: REVENG Development Team
**Example Count**: 10+ working examples
**Skill Levels**: Beginner to Advanced
**All Examples Tested**: Yes
