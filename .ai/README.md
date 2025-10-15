# REVENG for AI Coding Assistants

**Welcome, AI assistant!** This directory contains everything you need to work effectively with the REVENG Universal Reverse Engineering Platform.

## 🎯 Quick Start for AI Agents

### 1. Project Overview
REVENG is a universal reverse engineering platform that can:
- Analyze any binary (Java, C#, Python, Native)
- Decompile and reconstruct binaries
- Use AI for intelligent analysis
- Generate human-readable source code
- Reassemble modified binaries

### 2. Key Entry Points
- **Main Pipeline**: `reveng_analyzer.py` (8-step analysis)
- **Tool Categories**: `tools/` directory (66+ specialized tools)
- **Documentation**: `docs/` directory (comprehensive guides)
- **Web Interface**: `web_interface/` (optional React UI)

### 3. Common Tasks

#### Analyze a Binary
```bash
# Basic analysis
python reveng_analyzer.py binary.exe

# With specific options
python reveng_analyzer.py app.jar --no-enhanced
```

#### Use Individual Tools
```bash
# Language detection
python tools/language_detector.py binary.exe

# AI analysis
python tools/ai_recompiler_converter.py binary.exe

# Binary reconstruction
python tools/binary_reassembler_v2.py --original a.exe --source code/ --output rebuilt.exe
```

## 📁 Project Structure

```
reveng-main/
├── reveng_analyzer.py          # Main entry point (8-step pipeline)
├── tools/                      # 66+ analysis tools (categorized)
│   ├── core/                   # Core analysis (8 tools)
│   ├── languages/              # Multi-language (6 tools)
│   ├── ai/                     # AI enhancement (5 tools)
│   ├── quality/                # Code quality (4 tools)
│   ├── binary/                 # Binary operations (5 tools)
│   ├── visualization/           # Visualization (3 tools)
│   ├── enterprise/             # Enterprise (4 tools)
│   ├── security/               # ML/Security (8 tools)
│   ├── config/                 # Configuration (4 tools)
│   └── utils/                  # Utilities (remaining tools)
├── docs/                       # Comprehensive documentation
├── examples/                   # Usage examples
├── tests/                      # Test suite
├── web_interface/              # Optional web UI
└── .ai/                       # AI agent guidance (this directory)
```

## 🔧 Tool Selection Guide

### For Binary Analysis
```python
# 1. Language Detection
python tools/language_detector.py binary.exe

# 2. Core Analysis (choose based on language)
python tools/ai_recompiler_converter.py binary.exe          # AI-powered
python tools/optimal_binary_analysis.py binary.exe          # Ghidra-based
python tools/java_bytecode_analyzer.py app.jar              # Java
python tools/csharp_il_analyzer.py MyApp.exe                # C#

# 3. Code Processing
python tools/human_readable_converter_fixed.py              # Clean code
python tools/code_formatter.py human_readable_code/         # Format
python tools/type_inference_engine.py --functions funcs.json # Types

# 4. Binary Reconstruction
python tools/binary_reassembler_v2.py --original a.exe --source code/ --output rebuilt.exe
```

### For AI Enhancement
```python
# Check AI availability
python tools/ollama_preflight.py

# Run AI analysis
python tools/ai_analyzer_enhanced.py
python tools/ollama_analyzer.py code.c

# Generate reports
python tools/executive_reporting_engine.py
```

## 📚 Essential Documentation

### For AI Assistants
- **[AI Assistant Guide](../docs/guides/AI_ASSISTANT_GUIDE.md)** - Comprehensive guide
- **[Claude Integration](../docs/guides/CLAUDE_INTEGRATION.md)** - Claude-specific guidance
- **[Tool Development](../docs/guides/AI_ASSISTANT_GUIDE.md#tool-development)** - Creating new tools

### For Understanding the System
- **[Architecture](../docs/architecture/ARCHITECTURE.md)** - System architecture
- **[Project Structure](../docs/development/PROJECT_STRUCTURE.md)** - Code organization
- **[API Reference](../docs/api/API_REFERENCE.md)** - Complete API docs

### For Users
- **[Quick Start](../docs/QUICK_START.md)** - 5-minute setup
- **[User Guide](../docs/USER_GUIDE.md)** - Complete usage guide
- **[Installation](../INSTALLATION.md)** - Installation instructions

## 🚀 Common Development Tasks

### Adding a New Analysis Tool
1. Create tool in appropriate `tools/category/` directory
2. Follow naming convention: `snake_case.py`
3. Add to `tools/categories.json`
4. Update imports in `reveng_analyzer.py`
5. Create tests in `tests/`
6. Update documentation

### Fixing Analysis Issues
1. Check logs in project root (`*.log` files)
2. Verify toolchain: `python tools/check_toolchain.py --fix`
3. Test individual tools
4. Check import paths after reorganization

### Enhancing AI Analysis
1. Check Ollama status: `python tools/ollama_preflight.py`
2. Configure AI settings: `python tools/config_manager.py`
3. Run enhanced analysis: `python tools/ai_analyzer_enhanced.py`
4. Generate reports: `python tools/executive_reporting_engine.py`

## 🔍 Code Patterns

### Tool Structure Pattern
```python
#!/usr/bin/env python3
"""
Tool Name - Brief description

Usage: python tools/category/tool_name.py [options]
"""

import argparse
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='Tool description')
    parser.add_argument('input', help='Input file or directory')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    try:
        # Tool implementation
        result = process_input(args.input)
        if args.output:
            save_output(result, args.output)
        else:
            print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### Analysis Pipeline Pattern
```python
def analyze_binary(binary_path: str) -> AnalysisResult:
    """Standard analysis pipeline"""
    # Step 1: Language detection
    language = detect_language(binary_path)
    
    # Step 2: Route to analyzer
    if language == 'java':
        return analyze_java(binary_path)
    elif language == 'csharp':
        return analyze_csharp(binary_path)
    else:
        return analyze_native(binary_path)
```

## 🐛 Troubleshooting

### Common Issues
- **Tool Not Found**: Check if tool exists in new categorized structure
- **Import Errors**: Update import paths after reorganization
- **Permission Errors**: Check file permissions
- **Memory Issues**: Use smaller files for testing

### Debugging Tools
```python
# Add debugging to tools
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def debug_tool():
    logger.debug("Starting tool execution")
    # Tool implementation
    logger.debug("Tool execution completed")
```

## 📊 Performance Optimization

### Memory Management
```python
# For large files
def process_large_file(file_path: str):
    """Process large files in chunks"""
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            process_chunk(chunk)
```

### Parallel Processing
```python
# For multiple files
from concurrent.futures import ThreadPoolExecutor

def process_multiple_files(file_paths: List[str]):
    """Process multiple files in parallel"""
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(process_file, path) for path in file_paths]
        results = [future.result() for future in futures]
    return results
```

## 🔄 Maintenance Tasks

### Regular Tasks
- **Code Quality**: Run `python scripts/development/lint_codebase.py`
- **Testing**: Run `python -m pytest tests/`
- **Documentation**: Update README files
- **Dependencies**: Update requirements.txt

### Weekly Tasks
- **Cleanup**: Run `python scripts/maintenance/cleanup_legacy.py`
- **Performance**: Check tool performance metrics
- **Security**: Review security updates
- **Updates**: Update dependencies

## 🆘 Getting Help

- **Documentation**: See [AI Assistant Guide](../docs/guides/AI_ASSISTANT_GUIDE.md)
- **Tool Issues**: Check tool output for error messages
- **Dependencies**: Verify all requirements are installed
- **Examples**: Check `examples/` directory for usage examples
- **GitHub Issues**: [Report issues](https://github.com/oimiragieo/reveng-main/issues)

---

**Last Updated**: January 2025  
**For AI Assistants**: This guide provides everything needed to work effectively with REVENG
