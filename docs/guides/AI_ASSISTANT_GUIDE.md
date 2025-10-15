# REVENG Agent Guide

**Dedicated guide for AI coding assistants working with the REVENG codebase**

## 🎯 Quick Reference

### Project Architecture
```
reveng-main/
├── reveng_analyzer.py          # Main entry point (8-step pipeline)
├── tools/                      # 66+ analysis tools (categorized)
├── docs/                       # Complete documentation
├── examples/                   # Usage examples
├── tests/                      # Test suite
└── web_interface/              # Functional web UI
```

### Key Entry Points
- **Main Pipeline**: `reveng_analyzer.py` (8-step analysis)
- **Tool Categories**: `tools/categories.json` (machine-readable)
- **Documentation Hub**: `docs/README.md`
- **AI Assistant Guide**: `CLAUDE.md`

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

### For Enterprise Features
```python
# Audit logging
python tools/audit_trail.py

# Health monitoring
python tools/enhanced_health_monitor.py

# Plugin development
python tools/plugin_system.py create MyPlugin
```

## 📁 File Dependency Map

### Core Dependencies
```
reveng_analyzer.py
├── tools/ai_recompiler_converter.py
├── tools/optimal_binary_analysis.py
├── tools/ai_source_inspector.py
├── tools/human_readable_converter_fixed.py
├── tools/deobfuscation_tool.py
└── tools/implementation_tool.py
```

### Tool Dependencies
```
tools/binary_reassembler_v2.py
├── tools/check_toolchain.py
├── tools/compilation_tester.py
├── tools/binary_validator.py
└── tools/validation_config.py
```

### AI Dependencies
```
tools/ai_analyzer_enhanced.py
├── tools/ollama_preflight.py
├── tools/ollama_analyzer.py
└── tools/ai_enhanced_data_models.py
```

## 🎯 Common Tasks

### Task 1: Analyze a Binary
```python
# Step 1: Detect language
result = subprocess.run(['python', 'tools/language_detector.py', 'binary.exe'])

# Step 2: Route to appropriate analyzer
if result.returncode == 0:
    # Use language-specific analyzer
    subprocess.run(['python', 'tools/optimal_binary_analysis.py', 'binary.exe'])
else:
    # Use universal analyzer
    subprocess.run(['python', 'tools/ai_recompiler_converter.py', 'binary.exe'])
```

### Task 2: Add New Analyzer
```python
# 1. Create tool in tools/
# tools/new_analyzer.py

# 2. Add to categories.json
# "core_analysis": ["new_analyzer.py"]

# 3. Add to main pipeline
# reveng_analyzer.py: _step2_disassembly()

# 4. Create tests
# tests/test_new_analyzer.py
```

### Task 3: Fix Analysis Issues
```python
# 1. Check logs
# *.log files in root directory

# 2. Verify toolchain
python tools/check_toolchain.py --fix

# 3. Test individual tools
python tools/ai_recompiler_converter.py --help
python tools/optimal_binary_analysis.py --help

# 4. Run validation
python tools/binary_validator.py original.exe rebuilt.exe
```

### Task 4: Enhance AI Analysis
```python
# 1. Check Ollama status
python tools/ollama_preflight.py

# 2. Configure AI settings
python tools/config_manager.py set ai.ollama.model deepseek-coder

# 3. Run enhanced analysis
python tools/ai_analyzer_enhanced.py

# 4. Generate reports
python tools/executive_reporting_engine.py
```

## 🔍 Code Patterns

### Tool Structure Pattern
```python
#!/usr/bin/env python3
"""
Tool Name - Brief description

Usage: python tools/tool_name.py [options]
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

### Error Handling Pattern
```python
def safe_execute(func, *args, **kwargs):
    """Safe execution with error handling"""
    try:
        return func(*args, **kwargs)
    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return None
    except PermissionError as e:
        logger.error(f"Permission denied: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return None
```

## 🧪 Testing Patterns

### Unit Test Pattern
```python
# tests/test_tool_name.py
import pytest
from tools.tool_name import main_function

class TestToolName:
    def test_basic_functionality(self):
        """Test basic functionality"""
        result = main_function("test_input")
        assert result is not None
        
    def test_error_handling(self):
        """Test error conditions"""
        with pytest.raises(ValueError):
            main_function(None)
            
    def test_file_processing(self):
        """Test file processing"""
        result = main_function("test_file.txt")
        assert "processed" in result
```

### Integration Test Pattern
```python
def test_analysis_pipeline():
    """Test complete analysis pipeline"""
    # Setup
    test_binary = "test_samples/sample.exe"
    
    # Execute
    result = subprocess.run(['python', 'reveng_analyzer.py', test_binary])
    
    # Verify
    assert result.returncode == 0
    assert Path("analysis_sample/universal_analysis_report.json").exists()
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

### Caching
```python
# For expensive operations
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_analysis(binary_hash: str):
    """Cache expensive analysis results"""
    return perform_analysis(binary_hash)
```

## 🔧 Configuration Management

### Tool Configuration
```python
# tools/config_manager.py
import yaml
from pathlib import Path

class ConfigManager:
    def __init__(self, config_path: str = ".reveng/config.yaml"):
        self.config_path = Path(config_path)
        self.config = self.load_config()
    
    def load_config(self):
        """Load configuration from YAML file"""
        if self.config_path.exists():
            with open(self.config_path) as f:
                return yaml.safe_load(f)
        return self.default_config()
    
    def default_config(self):
        """Return default configuration"""
        return {
            'ai': {'provider': 'ollama', 'model': 'auto'},
            'analysis': {'timeout': 300, 'max_functions': 100},
            'output': {'format': 'json', 'verbose': False}
        }
```

### Environment Variables
```python
# Environment variable support
import os

def get_config_value(key: str, default=None):
    """Get configuration value from environment or config file"""
    env_key = key.upper().replace('.', '_')
    return os.getenv(env_key, default)
```

## 🚀 Deployment Patterns

### Docker Deployment
```dockerfile
# Dockerfile for REVENG
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
RUN python -m compileall tools/

CMD ["python", "reveng_analyzer.py"]
```

### Kubernetes Deployment
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reveng-analyzer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: reveng-analyzer
  template:
    metadata:
      labels:
        app: reveng-analyzer
    spec:
      containers:
      - name: reveng
        image: reveng:latest
        ports:
        - containerPort: 8000
```

## 🔍 Debugging Guide

### Common Issues

**Tool Not Found:**
```bash
# Check if tool exists
ls -la tools/tool_name.py

# Check Python path
python -c "import sys; print(sys.path)"
```

**Import Errors:**
```bash
# Install missing dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

**Permission Errors:**
```bash
# Check file permissions
ls -la tools/tool_name.py
chmod +x tools/tool_name.py
```

**Memory Issues:**
```bash
# Use smaller files for testing
# Increase system memory
# Use streaming for large files
```

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

## 📚 Learning Resources

### Documentation
- **[Main README](README.md)** - Project overview
- **[Developer Guide](docs/DEVELOPER_GUIDE.md)** - Development workflows
- **[User Guide](docs/USER_GUIDE.md)** - Usage documentation
- **[CLAUDE.md](CLAUDE.md)** - Claude Code guide

### Examples
- **[examples/](examples/)** - Usage examples
- **[test_samples/](test_samples/)** - Sample files for testing
- **[web_interface/](web_interface/)** - Web UI examples

### Tools Reference
- **[tools/README.md](tools/README.md)** - Complete tools documentation
- **[tools/categories.json](tools/categories.json)** - Machine-readable categorization

## 🔄 Maintenance Tasks

### Regular Tasks
- **Code Quality**: Run `python scripts/lint_codebase.py`
- **Testing**: Run `python -m pytest tests/`
- **Documentation**: Update README files
- **Dependencies**: Update requirements.txt

### Weekly Tasks
- **Cleanup**: Run `python scripts/cleanup_legacy.py`
- **Performance**: Check tool performance metrics
- **Security**: Review security updates
- **Updates**: Update dependencies

### Monthly Tasks
- **Architecture Review**: Review tool architecture
- **Performance Optimization**: Optimize slow tools
- **Feature Planning**: Plan new features
- **Documentation Review**: Update documentation

---

**Last Updated**: January 2025  
**Maintainer**: REVENG Development Team  
**For AI Assistants**: This guide provides everything needed to work effectively with the REVENG codebase
