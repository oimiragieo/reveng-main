# Common Development Tasks

This guide covers the most common tasks you'll encounter when working with REVENG as an AI coding assistant.

## 🔍 Binary Analysis Tasks

### 1. Analyze Any Binary
```bash
# Basic analysis (auto-detects language)
python reveng_analyzer.py binary.exe
python reveng_analyzer.py application.jar
python reveng_analyzer.py script.pyc

# With specific options
python reveng_analyzer.py binary.exe --no-enhanced
python reveng_analyzer.py app.jar --config .reveng/config.yaml
```

### 2. Language-Specific Analysis
```bash
# Java bytecode
python tools/languages/java_bytecode_analyzer.py app.jar

# C# .NET assembly
python tools/languages/csharp_il_analyzer.py MyApp.exe

# Python bytecode
python tools/languages/python_bytecode_analyzer.py script.pyc

# Native binary (Ghidra)
python tools/core/optimal_binary_analysis.py binary.exe
```

### 3. AI-Enhanced Analysis
```bash
# Check AI availability
python tools/ai/ollama_preflight.py

# Run AI analysis
python tools/ai/ai_analyzer_enhanced.py
python tools/ai/ollama_analyzer.py code.c

# Generate executive reports
python tools/visualization/executive_reporting_engine.py
```

## 🛠️ Tool Development Tasks

### 1. Create New Analysis Tool
```python
# 1. Create tool file in appropriate category
# tools/security/new_security_analyzer.py

#!/usr/bin/env python3
"""
New Security Analyzer - Brief description

Usage: python tools/security/new_security_analyzer.py [options]
"""

import argparse
import sys
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description='New Security Analyzer')
    parser.add_argument('input', help='Input file or directory')
    parser.add_argument('-o', '--output', help='Output file')
    parser.add_argument('--verbose', action='store_true', help='Verbose output')
    args = parser.parse_args()
    
    try:
        # Tool implementation
        result = analyze_security(args.input)
        if args.output:
            save_results(result, args.output)
        else:
            print(result)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
```

### 2. Add Tool to Categories
```json
// Update tools/categories.json
{
  "security": [
    "existing_tool.py",
    "new_security_analyzer.py"
  ]
}
```

### 3. Update Main Pipeline
```python
# In reveng_analyzer.py, add new step
def _step9_security_analysis(self):
    """Step 9: Security analysis"""
    logger.info("Step 9: Security analysis")
    
    try:
        result = subprocess.run([
            sys.executable, "tools/security/new_security_analyzer.py", self.binary_path
        ], capture_output=True, text=True, timeout=300, check=False)
        
        if result.returncode == 0:
            logger.info("Security analysis completed successfully")
            self.results['step9'] = {'status': 'success', 'output': result.stdout}
        else:
            logger.warning(f"Security analysis completed with warnings: {result.stderr}")
            self.results['step9'] = {'status': 'warning', 'output': result.stdout, 'error': result.stderr}
    except Exception as e:
        logger.error(f"Error in security analysis: {e}")
        self.results['step9'] = {'status': 'error', 'error': str(e)}
```

### 4. Create Tests
```python
# tests/test_new_security_analyzer.py
import pytest
from tools.security.new_security_analyzer import main

class TestNewSecurityAnalyzer:
    def test_basic_functionality(self):
        """Test basic functionality"""
        result = main("test_input")
        assert result is not None
        
    def test_error_handling(self):
        """Test error conditions"""
        with pytest.raises(ValueError):
            main(None)
            
    def test_file_processing(self):
        """Test file processing"""
        result = main("test_file.txt")
        assert "analyzed" in result
```

## 🔧 Code Quality Tasks

### 1. Format Generated Code
```bash
# Format C code with clang-format
python tools/quality/code_formatter.py human_readable_code/ --pattern "*.c"

# Format with specific style
python tools/quality/code_formatter.py human_readable_code/ --style llvm
```

### 2. Infer Real Types
```bash
# Extract function signatures from Ghidra
python tools/quality/type_inference_engine.py \
    --functions analysis_binary/functions.json \
    --output typed_signatures.h

# Use AI for type inference
python tools/quality/type_inference_engine.py \
    --functions analysis_binary/functions.json \
    --ai-enhanced \
    --output ai_typed_signatures.h
```

### 3. Test Compilation
```bash
# Test if generated code compiles
python tools/quality/compilation_tester.py human_readable_code/

# Test with specific compiler
python tools/quality/compilation_tester.py human_readable_code/ --compiler gcc
```

## 🔄 Binary Reconstruction Tasks

### 1. Reassemble Binary
```bash
# Full reconstruction pipeline
python tools/binary/binary_reassembler_v2.py \
    --original binary.exe \
    --source human_readable_code/ \
    --output rebuilt.exe \
    --arch auto \
    --validation-mode smoke_test

# With specific architecture
python tools/binary/binary_reassembler_v2.py \
    --original binary.exe \
    --source human_readable_code/ \
    --output rebuilt.exe \
    --arch x86_64
```

### 2. Validate Reconstruction
```bash
# Validate rebuilt binary
python tools/binary/binary_validator.py original.exe rebuilt.exe

# With specific validation mode
python tools/binary/binary_validator.py original.exe rebuilt.exe --mode checksum
```

### 3. Compare Binaries
```bash
# Binary diff analysis
python tools/binary/binary_diff.py original.exe modified.exe

# Generate diff report
python tools/binary/binary_diff.py original.exe modified.exe --output diff_report.json
```

## 📊 Visualization Tasks

### 1. Generate Call Graphs
```bash
# Interactive call graph
python tools/visualization/code_visualizer.py analysis_dir/ --type call_graph

# Both call graph and dependency graph
python tools/visualization/code_visualizer.py analysis_dir/ --type both
```

### 2. Create Executive Reports
```bash
# Generate executive summary
python tools/visualization/executive_reporting_engine.py

# Technical report
python tools/visualization/technical_reporting_engine.py
```

## 🔒 Security Analysis Tasks

### 1. Malware Classification
```bash
# ML-based malware classification
python tools/security/ml_malware_classifier.py binary.exe

# With confidence scores
python tools/security/ml_malware_classifier.py binary.exe --verbose
```

### 2. Vulnerability Discovery
```bash
# Automated vulnerability discovery
python tools/security/vulnerability_discovery_engine.py binary.exe

# With specific vulnerability types
python tools/security/vulnerability_discovery_engine.py binary.exe --types buffer_overflow,use_after_free
```

### 3. Threat Intelligence
```bash
# Threat intelligence correlation
python tools/security/threat_intelligence_correlator.py binary.exe

# Corporate exposure analysis
python tools/security/corporate_exposure_detector.py binary.exe
```

## 🏢 Enterprise Tasks

### 1. Audit Logging
```python
# Enable audit trail
from tools.enterprise.audit_trail import AuditLogger

audit = AuditLogger()
session_id = audit.start_session(['app.jar'], ['java'])
audit.log_file_analysis('app.jar', 'java', success=True, details={})
audit.generate_report('compliance', 'compliance_report.json')
```

### 2. Plugin Development
```bash
# Create new plugin
python tools/enterprise/plugin_system.py create MyPlugin --type analyzer

# Load plugin
python tools/enterprise/plugin_system.py load MyPlugin
```

### 3. Health Monitoring
```bash
# Check system health
python tools/enterprise/enhanced_health_monitor.py

# GPU acceleration check
python tools/enterprise/gpu_accelerator.py info
```

## 🧪 Testing Tasks

### 1. Run Test Suite
```bash
# Run all tests
python -m pytest tests/

# Run specific test category
python -m pytest tests/test_pipeline.py

# Run with coverage
python -m pytest tests/ --cov=tools --cov-report=html
```

### 2. Test Individual Tools
```bash
# Test specific tool
python tools/core/ai_recompiler_converter.py --help
python tools/core/ai_recompiler_converter.py test_binary.exe

# Test with verbose output
python tools/core/ai_recompiler_converter.py test_binary.exe --verbose
```

### 3. Integration Testing
```bash
# Test complete pipeline
python reveng_analyzer.py test_samples/calc.exe

# Test web interface
cd web_interface && npm test
```

## 🔧 Maintenance Tasks

### 1. Clean Up Generated Files
```bash
# Clean analysis outputs
python scripts/maintenance/clean_outputs.py

# Clean legacy files
python scripts/maintenance/cleanup_legacy.py
```

### 2. Update Dependencies
```bash
# Check for updates
pip list --outdated

# Update requirements
pip install -r requirements.txt --upgrade
```

### 3. Code Quality Checks
```bash
# Lint codebase
python scripts/development/lint_codebase.py

# Format code
black tools/
isort tools/
```

## 🚀 Performance Optimization Tasks

### 1. Memory Management
```python
# For large files, use streaming
def process_large_file(file_path: str):
    """Process large files in chunks"""
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            process_chunk(chunk)
```

### 2. Parallel Processing
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

### 3. Caching
```python
# For expensive operations
from functools import lru_cache

@lru_cache(maxsize=128)
def expensive_analysis(binary_hash: str):
    """Cache expensive analysis results"""
    return perform_analysis(binary_hash)
```

## 🐛 Troubleshooting Tasks

### 1. Debug Tool Issues
```bash
# Check tool exists
ls tools/category/tool_name.py

# Check Python path
python -c "import sys; print(sys.path)"

# Check permissions
ls -la tools/category/tool_name.py
```

### 2. Fix Import Errors
```bash
# Install missing dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Check imports
python -c "import tools.category.tool_name"
```

### 3. Memory Issues
```bash
# Use smaller files for testing
# Increase system memory
# Use streaming for large files
```

## 📝 Documentation Tasks

### 1. Update Tool Documentation
```bash
# Generate tool documentation
python scripts/maintenance/generate_docs.py

# Update README files
# Check for broken links
```

### 2. Create Examples
```bash
# Run examples
python scripts/testing/run_examples.py

# Create new examples
# Update example documentation
```

---

**Remember**: Always test your changes thoroughly and update documentation when adding new features or tools.
