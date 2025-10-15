# REVENG Tool Selection Guide

This guide helps you choose the right tools for your analysis tasks.

## 🎯 Tool Categories Overview

| Category | Count | Purpose | Key Tools |
|----------|-------|---------|-----------|
| **Core Analysis** | 8 | Fundamental binary analysis | `ai_recompiler_converter.py`, `optimal_binary_analysis.py` |
| **Multi-Language** | 6 | Java, C#, Python analysis | `java_bytecode_analyzer.py`, `csharp_il_analyzer.py` |
| **AI Enhancement** | 5 | AI-powered analysis | `ai_analyzer_enhanced.py`, `ollama_analyzer.py` |
| **Code Quality** | 4 | Formatting, validation | `code_formatter.py`, `type_inference_engine.py` |
| **Binary Operations** | 5 | Binary manipulation | `binary_reassembler_v2.py`, `binary_validator.py` |
| **Visualization** | 3 | Interactive visualizations | `code_visualizer.py`, `executive_reporting_engine.py` |
| **Enterprise** | 4 | Audit, plugins, monitoring | `audit_trail.py`, `plugin_system.py` |
| **Security** | 8 | ML and security analysis | `ml_malware_classifier.py`, `vulnerability_discovery_engine.py` |
| **Configuration** | 4 | Configuration management | `config_manager.py`, `ghidra_mcp_connector.py` |
| **Utilities** | 19 | Supporting utilities | Various helper tools |

## 🔍 Analysis Workflow Tools

### 1. Language Detection
**Tool**: `tools/languages/language_detector.py`
**Purpose**: Auto-detect file type and language
**Usage**:
```bash
python tools/languages/language_detector.py binary.exe
python tools/languages/language_detector.py application.jar
python tools/languages/language_detector.py script.pyc
```

### 2. Core Analysis (Choose Based on Language)

#### For Native Binaries (PE/ELF/Mach-O)
**Tool**: `tools/core/optimal_binary_analysis.py`
**Purpose**: Ghidra-based disassembly
**Usage**:
```bash
python tools/core/optimal_binary_analysis.py binary.exe
```

#### For Java Bytecode
**Tool**: `tools/languages/java_bytecode_analyzer.py`
**Purpose**: Java .class/.jar analysis
**Usage**:
```bash
python tools/languages/java_bytecode_analyzer.py app.jar
python tools/languages/java_bytecode_analyzer.py MyClass.class
```

#### For C# .NET Assemblies
**Tool**: `tools/languages/csharp_il_analyzer.py`
**Purpose**: C# IL analysis
**Usage**:
```bash
python tools/languages/csharp_il_analyzer.py MyApp.exe
```

#### For Python Bytecode
**Tool**: `tools/languages/python_bytecode_analyzer.py`
**Purpose**: Python .pyc analysis
**Usage**:
```bash
python tools/languages/python_bytecode_analyzer.py script.pyc
```

### 3. AI-Powered Analysis
**Tool**: `tools/core/ai_recompiler_converter.py`
**Purpose**: AI-powered analysis with evidence
**Usage**:
```bash
python tools/core/ai_recompiler_converter.py binary.exe
```

### 4. Deep Inspection
**Tool**: `tools/core/ai_source_inspector.py`
**Purpose**: Deep AI inspection and analysis
**Usage**:
```bash
python tools/core/ai_source_inspector.py
```

## 🛠️ Code Processing Tools

### 1. Human-Readable Conversion
**Tool**: `tools/core/human_readable_converter_fixed.py`
**Purpose**: Generate clean, readable source code
**Usage**:
```bash
python tools/core/human_readable_converter_fixed.py
```

### 2. Code Formatting
**Tool**: `tools/quality/code_formatter.py`
**Purpose**: Format generated C code with clang-format
**Usage**:
```bash
python tools/quality/code_formatter.py human_readable_code/ --pattern "*.c"
```

### 3. Type Inference
**Tool**: `tools/quality/type_inference_engine.py`
**Purpose**: Infer real types from Ghidra analysis
**Usage**:
```bash
python tools/quality/type_inference_engine.py \
    --functions analysis_binary/functions.json \
    --output typed_signatures.h
```

### 4. Deobfuscation
**Tool**: `tools/core/deobfuscation_tool.py`
**Purpose**: Domain splitting and organization
**Usage**:
```bash
python tools/core/deobfuscation_tool.py
```

### 5. Implementation Generation
**Tool**: `tools/core/implementation_tool.py`
**Purpose**: Generate missing feature implementations
**Usage**:
```bash
python tools/core/implementation_tool.py
```

## 🔄 Binary Reconstruction Tools

### 1. Binary Reassembly (THE GAME CHANGER!)
**Tool**: `tools/binary/binary_reassembler_v2.py`
**Purpose**: Full C → executable pipeline
**Usage**:
```bash
python tools/binary/binary_reassembler_v2.py \
    --original binary.exe \
    --source human_readable_code/ \
    --output rebuilt.exe \
    --arch auto \
    --validation-mode smoke_test
```

### 2. Binary Validation
**Tool**: `tools/binary/binary_validator.py`
**Purpose**: Validate rebuilt binary against original
**Usage**:
```bash
python tools/binary/binary_validator.py original.exe rebuilt.exe
```

### 3. Binary Diff
**Tool**: `tools/binary/binary_diff.py`
**Purpose**: Compare original vs modified binary
**Usage**:
```bash
python tools/binary/binary_diff.py original.exe modified.exe
```

### 4. Compilation Testing
**Tool**: `tools/quality/compilation_tester.py`
**Purpose**: Test if generated code compiles
**Usage**:
```bash
python tools/quality/compilation_tester.py human_readable_code/
```

## 🤖 AI Enhancement Tools

### 1. AI Analyzer Enhanced
**Tool**: `tools/ai/ai_analyzer_enhanced.py`
**Purpose**: Enhanced AI analysis
**Usage**:
```bash
python tools/ai/ai_analyzer_enhanced.py
```

### 2. Ollama Integration
**Tool**: `tools/ai/ollama_analyzer.py`
**Purpose**: Local LLM analysis via Ollama
**Usage**:
```bash
python tools/ai/ollama_analyzer.py code.c
```

### 3. Ollama Preflight
**Tool**: `tools/ai/ollama_preflight.py`
**Purpose**: Check Ollama availability and models
**Usage**:
```bash
python tools/ai/ollama_preflight.py
python tools/ai/ollama_preflight.py --setup
```

## 📊 Visualization Tools

### 1. Code Visualizer
**Tool**: `tools/visualization/code_visualizer.py`
**Purpose**: Interactive call graphs and dependency diagrams
**Usage**:
```bash
python tools/visualization/code_visualizer.py analysis_dir/ --type call_graph
python tools/visualization/code_visualizer.py analysis_dir/ --type both
```

### 2. Executive Reporting
**Tool**: `tools/visualization/executive_reporting_engine.py`
**Purpose**: Generate executive summary reports
**Usage**:
```bash
python tools/visualization/executive_reporting_engine.py
```

### 3. Technical Reporting
**Tool**: `tools/visualization/technical_reporting_engine.py`
**Purpose**: Generate technical reports
**Usage**:
```bash
python tools/visualization/technical_reporting_engine.py
```

## 🔒 Security Analysis Tools

### 1. Malware Classification
**Tool**: `tools/security/ml_malware_classifier.py`
**Purpose**: ML-based malware classification
**Usage**:
```bash
python tools/security/ml_malware_classifier.py binary.exe
```

### 2. Vulnerability Discovery
**Tool**: `tools/security/vulnerability_discovery_engine.py`
**Purpose**: Automated vulnerability discovery
**Usage**:
```bash
python tools/security/vulnerability_discovery_engine.py binary.exe
```

### 3. Threat Intelligence
**Tool**: `tools/security/threat_intelligence_correlator.py`
**Purpose**: Threat intelligence correlation
**Usage**:
```bash
python tools/security/threat_intelligence_correlator.py binary.exe
```

### 4. Corporate Exposure
**Tool**: `tools/security/corporate_exposure_detector.py`
**Purpose**: Corporate data exposure detection
**Usage**:
```bash
python tools/security/corporate_exposure_detector.py binary.exe
```

### 5. MITRE ATT&CK Mapping
**Tool**: `tools/security/mitre_attack_mapper.py`
**Purpose**: Map to MITRE ATT&CK framework
**Usage**:
```bash
python tools/security/mitre_attack_mapper.py binary.exe
```

## 🏢 Enterprise Tools

### 1. Audit Trail
**Tool**: `tools/enterprise/audit_trail.py`
**Purpose**: SOC 2 / ISO 27001 compliant logging
**Usage**:
```python
from tools.enterprise.audit_trail import AuditLogger

audit = AuditLogger()
session_id = audit.start_session(['app.jar'], ['java'])
audit.log_file_analysis('app.jar', 'java', success=True, details={})
```

### 2. Plugin System
**Tool**: `tools/enterprise/plugin_system.py`
**Purpose**: Extensible plugin architecture
**Usage**:
```bash
python tools/enterprise/plugin_system.py create MyPlugin --type analyzer
python tools/enterprise/plugin_system.py load MyPlugin
```

### 3. GPU Acceleration
**Tool**: `tools/enterprise/gpu_accelerator.py`
**Purpose**: GPU acceleration for compute-intensive tasks
**Usage**:
```bash
python tools/enterprise/gpu_accelerator.py info
python tools/enterprise/gpu_accelerator.py benchmark
```

### 4. Health Monitoring
**Tool**: `tools/enterprise/enhanced_health_monitor.py`
**Purpose**: System health monitoring
**Usage**:
```bash
python tools/enterprise/enhanced_health_monitor.py
```

## ⚙️ Configuration Tools

### 1. Config Manager
**Tool**: `tools/config/config_manager.py`
**Purpose**: YAML-based configuration management
**Usage**:
```bash
python tools/config/config_manager.py show
python tools/config/config_manager.py set ai.ollama.model deepseek-coder
```

### 2. Ghidra MCP Connector
**Tool**: `tools/config/ghidra_mcp_connector.py`
**Purpose**: Ghidra MCP server connectivity
**Usage**:
```bash
python tools/config/ghidra_mcp_connector.py
```

### 3. Toolchain Check
**Tool**: `tools/binary/check_toolchain.py`
**Purpose**: Verify toolchain and dependencies
**Usage**:
```bash
python tools/binary/check_toolchain.py --fix
```

## 🛠️ Utility Tools

### 1. Progress Reporter
**Tool**: `tools/utils/progress_reporter.py`
**Purpose**: Progress reporting and status updates
**Usage**:
```bash
python tools/utils/progress_reporter.py
```

### 2. Export Formats
**Tool**: `tools/utils/export_formats.py`
**Purpose**: Export format conversion
**Usage**:
```bash
python tools/utils/export_formats.py
```

### 3. Interactive Mode
**Tool**: `tools/utils/interactive_mode.py`
**Purpose**: Interactive analysis mode
**Usage**:
```bash
python tools/utils/interactive_mode.py
```

## 🎯 Tool Selection Decision Tree

### For Binary Analysis
1. **Start with**: `language_detector.py` to identify file type
2. **Route to appropriate analyzer**:
   - Native binary → `optimal_binary_analysis.py`
   - Java → `java_bytecode_analyzer.py`
   - C# → `csharp_il_analyzer.py`
   - Python → `python_bytecode_analyzer.py`
3. **Add AI enhancement**: `ai_recompiler_converter.py`
4. **Deep inspection**: `ai_source_inspector.py`

### For Code Processing
1. **Generate clean code**: `human_readable_converter_fixed.py`
2. **Format code**: `code_formatter.py`
3. **Infer types**: `type_inference_engine.py`
4. **Deobfuscate**: `deobfuscation_tool.py`
5. **Implement missing features**: `implementation_tool.py`

### For Binary Reconstruction
1. **Reassemble**: `binary_reassembler_v2.py`
2. **Validate**: `binary_validator.py`
3. **Test compilation**: `compilation_tester.py`
4. **Compare**: `binary_diff.py`

### For Security Analysis
1. **Classify malware**: `ml_malware_classifier.py`
2. **Find vulnerabilities**: `vulnerability_discovery_engine.py`
3. **Threat intelligence**: `threat_intelligence_correlator.py`
4. **Corporate exposure**: `corporate_exposure_detector.py`

### For Visualization
1. **Call graphs**: `code_visualizer.py`
2. **Executive reports**: `executive_reporting_engine.py`
3. **Technical reports**: `technical_reporting_engine.py`

## 🔧 Tool Development Patterns

### Standard Tool Structure
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

## 📊 Tool Performance Guidelines

### Memory Management
- Use streaming for large files
- Implement chunked processing
- Clear large objects when done

### Parallel Processing
- Use ThreadPoolExecutor for I/O bound tasks
- Use ProcessPoolExecutor for CPU bound tasks
- Limit concurrent operations

### Caching
- Cache expensive operations
- Use LRU cache for repeated calculations
- Clear cache when memory is low

---

**Remember**: Choose tools based on your specific analysis needs and always test with small files first.
