# REVENG Tools

This directory contains 66+ analysis tools organized by category for the REVENG Universal Reverse Engineering Platform.

## 📋 Tool Categories

### 🔍 Core Analysis (8 tools)
**Purpose**: Fundamental binary analysis and disassembly

| Tool | Purpose | Usage |
|------|---------|-------|
| `ai_recompiler_converter.py` | AI-powered analysis with evidence | `python tools/core/ai_recompiler_converter.py binary.exe` |
| `optimal_binary_analysis.py` | Ghidra disassembly integration | `python tools/core/optimal_binary_analysis.py binary.exe` |
| `ai_source_inspector.py` | Deep AI inspection and analysis | `python tools/core/ai_source_inspector.py` |
| `human_readable_converter_fixed.py` | Source code cleanup and documentation | `python tools/core/human_readable_converter_fixed.py` |
| `deobfuscation_tool.py` | Domain splitting and organization | `python tools/core/deobfuscation_tool.py` |
| `implementation_tool.py` | Missing feature implementation | `python tools/core/implementation_tool.py` |
| `binary_reassembler_v2.py` | **Binary reassembly (GAME CHANGER!)** | `python tools/core/binary_reassembler_v2.py --original a.exe --source code/` |
| `binary_validator.py` | Binary validation and verification | `python tools/core/binary_validator.py original.exe rebuilt.exe` |

### 🌐 Multi-Language Support (6 tools)
**Purpose**: Analysis across different programming languages

| Tool | Purpose | Usage |
|------|---------|-------|
| `language_detector.py` | Auto-detect file types | `python tools/languages/language_detector.py binary.exe` |
| `java_bytecode_analyzer.py` | Java .class/.jar analysis | `python tools/languages/java_bytecode_analyzer.py app.jar` |
| `csharp_il_analyzer.py` | C# .NET assembly analysis | `python tools/languages/csharp_il_analyzer.py MyApp.exe` |
| `python_bytecode_analyzer.py` | Python .pyc analysis | `python tools/languages/python_bytecode_analyzer.py script.pyc` |
| `java_project_reconstructor.py` | Maven/Gradle project reconstruction | `python tools/languages/java_project_reconstructor.py app.jar` |
| `java_deobfuscator_advanced.py` | Advanced Java deobfuscation | `python tools/languages/java_deobfuscator_advanced.py decompiled/` |

### 🤖 AI Enhancement (5 tools)
**Purpose**: AI-powered analysis and enhancement

| Tool | Purpose | Usage |
|------|---------|-------|
| `ai_analyzer_enhanced.py` | Enhanced AI analysis | `python tools/ai/ai_analyzer_enhanced.py` |
| `ollama_analyzer.py` | Local LLM analysis via Ollama | `python tools/ai/ollama_analyzer.py code.c` |
| `ollama_preflight.py` | Ollama availability checker | `python tools/ai/ollama_preflight.py` |
| `ai_enhanced_analyzer.py` | Advanced AI analysis | `python tools/ai/ai_enhanced_analyzer.py` |
| `ai_enhanced_data_models.py` | AI data models and structures | `python tools/ai/ai_enhanced_data_models.py` |

### 🎨 Code Quality (4 tools)
**Purpose**: Code formatting, validation, and quality improvement

| Tool | Purpose | Usage |
|------|---------|-------|
| `code_formatter.py` | C code formatting with clang-format | `python tools/quality/code_formatter.py human_readable_code/` |
| `type_inference_engine.py` | Real type inference from Ghidra | `python tools/quality/type_inference_engine.py --functions funcs.json` |
| `c_type_parser.py` | C type parsing and validation | `python tools/quality/c_type_parser.py` |
| `compilation_tester.py` | Compilation testing and error reporting | `python tools/quality/compilation_tester.py source_dir/` |

### 🔧 Binary Operations (5 tools)
**Purpose**: Binary manipulation and reconstruction

| Tool | Purpose | Usage |
|------|---------|-------|
| `binary_diff.py` | Binary comparison and diffing | `python tools/binary/binary_diff.py original.exe modified.exe` |
| `check_toolchain.py` | Toolchain verification | `python tools/binary/check_toolchain.py --fix` |
| `validation_config.py` | Validation configuration | `python tools/binary/validation_config.py --create-config val.json` |
| `validation_manifest_loader.py` | Validation manifest loading | `python tools/binary/validation_manifest_loader.py` |
| `c_implementation_generator.py` | C code implementation generation | `python tools/binary/c_implementation_generator.py` |

### 📊 Visualization (3 tools)
**Purpose**: Interactive visualizations and reporting

| Tool | Purpose | Usage |
|------|---------|-------|
| `code_visualizer.py` | Interactive call graphs | `python tools/visualization/code_visualizer.py analysis_dir/` |
| `executive_reporting_engine.py` | Executive summary generation | `python tools/visualization/executive_reporting_engine.py` |
| `technical_reporting_engine.py` | Technical report generation | `python tools/visualization/technical_reporting_engine.py` |

### 🏢 Enterprise Features (4 tools)
**Purpose**: Enterprise-grade features and compliance

| Tool | Purpose | Usage |
|------|---------|-------|
| `audit_trail.py` | SOC 2 / ISO 27001 compliant logging | `python tools/enterprise/audit_trail.py` |
| `plugin_system.py` | Extensible plugin architecture | `python tools/enterprise/plugin_system.py create MyPlugin` |
| `gpu_accelerator.py` | GPU acceleration for compute-intensive tasks | `python tools/enterprise/gpu_accelerator.py info` |
| `enhanced_health_monitor.py` | System health monitoring | `python tools/enterprise/enhanced_health_monitor.py` |

### 🔒 ML/Security (8 tools)
**Purpose**: Machine learning and security analysis

| Tool | Purpose | Usage |
|------|---------|-------|
| `ml_malware_classifier.py` | ML-based malware classification | `python tools/security/ml_malware_classifier.py` |
| `ml_vulnerability_predictor.py` | Vulnerability prediction using ML | `python tools/security/ml_vulnerability_predictor.py` |
| `vulnerability_discovery_engine.py` | Automated vulnerability discovery | `python tools/security/vulnerability_discovery_engine.py` |
| `threat_intelligence_correlator.py` | Threat intelligence correlation | `python tools/security/threat_intelligence_correlator.py` |
| `corporate_exposure_detector.py` | Corporate data exposure detection | `python tools/security/corporate_exposure_detector.py` |
| `mitre_attack_mapper.py` | MITRE ATT&CK framework mapping | `python tools/security/mitre_attack_mapper.py` |
| `complexity_scorer.py` | Code complexity analysis | `python tools/security/complexity_scorer.py` |
| `nlp_code_analyzer.py` | Natural language processing for code | `python tools/security/nlp_code_analyzer.py` |

### ⚙️ Configuration (3 tools)
**Purpose**: Configuration management and setup

| Tool | Purpose | Usage |
|------|---------|-------|
| `config_manager.py` | YAML-based configuration | `python tools/config/config_manager.py show` |
| `enhanced_config_manager.py` | Enhanced configuration management | `python tools/config/enhanced_config_manager.py` |
| `ghidra_mcp_connector.py` | Ghidra MCP server connectivity | `python tools/config/ghidra_mcp_connector.py` |

### 🛠️ Utilities (19 tools)
**Purpose**: Supporting utilities and helper functions

| Tool | Purpose | Usage |
|------|---------|-------|
| `progress_reporter.py` | Progress reporting and status updates | `python tools/utils/progress_reporter.py` |
| `export_formats.py` | Export format conversion | `python tools/utils/export_formats.py` |
| `export_integration_engine.py` | Export integration | `python tools/utils/export_integration_engine.py` |
| `functional_code_generator.py` | Functional code generation | `python tools/utils/functional_code_generator.py` |
| `enhanced_code_generator.py` | Enhanced code generation | `python tools/utils/enhanced_code_generator.py` |
| `reconstruction_comparator.py` | Reconstruction comparison | `python tools/utils/reconstruction_comparator.py` |
| `purge_stubs.py` | Stub code cleanup | `python tools/utils/purge_stubs.py` |
| `proguard_mapper.py` | ProGuard mapping | `python tools/utils/proguard_mapper.py` |
| `interactive_mode.py` | Interactive analysis mode | `python tools/utils/interactive_mode.py` |
| `live_demonstration_engine.py` | Live demonstration | `python tools/utils/live_demonstration_engine.py` |
| `demonstration_generator.py` | Demonstration generation | `python tools/utils/demonstration_generator.py` |
| `educational_content_generator.py` | Educational content generation | `python tools/utils/educational_content_generator.py` |
| `training_material_generator.py` | Training material generation | `python tools/utils/training_material_generator.py` |
| `comprehensive_reporting_system.py` | Comprehensive reporting | `python tools/utils/comprehensive_reporting_system.py` |
| `ml_pipeline_orchestrator.py` | ML pipeline orchestration | `python tools/utils/ml_pipeline_orchestrator.py` |
| `vulnerability_dataset_loader.py` | Vulnerability dataset loading | `python tools/utils/vulnerability_dataset_loader.py` |
| `enhanced_health_monitor.py` | Enhanced health monitoring | `python tools/utils/enhanced_health_monitor.py` |
| `mitre_attack_mapper_backup.py` | MITRE ATT&CK mapper backup | `python tools/utils/mitre_attack_mapper_backup.py` |
| `test_file.txt` | Test file for validation | `python tools/utils/test_file.txt` |

## 🚀 Quick Start

### Basic Analysis Pipeline
```bash
# 1. Analyze binary
python reveng_analyzer.py binary.exe

# 2. Format generated code
python tools/quality/code_formatter.py human_readable_code/

# 3. Infer types
python tools/quality/type_inference_engine.py --functions analysis_binary/functions.json

# 4. Reassemble binary
python tools/core/binary_reassembler_v2.py --original binary.exe --source human_readable_code/ --output rebuilt.exe
```

### Multi-Language Analysis
```bash
# Java analysis
python tools/languages/java_bytecode_analyzer.py application.jar

# C# analysis
python tools/languages/csharp_il_analyzer.py MyApp.exe

# Python analysis
python tools/languages/python_bytecode_analyzer.py script.pyc
```

### AI-Enhanced Analysis
```bash
# Check Ollama availability
python tools/ai/ollama_preflight.py

# Run AI analysis
python tools/ai/ai_analyzer_enhanced.py

# Generate reports
python tools/visualization/executive_reporting_engine.py
```

## 🔧 Tool Development

### Adding New Tools
1. **Create Tool File** in appropriate category directory
2. **Follow Naming Convention**: `snake_case.py`
3. **Add to categories.json** (if needed)
4. **Update imports** in main pipeline
5. **Create tests** in `tests/`
6. **Update documentation**

### Tool Standards
- **Naming**: Use snake_case for file names
- **Documentation**: Include docstrings and usage examples
- **Error Handling**: Graceful error handling with clear messages
- **Logging**: Use appropriate logging levels
- **Testing**: Include unit tests for new tools
- **Performance**: Optimize for large files and datasets

## 📊 Tool Metrics

| Category | Count | Lines | Complexity |
|----------|-------|-------|------------|
| Core Analysis | 8 | ~2,400 | Medium-High |
| Multi-Language | 6 | ~1,800 | Medium |
| AI Enhancement | 5 | ~1,500 | High |
| Code Quality | 4 | ~1,200 | Medium |
| Binary Operations | 5 | ~1,500 | High |
| Visualization | 3 | ~900 | Medium |
| Enterprise | 4 | ~1,200 | High |
| ML/Security | 8 | ~2,400 | High |
| Configuration | 3 | ~900 | Medium |
| Utilities | 19 | ~5,700 | Low-Medium |
| **Total** | **66** | **~18,000** | **Medium** |

## 🔍 Tool Dependencies

### Core Dependencies
- **Python 3.11+**
- **requests** - HTTP client for API calls
- **lief** - Binary manipulation
- **keystone-engine** - Multi-architecture assembler
- **capstone** - Multi-architecture disassembler

### AI/ML Dependencies
- **ollama** - Local LLM integration
- **anthropic** - Claude API integration
- **openai** - GPT API integration
- **scikit-learn** - Machine learning
- **tensorflow** - Deep learning

### Visualization Dependencies
- **networkx** - Graph analysis
- **pydot** - Graph visualization
- **matplotlib** - Plotting
- **plotly** - Interactive plots

### Enterprise Dependencies
- **docker** - Containerization
- **kubernetes** - Orchestration
- **redis** - Caching
- **mongodb** - Database

## 🐛 Troubleshooting

### Common Issues
- **Tool Not Found**: Check if tool exists in new categorized structure
- **Import Errors**: Update import paths after reorganization
- **Permission Errors**: Check file permissions
- **Memory Issues**: Use smaller files for testing

### Getting Help
- **Tool Issues**: Check tool output for error messages
- **Dependencies**: Verify all requirements are installed
- **Documentation**: See individual tool docstrings
- **Examples**: Check `examples/` directory for usage examples

## 📚 Related Documentation

- **[Main README](../README.md)** - Project overview
- **[Developer Guide](../docs/DEVELOPER_GUIDE.md)** - Development workflows
- **[User Guide](../docs/USER_GUIDE.md)** - Usage documentation
- **[AI Assistant Guide](../docs/guides/AI_ASSISTANT_GUIDE.md)** - For AI agents
- **[Tool Guide](../.ai/tool-guide.md)** - Detailed tool selection guide

## 🔄 Tool Lifecycle

### Maintenance
- **Regular Updates**: Keep tools current with project changes
- **Bug Fixes**: Address reported issues promptly
- **Performance**: Optimize for large datasets
- **Documentation**: Keep examples and usage current

### Deprecation
- **Notice Period**: 6 months advance notice
- **Migration Guide**: Clear migration instructions
- **Replacement**: New tool or alternative approach
- **Archive**: Move to `archived/` directory

---

**Last Updated**: January 2025  
**Maintainer**: REVENG Development Team  
**Total Tools**: 66+  
**Total Lines**: ~18,000