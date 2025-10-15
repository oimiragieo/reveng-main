# REVENG Migration Guide

This guide helps existing users migrate to the new REVENG 2.1.0 organization structure.

## What Changed

### File Organization
- **Root directory cleanup**: 20+ markdown files moved to organized `/docs/` structure
- **Tool categorization**: 66 tools organized into logical subdirectories
- **Script organization**: Scripts organized by purpose (setup, maintenance, testing, deployment)
- **Examples enhancement**: Added Jupyter notebooks and real-world use cases

### New Structure
```
reveng-main/
├── README.md                    # New comprehensive README
├── docs/                        # All documentation (NEW)
│   ├── README.md               # Documentation hub
│   ├── guides/                 # Specialized guides
│   ├── api/                    # API documentation
│   ├── architecture/           # Architecture docs
│   ├── development/            # Development docs
│   ├── legal/                  # Legal documents
│   └── tutorials/              # Step-by-step tutorials
├── tools/                       # Reorganized tools (NEW STRUCTURE)
│   ├── core/                   # Core analysis (8 tools)
│   ├── languages/              # Multi-language (6 tools)
│   ├── ai/                     # AI enhancement (5 tools)
│   ├── quality/                # Code quality (4 tools)
│   ├── binary/                 # Binary operations (5 tools)
│   ├── visualization/           # Visualization (3 tools)
│   ├── enterprise/             # Enterprise (4 tools)
│   ├── security/               # ML/Security (8 tools)
│   ├── config/                 # Configuration (3 tools)
│   └── utils/                  # Utilities (remaining tools)
├── scripts/                     # Reorganized scripts (NEW STRUCTURE)
│   ├── setup/                  # Setup scripts
│   ├── maintenance/            # Maintenance scripts
│   ├── testing/                # Testing scripts
│   ├── deployment/             # Deployment scripts
│   └── development/            # Development scripts
├── examples/                    # Enhanced examples (NEW CONTENT)
│   ├── jupyter/                # Jupyter notebooks
│   └── use-cases/              # Real-world use cases
├── .ai/                        # AI agent guidance (NEW)
│   ├── README.md               # AI assistant entry point
│   ├── project-overview.md     # Quick project summary
│   ├── common-tasks.md         # Common development tasks
│   ├── tool-guide.md           # Tool selection guide
│   └── troubleshooting.md      # Common issues
└── models/                     # Model management (NEW SYSTEM)
    ├── download_models.py      # Model download script
    └── .gitignore              # Ignore .pkl files
```

## Migration Steps

### 1. Update Import Paths

**Old imports:**
```python
from tools.ai_recompiler_converter import AIRecompilerConverter
from tools.language_detector import LanguageDetector
from tools.ollama_preflight import OllamaPreflightChecker
```

**New imports:**
```python
from tools.core.ai_recompiler_converter import AIRecompilerConverter
from tools.languages.language_detector import LanguageDetector
from tools.ai.ollama_preflight import OllamaPreflightChecker
```

### 2. Update Tool Paths

**Old paths:**
```bash
python tools/ai_recompiler_converter.py binary.exe
python tools/language_detector.py binary.exe
python tools/ollama_preflight.py
```

**New paths:**
```bash
python tools/core/ai_recompiler_converter.py binary.exe
python tools/languages/language_detector.py binary.exe
python tools/ai/ollama_preflight.py
```

### 3. Update Script Paths

**Old paths:**
```bash
python scripts/lint_codebase.py
python scripts/run_enhanced_tests.py
python scripts/cleanup_legacy.py
```

**New paths:**
```bash
python scripts/development/lint_codebase.py
python scripts/testing/run_enhanced_tests.py
python scripts/maintenance/cleanup_legacy.py
```

### 4. Update Documentation References

**Old references:**
```markdown
[Architecture Guide](ARCHITECTURE.md)
[API Reference](API_REFERENCE.md)
[Project Structure](PROJECT_STRUCTURE.md)
```

**New references:**
```markdown
[Architecture Guide](docs/architecture/ARCHITECTURE.md)
[API Reference](docs/api/API_REFERENCE.md)
[Project Structure](docs/development/PROJECT_STRUCTURE.md)
```

## Tool Category Mapping

### Core Analysis Tools
- `ai_recompiler_converter.py` → `tools/core/`
- `optimal_binary_analysis.py` → `tools/core/`
- `ai_source_inspector.py` → `tools/core/`
- `human_readable_converter_fixed.py` → `tools/core/`
- `deobfuscation_tool.py` → `tools/core/`
- `implementation_tool.py` → `tools/core/`
- `binary_reassembler_v2.py` → `tools/core/`
- `binary_validator.py` → `tools/core/`

### Multi-Language Tools
- `language_detector.py` → `tools/languages/`
- `java_bytecode_analyzer.py` → `tools/languages/`
- `csharp_il_analyzer.py` → `tools/languages/`
- `python_bytecode_analyzer.py` → `tools/languages/`
- `java_project_reconstructor.py` → `tools/languages/`
- `java_deobfuscator_advanced.py` → `tools/languages/`

### AI Enhancement Tools
- `ai_analyzer_enhanced.py` → `tools/ai/`
- `ollama_analyzer.py` → `tools/ai/`
- `ollama_preflight.py` → `tools/ai/`
- `ai_enhanced_analyzer.py` → `tools/ai/`
- `ai_enhanced_data_models.py` → `tools/ai/`

### Code Quality Tools
- `code_formatter.py` → `tools/quality/`
- `type_inference_engine.py` → `tools/quality/`
- `c_type_parser.py` → `tools/quality/`
- `compilation_tester.py` → `tools/quality/`

### Binary Operations Tools
- `binary_diff.py` → `tools/binary/`
- `check_toolchain.py` → `tools/binary/`
- `validation_config.py` → `tools/binary/`
- `validation_manifest_loader.py` → `tools/binary/`
- `c_implementation_generator.py` → `tools/binary/`

### Visualization Tools
- `code_visualizer.py` → `tools/visualization/`
- `executive_reporting_engine.py` → `tools/visualization/`
- `technical_reporting_engine.py` → `tools/visualization/`

### Enterprise Tools
- `audit_trail.py` → `tools/enterprise/`
- `plugin_system.py` → `tools/enterprise/`
- `gpu_accelerator.py` → `tools/enterprise/`
- `enhanced_health_monitor.py` → `tools/enterprise/`

### Security Tools
- `ml_malware_classifier.py` → `tools/security/`
- `ml_vulnerability_predictor.py` → `tools/security/`
- `vulnerability_discovery_engine.py` → `tools/security/`
- `threat_intelligence_correlator.py` → `tools/security/`
- `corporate_exposure_detector.py` → `tools/security/`
- `mitre_attack_mapper.py` → `tools/security/`
- `complexity_scorer.py` → `tools/security/`
- `nlp_code_analyzer.py` → `tools/security/`

### Configuration Tools
- `config_manager.py` → `tools/config/`
- `enhanced_config_manager.py` → `tools/config/`
- `ghidra_mcp_connector.py` → `tools/config/`

### Utility Tools
- All remaining tools → `tools/utils/`

## Script Category Mapping

### Setup Scripts
- `bootstrap_windows.bat` → `scripts/setup/`
- `bootstrap_linux.sh` → `scripts/setup/`
- `setup_java_analysis.py` → `scripts/setup/`
- `verify_installation.py` → `scripts/setup/`

### Development Scripts
- `lint_codebase.py` → `scripts/development/`
- `lint_codebase.bat` → `scripts/development/`

### Testing Scripts
- `run_enhanced_tests.py` → `scripts/testing/`
- `run_examples.py` → `scripts/testing/`

### Deployment Scripts
- `deploy_enhanced_analysis.py` → `scripts/deployment/`

### Maintenance Scripts
- `cleanup_legacy.py` → `scripts/maintenance/`
- `clean_outputs.py` → `scripts/maintenance/`
- `generate_docs.py` → `scripts/maintenance/`

## Documentation Mapping

### Moved to docs/
- `ARCHITECTURE.md` → `docs/architecture/ARCHITECTURE.md`
- `API_REFERENCE.md` → `docs/api/API_REFERENCE.md`
- `PROJECT_STRUCTURE.md` → `docs/development/PROJECT_STRUCTURE.md`
- `PROJECT_ROADMAP.md` → `docs/development/ROADMAP.md`
- `TODO.md` → `docs/development/TODO.md`
- `RELEASE_NOTES.md` → `docs/RELEASE_NOTES.md`
- `PRIVACY.md` → `docs/legal/PRIVACY.md`

### Moved to docs/guides/
- `AGENT_GUIDE.md` → `docs/guides/AI_ASSISTANT_GUIDE.md`
- `CLAUDE.md` → `docs/guides/CLAUDE_INTEGRATION.md`

## New Features

### AI Agent Support
- **New directory**: `.ai/` with comprehensive AI agent guidance
- **Entry point**: `.ai/README.md` for AI assistants
- **Tool guide**: `.ai/tool-guide.md` for tool selection
- **Troubleshooting**: `.ai/troubleshooting.md` for common issues

### Model Management
- **New system**: `models/download_models.py` for downloading ML models
- **Git ignore**: `.pkl` files no longer tracked in git
- **Download script**: Automated model download with checksum verification

### Enhanced Examples
- **Jupyter notebooks**: `examples/jupyter/getting-started.ipynb`
- **Use cases**: Real-world scenarios in `examples/use-cases/`
- **Tutorials**: Step-by-step guides for common tasks

### GitHub Integration
- **Issue templates**: Bug reports, feature requests, questions
- **PR template**: Comprehensive pull request template
- **Workflows**: Automated testing, linting, documentation, releases

## Backward Compatibility

### Compatibility Shims
The main `reveng_analyzer.py` has been updated to use the new tool paths. All existing functionality remains the same.

### Deprecated Files
- Old tool paths are no longer available
- Old script paths are no longer available
- Old documentation paths are no longer available

## Migration Checklist

### For Users
- [ ] Update any custom scripts that reference old tool paths
- [ ] Update any custom scripts that reference old script paths
- [ ] Update any custom scripts that reference old documentation paths
- [ ] Download ML models using `python models/download_models.py`
- [ ] Review new documentation structure in `docs/`

### For Developers
- [ ] Update import statements in custom tools
- [ ] Update tool paths in custom scripts
- [ ] Update documentation references
- [ ] Test with new organization structure
- [ ] Update CI/CD pipelines if applicable

### For AI Assistants
- [ ] Review new AI agent guidance in `.ai/`
- [ ] Update tool selection logic
- [ ] Update troubleshooting procedures
- [ ] Test with new tool organization

## Getting Help

### Documentation
- **New structure**: Check `docs/README.md` for navigation
- **AI assistants**: Start with `.ai/README.md`
- **Tool reference**: See `tools/README.md`

### Support
- **GitHub Issues**: [Report issues](https://github.com/oimiragieo/reveng-main/issues)
- **GitHub Discussions**: [Community support](https://github.com/oimiragieo/reveng-main/discussions)
- **Troubleshooting**: See `.ai/troubleshooting.md`

## Version Information

- **Previous version**: 2.0.0
- **New version**: 2.1.0
- **Migration date**: January 2025
- **Breaking changes**: File organization only, functionality unchanged

---

**Note**: This migration maintains full backward compatibility for the main REVENG functionality. Only file organization has changed to improve maintainability and user experience.
