# Directory: src/reveng (Root Package)

## Overview
This is the root package of the REVENG Universal Reverse Engineering Platform. It provides the main entry points, core analyzer, and high-level APIs for binary analysis, malware detection, and binary reconstruction. The package is designed for enterprise-grade reverse engineering with AI-powered capabilities.

## Files in This Directory

### __init__.py
- **Purpose**: Package initialization and public API exports
- **Key Classes**: Exports `REVENGAnalyzer`, `REVENGAPI`, `MLIntegration`, `MLIntegrationConfig`
- **Key Functions**: `main`, `get_version`, `get_version_info`, `analyze_binary`, `detect_malware`, `reconstruct_binary`
- **Dependencies**: `.analyzer`, `.api`, `.cli`, `.ml`, `.version`
- **Used By**: External users importing the reveng package
- **Package Metadata**: Version 4.0.0 (ULTRATHINK Optimization), MIT License, supports Python 3.9+

### __main__.py
- **Purpose**: Entry point for running REVENG as a module (`python -m reveng`)
- **Key Classes**: None
- **Key Functions**: Imports and calls `main()` from `.cli`
- **Dependencies**: `.cli`
- **Used By**: Python when executing `python -m reveng`

### ai_api.py
- **Purpose**: AI-optimized Python API designed specifically for AI agents (Claude, GPT, etc.)
- **Key Classes**:
  - `REVENG_AI_API`: Main AI-optimized API class
  - `AnalysisMode`: Enum for analysis depth levels (QUICK, STANDARD, DEEP, REBUILD)
  - `TriageResult`: Dataclass for triage results with threat level and confidence
  - `CryptoDetails`: Dataclass for cryptography findings
  - `NetworkDetails`: Dataclass for network communication findings
  - `TranslationGuide`: Dataclass for C-to-Python translation hints
- **Key Functions**:
  - `triage_binary()`: Fast (<30s) threat assessment
  - `ask()`: Natural language queries about binaries
  - `get_crypto_details()`: Extract cryptographic operations
  - `get_network_details()`: Extract network indicators
  - `get_translation_hints()`: Generate C-to-Python translation guide
  - `analyze_binary()`: Comprehensive analysis with multiple modes
  - `explain_binary()`: Natural language explanation of binary functionality
  - `find_vulnerabilities()`: Vulnerability detection
  - `extract_iocs()`: Extract indicators of compromise
  - `compare_binaries()`: Binary comparison and similarity analysis
  - `quick_triage()`: Convenience function for rapid triage
  - `quick_ask()`: Convenience function for NL queries
- **Dependencies**:
  - `..tools.ai.ai_enhanced.instant_triage`
  - `..tools.ai.ai_enhanced.nl_interface`
  - `..tools.translation`
  - `.analyzer.REVENGAnalyzer`
- **Used By**: AI agents, automation scripts requiring structured responses

### analyzer.py
- **Purpose**: Core REVENG analyzer implementing the 13-step analysis pipeline
- **Key Classes**:
  - `REVENGAnalyzer`: Main analyzer class with comprehensive binary analysis
  - `EnhancedAnalysisFeatures`: Feature flags for enhanced analysis modules
- **Key Functions**:
  - `analyze_binary()`: Main analysis orchestrator (13 steps)
  - `_step1_ai_analysis()`: AI-powered binary analysis
  - `_step2_disassembly()`: Complete disassembly (native/Java/C#/Python)
  - `_step3_ai_inspection()`: AI inspection with extra thinking
  - `_step4_specifications()`: Specification library creation
  - `_step5_human_readable()`: Human-readable code conversion
  - `_step6_deobfuscation()`: Deobfuscation and domain splitting
  - `_step7_implementation()`: Implementation of missing features
  - `_step8_validation()`: Binary validation
  - `_step9_corporate_exposure()`: Corporate data exposure analysis (enhanced)
  - `_step10_vulnerability_discovery()`: Automated vulnerability discovery (enhanced)
  - `_step11_threat_intelligence()`: Threat intelligence correlation (enhanced)
  - `_step12_enhanced_reconstruction()`: Enhanced binary reconstruction (enhanced)
  - `_step13_demonstration_generation()`: Security demonstration generation (enhanced)
  - `get_capabilities()`: Returns analyzer capabilities metadata
- **Dependencies**:
  - `reveng.core.error_codes`
  - `reveng.core.dependency_manager`
  - `reveng.tools.config.ghidra_engine`
  - `reveng.tools.languages.*` (Java, C#, Python analyzers)
  - `reveng.tools.core.*` (Various analysis tools)
  - `reveng.security.*` (Enhanced security modules)
  - `reveng.pipeline.steps`
- **Used By**: `REVENGAPI`, `cli`, `ai_api`, web interface

### api.py
- **Purpose**: Unified programmatic API for integration with other tools and automation
- **Key Classes**:
  - `REVENGAPI`: Main unified API class
- **Key Functions**:
  - `analyze_binary()`: Full binary analysis with standardized results
  - `reconstruct_binary()`: Binary-to-source reconstruction
  - `detect_malware()`: Malware detection and threat classification
  - `_calculate_hash()`: File hash calculation
  - `_detect_binary_type()`: Binary format detection (PE/ELF/Mach-O)
  - `_detect_architecture()`: Architecture detection
  - `_calculate_confidence()`: Overall confidence score calculation
  - Convenience functions: `analyze_binary()`, `detect_malware()`, `reconstruct_binary()`
- **Dependencies**:
  - `.analyzer.REVENGAnalyzer`
  - `.core.exceptions`
  - `.core.validation`
  - `.ml.MLIntegration`
- **Used By**: Automation scripts, third-party integrations, CI/CD pipelines

### cli.py
- **Purpose**: Command-line interface for REVENG platform
- **Key Classes**: None
- **Key Functions**:
  - `create_parser()`: Creates argument parser with all subcommands
  - `create_enhanced_features()`: Parse enhanced analysis feature flags
  - `handle_analyze_command()`: Handle binary analysis command
  - `handle_serve_command()`: Start web interface server
  - `handle_ask_command()`: Natural language interface
  - `handle_ai_command()`: AI assistant for interactive analysis
  - `handle_triage_command()`: Instant triage (<30s threat assessment)
  - `handle_vt_lookup_command()`: VirusTotal hash lookup
  - `handle_vt_submit_command()`: Submit file to VirusTotal
  - `handle_generate_yara_command()`: Generate YARA rules
  - `handle_scan_yara_command()`: Scan with YARA rules
  - `handle_diff_command()`: Binary diffing
  - `handle_patch_analysis_command()`: Security patch analysis
  - `handle_detect_packer_command()`: Packer detection
  - `handle_unpack_command()`: Binary unpacking
  - `handle_enhance_code_command()`: AI code quality enhancement
  - `main()`: Main entry point
- **Dependencies**: All REVENG subsystems (tools, ai, security, etc.)
- **Used By**: Command-line users, shell scripts

### version.py
- **Purpose**: Version management and information
- **Key Classes**: None
- **Key Functions**:
  - `get_version()`: Get version string
  - `get_version_info()`: Get version tuple (major, minor, patch)
  - `get_version_string()`: Formatted version string
  - `get_build_info()`: Build information dictionary
  - `get_system_info()`: System compatibility info
  - `is_compatible_python()`: Check Python version compatibility
  - `get_minimum_requirements()`: Minimum system requirements
  - `read_version_from_file()`: Read version from VERSION file
- **Dependencies**: None (stdlib only)
- **Used By**: `__init__.py`, `cli.py`, packaging scripts
- **Version Info**: 4.0.0 (ULTRATHINK Optimization/Stable), Python 3.9+ required

## Architecture
The root package serves as the main interface layer for REVENG:

```
┌─────────────────────────────────────┐
│        User/AI Agent Input          │
└──────────────┬──────────────────────┘
               │
       ┌───────┴───────┐
       │  Entry Points │
       ├───────────────┤
       │ cli.py        │ ── Command-line interface
       │ __main__.py   │ ── Module execution
       └───────┬───────┘
               │
       ┌───────┴────────┐
       │   API Layer    │
       ├────────────────┤
       │ api.py         │ ── Unified programmatic API
       │ ai_api.py      │ ── AI-optimized API
       └────────┬───────┘
                │
       ┌────────┴────────┐
       │  Core Analyzer  │
       ├─────────────────┤
       │ analyzer.py     │ ── 13-step pipeline
       │                 │    • Steps 1-8: Core analysis
       │                 │    • Steps 9-13: Enhanced (AI)
       └─────────┬───────┘
                 │
         ┌───────┴────────────┐
         │   Subsystems       │
         ├────────────────────┤
         │ tools/             │ ── Analysis tools
         │ ai/                │ ── AI components
         │ security/          │ ── Security modules
         │ ml/                │ ── Machine learning
         │ pipeline/          │ ── Pipeline steps
         └────────────────────┘
```

## Key Concepts

### 13-Step Analysis Pipeline
The analyzer implements a comprehensive 13-step pipeline:

**Core Steps (1-8)**:
1. AI-powered binary analysis
2. Complete disassembly (multi-language support)
3. AI inspection with extended thinking
4. Specification library creation
5. Human-readable code conversion
6. Deobfuscation and domain splitting
7. Implementation of missing features
8. Binary validation

**Enhanced Steps (9-13)** (AI-powered, optional):
9. Corporate data exposure analysis
10. Automated vulnerability discovery
11. Threat intelligence correlation
12. Enhanced binary reconstruction
13. Security demonstration generation

### Multi-Language Support
- Native binaries (PE, ELF, Mach-O) via Ghidra
- Java bytecode (.jar, .class)
- C# IL (.dll, .exe)
- Python bytecode (.pyc)

### Ghidra-First Architecture
The analyzer uses a "Ghidra-first" approach where Ghidra Analysis Server is the primary analysis engine:
- Decompiled C code (not just disassembly)
- Control flow graphs (CFG)
- Cross-references (xrefs)
- Data flow analysis
- Fail-fast if Ghidra server unavailable (with graceful degradation)

### AI Integration
Three levels of AI integration:
1. **Heuristic**: Basic analysis without AI
2. **Ollama**: Local LLM for code analysis
3. **Enhanced**: Full AI-powered analysis with ML models

### Progress Callbacks
The analyzer supports structured progress reporting via callbacks:
```python
def progress_callback(event_type: str, data: Dict[str, Any]):
    print(f"[{event_type}] {data}")

analyzer = REVENGAnalyzer(
    binary_path="malware.exe",
    progress_callback=progress_callback
)
```

Events: `analysis_start`, `step_start`, `step_complete`, `error`, `analysis_complete`

## Usage Examples

### Basic Analysis (CLI)
```bash
# Analyze a binary
reveng analyze malware.exe

# Disable enhanced analysis
reveng analyze malware.exe --no-enhanced

# Custom output directory
reveng analyze malware.exe --output-dir /tmp/analysis

# Skip specific enhanced modules
reveng analyze malware.exe --no-corporate --no-demo
```

### Programmatic API
```python
from reveng.api import REVENGAPI

# Create API instance
api = REVENGAPI()

# Analyze binary
result = api.analyze_binary("malware.exe", enhanced=True)

# Check results
print(f"Type: {result['classification']['language']}")
print(f"Functions: {len(result['analysis']['functions'])}")
print(f"Confidence: {result['confidence']}")

# Detect malware
threat = api.detect_malware("suspicious.exe")
if threat['threat_assessment']['is_malware']:
    print(f"Malware detected: {threat['threat_assessment']['malware_family']}")
```

### AI-Optimized API
```python
from reveng.ai_api import REVENG_AI_API, AnalysisMode

# Create AI API
api = REVENG_AI_API(use_ollama=True)

# Quick triage (<30 seconds)
triage = api.triage_binary("unknown.exe")
print(f"Threat: {triage.threat_level} ({triage.threat_score}/100)")
print(f"Malicious: {triage.is_malicious}")
print(f"Capabilities: {triage.detected_capabilities}")

# Natural language queries
response = api.ask("What does this binary do?", "malware.exe")
print(f"Answer: {response.answer}")
print(f"Confidence: {response.confidence}")

# Full analysis with rebuild hints
result = api.analyze_binary("app.exe", mode=AnalysisMode.REBUILD)
```

### Core Analyzer
```python
from reveng.analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures

# Configure enhanced features
features = EnhancedAnalysisFeatures()
features.enable_corporate_exposure = True
features.enable_vulnerability_discovery = True
features.enable_threat_intelligence = False  # Disable this one

# Create analyzer with progress tracking
def on_progress(event_type, data):
    if event_type == "step_start":
        print(f"Starting step {data['step']}: {data['name']}")
    elif event_type == "step_complete":
        print(f"Completed step {data['step']}")

analyzer = REVENGAnalyzer(
    binary_path="malware.exe",
    enhanced_features=features,
    progress_callback=on_progress
)

# Run analysis
summary = analyzer.analyze_binary()

# Check results
if summary['status'] == 'success':
    print(f"Analysis folder: {summary['analysis_folder']}")
    print(f"Enhanced modules: {summary['enabled_module_count']}")
```

## Configuration

### Environment Variables
- `VT_API_KEY`: VirusTotal API key for threat intelligence
- `OLLAMA_HOST`: Ollama server URL (default: http://localhost:11434)

### Configuration Files
Enhanced analysis can be configured via JSON:
```json
{
  "enhanced_analysis": {
    "enable_enhanced_analysis": true,
    "enable_corporate_exposure": true,
    "enable_vulnerability_discovery": true,
    "enable_threat_intelligence": true,
    "enable_enhanced_reconstruction": true,
    "enable_demonstration_generation": false
  }
}
```

Load with: `reveng analyze malware.exe --config config.json`

### Analysis Output Structure
```
analysis_<binary_name>/
├── universal_analysis_report.json    # Comprehensive report
├── audit_logs/                        # Audit trail (if enabled)
├── functions/                         # Decompiled functions (from Ghidra)
│   ├── func_401000.c
│   ├── func_401100.c
│   └── ...
├── java_analysis/                     # Java-specific (if applicable)
├── csharp_analysis/                   # C#-specific (if applicable)
├── python_analysis/                   # Python-specific (if applicable)
└── validation_report.json             # Validation results (if rebuilt)
```

## Testing

### Unit Tests
```bash
# Run all tests
pytest tests/

# Test specific module
pytest tests/test_analyzer.py

# Test with coverage
pytest --cov=reveng tests/
```

### Integration Tests
```bash
# Test full analysis pipeline
pytest tests/integration/test_full_pipeline.py

# Test multi-language support
pytest tests/integration/test_multilang.py
```

### Manual Testing
```bash
# Test basic analysis
reveng analyze test_binaries/simple.exe

# Test enhanced modules
reveng analyze test_binaries/malware.exe

# Test AI features
reveng ask "Is this malware?" test_binaries/suspicious.exe
```

## Related Modules

### Core Dependencies
- `src/reveng/core/`: Core utilities (error handling, validation, dependency management)
- `src/reveng/tools/`: Analysis tools (decompilers, diffing, etc.)
- `src/reveng/ai/`: AI components (assistants, models)
- `src/reveng/ml/`: Machine learning integration
- `src/reveng/security/`: Security analysis modules
- `src/reveng/pipeline/`: Pipeline step implementations

### External Dependencies
- **Ghidra**: Required for native binary analysis (must run Ghidra Analysis Server)
- **Ollama**: Optional, for local LLM-powered analysis
- **Java 17+**: Required for Ghidra and Java bytecode analysis
- **Various decompilers**: ILSpy (C#), pycdc (Python), etc.

### Optional Integrations
- VirusTotal API (threat intelligence)
- YARA (rule-based detection)
- Various unpacking tools (UPX, etc.)

## Notes

### Architecture Evolution
- **v1.x**: Basic disassembly and decompilation
- **v2.x**: Added AI analysis and multi-language support
- **v3.x**: Ghidra-first architecture, enhanced modules, structured APIs

### Performance Considerations
- Triage mode: <30 seconds (instant threat assessment)
- Standard analysis: 2-5 minutes (depends on binary size)
- Deep analysis: 10-30 minutes (full enhanced modules)
- Rebuild mode: 15-45 minutes (includes translation hints)

### Ghidra Server Requirement
The analyzer requires Ghidra Analysis Server to be running:
```bash
# Start Ghidra server (typically on port 13370)
python -m reveng.tools.config.ghidra_server
```

Without Ghidra, analysis will gracefully degrade but with limited functionality.

### Enhanced Modules
Enhanced modules (steps 9-13) require additional dependencies:
- Corporate exposure: NLP models for sensitive data detection
- Vulnerability discovery: Static analysis engines
- Threat intelligence: VirusTotal API, YARA rules
- Enhanced reconstruction: Code generation models
- Demonstration generation: Report templating engines

### Audit Trail
When audit logging is enabled, all analysis actions are logged with:
- Timestamp
- User/session ID
- Target files
- Analysis types
- Results and errors

### Error Handling
The analyzer uses structured error codes (see `reveng.core.error_codes`):
- `BINARY_NOT_FOUND`: Target binary doesn't exist
- `TOOL_GHIDRA_SERVER_UNAVAILABLE`: Ghidra server not running
- `ANALYSIS_STEP_FAILED`: Generic step failure
- `ML_MODEL_NOT_AVAILABLE`: ML model not loaded

Each error includes:
- Error code
- Severity level
- Human-readable message
- Recovery suggestions
- Additional details

### Best Practices
1. Always run Ghidra Analysis Server before analysis
2. Use triage mode for rapid incident response
3. Enable enhanced modules only when needed (performance impact)
4. Use progress callbacks for long-running analyses
5. Check tool availability with `get_capabilities()` before analysis
6. Save analysis results to custom directory for better organization
7. Use AI API for agent-based automation (structured responses)
8. Use unified API for traditional integrations (JSON responses)

### Future Enhancements
- Support for more binary formats (WebAssembly, etc.)
- Distributed analysis across multiple Ghidra servers
- Real-time analysis streaming
- Plugin system for custom analyzers
- Cloud-based analysis service
