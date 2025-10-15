# CLAUDE.md

**AI Assistant Guide for REVENG Universal Reverse Engineering Platform**

This file provides comprehensive guidance for AI coding assistants working with the REVENG codebase.

## 🎯 Quick Reference

### Project Overview
**REVENG** is a universal reverse engineering platform supporting Java, C#, Python, and native binaries with AI-powered analysis and binary reassembly capabilities.

### Key Features
- ✅ **Multi-Language Support** - Java, C#, Python, Native (PE/ELF/Mach-O)
- ✅ **AI-Powered Analysis** - Ollama/Anthropic/OpenAI integration
- ✅ **Binary Reassembly** - Full C → executable pipeline (GAME CHANGER!)
- ✅ **Professional Disassembly** - Ghidra + 16 GhidraMCP features
- ✅ **Enterprise Features** - Audit trails, plugin system, GPU acceleration

### Supported Formats
- **Native binaries**: PE (.exe, .dll), ELF (.so, .elf), Mach-O (.dylib)
- **Java bytecode**: .class, .jar, .war, .ear
- **C# assemblies**: .exe, .dll with IL
- **Python bytecode**: .pyc, .pyo

## 🚀 Quick Start Commands

### Basic Analysis
```bash
# Analyze any binary
python reveng_analyzer.py binary.exe

# Results in organized directories:
# - analysis_binary/           # JSON reports
# - human_readable_code/       # Cleaned C code
# - deobfuscated_app/          # Domain-organized modules
```

### Tool Selection Guide
```bash
# Language Detection
python tools/language_detector.py binary.exe

# Core Analysis (choose based on language)
python tools/ai_recompiler_converter.py binary.exe          # AI-powered
python tools/optimal_binary_analysis.py binary.exe          # Ghidra-based
python tools/java_bytecode_analyzer.py app.jar              # Java
python tools/csharp_il_analyzer.py MyApp.exe                # C#

# Code Processing
python tools/human_readable_converter_fixed.py              # Clean code
python tools/code_formatter.py human_readable_code/         # Format
python tools/type_inference_engine.py --functions funcs.json # Types

# Binary Reconstruction (THE GAME CHANGER!)
python tools/binary_reassembler_v2.py --original a.exe --source code/ --output rebuilt.exe
```

### AI Enhancement
```bash
# Check AI availability
python tools/ollama_preflight.py

# Run AI analysis
python tools/ai_analyzer_enhanced.py
python tools/ollama_analyzer.py code.c

# Generate reports
python tools/executive_reporting_engine.py
```

## 📁 Project Structure

```
reveng-main/
├── reveng_analyzer.py          # Main entry point (8-step pipeline)
├── tools/                      # 66+ analysis tools (categorized)
│   ├── README.md              # Complete tools documentation
│   ├── categories.json        # Machine-readable categorization
│   └── *.py                   # Analysis tools
├── docs/                       # Complete documentation
├── examples/                   # Usage examples
├── tests/                      # Test suite
├── web_interface/              # Functional web UI
└── AGENT_GUIDE.md             # Dedicated AI assistant guide
```

## 🔧 Tool Categories Quick Reference

| Category | Tools | Purpose |
|----------|-------|---------|
| **Core Analysis** | 8 tools | Fundamental binary analysis |
| **Multi-Language** | 6 tools | Java, C#, Python analysis |
| **AI Enhancement** | 5 tools | AI-powered analysis |
| **Code Quality** | 4 tools | Formatting, validation |
| **Binary Operations** | 5 tools | Binary manipulation |
| **Visualization** | 3 tools | Interactive visualizations |
| **Enterprise** | 4 tools | Audit, plugins, monitoring |
| **ML/Security** | 8 tools | ML and security analysis |
| **Configuration** | 4 tools | Configuration management |
| **Utilities** | 19 tools | Supporting utilities |

## System Requirements

- **Java 21 (64-bit)** - Required for Ghidra
- **Ghidra** - Extract to `C:\ghidra` and set up GhidraMCP server
- **Python 3.x** with dependencies: `pip install -r requirements.txt`
  - `requests>=2.28.1`
  - `ghidramcp>=0.1.0`
  - `lief>=0.13.0` - Binary manipulation (NOT optional)
  - `keystone-engine>=0.9.2` - Multi-arch assembler
  - `capstone>=5.0.0` - Multi-arch disassembler
- **GhidraMCP Server** must be running at `http://localhost:13337/mcp`
- **Compiler toolchain** - gcc or clang (for reassembly feature)
- **Ollama** (optional) - For local AI analysis without API keys

### Quick Installation
```bash
# Windows
scripts\bootstrap_windows.bat

# Linux
bash scripts/bootstrap_linux.sh

# Manual
pip install -r requirements.txt
pip install -r requirements-dev.txt  # For development tools

# For Java bytecode analysis (optional)
pip install -r requirements-java.txt
# Also download Java decompilers: CFR, Fernflower, or Procyon
# See requirements-java.txt for details
```

## Running Analysis

### Complete 8-Step Analysis
```bash
# Auto-detect binary/bytecode in current directory
python reveng_analyzer.py

# Specify binary/bytecode path
python reveng_analyzer.py path/to/binary.exe
python reveng_analyzer.py path/to/application.jar  # Java JAR files
python reveng_analyzer.py path/to/MyClass.class    # Java class files

# With specific configuration
python reveng_analyzer.py binary.exe --config .reveng/config.yaml
```

The analyzer automatically detects the file type and routes to the appropriate analysis pipeline.

This executes all 8 steps automatically:
1. **File type detection** - Auto-detect native binary vs Java bytecode vs .NET assembly
2. **AI-powered analysis** - Confidence scoring, evidence-backed claims
3. **Complete disassembly** - Routes to Ghidra (native) or Java analyzer (bytecode)
   - Native: 100+ functions via GhidraMCP
   - Java: Multi-decompiler analysis (CFR/Fernflower/Procyon)
4. **AI inspection** - Deep analysis with extra thinking
5. **Specification library** - Architecture, API, performance docs
6. **Human-readable code** - Uses human_readable_converter_fixed.py
7. **Deobfuscation** - Domain splitting (6 functional domains)
8. **Implementation** - Missing features
9. **Binary validation** - Checksum or smoke tests

### Individual Tool Usage
```bash
# Language detection
python tools/language_detector.py binary.exe
python tools/language_detector.py application.jar

# Java bytecode analysis
python tools/java_bytecode_analyzer.py MyClass.class
python tools/java_bytecode_analyzer.py application.jar

# Native binary analysis (traditional pipeline)
python tools/ai_recompiler_converter.py binary.exe
python tools/optimal_binary_analysis.py binary.exe
python tools/ai_source_inspector.py
python tools/human_readable_converter_fixed.py
python tools/deobfuscation_tool.py
python tools/implementation_tool.py
```

## Architecture

### Core Components

**reveng_analyzer.py**: Main orchestrator (renamed from universal_binary_analyzer.py) that runs the 8-step pipeline. Handles subprocess management, timeout handling (300-600s per step), Ollama preflight checks, and generates final JSON report.

**tools/**: Individual analysis tools that can be run independently:

*Multi-Language Support (NEW!):*
- `language_detector.py` - Auto-detect file types (native binaries, Java bytecode, .NET assemblies, Python bytecode)
- `java_bytecode_analyzer.py` - Java .class/.jar/.war/.ear analysis with multi-decompiler support

*Native Binary Analysis:*
- `ai_recompiler_converter.py` - AI-powered analysis with evidence-backed rename suggestions, prototype suggestions, and confidence scoring
- `optimal_binary_analysis.py` - GhidraMCP integration for comprehensive disassembly (uses all 16 MCP features)
- `ghidra_mcp_connector.py` - Python wrapper for Ghidra MCP server connectivity

*Code Processing:*
- `ai_source_inspector.py` - Deep function-level analysis with feature identification
- `human_readable_converter_fixed.py` - Source code cleanup and documentation (use this, not the deprecated version)
- `deobfuscation_tool.py` - Domain splitting (File I/O, Memory, Network, JavaScript, Utility, Error)
- `implementation_tool.py` - Auto-generates missing feature implementations

*Configuration & AI:*
- `config_manager.py` - YAML-based configuration management
- `ollama_preflight.py` - Ollama availability checker with model auto-selection
- `ollama_analyzer.py` - Local LLM-based code analysis via Ollama

### Data Flow

1. Binary → AI Recompiler → `ai_recompiler_analysis_[binary]/` (clusters, evidence, IOCs, prototypes, renames, summaries)
2. Binary → Optimal Analysis → `src_optimal_analysis_[binary]/` (30+ categorized subdirectories: functions, decompiled, imports, exports, crypto, algorithms, etc.)
3. Source → AI Inspector → `SPECS/` (7 markdown docs: overview.md, architecture.md, features.md, api.md, data_flow.md, performance.md, security.md)
4. Source → Human Readable → `human_readable_code/`
5. Code → Deobfuscation → `deobfuscated_app/` (6 domain-specific modules)
6. Gaps → Implementation → `implementations/`
7. All results → `analysis_[binary]/universal_analysis_report.json`

### GhidraMCP Integration

The system uses **all 16 GhidraMCP features** via HTTP MCP server:
- Function/class/string listing and filtering
- Decompilation and disassembly
- Cross-references (xrefs) and call graphs
- Crypto pattern detection
- Import/export analysis
- Type system (structures, enums, local types)
- Memory/data reading
- Code modification (renaming, comments, prototypes)

## Output Structure

After analysis, expect these directories:
- `analysis_[binary_name]/` - Contains final JSON report
- `ai_recompiler_analysis_[binary]/` - AI analysis artifacts (clusters/, evidence/, functions/, iocs/, prototypes/, renames/, reports/, summaries/, todos/)
- `src_optimal_analysis_[binary]/` - 30+ categorized folders (algorithms/, api_sequences/, call_graphs/, classes/, constants/, crypto/, data/, debug/, decompiled/, enums/, exports/, extensions/, functions/, headers/, imports/, main/, ...)
- `SPECS/` - 7 specification documents
- `human_readable_code/` - Cleaned source files
- `deobfuscated_app/` - Domain-organized modules
- `implementations/` - Auto-generated feature implementations

## Key Patterns

### Evidence-Based AI Analysis
The AI recompiler uses an evidence system with confidence levels (LOW=0.3, MEDIUM=0.6, HIGH=0.8, VERY_HIGH=0.95). All rename suggestions and prototype changes are backed by Evidence objects containing type, value, function address, offset, confidence, and source.

### Function Categorization
Functions are categorized into 6 domains:
- **File I/O**: file_open, file_read, file_write, file_close, file_exists, etc.
- **Memory Management**: memory_alloc, memory_free, memory_copy, memory_pool_*, etc.
- **Network Communication**: network_connect, network_send, network_recv, network_ssl_*, etc.
- **JavaScript Runtime**: js_engine_init, js_parse_script, js_execute_code, js_garbage_collect, etc.
- **Utility Functions**: parse_args, validate_input, format_output, log_activity, etc.
- **Error Handling**: handle_error, cleanup_resources, etc.

### Timeout Handling
Tools use subprocess timeouts: 300s for AI tools, 600s for disassembly. Results tracked with status: 'success', 'warning', 'error', 'timeout'.

## Configuration Management

### YAML Configuration System
Configuration is managed via `.reveng/config.yaml` with support for:
- **AI providers**: Ollama (local), Anthropic, OpenAI
- **Ghidra MCP**: Connection settings and fallback behavior
- **Validation**: Checksum vs smoke test modes
- **Compilation**: Auto-detect compiler, platform-aware builds
- **Security**: IOC defanging, security analysis settings
- **Performance**: Caching, parallel workers

### Configuration Commands
```bash
# View current config
python tools/config_manager.py show

# Set specific value
python tools/config_manager.py set ai.ollama.model deepseek-coder

# Check Ollama status and models
python tools/ollama_preflight.py

# Test Ollama analysis
python tools/ollama_analyzer.py deobfuscated_app/memory/memory_alloc.c
```

### Environment Variables
Configuration values support environment variable expansion:
- `${ANTHROPIC_API_KEY}` - Anthropic API key
- `${OPENAI_API_KEY}` - OpenAI API key

## Common Development Tasks

### Adding a New Analysis Step
1. Create tool in `tools/` following `analysis_template.py` pattern
2. Add step method in `REVENGAnalyzer` class (reveng_analyzer.py)
3. Call step method in `analyze_binary()` workflow
4. Update final report generation to include new step

### Extending GhidraMCP Features
The system queries `http://localhost:13337/mcp` endpoints. Add new feature calls in `optimal_binary_analysis.py` or use the `GhidraMCPConnector` wrapper in `tools/ghidra_mcp_connector.py` for proper connection handling and fallback logic.

### Modifying Analysis Depth
Adjust function count/depth in `optimal_binary_analysis.py:get_optimal_functions()`. Default extracts 100+ functions across 10 categories (core, JS runtime, file I/O, memory, network, crypto, utilities, string operations, threading, misc).

### Running Tests
```bash
# Run full test suite
python -m pytest tests/

# Run specific test
python tests/test_pipeline.py

# Test validation defaults
python -m pytest tests/test_pipeline.py::TestValidationDefaults -v

# Test type parser
python -m pytest tests/test_pipeline.py::TestCTypeParser -v
```

## Enhancement Tools (New!)

The system now includes professional-grade enhancement tools for code quality, type inference, and binary reassembly.

### Code Formatting
```bash
# Format generated C code with clang-format + static analysis
python tools/code_formatter.py human_readable_code/ --pattern "*.c"
```
Automatically formats C code using clang-format and runs cppcheck static analysis. Requires: `clang-format`, `cppcheck` (install via package manager).

### Type Inference
```bash
# Infer real types from Ghidra decompiler analysis
python tools/type_inference_engine.py \
    --functions analysis_droid/functions.json \
    --output typed_signatures.h
```
Extracts actual function signatures from Ghidra instead of generic `void` stubs. Generates signatures like: `int file_open(char *filename, int flags)`. Uses cross-reference analysis and pattern matching for confidence scoring.

### Binary Reassembly (CRITICAL NEW FEATURE)
```bash
# Reassemble modified C code back to executable binary
# IMPORTANT: Use binary_reassembler_v2.py (not the deprecated v1)
python tools/binary_reassembler_v2.py \
    --original droid.exe \
    --source human_readable_code/ \
    --output reassembled.exe \
    --arch auto \
    --validation-mode smoke_test
```
**This is the game-changing feature** - full binary reassembly pipeline:
- Compiles C → object files
- Links into executable
- Validates output binary
- Supports patching with LIEF library
- Multi-architecture support (x86, x86_64, ARM, ARM64)

Requires: `gcc` or `clang`, optional: `lief`, `keystone-engine` for advanced features.

### Installation
```bash
# Install all enhancement dependencies
pip install -r requirements-dev.txt
```

Includes: black, isort, pylint, lief, keystone-engine, capstone, pytest, networkx, and more.

**See detailed guides**:
- [IMPROVEMENT_ROADMAP.md](IMPROVEMENT_ROADMAP.md) - Complete enhancement roadmap with 6 phases
- [QUICK_START_IMPROVEMENTS.md](QUICK_START_IMPROVEMENTS.md) - Quick start for using new tools

## Troubleshooting

**Binary not detected**: Check file extensions (.exe, .dll, .so, .dylib, .bin, .elf) or specify full path

**GhidraMCP connection fails**: Verify Ghidra is running with MCP server on port 13337

**Analysis timeouts**: Increase timeout values in `universal_binary_analyzer.py` (currently 300-600s)

**Missing output folders**: Check logs (*.log files in root) for tool execution errors

**Java not found**: Ensure Java 21 is installed and in PATH

## Ollama AI Integration (NEW!)

The system supports local AI analysis via Ollama with automatic model selection and fallback.

### Quick Setup
```bash
# Windows: Use bootstrap script
scripts\bootstrap_windows.bat

# Linux/macOS: Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model (recommended: phi for speed, deepseek-coder for quality)
ollama pull phi
ollama pull deepseek-coder

# Configure in .reveng/config.yaml
ai:
  provider: ollama
  ollama:
    model: auto  # Auto-selects best available model

# Check Ollama status
python tools/ollama_preflight.py
```

### Supported AI Providers
1. **Ollama** (local, recommended) - No API keys, runs locally
   - Models: phi, codellama, deepseek-coder, qwen2.5-coder, llama3.1
2. **Anthropic** - Requires `ANTHROPIC_API_KEY` env var
3. **OpenAI** - Requires `OPENAI_API_KEY` env var

### Fallback Behavior
If AI is unavailable or disabled, the system falls back to heuristic-based analysis. Configure in `.reveng/config.yaml`:
```yaml
analysis:
  enable_ai: true
  fallback_to_heuristics: true
```

## Log Files

All tools generate logs in project root:
- `reveng_analyzer.log` - Main orchestrator log (renamed from universal_binary_analyzer.log)
- `ai_recompiler_converter.log` - Step 1 AI analysis
- `optimal_binary_analysis.log` - Step 2 disassembly
- `ai_source_inspector.log` - Step 3 inspection
- `human_readable_converter.log` - Step 4 conversion (use *_fixed version)
- `deobfuscation_tool.log` - Step 5 deobfuscation
- `implementation_tool.log` - Step 6 implementation

Check these first when debugging failures.

## Important File Versions

### USE THESE (Production-Ready):
- `tools/human_readable_converter_fixed.py` - Generates real implementations
- `tools/binary_reassembler_v2.py` - Working binary reassembly with validation
- `reveng_analyzer.py` - Main entry point (8-step pipeline)

### DEPRECATED (DO NOT USE):
- `deprecated_legacy/human_readable_converter.py` - Generates broken stubs
- `deprecated_legacy/binary_reassembler.py` - LIEF patching no-op bug
- `universal_binary_analyzer.py` - Renamed to reveng_analyzer.py

The deprecated versions were moved to `deprecated_legacy/` folder after critical bugs were fixed. See [CRITICAL_BUGFIXES.md](CRITICAL_BUGFIXES.md) for details on the 9 bugs resolved.

## Key Architectural Patterns

### Evidence-Based Analysis
All AI-powered rename suggestions use an Evidence system:
```python
Evidence(
    type="string_reference",
    value="opening file: %s",
    function_address=0x401000,
    offset=0x10,
    confidence=0.85,  # HIGH confidence
    source="decompiler"
)
```

### Configuration Hierarchy
1. `.reveng/config.yaml` - User configuration
2. Environment variables - API keys, overrides
3. Command-line arguments - Runtime overrides
4. Defaults - Fallback values

### Fallback Strategy
Every component has graceful degradation:
- **Ghidra unavailable** → Use fallback disassembly
- **Java decompilers unavailable** → Use javap or basic bytecode analysis
- **AI unavailable** → Use heuristic analysis
- **Validation fails** → Use checksum mode instead of smoke tests
- **Compiler missing** → Report available options

## Java Bytecode Analysis (NEW!)

The system now supports Java bytecode analysis with automatic detection and multi-decompiler support.

### Supported Java Formats
- **.class** - Individual Java class files
- **.jar** - Java archives (standard applications)
- **.war** - Web application archives
- **.ear** - Enterprise application archives

### How It Works

**1. Automatic Detection**
The language detector identifies Java files by:
- Magic bytes (`0xCAFEBABE` for .class files)
- ZIP signature + META-INF/MANIFEST.MF for JARs
- File extension (.class, .jar, .war, .ear)

**2. Multi-Decompiler Analysis**
The Java analyzer can use multiple decompilers for cross-validation:
- **CFR** (recommended) - Best for modern Java, handles lambdas well
- **Fernflower** - Included with IntelliJ, good for older Java
- **Procyon** - Excellent for Java 8+ features

**3. Obfuscation Detection**
Automatically detects common obfuscation patterns:
- ProGuard (short variable names: a, b, c)
- Allatori (control flow obfuscation)
- DexGuard (string encryption, Android-specific)

### Example Usage

```bash
# Analyze a JAR file
python reveng_analyzer.py application.jar

# Just detect file type
python tools/language_detector.py application.jar

# Direct Java analysis (skip full pipeline)
python tools/java_bytecode_analyzer.py application.jar -o java_output/

# Analyze obfuscated JAR
python tools/java_bytecode_analyzer.py obfuscated.jar
# Output will include obfuscation detection report
```

### Setup for Java Analysis

1. **Install Java dependencies:**
```bash
pip install -r requirements-java.txt
```

2. **Download decompilers** (at least one):
```bash
# Create decompilers directory
mkdir -p tools/decompilers

# Download CFR (recommended)
cd tools/decompilers
wget https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar

# Optional: Download Fernflower
wget https://github.com/fesh0r/fernflower/releases/latest/download/fernflower.jar

# Optional: Download Procyon
wget https://github.com/mstrobel/procyon/releases/latest/download/procyon-decompiler.jar
```

3. **Verify Java installation:**
```bash
java -version  # Should show Java 11 or later
javap -version  # Should be available
```

### Output Structure for Java Analysis

```
analysis_application/
├── java_analysis/
│   ├── MyClass_analysis.json
│   ├── AnotherClass_analysis.json
│   └── decompiled/
│       ├── cfr/
│       │   └── com/example/MyClass.java
│       ├── fernflower/
│       │   └── com/example/MyClass.java
│       └── procyon/
│           └── com/example/MyClass.java
└── universal_analysis_report.json
```

### Java-Specific Features

**Obfuscation Report:**
```json
{
  "class_name": "a",
  "obfuscated": true,
  "obfuscation_indicators": [
    "short_class_name",
    "short_method_names",
    "random_field_names"
  ],
  "confidence": 0.92
}
```

**Decompilation Comparison:**
- Runs multiple decompilers in parallel
- Cross-references results for accuracy
- Reports decompilation confidence scores
- Highlights inconsistencies between decompilers

### Limitations & Future Work

**Current limitations:**
- Decompilers must be downloaded manually
- No automatic deobfuscation yet (detection only)
- Limited to 100 classes per analysis (performance)

**Planned enhancements:**
- ~~Automatic deobfuscation using ML models~~ ✅ IMPLEMENTED (Phase 2 - see tools/java_ai_analyzer.py)
- Integration with Ghidra's Java support (future)
- Support for Android DEX files (future)
- ~~Maven/Gradle dependency reconstruction~~ ✅ IMPLEMENTED (Phase 3 - see tools/java_project_reconstructor.py)

---

## 🚀 Phase 3 Advanced Features (NEW!)

REVENG now includes comprehensive enterprise features implemented in Phase 3.

### Multi-Language Support

| Language | Detection | Analysis | Status |
|----------|-----------|----------|--------|
| **Java** | ✅ | ✅ Full (Phase 1) | Production |
| **C#** | ✅ | ✅ Full (Phase 3) | Production |
| **Python** | ✅ | ✅ Full (Phase 3) | Production |
| **Native** | ✅ | ✅ Ghidra | Production |

### Java Advanced Features

**Project Reconstruction** ([tools/java_project_reconstructor.py](tools/java_project_reconstructor.py))
```bash
python tools/java_project_reconstructor.py app.jar java_analysis -o reconstructed_project
cd reconstructed_project && mvn compile
```

**Advanced Deobfuscation** ([tools/java_deobfuscator_advanced.py](tools/java_deobfuscator_advanced.py))
```bash
python tools/java_deobfuscator_advanced.py decompiled_code/ -o deobfuscated/
# Applies: control flow simplification, string decryption, dead code elimination, constant folding
```

### C# IL Analysis ([tools/csharp_il_analyzer.py](tools/csharp_il_analyzer.py))

```bash
python tools/csharp_il_analyzer.py MyApp.exe -o csharp_analysis
# Outputs: IL disassembly, C# decompilation, obfuscation detection
```

**Features:**
- .NET assembly detection (CLR header check)
- ildasm IL disassembly
- ILSpy C# decompilation
- Obfuscation detection (ConfuserEx, .NET Reactor, Eazfuscator)

### Python Bytecode Analysis ([tools/python_bytecode_analyzer.py](tools/python_bytecode_analyzer.py))

```bash
python tools/python_bytecode_analyzer.py script.pyc -o python_analysis
# Auto-detects Python version (2.7-3.12), uses best decompiler
```

**Decompilers:**
- uncompyle6 (Python 2.7-3.8)
- decompyle3 (Python 3.7-3.9)
- pycdc (Python 3.10+)

### Interactive Visualizations ([tools/code_visualizer.py](tools/code_visualizer.py))

```bash
python tools/code_visualizer.py analysis_dir --type both -o visualizations
# Generates: call_graph.html (interactive), dependency_graph.html, PNG exports
```

Uses **vis.js** for interactive HTML graphs with click-to-explore functionality.

### Enterprise Audit Trail ([tools/audit_trail.py](tools/audit_trail.py))

SOC 2 / ISO 27001 compliant logging:
```python
from tools.audit_trail import AuditLogger

audit = AuditLogger()
session_id = audit.start_session(['app.jar'], ['java'])
audit.log_file_analysis('app.jar', 'java', success=True, details={})
audit.generate_report('compliance', 'compliance_report.json')
```

### Plugin System ([tools/plugin_system.py](tools/plugin_system.py))

```bash
python tools/plugin_system.py create MyPlugin --type analyzer
python tools/plugin_system.py load MyPlugin
```

### GPU Acceleration ([tools/gpu_accelerator.py](tools/gpu_accelerator.py))

```bash
python tools/gpu_accelerator.py info        # Check GPU
python tools/gpu_accelerator.py benchmark   # Run tests
```

**Backends:** CUDA, OpenCL, Metal (Apple Silicon), CPU fallback

---