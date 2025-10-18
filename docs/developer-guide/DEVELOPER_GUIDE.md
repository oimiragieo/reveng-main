# REVENG Developer Guide

Architecture, development workflows, and contribution guidelines.

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Core Components](#core-components)
3. [Development Setup](#development-setup)
4. [Adding New Analyzers](#adding-new-analyzers)
5. [Plugin Development](#plugin-development)
6. [Testing](#testing)
7. [Contributing](#contributing)
8. [Code Style](#code-style)

---

## Architecture Overview

REVENG follows a modular pipeline architecture with language-specific analyzers.

### High-Level Architecture

```
User Input (Binary)
    ↓
Language Detection (tools/language_detector.py)
    ↓
Main Pipeline (reveng_analyzer.py)
    ↓
    ├── Java Analyzer (tools/java_bytecode_analyzer.py)
    ├── C# Analyzer (tools/csharp_il_analyzer.py)
    ├── Python Analyzer (tools/python_bytecode_analyzer.py)
    └── Native Analyzer (Ghidra MCP)
    ↓
Deobfuscation & Enhancement
    ├── Advanced Deobfuscator
    ├── AI Analyzer
    └── Project Reconstructor
    ↓
Visualization & Reporting
    ├── Call Graph Generator
    ├── Audit Logger
    └── Report Generator
    ↓
Output (JSON, Markdown, Visualizations)
```

### Key Design Principles

1. **Modularity**: Each analyzer is self-contained
2. **Graceful Degradation**: Fallbacks when tools unavailable
3. **Confidence Scoring**: All detections scored 0.0-1.0
4. **Extensibility**: Plugin system for custom analyzers
5. **Comprehensive Logging**: Debug logs for all operations

---

## Core Components

### Main Pipeline (`reveng_analyzer.py`)

Central orchestrator that:
- Detects file type
- Routes to appropriate analyzer
- Manages 7-step analysis workflow
- Generates final report
- Handles audit logging

**Key methods**:
- `_step1_file_detection()` - Language detection
- `_step2_disassembly()` - Routing to analyzers
- `_java_disassembly()` - Java analysis
- `_csharp_disassembly()` - C# analysis
- `_python_disassembly()` - Python analysis
- `_native_disassembly()` - Native binary analysis

### Language Detector (`tools/language_detector.py`)

Detects file type using:
- Magic bytes (first 4 bytes)
- File structure analysis
- Archive inspection (ZIP for JAR)
- Extension hints

**Returns**:
```python
FileTypeInfo(
    language='java',
    format='jar',
    confidence=1.0,
    architecture=None,
    metadata={...}
)
```

### Java Bytecode Analyzer (`tools/java_bytecode_analyzer.py`)

Decompiles Java bytecode with:
- CFR (default)
- Fernflower
- Procyon
- Cross-validation

**Key features**:
- JAR extraction
- Multi-decompiler execution
- Obfuscation detection
- Result merging

### C# IL Analyzer (`tools/csharp_il_analyzer.py`)

Analyzes .NET assemblies with:
- ildasm (IL disassembly)
- ILSpy (C# decompilation)
- Obfuscation detection

**Key features**:
- CLR header detection
- IL code extraction
- C# source reconstruction
- .csproj generation

### Python Bytecode Analyzer (`tools/python_bytecode_analyzer.py`)

Decompiles Python bytecode with:
- uncompyle6 (Python 2.7-3.8)
- decompyle3 (Python 3.7-3.8)
- pycdc (Python 2.x-3.11)

**Key features**:
- Version detection via magic numbers
- Decompiler selection
- Obfuscation detection (PyArmor, Nuitka)

### AI Analyzer (`tools/java_ai_analyzer.py`)

Enhances analysis with LLMs:
- Ollama integration
- Anthropic/OpenAI APIs
- Security analysis
- Name suggestions

**Key features**:
- Batch processing
- Confidence scoring
- Multi-provider support
- Graceful fallback

### Project Reconstructor (`tools/java_project_reconstructor.py`)

Rebuilds project structure:
- Maven/Gradle generation
- Package inference
- Dependency detection
- Resource organization

### Advanced Deobfuscator (`tools/java_deobfuscator_advanced.py`)

Deobfuscation techniques:
- Control flow simplification
- String decryption (Base64, XOR)
- Dead code elimination
- Constant folding

### Code Visualizer (`tools/code_visualizer.py`)

Generates visualizations:
- Interactive HTML (vis.js)
- Static PNG (Graphviz)
- JSON export

### Audit Logger (`tools/audit_trail.py`)

Enterprise logging:
- Session tracking
- Event logging (JSONL)
- Security events
- Compliance reporting

### Plugin System (`tools/plugin_system.py`)

Extensible architecture:
- Plugin discovery
- Lifecycle management
- Hook system
- Template generation

---

## Development Setup

### Prerequisites

- Python 3.8+
- Java 21 (64-bit)
- Ghidra with GhidraMCP
- Git

### Installation

```bash
# Clone repository
git clone <repo-url>
cd droid-main

# Install dependencies
pip install -r requirements.txt

# Set up configuration
cp .reveng/config.yaml.example .reveng/config.yaml
# Edit config.yaml with your settings

# Verify setup
python reveng_analyzer.py --help
```

### Development Dependencies

```bash
pip install -r requirements-dev.txt
```

Includes:
- pytest (testing)
- black (code formatting)
- pylint (linting)
- mypy (type checking)

---

## Adding New Analyzers

### Step 1: Create Analyzer Class

Create `tools/mylang_analyzer.py`:

```python
from pathlib import Path
from dataclasses import dataclass
from typing import Dict, Any

@dataclass
class MyLangAnalysisResult:
    success: bool
    output_file: str
    metadata: Dict[str, Any]
    error: str = None

class MyLangAnalyzer:
    def __init__(self, output_dir: str = "mylang_analysis"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze(self, file_path: str) -> MyLangAnalysisResult:
        """Analyze MyLang file"""
        try:
            # 1. Validate file
            if not self._is_mylang_file(file_path):
                return MyLangAnalysisResult(
                    success=False,
                    output_file="",
                    metadata={},
                    error="Not a MyLang file"
                )

            # 2. Perform analysis
            result = self._run_analysis(file_path)

            # 3. Return result
            return MyLangAnalysisResult(
                success=True,
                output_file=str(self.output_dir / "output.txt"),
                metadata={'version': result.version}
            )
        except Exception as e:
            return MyLangAnalysisResult(
                success=False,
                output_file="",
                metadata={},
                error=str(e)
            )

    def _is_mylang_file(self, file_path: str) -> bool:
        """Check if file is MyLang"""
        # Check magic bytes, extension, etc.
        return file_path.endswith('.mylang')

    def _run_analysis(self, file_path: str):
        """Run actual analysis"""
        # Implement analysis logic
        pass
```

### Step 2: Add Language Detection

Update `tools/language_detector.py`:

```python
def detect_mylang(self, file_path: str) -> Optional[FileTypeInfo]:
    """Detect MyLang files"""
    with open(file_path, 'rb') as f:
        magic = f.read(4)

    if magic == b'MLNG':  # MyLang magic bytes
        return FileTypeInfo(
            language='mylang',
            format='mylang',
            confidence=1.0,
            architecture=None,
            metadata={'version': 'unknown'}
        )
    return None

# Add to detect() method:
result = self.detect_mylang(file_path)
if result:
    return result
```

### Step 3: Add Pipeline Routing

Update `reveng_analyzer.py`:

```python
def _step2_disassembly(self):
    """Route to appropriate analyzer"""
    if self.file_type and self.file_type.language == 'mylang':
        logger.info("MyLang file detected - using MyLang analyzer")
        return self._mylang_disassembly()
    # ... existing routing ...

def _mylang_disassembly(self):
    """Disassembly for MyLang files"""
    logger.info("Running MyLang analysis")
    try:
        from tools.mylang_analyzer import MyLangAnalyzer
        analyzer = MyLangAnalyzer(
            output_dir=str(self.analysis_folder / "mylang_analysis")
        )
        result = analyzer.analyze(self.binary_path)

        logger.info(f"MyLang analysis completed - success: {result.success}")

        self.results['step2'] = {
            'status': 'success' if result.success else 'error',
            'mode': 'mylang',
            'output_file': result.output_file,
            'metadata': result.metadata
        }
    except ImportError as e:
        logger.error(f"MyLang analyzer not available: {e}")
        self.results['step2'] = {
            'status': 'error',
            'error': 'mylang_analyzer_not_found'
        }
```

### Step 4: Add Tests

Create `tests/test_mylang_analyzer.py`:

```python
import pytest
from tools.mylang_analyzer import MyLangAnalyzer

def test_mylang_detection():
    analyzer = MyLangAnalyzer()
    result = analyzer.analyze("test_files/sample.mylang")
    assert result.success

def test_mylang_invalid_file():
    analyzer = MyLangAnalyzer()
    result = analyzer.analyze("test_files/invalid.txt")
    assert not result.success
```

### Step 5: Add Documentation

Create `docs/MYLANG_ANALYSIS.md` documenting:
- Supported versions
- Analysis features
- Output format
- Usage examples

---

## Plugin Development

### Generate Plugin Template

```bash
python tools/plugin_system.py generate my_plugin
```

### Plugin Structure

```python
# plugins/my_plugin/plugin.py

class MyPlugin:
    """Custom analyzer plugin"""

    def __init__(self):
        self.name = "my_plugin"
        self.version = "1.0.0"

    def on_load(self):
        """Called when plugin loads"""
        print(f"{self.name} loaded")

    def on_unload(self):
        """Called when plugin unloads"""
        print(f"{self.name} unloaded")

    def pre_analysis(self, file_path: str) -> dict:
        """Hook: Before analysis starts"""
        return {'modified_path': file_path}

    def post_analysis(self, results: dict) -> dict:
        """Hook: After analysis completes"""
        results['my_plugin_data'] = "custom data"
        return results
```

### Plugin Metadata

```yaml
# plugins/my_plugin/plugin.yaml
name: my_plugin
version: 1.0.0
author: Your Name
description: Custom analyzer for special files
entry_point: plugin.MyPlugin

hooks:
  - pre_analysis
  - post_analysis

dependencies:
  - requests>=2.28.0
  - custom_lib>=1.0.0
```

### Register Plugin

```python
from tools.plugin_system import PluginManager

pm = PluginManager()
pm.load_plugin("my_plugin")

# Trigger hooks
pm.trigger_hook("pre_analysis", file_path="test.bin")
```

---

## Testing

### Run All Tests

```bash
pytest tests/
```

### Run Specific Test

```bash
pytest tests/test_java_bytecode_analyzer.py
```

### Test Coverage

```bash
pytest --cov=tools tests/
```

### Test Structure

```
tests/
├── test_language_detector.py
├── test_java_bytecode_analyzer.py
├── test_csharp_il_analyzer.py
├── test_python_bytecode_analyzer.py
├── test_reveng_analyzer.py
└── test_files/
    ├── sample.jar
    ├── sample.exe (.NET)
    └── sample.pyc
```

---

## Contributing

### Workflow

1. Fork repository
2. Create feature branch: `git checkout -b feature/my-feature`
3. Make changes
4. Add tests
5. Run linting: `pylint tools/`
6. Run tests: `pytest`
7. Commit: `git commit -m "Add my feature"`
8. Push: `git push origin feature/my-feature`
9. Create pull request

### Code Review Checklist

- [ ] Code follows style guide
- [ ] Tests added and passing
- [ ] Documentation updated
- [ ] No breaking changes (or documented)
- [ ] Logging added for key operations
- [ ] Error handling implemented
- [ ] Graceful fallbacks provided

---

## Code Style

### Python Style Guide

- Follow PEP 8
- Use type hints
- Document all public methods
- Keep functions focused (<50 lines)
- Use descriptive variable names

### Example

```python
from typing import Optional, Dict, Any
from dataclasses import dataclass

@dataclass
class AnalysisResult:
    """Result of binary analysis"""
    success: bool
    output_path: str
    metadata: Dict[str, Any]
    error: Optional[str] = None

def analyze_file(file_path: str, options: Dict[str, Any]) -> AnalysisResult:
    """
    Analyze binary file

    Args:
        file_path: Path to binary file
        options: Analysis options

    Returns:
        AnalysisResult with success status and metadata

    Raises:
        FileNotFoundError: If file doesn't exist
    """
    try:
        # Implementation
        return AnalysisResult(
            success=True,
            output_path="/output/path",
            metadata={'version': '1.0'}
        )
    except Exception as e:
        return AnalysisResult(
            success=False,
            output_path="",
            metadata={},
            error=str(e)
        )
```

### Logging Style

```python
import logging

logger = logging.getLogger(__name__)

# Info for normal operations
logger.info("Starting analysis of file.jar")

# Debug for detailed info
logger.debug(f"Using decompiler: {decompiler_name}")

# Warning for non-critical issues
logger.warning("Optional decompiler not available, using fallback")

# Error for failures
logger.error(f"Analysis failed: {error_message}")
```

---

## Architecture Decisions

### Why Modular Analyzers?

- **Maintainability**: Each analyzer isolated
- **Testability**: Easy to unit test
- **Extensibility**: Add new languages without touching existing code
- **Reusability**: Analyzers usable standalone

### Why Multiple Decompilers?

- **Accuracy**: Cross-validation improves results
- **Coverage**: Different decompilers handle different patterns
- **Robustness**: Fallback if one fails

### Why Confidence Scoring?

- **Transparency**: User knows detection reliability
- **Decision Making**: Can filter low-confidence results
- **Metrics**: Track accuracy over time

### Why Plugin System?

- **Extensibility**: Users can add custom analyzers
- **Flexibility**: No need to modify core code
- **Community**: Enable community contributions

---

For usage instructions, see [User Guide](USER_GUIDE.md)
For implementation history, see [Implementation Guide](IMPLEMENTATION.md)
