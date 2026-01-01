# Advanced Examples

This directory contains advanced examples demonstrating REVENG's powerful features.

## Available Examples

### full_recompilation_demo.py
**Purpose**: Demonstrate complete binary-to-binary reconstruction pipeline

**Features**:
- Binary decompilation using Ghidra
- AI-powered code enhancement with Gemini
- Recompilation with GCC/Clang
- Behavioral validation

**Prerequisites**:
- Ghidra server running (port 13370)
- GCC compiler installed
- GEMINI_API_KEY environment variable set

**Usage**:
```bash
python examples/advanced/full_recompilation_demo.py --binary <path-to-binary>
```

---

### v4_0_features_demo.py
**Purpose**: Showcase v4.0 Enterprise AI Tool Suite features

**Features**:
- Incremental compilation (ccache/sccache)
- Smart compiler with AI error recovery
- GPU acceleration framework
- LLM4Decompile integration
- Symbolic execution engine
- LLVM binary lifting

**Prerequisites**:
- Optional: `tqdm` for progress bars (`pip install tqdm`)
- Optional: `networkx` for semantic diffing (`pip install networkx`)
- Optional: GPU support (CUDA/ROCm/MPS)

**Usage**:
```bash
python examples/advanced/v4_0_features_demo.py
```

**Note**: Some demos require optional dependencies. The script will skip features with missing dependencies gracefully.

---

### gemini_feedback_demo.py
**Purpose**: Demonstrate Gemini AI feedback loop for continuous improvement

**Features**:
- Self-improving codebase analysis
- AI-powered bug detection
- Feature suggestions
- Progress tracking

**Prerequisites**:
- GEMINI_API_KEY environment variable set

**Usage**:
```bash
export GEMINI_API_KEY="your-api-key"
python examples/advanced/gemini_feedback_demo.py
```

---

## Quick Start

1. **Prerequisites**: Complete basic examples first
2. **Configuration**: Set up required API keys and services
3. **Run examples**: Start with `gemini_feedback_demo.py` (simplest setup)

## Learning Path

### Step 1: Gemini Feedback Loop
1. Study `gemini_feedback_demo.py`
2. Understand AI self-improvement concepts
3. Run with your own projects

### Step 2: Full Recompilation
1. Set up Ghidra server
2. Study `full_recompilation_demo.py`
3. Try with different binary types

### Step 3: v4.0 Features
1. Review `v4_0_features_demo.py`
2. Install optional dependencies as needed
3. Experiment with GPU acceleration

## Code Patterns

### Custom Analyzers

```python
from reveng.analyzer import REVENGAnalyzer

class MyCustomAnalyzer(REVENGAnalyzer):
    def __init__(self, binary_path):
        super().__init__(binary_path)
        self.custom_config = {
            'timeout': 600,
            'max_functions': 1000,
            'enable_ai': True
        }

    def custom_analysis(self):
        """Custom analysis logic"""
        # Your custom analysis here
        pass
```

### Batch Processing

```python
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from reveng.analyzer import REVENGAnalyzer

class BatchProcessor:
    def __init__(self, input_dir, output_dir):
        self.input_dir = Path(input_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

    def process_binary(self, binary_path):
        """Process single binary"""
        try:
            analyzer = REVENGAnalyzer(str(binary_path))
            success = analyzer.analyze_binary()
            return f"{'OK' if success else 'FAIL'}: {binary_path.name}"
        except Exception as e:
            return f"ERROR: {binary_path.name}: {e}"

    def process_all(self, max_workers=4):
        """Process all binaries in parallel"""
        binary_files = list(self.input_dir.glob("*.exe")) + \
                      list(self.input_dir.glob("*.jar"))

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = list(executor.map(self.process_binary, binary_files))

        return results
```

## Troubleshooting

### Common Issues

1. **Ghidra Server Not Running**:
   ```bash
   cd external/ghidra-server
   python ghidra_http_server.py
   ```

2. **Missing API Key**:
   ```bash
   export GEMINI_API_KEY="your-api-key"
   ```

3. **Memory Issues**:
   ```bash
   # Reduce max_functions for large binaries
   python examples/advanced/full_recompilation_demo.py --max-functions 100
   ```

### Debug Mode

```bash
# Enable debug logging
python examples/advanced/full_recompilation_demo.py --debug

# Verbose output
python examples/advanced/v4_0_features_demo.py --verbose
```

## Related Documentation

- **[Main Examples README](../README.md)** - All examples overview
- **[Basic Examples](../basic/README.md)** - Basic usage examples
- **[Installation Guide](../../INSTALLATION.md)** - Setup instructions
- **[API Reference](../../docs/api/API_REFERENCE.md)** - Python API

---

**Advanced Examples** - Master REVENG's powerful v4.0 Enterprise features
