# Advanced Examples Directory

## Overview

The `examples/advanced/` directory contains advanced REVENG examples demonstrating sophisticated features like binary reconstruction, AI integration, and automated feedback loops.

**Purpose**: Showcase advanced REVENG capabilities for experienced users.

**Location**: `/home/user/reveng-main/examples/advanced/`

## Directory Contents

```
advanced/
├── claude.md                          # This file
├── README.md                          # Advanced examples guide (8,455 bytes)
├── full_recompilation_demo.py         # Complete recompilation pipeline (9,854 bytes)
├── gemini_feedback_demo.py            # Gemini feedback loop (3,326 bytes)
└── v4_0_features_demo.py              # v4.0 features demo (16,561 bytes)
```

## Key Files

### Full Recompilation Demo

**full_recompilation_demo.py** (9,854 bytes)
- Demonstrates complete binary reconstruction pipeline
- Binary → Decompilation → AI Enhancement → Recompilation
- Includes vulnerability analysis and exploit generation
- Shows behavioral validation

**Features Demonstrated:**
- Ghidra decompilation integration
- Gemini AI code enhancement
- GCC/Clang recompilation
- Binary equivalence testing
- Security vulnerability detection
- Automated exploit generation

### Gemini Feedback Demo

**gemini_feedback_demo.py** (3,326 bytes)
- Demonstrates self-improving AI system
- Continuous codebase analysis
- Automated improvement suggestions
- Bug detection and fixes

**Features Demonstrated:**
- Gemini feedback loop
- Codebase self-analysis
- Improvement tracking
- Automated reporting

### v4.0 Features Demo

**v4_0_features_demo.py** (16,561 bytes)
- Comprehensive showcase of v4.0 features
- Advanced ML integration
- Enhanced analysis capabilities
- Performance optimizations

**Features Demonstrated:**
- ML-powered analysis
- Advanced decompilation
- Enhanced security analysis
- API improvements

## Usage

### Prerequisites

```bash
# Ensure all dependencies installed
pip install -r requirements.txt

# Set up API keys
export GEMINI_API_KEY="your-key-here"

# Start Ghidra server (for recompilation demo)
cd external/ghidra-server
python ghidra_http_server.py &
```

### Running Examples

```bash
# Full recompilation pipeline
python examples/advanced/full_recompilation_demo.py

# With custom binary
python examples/advanced/full_recompilation_demo.py --binary /path/to/binary.exe

# Gemini feedback loop
python examples/advanced/gemini_feedback_demo.py

# v4.0 features showcase
python examples/advanced/v4_0_features_demo.py
```

### Expected Output

Each example generates comprehensive output:
- **Console logs**: Real-time progress
- **Analysis reports**: Detailed findings
- **Source code**: Decompiled and enhanced code
- **Recompiled binaries**: GCC/Clang output
- **Validation results**: Equivalence testing
- **Exploits**: PoC exploit code (when applicable)

## Related Documentation
- `docs/guides/REBUILD_WORKFLOW_EXAMPLE.md` - Detailed rebuild workflow
- `docs/guides/ai-enhancements.md` - AI enhancement guide
- `docs/api/AI_API_REFERENCE.md` - AI API documentation

## Notes

### Performance Considerations
- Full recompilation can take 3-5 minutes for large binaries
- Requires 2GB+ RAM for complex binaries
- GPU acceleration available for ML operations
- Network connection required for AI APIs

### Security Notice
- Examples generate working exploits for demonstration
- Only use on authorized binaries
- Follow responsible disclosure practices
- See SECURITY.md for guidelines

---

**Target Audience**: Advanced users, researchers, developers
**Prerequisites**: REVENG setup, AI API keys, Ghidra server
**Execution Time**: 3-10 minutes per example
