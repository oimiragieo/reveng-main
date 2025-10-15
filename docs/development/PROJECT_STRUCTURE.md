# Project Structure

## Directory Layout

```
universal-binary-analyzer/
├── tools/                          # Active analysis tools (PRODUCTION READY)
│   ├── binary_reassembler_v2.py   # ✅ Use this (NOT v1!)
│   ├── human_readable_converter_fixed.py  # ✅ Use this (NOT old!)
│   ├── validation_config.py       # ✅ Configurable validation
│   ├── c_type_parser.py           # ✅ Robust type parser
│   ├── type_inference_engine.py   # ✅ Type inference
│   ├── code_formatter.py          # ✅ Code quality
│   ├── ai_recompiler_converter.py # AI-powered analysis
│   ├── optimal_binary_analysis.py # Ghidra integration
│   ├── ai_source_inspector.py     # Deep inspection
│   ├── deobfuscation_tool.py      # Domain splitting
│   └── implementation_tool.py     # Feature implementation
│
├── analysis_templates/             # Templates for custom tools
│   └── analysis_template.py
│
├── docs/                          # User documentation
│   └── README.md
│
├── deprecated_legacy/             # Archived broken versions (DO NOT USE)
│   ├── binary_reassembler.py     # ⚠️ BROKEN: No-op LIEF patching
│   └── human_readable_converter.py  # ⚠️ BROKEN: Generates stubs
│
├── logs/                          # Runtime logs (auto-generated)
│   ├── universal_binary_analyzer.log
│   ├── ai_recompiler_converter.log
│   └── *.log
│
├── outputs/                       # Analysis results (auto-generated)
│   ├── analysis_[binary]/
│   ├── src_optimal_analysis_[binary]/
│   ├── human_readable_code/
│   ├── deobfuscated_app/
│   └── SPECS/
│
├── universal_binary_analyzer.py   # Main orchestrator (7-step pipeline)
├── requirements.txt               # Python dependencies (RUNTIME)
├── requirements-dev.txt           # Development dependencies
│
├── .clang-format                  # C code formatting config
├── pyproject.toml                 # Python tool configs
├── .gitignore                     # Git ignore patterns
│
├── README.md                      # Main documentation
├── CLAUDE.md                      # AI assistant guide
├── CRITICAL_BUGFIXES.md          # Detailed bug analysis
├── BUGFIX_SUMMARY.md             # Quick reference
├── IMPROVEMENT_ROADMAP.md        # Future enhancements
├── IMPROVEMENTS_IMPLEMENTED.md   # Production features
├── EXECUTIVE_SUMMARY.md          # Business overview
├── QUICK_START_IMPROVEMENTS.md   # Enhancement guide
└── PROJECT_STRUCTURE.md          # This file
```

## Active Tools (Use These!)

### Core Pipeline
| File | Purpose | Status |
|------|---------|--------|
| `universal_binary_analyzer.py` | Main 7-step orchestrator | ✅ Active |
| `tools/ai_recompiler_converter.py` | AI analysis with evidence | ✅ Active |
| `tools/optimal_binary_analysis.py` | Ghidra disassembly | ✅ Active |
| `tools/ai_source_inspector.py` | Deep AI inspection | ✅ Active |
| `tools/deobfuscation_tool.py` | Domain splitting | ✅ Active |
| `tools/implementation_tool.py` | Feature implementation | ✅ Fixed |

### Enhancement Tools (NEW!)
| File | Purpose | Status |
|------|---------|--------|
| `tools/human_readable_converter_fixed.py` | Compilable code gen | ✅ **USE THIS** |
| `tools/binary_reassembler_v2.py` | Binary reassembly | ✅ **USE THIS** |
| `tools/validation_config.py` | Validation config | ✅ New |
| `tools/c_type_parser.py` | Type parsing | ✅ New |
| `tools/type_inference_engine.py` | Type inference | ✅ Fixed |
| `tools/code_formatter.py` | Code formatting | ✅ New |

## Deprecated Files (Archived)

**DO NOT USE THESE** - They contain critical bugs:

| File | Issue | Replacement |
|------|-------|-------------|
| `deprecated_legacy/binary_reassembler.py` | LIEF patching no-op, bad validation | `binary_reassembler_v2.py` |
| `deprecated_legacy/human_readable_converter.py` | Generates broken stubs | `human_readable_converter_fixed.py` |

## Auto-Generated Directories

These are created during analysis runs:

- **`analysis_[binary]/`** - JSON reports and metadata
- **`ai_recompiler_analysis_[binary]/`** - AI analysis artifacts
- **`src_optimal_analysis_[binary]/`** - Disassembled source (30+ categories)
- **`human_readable_code/`** - Cleaned C code
- **`deobfuscated_app/`** - Domain-organized modules
- **`SPECS/`** - Generated documentation (7 files)
- **`logs/`** - Runtime logs

## Documentation Files

| File | Purpose | Audience |
|------|---------|----------|
| `README.md` | Main project documentation | Users |
| `CLAUDE.md` | AI assistant guide | AI Assistants |
| `CRITICAL_BUGFIXES.md` | Detailed bug analysis (500+ lines) | Developers |
| `BUGFIX_SUMMARY.md` | Quick migration guide | Users |
| `IMPROVEMENT_ROADMAP.md` | 6-phase enhancement plan | Contributors |
| `IMPROVEMENTS_IMPLEMENTED.md` | Production features | Users |
| `EXECUTIVE_SUMMARY.md` | Business/ROI analysis | Stakeholders |
| `QUICK_START_IMPROVEMENTS.md` | Enhancement usage | Users |

## Configuration Files

| File | Purpose |
|------|---------|
| `.clang-format` | C/C++ code formatting (LLVM style) |
| `pyproject.toml` | Python tool configs (black, isort, pylint, pytest) |
| `.gitignore` | Git ignore patterns |
| `requirements.txt` | **Runtime** dependencies (lief, keystone, capstone) |
| `requirements-dev.txt` | Development dependencies (black, pytest, etc.) |

## Cleanup Maintenance

### Manual Cleanup
```bash
# Run cleanup script
chmod +x cleanup_project.sh
./cleanup_project.sh
```

### What Gets Cleaned
1. **Deprecated tools** → `deprecated_legacy/`
2. **Log files** → `logs/`
3. **Analysis outputs** → `outputs/`
4. **Python cache** → Deleted (`__pycache__`, `*.pyc`)

### After Cleanup
```
Project/
├── tools/              # Only active versions
├── deprecated_legacy/  # Archived broken code
├── logs/               # All .log files
├── outputs/            # All generated results
└── docs/               # Documentation
```

## File Naming Conventions

- **`*_v2.py`** - Improved version (use this over v1)
- **`*_fixed.py`** - Bug-fixed version (use this over original)
- **`*.log`** - Runtime logs (auto-generated)
- **`UPPERCASE.md`** - Important documentation
- **`lowercase.md`** - Standard documentation

## Size Reference

| Directory | Typical Size | Notes |
|-----------|-------------|-------|
| `tools/` | ~500 KB | Python source |
| `outputs/analysis_*` | 1-10 MB | Depends on binary size |
| `outputs/src_optimal_*` | 5-50 MB | 30+ subdirectories |
| `logs/` | 10-100 KB | Compressed text |
| `deprecated_legacy/` | ~50 KB | Archived once |

## Quick Commands

```bash
# Clean project
./cleanup_project.sh

# View structure
tree -L 2 -I 'outputs|logs|deprecated_legacy'

# Count active tools
ls tools/*.py | wc -l

# Check logs
tail -f logs/universal_binary_analyzer.log

# Remove all generated files
rm -rf outputs/ logs/ analysis_* src_optimal_* human_readable_code/ deobfuscated_app/ SPECS/
```

## Migration from Old Structure

If you have old project structure:

```bash
# 1. Run cleanup
./cleanup_project.sh

# 2. Update tool references
# Replace: tools/binary_reassembler.py
# With: tools/binary_reassembler_v2.py

# Replace: tools/human_readable_converter.py
# With: tools/human_readable_converter_fixed.py

# 3. Re-install dependencies
pip install -r requirements.txt

# 4. Verify
python -m compileall tools/*.py
```

## Maintenance

### Regular Tasks
- Run `cleanup_project.sh` after analysis runs
- Archive old `outputs/` periodically
- Clean `logs/` weekly
- Check `deprecated_legacy/` can be deleted after migration

### Never Delete
- `tools/` - Active code
- `*.md` documentation
- `requirements*.txt`
- Configuration files (`.clang-format`, `pyproject.toml`)

### Safe to Delete Anytime
- `logs/` - Can be regenerated
- `outputs/` - Analysis results
- `__pycache__/` - Python cache
- `*.pyc` - Compiled Python

---

**Last Updated**: After critical bug fixes (9 bugs resolved)
**Status**: Clean and organized ✅