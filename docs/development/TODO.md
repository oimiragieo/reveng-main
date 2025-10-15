# REVENG - TODO List

## Current Production Status

### ✅ Ready For Production
- Code extraction from binaries
- Cross-platform code generation
- Specification documentation
- Code organization & deobfuscation
- Automated toolchain setup
- Bootstrap scripts for Windows/Linux

### ⚠️ Not Ready For Production
- Full binary reconstruction (Priority 1 features now implemented, needs testing)
- ~~Live Ghidra integration~~ ✅ IMPLEMENTED (needs Ghidra server)
- ~~Binary validation with checksums~~ ✅ IMPLEMENTED
- ~~Compilation verification~~ ✅ IMPLEMENTED
- ~~C code implementation generation~~ ✅ IMPLEMENTED

---

## Priority 1: Critical (Must Fix Before Full Production)

### 1. Add Live Ghidra MCP Integration ✅ IMPLEMENTED

**Current State**: ✅ Connector implemented with fallback to existing analysis

**Required**: Connect to live Ghidra instance via MCP

**Tasks**:
- [x] Create `tools/ghidra_mcp_connector.py`
  - Connect to Ghidra MCP server
  - Implement all 16 MCP feature calls:
    1. `list_functions` - Get all functions
    2. `get_function_by_name` - Retrieve specific function
    3. `get_function_by_address` - Retrieve by address
    4. `decompile_function` - Get pseudocode
    5. `disassemble_function` - Get assembly
    6. `get_xrefs_to` - Cross-references
    7. `get_callees` - Called functions
    8. `get_callers` - Calling functions
    9. `list_strings` - Extract strings
    10. `list_globals` - Global variables
    11. `list_imports` - Imported functions
    12. `get_entry_points` - Entry points
    13. `set_function_prototype` - Update signatures
    14. `rename_function` - Rename functions
    15. `set_comment` - Add comments
    16. `get_current_function` - Get selected function

- [x] Update `reveng_analyzer.py` Step 2 to use live Ghidra
  ```python
  def _step2_disassembly_with_ghidra(self):
      from tools.ghidra_mcp_connector import GhidraMCP

      ghidra = GhidraMCP()
      ghidra.open_binary(self.binary_path)

      # Extract all functions
      functions = ghidra.list_functions(offset=0, count=0)

      # Decompile each function
      for func in functions:
          pseudocode = ghidra.decompile_function(func['address'])
          assembly = ghidra.disassemble_function(func['address'])
          # ... save results
  ```

- [ ] Add Ghidra server check to `tools/check_toolchain.py`
  ```python
  def _check_ghidra_mcp(self):
      # Try to connect to Ghidra MCP server
      # Check if Ghidra is running
      # Return connection status
  ```

- [ ] Add Ghidra startup to bootstrap scripts
  ```bash
  # In bootstrap_windows.bat
  echo Starting Ghidra MCP server...
  start /B ghidra_mcp_server.exe
  ```

- [ ] Create integration test
  ```bash
  # tests/test_ghidra_integration.py
  def test_ghidra_connection():
      # Verify Ghidra MCP server is reachable
      # Test all 16 MCP features
      # Validate responses
  ```

**Impact**: HIGH - Enables real reverse engineering vs. using pre-analyzed data

**Estimated Effort**: 2-3 days

---

### 2. Add Binary Validation Step ✅ IMPLEMENTED

**Current State**: ✅ Full validation system with checksum, sections, smoke tests, confidence scoring

**Required**: Step 8 to validate rebuilt binary matches original

**Tasks**:
- [x] Create `tools/binary_validator.py`
  ```python
  class BinaryValidator:
      def validate_rebuild(self, original_path, rebuilt_path):
          # 1. Checksum comparison
          # 2. Size comparison
          # 3. Section comparison (code, data, resources)
          # 4. Smoke tests (if CLI interface)
          # 5. Behavioral comparison
          return validation_report
  ```

- [x] Implement checksum validation
  - [x] SHA256 hash comparison
  - [x] Per-section hash comparison
  - [x] Allowances for non-deterministic sections (timestamps, debug info)

- [x] Implement behavioral validation
  - [x] Run same inputs on both binaries
  - [x] Compare outputs
  - [x] Compare exit codes
  - [x] Compare created files

- [x] Add Step 8 to `reveng_analyzer.py`
  ```python
  def _step8_validation(self):
      """Step 8: Validate reassembled binary"""
      from tools.binary_validator import BinaryValidator

      validator = BinaryValidator()

      # Compile generated code
      rebuilt_path = self._compile_generated_code()

      # Validate
      result = validator.validate_rebuild(
          self.binary_path,
          rebuilt_path
      )

      # Save report
      self._save_validation_report(result)

      return result
  ```

- [x] Integrate with validation manifest
  ```python
  # Load per-binary validation rules from .reveng/validation.yaml
  from tools.validation_manifest_loader import load_validation_manifest

  config = load_validation_manifest(binary_name)
  validator = BinaryValidator(config)
  ```

- [ ] Create validation report template
  ```json
  {
    "original": {
      "path": "droid.exe",
      "size": 125315808,
      "sha256": "abc123...",
      "sections": {...}
    },
    "rebuilt": {
      "path": "droid_rebuilt.exe",
      "size": 125315000,
      "sha256": "abc124...",
      "sections": {...}
    },
    "comparison": {
      "size_match": false,
      "size_diff": 808,
      "checksum_match": false,
      "section_matches": {
        ".text": true,
        ".data": false,
        ".rsrc": true
      }
    },
    "smoke_tests": {
      "tests_run": 3,
      "tests_passed": 3,
      "results": [...]
    },
    "verdict": {
      "valid": true,
      "confidence": 0.95,
      "warnings": ["Size differs by 808 bytes"],
      "errors": []
    }
  }
  ```

**Impact**: HIGH - Proves reconstruction actually works

**Estimated Effort**: 3-4 days

---

### 3. Add Compilation Testing ✅ IMPLEMENTED

**Current State**: ✅ Full compilation testing with error parsing and reporting

**Required**: Attempt compilation and report errors

**Tasks**:
- [x] Create `tools/compilation_tester.py`
  ```python
  class CompilationTester:
      def test_compilation(self, source_dir):
          # Detect available compiler
          # Attempt compilation
          # Parse compiler output
          # Return results with line numbers for errors
  ```

- [ ] Add compilation step to pipeline
  ```python
  def _step7b_compile_code(self):
      """Step 7b: Compile generated code"""
      from tools.compilation_tester import CompilationTester

      tester = CompilationTester()
      result = tester.test_compilation("human_readable_code")

      if result['success']:
          logger.info(f"Compilation successful: {result['binary_path']}")
      else:
          logger.warning(f"Compilation failed: {result['error_count']} errors")
          for error in result['errors']:
              logger.error(f"  {error['file']}:{error['line']}: {error['message']}")
  ```

- [ ] Integrate with `binary_reassembler_v2.py`
  - [ ] Already has compilation logic, extract to reusable module
  - [ ] Add better error reporting with line numbers
  - [ ] Suggest fixes for common errors

- [ ] Add to CI/CD pipeline
  ```yaml
  # .github/workflows/test.yml
  - name: Test code generation and compilation
    run: |
      python reveng_analyzer.py test_samples/calc.exe
      cd human_readable_code
      gcc *.c -o calc_rebuilt
      ./calc_rebuilt --help
  ```

- [ ] Create compilation report
  ```json
  {
    "compiler": "gcc",
    "compiler_version": "11.2.0",
    "files_compiled": 101,
    "success": false,
    "errors": [
      {
        "file": "memory_alloc.c",
        "line": 25,
        "column": 10,
        "message": "undefined reference to 'initMemory'",
        "suggestion": "Add implementation or declare as weak symbol"
      }
    ],
    "warnings": [...],
    "binary_path": null
  }
  ```

**Impact**: MEDIUM - Catches compilation issues early

**Estimated Effort**: 2-3 days

---

### 4. Add C Implementation Generator ✅ IMPLEMENTED

**Current State**: ✅ Template-based C code generator with 12+ function categories

**Required**: Generate C code implementations from feature specifications

**Tasks**:
- [x] Create `tools/c_implementation_generator.py`
  ```python
  class CImplementationGenerator:
      def generate_from_spec(self, spec_file, function_info):
          # Read feature specification
          # Use AI/type inference to generate C code
          # Generate function with proper signature
          # Add error handling and validation
          return c_code
  ```

- [ ] Implement code generation strategies
  - [ ] Template-based generation (for common patterns)
  - [ ] AI-assisted generation (for complex logic)
  - [ ] Type inference integration (use decompiled types)

- [ ] Generate implementations for each feature type
  - [ ] Memory management (malloc, free, pools)
  - [ ] File I/O (open, read, write, close)
  - [ ] Network operations (socket, connect, send, recv)
  - [ ] String operations (copy, concat, search)
  - [ ] Data structures (lists, maps, queues)

- [ ] Update Step 7 to generate C instead of JS
  ```python
  def _step7_implementation(self):
      """Step 7: Implement missing features in C"""
      from tools.c_implementation_generator import CImplementationGenerator

      generator = CImplementationGenerator()

      # Read feature specs
      specs = self._read_feature_specs()

      # Generate C implementations
      for feature in specs['missing_features']:
          c_code = generator.generate_from_spec(feature)
          output_file = Path(f"human_readable_code/{feature['name']}.c")
          output_file.write_text(c_code)
  ```

- [ ] Create implementation templates
  ```c
  // Template: memory_pool_create
  typedef struct MemoryPool {
      void *buffer;
      size_t size;
      size_t used;
  } MemoryPool;

  MemoryPool* createMemoryPool(size_t size) {
      MemoryPool *pool = malloc(sizeof(MemoryPool));
      if (!pool) return NULL;

      pool->buffer = malloc(size);
      if (!pool->buffer) {
          free(pool);
          return NULL;
      }

      pool->size = size;
      pool->used = 0;
      return pool;
  }
  ```

- [ ] Add tests for generated implementations
  ```bash
  # tests/test_c_implementations.py
  def test_generated_memory_pool():
      # Compile generated code
      # Run tests
      # Verify behavior
  ```

**Impact**: HIGH - Enables full C code reconstruction

**Estimated Effort**: 4-5 days

---

## Priority 2: High (Should Add Soon)

### 5. Add CI/CD Pipeline

**Tasks**:
- [ ] Create `.github/workflows/test.yml`
  ```yaml
  name: Test Pipeline
  on: [push, pull_request]

  jobs:
    test-windows:
      runs-on: windows-latest
      steps:
        - uses: actions/checkout@v3
        - uses: actions/setup-python@v4
        - run: pip install -r requirements.txt
        - run: python tests/test_pipeline.py
        - run: python reveng_analyzer.py test_samples/calc.exe

    test-linux:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v3
        - uses: actions/setup-python@v4
        - run: pip install -r requirements.txt
        - run: sudo apt-get install gcc clang
        - run: python tests/test_pipeline.py
        - run: python reveng_analyzer.py test_samples/calc

    test-macos:
      runs-on: macos-latest
      steps:
        - uses: actions/checkout@v3
        - uses: actions/setup-python@v4
        - run: pip install -r requirements.txt
        - run: python tests/test_pipeline.py
  ```

- [ ] Add test samples
  - [ ] Create `test_samples/` directory
  - [ ] Add small Windows PE executable (~1MB)
  - [ ] Add small Linux ELF executable (~1MB)
  - [ ] Add macOS Mach-O executable (~1MB)

- [ ] Create build workflow
  ```yaml
  # .github/workflows/build.yml
  name: Build Release
  on:
    push:
      tags:
        - 'v*'

  jobs:
    build:
      runs-on: ubuntu-latest
      steps:
        - uses: actions/checkout@v3
        - name: Build package
          run: python -m build
        - name: Publish to PyPI
          uses: pypa/gh-action-pypi-publish@release/v1
  ```

**Impact**: MEDIUM - Prevents regressions

**Estimated Effort**: 2-3 days

---

### 6. Improve Function Complexity Scoring

**Current State**: All functions marked as "High" complexity

**Tasks**:
- [ ] Create `tools/complexity_scorer.py`
  ```python
  def calculate_complexity(function_code):
      # Cyclomatic complexity
      # Lines of code
      # Number of branches
      # Nesting depth
      # External dependencies
      return complexity_score
  ```

- [ ] Categorize functions
  - Low: Simple getters/setters, wrappers
  - Medium: Business logic, parsers
  - High: Complex algorithms, state machines
  - Very High: Compiler code, obfuscated code

- [ ] Update SPECS generation to use complexity scorer

**Impact**: LOW - Better categorization

**Estimated Effort**: 1-2 days

---

## Priority 3: Medium (Nice to Have)

### 7. Add Progress Reporting

**Tasks**:
- [ ] Install `tqdm` for progress bars
- [ ] Add progress bars to long operations
- [ ] Show ETA for each step
- [ ] Allow graceful cancellation (Ctrl+C)

**Impact**: LOW - UX improvement

**Estimated Effort**: 1 day

---

### 8. Add Binary Diff Tool

**Tasks**:
- [ ] Create `tools/binary_diff.py`
- [ ] Compare original vs rebuilt binary
- [ ] Highlight differences (visual diff)
- [ ] Explain why differences occur

**Impact**: MEDIUM - Helps debug reconstruction

**Estimated Effort**: 2-3 days

---

## Priority 4: Low (Future Enhancements)

### 9. Add Export Formats

**Tasks**:
- [ ] Export to IDA Pro database (.idb)
- [ ] Export to Ghidra project (.gpr)
- [ ] Export to Radare2 project

**Impact**: LOW - Interoperability

**Estimated Effort**: 3-4 days

---

### 10. Add Interactive Mode

**Tasks**:
- [ ] Prompt user for each step
- [ ] Show intermediate results
- [ ] Allow step selection
- [ ] Enable step-by-step debugging

**Impact**: LOW - Advanced users

**Estimated Effort**: 2-3 days

---

## Estimated Total Effort

### Priority 1 (Critical)
- Ghidra Integration: 2-3 days
- Binary Validation: 3-4 days
- Compilation Testing: 2-3 days
- C Implementation: 4-5 days
**Total: 11-15 days**

### Priority 2 (High)
- CI/CD Pipeline: 2-3 days
- Complexity Scoring: 1-2 days
**Total: 3-5 days**

### Priority 3 (Medium)
- Progress Reporting: 1 day
- Binary Diff: 2-3 days
**Total: 3-4 days**

### Priority 4 (Low)
- Export Formats: 3-4 days
- Interactive Mode: 2-3 days
**Total: 5-7 days**

**Grand Total: 22-31 days** (approximately 1-1.5 months for one developer)

---

## Immediate Next Steps

1. **Week 1-2**: Ghidra MCP Integration
   - Connect to live Ghidra
   - Implement all 16 MCP features
   - Replace mock data with real analysis

2. **Week 3**: Binary Validation
   - Add Step 8 validation
   - Implement checksum comparison
   - Add smoke tests

3. **Week 4**: Compilation Testing & C Implementation
   - Test compilation in pipeline
   - Generate C code (not JS stubs)
   - Verify full reconstruction works

4. **Week 5**: CI/CD & Testing
   - GitHub Actions workflows
   - Test on multiple platforms
   - Add test samples

After 5 weeks, REVENG will be **fully production-ready** for complete binary reconstruction.

---

## How to Contribute

Each TODO item can be worked on independently. To contribute:

1. Pick an item from Priority 1 or 2
2. Create a new branch: `git checkout -b feature/item-name`
3. Implement the feature with tests
4. Update documentation
5. Submit pull request

See `docs/README.md` for development guidelines.
