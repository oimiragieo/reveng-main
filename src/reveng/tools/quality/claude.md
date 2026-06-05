# `claude.md` — `tools/quality`

**Repository path:** `src/reveng/tools/quality/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Code Quality Tools

### `c_type_parser.py`
- **Summary:** C Type Parser
- **Classes:**
  - `CType` — Parsed C type
  - `CParameter` — Function parameter with type and name
  - `CFunctionSignature` — Complete function signature
  - `CTypeParser` — Robust C type parser

### `code_formatter.py`
- **Summary:** Code Formatter Tool
- **Classes:**
  - `CodeFormatter` — Code Formatter Tool
- **Functions / coroutines:**
  - `def main()` — Main function

### `compilation_tester.py`
- **Summary:** REVENG Compilation Tester
- **Classes:**
  - `CompilationTester` — Test compilation of generated C code

### `type_inference_engine.py`
- **Summary:** Type Inference Engine
- **Classes:**
  - `TypeCategory` — Type categories
  - `Parameter` — Function parameter with inferred type
  - `FunctionSignature` — Complete function signature with types
  - `TypeInferenceEngine` — Type Inference Engine
- **Functions / coroutines:**
  - `def main()` — Main function

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
