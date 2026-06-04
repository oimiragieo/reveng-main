# `claude.md` — `compilation`

**Repository path:** `src/reveng/compilation/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** REVENG v4.0 - Advanced Compilation Module

### `incremental_compiler.py`
- **Summary:** Incremental Compilation with Intelligent Caching
- **Classes:**
  - `CompileResult` — Result of compilation operation
  - `BuildManifest` — Manifest tracking build state for incremental builds
  - `CompilationResult` — Compatibility result for the legacy single-file compilation API.
  - `CacheStats` — Compiler cache statistics for compatibility with legacy callers.
  - `DependencyGraph` — Dependency graph for tracking file dependencies
  - `IncrementalCompiler` — Incremental compilation with intelligent caching
  - `DistributedCompiler` — Distributed compilation across multiple machines

### `llvm_optimizer.py`
- **Summary:** LLVM Optimization Pipeline for Maximum Accuracy
- **Classes:**
  - `CompileResult` — Result of LLVM compilation
  - `LLVMOptimizationPipeline` — LLVM-based compilation for maximum accuracy
  - `PGOCompiler` — Profile-Guided Optimization for maximum performance

### `smart_compiler.py`
- **Summary:** Smart Compiler with AI-Powered Error Recovery
- **Classes:**
  - `CompileError` — Represents a compilation error
  - `CompileResult` — Result of compilation with error recovery
  - `SmartCompiler` — Self-healing compiler with automatic error recovery

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
