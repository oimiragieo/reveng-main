# `claude.md` — `javascript`

**Repository path:** `src/reveng/javascript/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** REVENG v6.0 - JavaScript Deobfuscation & Decompilation

### `babel_transformer.py`
- **Summary:** Babel AST Transformation Engine
- **Classes:**
  - `TransformResult` — Result from AST transformation
  - `BabelTransformer` — JavaScript AST transformer using Python
  - `CFGUnflattener` — Control Flow Graph unflattening
  - `StringArrayDeobfuscator` — String array deobfuscation

### `bundle_reverse_engineer.py`
- **Summary:** Bundle-oriented JavaScript reverse engineering workflow.
- **Classes:**
  - `BundleReverseEngineeringResult` — Structured output from the bundle reverse-engineering workflow.
  - `JavaScriptBundleReverseEngineer` — Reverse engineer a bundled JavaScript application into specs and domain files.

### `cache_system.py`
- **Summary:** Intelligent Caching System for JavaScript Deobfuscation
- **Classes:**
  - `CacheEntry` — A cache entry
  - `DeobfuscationCache` — LRU cache for deobfuscation results

### `cli.py`
- **Summary:** REVENG JavaScript CLI.
- **Classes:**
  - `CLI` — Command-line interface for JavaScript workflows.
- **Functions / coroutines:**
  - `async def main()` — Async entry point used by tests and wrappers.
  - `def console_main()` — Synchronous console entry point.

### `deobfuscator.py`
- **Summary:** JavaScript Deobfuscation Engine
- **Classes:**
  - `ObfuscationType` — Types of JavaScript obfuscation
  - `DeobfuscationStage` — Stages in the deobfuscation pipeline
  - `DeobfuscationResult` — Result from JavaScript deobfuscation
  - `JavaScriptDeobfuscator` — Comprehensive JavaScript deobfuscation pipeline

### `detectors.py`
- **Summary:** JavaScript Obfuscation Detection
- **Classes:**
  - `DetectionResult` — Result from obfuscation detection
  - `ObfuscationDetector` — Detects JavaScript obfuscation types

### `malware_detector.py`
- **Summary:** JavaScript Malware Detection Engine
- **Classes:**
  - `ThreatLevel` — Threat severity levels
  - `ThreatCategory` — Categories of threats
  - `ThreatIndicator` — A detected threat indicator
  - `MalwareAnalysisResult` — Result from malware analysis
  - `MalwareDetector` — JavaScript malware detection engine
  - `VulnerabilityScanner` — Scans JavaScript code for common vulnerabilities

### `source_map_recoverer.py`
- **Summary:** Source Map Recovery
- **Classes:**
  - `SourceMapResult` — Result from source map recovery
  - `SourceMapRecoverer` — Recover original source from webpack/browserify source maps

## Other files in this folder

- `README.md`

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
