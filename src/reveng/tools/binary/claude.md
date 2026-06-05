# `claude.md` — `tools/binary`

**Repository path:** `src/reveng/tools/binary/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Binary Processing Tools

### `binary_diff.py`
- **Summary:** REVENG Binary Diff Tool
- **Classes:**
  - `BinaryDiff` — Compare binaries at multiple levels

### `c_implementation_generator.py`
- **Summary:** REVENG C Implementation Generator
- **Classes:**
  - `CImplementationGenerator` — Generate C implementations from specifications

### `check_toolchain.py`
- **Summary:** REVENG Toolchain Checker
- **Classes:**
  - `Colors`
  - `ToolchainChecker` — Check for required REVENG toolchain components
- **Functions / coroutines:**
  - `def main()` — Main entry point

### `validation_config.py`
- **Summary:** Binary Validation Configuration
- **Classes:**
  - `ValidationMode` — Validation strategies
  - `SmokeTest` — Smoke test configuration
  - `ValidationConfig` — Binary validation configuration
  - `ValidationResult` — Versioned validation result contract.
  - `BinaryValidator` — Configurable binary validator

### `validation_manifest_loader.py`
- **Summary:** REVENG Validation Manifest Loader
- **Classes:**
  - `ValidationManifestLoader` — Load validation manifests from YAML/JSON
- **Functions / coroutines:**
  - `def load_validation_manifest()` — Load validation config from manifest file.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
