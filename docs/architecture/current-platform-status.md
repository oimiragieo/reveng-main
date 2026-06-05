# Current Platform Status

## Purpose

This document is a verification-first snapshot of what this checkout appears to support today. It is intended to counter stale release-note drift and product-brochure wording.

## Verified local facts

- Repository package version file currently says `4.0.0`.
- Package metadata currently presents the project as `beta`, not production-stable.
- The repository is large: a local count over `src/` and `tests/` Python files in this checkout is about `122,757` lines.
- The main CLI, package entrypoints, and a broad subsystem layout are real.
- The app reverse-engineering framework currently has working adapters for:
  - JavaScript bundles
  - JVM inputs
  - Python source, bytecode, zipapp, and PyInstaller-like frozen executables
  - .NET assemblies

## Real versus experimental

### Real foundations

- CLI and Python package structure
- Ghidra integration points
- MCP server surface
- YARA and malware-analysis related modules
- multiple language-specific analyzer/helper modules
- adapter-driven app reverse-engineering workflow with `SPECS` output

### Experimental or uneven areas

- exploit generation quality and reliability
- symbolic execution integration depth
- broad JavaScript deobfuscation completeness claims
- binary-to-source-to-binary equivalence claims
- production-readiness claims for the entire stack

## Guidance for shipping

If a release must be prepared in the next 24 hours:

- ship the CLI and adapter framework as the primary supported workflow
- describe advanced analysis, exploit, and deep deobfuscation paths as experimental
- tie every product claim to tests, tracked reports, or reproducible artifacts
- avoid language like `production-ready`, `world-class`, or `working exploits` unless the specific workflow is benchmarked and passing

## Follow-on work

- expand tracked corpus validation
- add unified validation/evidence fields to app-level outputs
- wire the adapter framework into MCP/API under the same contract
- keep top-level documentation synchronized with the verified state above
