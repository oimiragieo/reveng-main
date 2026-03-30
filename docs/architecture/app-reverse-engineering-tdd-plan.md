# App Reverse Engineering TDD Plan

## Purpose

This plan turns the new multi-language app reverse-engineering framework into a TDD-driven delivery track with explicit research-backed batches.

It is narrower than the full world-class platform roadmap. It focuses on the `reverse-engineer-app` framework and the language adapters that feed it.

## Research anchors

- Python stdlib docs support `dis`, `marshal`, `zipapp`, and importlib magic-number inspection for bytecode and archive analysis.
- PyInstaller docs confirm one-file bundles unpack to temporary `_MEI*` directories at runtime and that `pyi-archive_viewer` is the supported archive inspection tool.
- GitHub ecosystem signal points to `pyinstxtractor` and `pyinstxtractor-ng` as the common extractor family for PyInstaller archives.
- GitHub ecosystem signal for .NET still centers on `ILSpy`/`ilspycmd`, with `dnlib` and dnSpyEx as complementary tooling.
- Recent arXiv work such as DecompileBench and PCodeTrans reinforces that benchmarked validation and compilable/equivalent outputs matter more than readable pseudocode alone.

## Operating rules

1. Write failing tests for each adapter capability before implementation.
2. Prefer stdlib or first-party tooling first; use optional external tools as enhancements, not hard requirements.
3. Every adapter must emit the same normalized contract: `SPECS`, `analysis.json`, primary artifacts, provenance-friendly metadata.
4. Auto-detection should be conservative. Wrong routing is worse than requiring an explicit `--language`.
5. Extraction claims must degrade honestly when tooling is unavailable.

## Milestone batches

### Batch A: framework baseline

- Gate: parser, routing, normalized result contract, and JS/JVM/Python source flows are green.
- Tests:
  - framework unit tests
  - CLI parser and routing tests
  - one live CLI smoke test per stable adapter

### Batch B: Python packaging depth

- Gate: `.py`, `.pyc`, `.pyz`, and PyInstaller-like executables are covered.
- Tests first:
  - current-interpreter `.pyc` detection
  - zipapp extraction
  - PyInstaller marker detection and packaging-aware reporting
  - graceful behavior when `pyi-archive_viewer` is missing
- Implementation:
  - stdlib bytecode recovery
  - zipapp extraction
  - PyInstaller marker scan and optional archive-viewer integration

### Batch C: .NET adapter

- Gate: `.dll`/`.exe` assemblies produce `SPECS`, assembly metadata, IL/decompiled artifacts when available, and honest fallback warnings when `ilspycmd` is absent.
- Tests first:
  - assembly detection
  - metadata extraction
  - IL/decompiled artifact handling with and without external tools

### Batch D: corpus and evidence

- Gate: every adapter has at least one synthetic fixture and one real sample; reports expose validation grade and artifact references.
- Tests first:
  - adapter metadata round-tripping
  - evidence/artifact references in outputs
  - corpus-row preservation in benchmark metadata

### Batch E: product integration

- Gate: main CLI, API, and MCP share one framework path and one result vocabulary.
- Tests first:
  - CLI, API, and MCP contract parity
  - failure-path provenance
  - no-regression corpus smoke runs

## Current completion

- Batch A: complete for the current CLI/framework path
- Batch B: complete for source, bytecode, zipapp, and PyInstaller-like packaging analysis, including `pyi-archive_viewer` tool-state reporting and extractor-assisted Python entry recovery when available
- Batch C: complete for baseline `.NET` metadata, IL, fallback-report coverage, explicit ildasm/ILSpy tool-state reporting, and normalized ILSpy decompiled-project metadata
- Batch D: substantially complete; shared validation grade, evidence, provenance, corpus rollup reporting, and a checked-in smoke corpus now ship in machine-readable outputs across all current adapters across source plus packaged/compiled fixture shapes, but broader real-world sample coverage is still missing
- Batch E: substantially complete; CLI, API, MCP single-entry runs, plus manifest-driven API/MCP corpus execution and integration smoke coverage, now share one framework path and one result vocabulary for app reverse engineering

## Immediate next execution order

1. Replace synthetic or toy anchors with broader real-world corpus entries where the checkout can legally and reproducibly carry them.
2. Promote the environment-aware external-tool integrations (`ilspycmd`, `pyi-archive_viewer`) into CI jobs that install those tools and execute the real paths instead of skipping.
3. Replace synthetic anchors with broader real-sample anchors where the checkout can legally and reproducibly carry them.
4. Add environment-aware integration smoke coverage for external-tool-assisted paths such as `ilspycmd` and `pyi-archive_viewer`.
