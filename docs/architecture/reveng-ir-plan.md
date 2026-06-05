# REVENG IR Plan

This document defines the shared intermediate representation (IR) that will connect the three benchmark classes in this repo:

- Claude: bundled JavaScript / Node applications
- Droid: native bundled executables analyzed through Ghidra and native pipelines
- Codex/Cursor-style apps: packaged agent runtimes with service, tool, and storage graphs

## Goals

- Create one graph model for recovered entities and relationships.
- Keep adapter-specific extraction separate from shared scoring and provenance.
- Let benchmarks, scorecards, and CI gates operate on the same output shape.

## IR Shape

- `project`: one root node per analyzed target
- `domain`: high-level architectural slices such as `cli`, `auth`, `mcp`, `session`
- `dependency`: package or binary dependency
- `cli_flag`: command-line flags
- `slash_command`: slash command or tool-like command surface
- `endpoint`: URLs or transport endpoints

Relationships:

- `contains`
- `depends_on`
- `exposes`
- `connects_to`

## Phase Order

1. JS bundle workflow emits `project_ir.json`
2. Native/Ghidra workflow emits the same IR
3. Packaged-runtime adapter emits the same IR
4. Benchmarks score IR overlap, not just files on disk

## Current Status

- Shared IR models exist in `src/reveng/ir.py`
- JavaScript bundle workflow emits `artifacts/project_ir.json`
- Claude benchmark can now produce scored domain reconstruction plus IR
- Native app workflow now targets the same `artifacts/project_ir.json` contract

## Native Workflow Notes

- Treat Ghidra as the primary analysis database for native IR export.
- Keep `capa` and `FLOSS` as additive post-processing steps, not replacements for Ghidra output.
- Prefer bounded headless or service-backed execution with explicit timeouts and serialized artifacts:
  - `artifacts/ghidra_analysis.json`
  - `artifacts/decompiled_functions/`
  - `artifacts/project_ir.json`
  - optional enrichment artifacts such as `artifacts/capa.json` and `artifacts/floss.json`
