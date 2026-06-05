# Support Matrix

This page defines the current customer-facing support boundary for REVENG.

## Supported

### CLI threat triage

- Surface: CLI
- Platforms: Windows, Linux, macOS
- Scope: basic triage and reporting flows that do not depend on deep reconstruction

### App reverse engineering

- Surfaces: CLI, API, MCP
- Languages: JavaScript, JVM, Python, .NET
- Scope: adapter-driven `reverse-engineer-app` workflows with `SPECS`, `analysis.json`, validation, evidence, and provenance
- Notes:
  - packaged and compiled input shapes are covered by the tracked app corpus
  - optional external tools such as `ilspycmd` and `pyi-archive_viewer` improve recovery quality when present

## Limited Support

### Ghidra-backed native analysis

- Surfaces: CLI, API, MCP
- Platforms: primarily Windows and Linux
- Notes:
  - requires external Ghidra setup
  - not all native reconstruction paths meet GA-level evidence and performance gates today

## Experimental

### Exploit generation

- Status: experimental
- Reason: current output quality and validation are not sufficient for GA claims

### Symbolic execution workflows

- Status: experimental
- Reason: integration depth and customer-facing reliability are still uneven

## Source of Truth

The machine-readable source of truth for this page is:

- `docs/support_matrix.json`

Release gates should use that file rather than scraping this Markdown page.
