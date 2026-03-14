# Architecture Overview

REVENG is a Python package centered on `REVENGAnalyzer`, the CLI in `reveng.cli`, and a set of analysis subsystems that can be used directly or through MCP.

## Entry Points

- `src/reveng/cli.py` — command-line interface exposed as `reveng`
- `src/reveng/analyzer.py` — high-level analysis orchestrator
- `src/reveng/api.py` — structured programmatic API
- `src/reveng/ai_api.py` — AI-oriented convenience API
- `src/reveng/agent_sdk/mcp/` — MCP server and agent-facing tooling

## Runtime Flow

```text
CLI / Python API / MCP client
            |
            v
      REVENGAnalyzer
            |
            +--> file detection and environment checks
            +--> decompilation / reconstruction tooling
            +--> security and malware analysis
            +--> reporting and output artifacts
```

The analyzer writes outputs to `analysis_<binary-name>/` unless a custom directory is supplied.

## Package Map

The top-level package is broad, but most work falls into a few stable groups:

| Area | Purpose |
| --- | --- |
| `analyzer.py`, `cli.py`, `api.py`, `ai_api.py` | Public entry points |
| `core/` | shared exceptions, logging, validation, utilities |
| `integrations/ghidra/` and `server/` | Ghidra clients plus local HTTP server support |
| `pipeline/`, `pipelines/` | orchestration and pipeline definitions |
| `security/`, `malware/`, `ml/` | vulnerability analysis, behavioral forensics, anomaly models |
| `diffing/`, `compilation/`, `deobfuscation/`, `devirtualization/` | binary transformation and reconstruction workflows |
| `reporting/` | rendered reports and visualization helpers |
| `plugins/` | plugin base classes and manager utilities |
| `javascript/` | JavaScript deobfuscation and malware analysis |

## Analyzer Responsibilities

`REVENGAnalyzer` is responsible for:

1. locating or validating the target binary
2. creating the output directory
3. detecting file type and optional capabilities
4. coordinating decompilation, enrichment, and analysis steps
5. recording structured results and progress events

Feature flags are carried by `EnhancedAnalysisFeatures`, which can disable optional corporate exposure, vulnerability, threat-intelligence, reconstruction, or demonstration stages.

## Ghidra Integration

Native reconstruction flows depend on the local Ghidra HTTP server in `external/ghidra-server/ghidra_http_server.py`.

- Default URL: `http://127.0.0.1:13370`
- Client modules: `src/reveng/integrations/ghidra/`
- CLI commands that benefit most: `analyze`, `decompile`, `recompile`

When Ghidra is unavailable, REVENG is designed to fail fast for Ghidra-dependent operations instead of silently inventing results.

## Pipeline Notes

The repository contains both `pipeline/` and `pipelines/` packages. In practice, the important design constraints are:

- explicit dependencies between stages
- structured dictionaries exchanged between stages
- graceful handling of optional capabilities
- output directories that preserve intermediate artifacts for later inspection

## Outputs

A typical run emits some combination of:

- structured JSON summaries
- decompiled or reconstructed source files
- reports and visualizations
- audit logs
- analysis subdirectories for follow-on tooling

For command-level usage, see [CLI Usage](../user-guide/cli-usage.md). For development workflows, see [Developer Guide](../developer-guide/DEVELOPER_GUIDE.md).
