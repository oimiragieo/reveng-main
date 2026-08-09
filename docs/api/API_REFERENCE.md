# REVENG API Reference

> **Maturity:** preview · prefer [Python API reference](../reference/python-api.md) for the maintained index
>
> Match method claims to [support matrix](../support/support-matrix.md). No invented success %.

This page keeps stable Python-facing APIs in one place. Correct analyzer import: **`reveng.analysis.analyzer`** (not `reveng.analyzer`).

## Public imports

```python
from reveng import REVENGAnalyzer, analyze_binary, detect_malware, reconstruct_binary
from reveng.api import REVENGAPI
from reveng.analysis.analyzer import EnhancedAnalysisFeatures, REVENGAnalyzer
from reveng.ai_api import REVENG_AI_API
```

## `REVENGAnalyzer`

Low-level orchestrator used by the CLI and higher-level APIs.

```python
from reveng.analysis.analyzer import EnhancedAnalysisFeatures, REVENGAnalyzer

features = EnhancedAnalysisFeatures()
features.enable_vulnerability_discovery = True

analyzer = REVENGAnalyzer(
    binary_path="sample.exe",
    check_ollama=True,
    enhanced_features=features,
    analysis_folder="analysis_sample",
)
summary = analyzer.analyze_binary()
```

### Constructor

```python
REVENGAnalyzer(
    binary_path: str | None = None,
    check_ollama: bool = True,
    enhanced_features: EnhancedAnalysisFeatures | None = None,
    progress_callback: Callable[[str, dict], None] | None = None,
    analysis_folder: str | None = None,
)
```

### Useful methods

- `analyze_binary()` — main analysis flow (preview; native often Ghidra-limited)
- `get_capabilities()` — agent-friendly capability metadata

### Feature flags

`EnhancedAnalysisFeatures` toggles:

- `enable_enhanced_analysis`
- `enable_corporate_exposure`
- `enable_vulnerability_discovery`
- `enable_threat_intelligence`
- `enable_enhanced_reconstruction`
- `enable_demonstration_generation`

## `REVENGAPI`

Structured API for scripts and integrations (`src/reveng/api.py`).

```python
from reveng.api import REVENGAPI

api = REVENGAPI(config={"max_file_size_mb": 500})
result = api.analyze_binary("sample.exe", enhanced=True)
# result is a contract-shaped dict — read status / provenance fields
```

### Methods

| Method | Maturity note |
| --- | --- |
| `analyze_binary(...)` | preview; native limited without Ghidra |
| `reconstruct_binary(...)` | managed vs native — see matrix |
| `detect_malware(...)` | preview; **not** the same as core MCP binary detect (unsupported there) |
| `reverse_engineer_app(...)` | **supported** for JS/JVM/Python/.NET |
| `run_app_reverse_engineering_corpus(...)` | honesty / corpus tooling |

Convenience helpers: `from reveng import analyze_binary, detect_malware, reconstruct_binary`.

## `REVENG_AI_API`

Agent-oriented façade (`src/reveng/ai_api.py`). Preview; needs Ollama or cloud keys.

```python
from reveng.ai_api import REVENG_AI_API

ai = REVENG_AI_API(use_ollama=True, ollama_model="auto")
triage = ai.triage_binary("sample.exe")
answer = ai.ask("What does this binary do?", "sample.exe")
```

Methods include `triage_binary`, `ask`, `get_crypto_details`, `get_network_details`, `analyze_binary`, `explain_binary`, `find_vulnerabilities` (symbolic/vuln paths remain **experimental** where matrix says so).

## Example: script-friendly analysis

```python
from reveng.api import REVENGAPI

api = REVENGAPI()
result = api.analyze_binary("sample.exe", enhanced=False)

print(result.get("binary"))
print(result.get("classification"))
print(result.get("confidence"))  # schema field — not a marketed accuracy rate
```

## Example: app reverse engineering (supported)

```python
from reveng.api import REVENGAPI

api = REVENGAPI()
meta = api.reverse_engineer_app("app.jar", language="jvm")
```

## Web / MCP

- CLI `serve` starts the local web UI when web extras are installed.
- MCP tools: [reference/mcp-tools.md](../reference/mcp-tools.md) — preview, not production-ready.
- Exploit generation remains **experimental** on CLI; do not document as GA API.

## Notes

- Prefer [reference/python-api.md](../reference/python-api.md) when linking from new docs.
- CLI: [reference/cli.md](../reference/cli.md).
- Inspect current source before building against internal server modules.
