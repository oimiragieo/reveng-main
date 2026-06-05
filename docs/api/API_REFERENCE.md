# REVENG API Reference

This page keeps the stable Python-facing APIs in one place. It replaces the older split between the generic API doc and the AI API doc.

## Core API

## Public Imports

```python
from reveng import REVENGAnalyzer, analyze_binary, detect_malware, reconstruct_binary
from reveng.api import REVENGAPI
from reveng.ai_api import REVENG_AI_API
```

## `REVENGAnalyzer`

`REVENGAnalyzer` is the low-level orchestrator used by the CLI and higher-level APIs.

```python
from reveng.analyzer import EnhancedAnalysisFeatures, REVENGAnalyzer

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

- `analyze_binary()` -> run the main analysis flow
- `get_capabilities()` -> return agent-friendly capability metadata

### Feature flags

`EnhancedAnalysisFeatures` exposes these toggles:

- `enable_enhanced_analysis`
- `enable_corporate_exposure`
- `enable_vulnerability_discovery`
- `enable_threat_intelligence`
- `enable_enhanced_reconstruction`
- `enable_demonstration_generation`

## `REVENGAPI`

`REVENGAPI` is the main structured Python API for scripts and integrations.

```python
from reveng.api import REVENGAPI

api = REVENGAPI(config={"max_file_size_mb": 500})
result = api.analyze_binary("sample.exe", enhanced=True)
```

### Methods

- `analyze_binary(binary_path, enhanced=False, modules=None)`
- `reconstruct_binary(binary_path, output_format="c")`
- `detect_malware(binary_path)`
- `reverse_engineer_app(input_path, language="auto", output_dir=None, **options)`

### Convenience functions

The package also exposes script-friendly helpers with the same names:

```python
from reveng import analyze_binary, detect_malware, reconstruct_binary
```

## Tool APIs

## `REVENG_AI_API`

`REVENG_AI_API` is the agent-oriented facade that returns structured dataclasses for triage and natural-language workflows.

```python
from reveng.ai_api import REVENG_AI_API

ai = REVENG_AI_API(use_ollama=True, ollama_model="auto")
triage = ai.triage_binary("sample.exe")
answer = ai.ask("What does this binary do?", "sample.exe")
```

### Methods

- `triage_binary(binary_path, include_reasoning=True)`
- `ask(question, binary_path=None, analysis_results=None, conversational=False)`
- `get_crypto_details(binary_path)`
- `get_network_details(binary_path)`
- `get_translation_hints(source_path)`
- `analyze_binary(binary_path, mode=...)`
- `explain_binary(binary_path, detail_level="standard")`
- `find_vulnerabilities(binary_path, vulnerability_types=None)`

### Common dataclasses

- `TriageResponse`
- `AskResponse`
- `AnalysisSummary`
- `CapabilityReport`

## Example: script-friendly analysis

```python
from reveng.api import REVENGAPI

api = REVENGAPI()
result = api.analyze_binary("sample.exe", enhanced=True)

print(result.summary["file_type"])
print(result.summary["imports_count"])
```

## Example: AI-first workflow

```python
from reveng.ai_api import REVENG_AI_API

ai = REVENG_AI_API(use_ollama=True, ollama_model="auto")
triage = ai.triage_binary("sample.exe")

if triage.is_malicious:
    print(triage.threat_level, triage.threat_score)

response = ai.ask("Summarize the network behavior", "sample.exe")
print(response)
```

## Web Interface API

The CLI exposes a `serve` command for the local web interface. Internal server and MCP entry points live under `src/reveng/server/` and `src/reveng/agent_sdk/`. Treat those modules as implementation details unless you are working directly inside the repository.

## Notes

- The Python APIs are the most stable integration surface in this repository.
- CLI workflows are documented in [CLI Usage](../user-guide/cli-usage.md).
- Internal server endpoints and experimental modules change more often; inspect the current source before building against them directly.
