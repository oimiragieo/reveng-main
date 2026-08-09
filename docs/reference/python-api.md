# Reference: Python API

> **Maturity:** preview · method availability ≠ GA — match [support matrix](../support/support-matrix.md)
>
> Canonical façade: `REVENGAPI` in `src/reveng/api.py`

## Correct imports

```python
from reveng.api import REVENGAPI
from reveng.analysis.analyzer import EnhancedAnalysisFeatures, REVENGAnalyzer
from reveng.ai_api import REVENG_AI_API
```

| Correct | Incorrect / dead |
| --- | --- |
| `reveng.analysis.analyzer` | `reveng.analyzer` |
| `reveng.cli` package | `src/reveng/cli.py` |

Package-level lazy exports also work:

```python
from reveng import REVENGAPI, REVENGAnalyzer, analyze_binary, detect_malware, reconstruct_binary
```

## `REVENGAPI`

```python
from reveng.api import REVENGAPI

api = REVENGAPI(config={"max_file_size_mb": 500})
result = api.analyze_binary("sample.exe", enhanced=False)
```

### Methods (inspect source for signatures)

| Method | Role | Maturity note |
| --- | --- | --- |
| `analyze_binary(path, enhanced=False, modules=None)` | Structured analysis contract | preview; native often Ghidra-limited |
| `reconstruct_binary(path, output_format="c")` | Reconstruction helper | managed vs native — see matrix |
| `detect_malware(path)` | Threat classification via ML helpers | preview; not the same as core MCP `detect_malware` |
| `reverse_engineer_app(...)` | App RE → same contract as CLI/MCP | **supported** for JS/JVM/Python/.NET |
| `run_app_reverse_engineering_corpus(...)` | Manifest corpus rollup | honesty / gate tooling |

Module-level helpers wrap the same class: `analyze_binary`, `detect_malware`, `reconstruct_binary`, `reverse_engineer_app`.

Returns are contract-shaped dicts (`AnalysisResultContract`, etc.) with provenance fields — prefer those over invented confidence narratives. Example docstrings in `api.py` may show illustrative `confidence` values; treat them as schema examples, not measured rates.

## `REVENGAnalyzer`

Lower-level orchestrator used by CLI and APIs:

```python
from reveng.analysis.analyzer import EnhancedAnalysisFeatures, REVENGAnalyzer

features = EnhancedAnalysisFeatures()
analyzer = REVENGAnalyzer(
    binary_path="sample.exe",
    check_ollama=True,
    enhanced_features=features,
    analysis_folder="analysis_sample",
)
summary = analyzer.analyze_binary()
```

## `REVENG_AI_API`

Agent-oriented helpers (`triage_binary`, `ask`, …) in `src/reveng/ai_api.py`. Requires a configured provider (Ollama / API keys). Preview maturity.

## Honesty

- Prefer reading returned `status` / validation / evidence fields over assuming success from “no exception.”
- Core MCP `detect_malware` with `type=binary` returns **unsupported** — do not document API + MCP as equivalent for that path.
- Exploit generation is **experimental** on CLI; do not market API wrappers as production exploit tooling.

## Related

- [Result contracts](../explanation/result-contracts.md)
- Legacy consolidated page: [API_REFERENCE.md](../api/API_REFERENCE.md) (kept for navigation; prefer this reference)
- [CLI reference](cli.md)
