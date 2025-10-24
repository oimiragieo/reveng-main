# Package Map

This table highlights the primary Python packages exposed by the REVENG source tree after the structural refactor.

| Package | Purpose | Key Modules |
| --- | --- | --- |
| `reveng.analyzer` | Legacy orchestrator class, progressively delegating to `reveng.pipeline` helpers. | `REVENGAnalyzer` |
| `reveng.pipeline` | Shared context objects and step implementations. | `steps.vulnerability`, `steps.threat_intel`, `pipeline_engine` |
| `reveng.agents` | AI-facing utilities and orchestration layers. | `ai.ai_enhanced_analyzer`, `ai.instant_triage`, `ai.nl_interface` |
| `reveng.security` | Security analytics, ML classifiers, and correlators. | `ml_malware_classifier`, `threat_intelligence_correlator`, `vulnerability_discovery_engine` |
| `reveng.reporting` | Visual and executive reporting engines. | `visualization.code_visualizer`, `visualization.executive_reporting_engine` |
| `reveng.integrations` | External service connectors (Ghidra MCP, HTTP clients). | `ghidra.ghidra_mcp_connector`, `ghidra.ghidra_http_client` |
| `reveng.tools` | Compatibility shim exposing the historic wildcard namespace. | `__getattr__` lazy registry |

Supporting directories:

- `ops/scripts/` — project automation (test runner, release helpers).
- `reports/security/` — generated audit artefacts stored alongside the repo.
- `docs/history/` — archived programme reports migrated from the repository root.

Refer to [`docs/developer-guide/architecture.md`](../developer-guide/architecture.md) for lower-level diagrams and class relationships.
