# AI providers

> **Maturity:** AI is **optional** for many triage / app RE paths · providers are integrations, not a GA capability by themselves
>
> Prefer matrix language over “AI-powered” marketing. See [maturity badges](../support/maturity-badges.md) and [honesty rules](../support/honesty-rules.md).

LLM-backed analysis lives primarily under `src/reveng/agents/ai/`. Shared AI **data models** that security also needs live in `reveng.core.ai_models` so `reveng.security` never imports this package ([Architecture overview](architecture-overview.md), `.importlinter`).

## Provider registry

Module: `src/reveng/agents/ai/ai_provider_registry.py`

Factory: **`get_analyzer(provider=None)`**

Resolution order:

1. `provider` argument to `get_analyzer()`
2. `REVENG_AI_PROVIDER` environment variable
3. `config.yaml` `ai.provider`
4. Default: **`ollama`**

| Provider key | Implementation | Notes |
| --- | --- | --- |
| `ollama` | `ollama_analyzer.py` — `OllamaAnalyzer` | Local / free default; optional if daemon absent |
| `anthropic` | `anthropic_analyzer.py` — `AnthropicAnalyzer` | Cloud API |
| `openai` | `openai_analyzer.py` — `OpenAIAnalyzer` | Cloud API |
| `claude-cli` | `claude_cli_analyzer.py` — `ClaudeCodeCLIAnalyzer` | Shells out to `claude -p` (aliases: `claude_code`, `claude-code`, `claude_cli`) |

Breadcrumb: `src/reveng/agents/ai/claude.md`.

Related helpers:

- `ollama_preflight.py` — `OllamaPreflightChecker`
- `ai_enhanced_orchestrator.py` — `AIEnhancedAnalyzer` for enhanced binary modules
- VRL runner honors `REVENG_AI_PROVIDER` in `scripts/run_vrl.py` ([VRL and verification](vrl-and-verification.md))

## `enable_ai` gates

AI is gated at the analyzer surface, not only by provider availability.

`REVENGAnalyzer` (`src/reveng/analysis/analyzer.py`):

- Constructor flag `enable_ai: bool = True`
- When `False`:
  - Steps 1 and 3 are skipped (`reason: enable_ai_false`)
  - Enhanced AI feature flags are forced off
  - Ollama preflight is suppressed (`effective_check_ollama = enable_ai and check_ollama`)

MCP enterprise path threads the same knob (`enable_ai` tool arg → `REVENGAnalyzer(..., enable_ai=...)`) — see `reveng_enterprise_server.py` and `tests/unit/test_mcp_enterprise_knobs.py`. Silently ignoring `enable_ai` is a contract bug.

## Optional Ollama

Ollama is the **default** provider but not a hard dependency for every command:

- Import / preflight failures fall back to heuristics or skipped AI steps depending on the path
- App RE adapters do not require an LLM to produce SPECS / analysis.json
- Docs must not claim “requires Ollama” for supported app RE or CLI triage

When Ollama **is** desired: run a local daemon, keep `REVENG_AI_PROVIDER=ollama` (or omit), and leave `enable_ai=True`.

## Security boundary

`reveng.security` **must not** import `reveng.agents.ai` / `reveng.ai`. If you need a shared type, put it in `reveng.core.ai_models` and keep providers behind the agents package.

## Related

- [Analysis pipeline](analysis-pipeline.md)
- [Wire MCP tool](../how-to/engineer/wire-mcp-tool.md)
- [Support matrix](../support/support-matrix.md)

## Java AI analyzer

`JavaAIAnalyzer` supports **ollama** locally. `openai` / `anthropic` raise `NotImplementedError` at construction (unsupported preflight).
