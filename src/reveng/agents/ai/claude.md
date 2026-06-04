# `claude.md` — `agents/ai`

**Repository path:** `src/reveng/agents/ai/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `ai_enhanced/` — [`claude.md`](ai_enhanced/claude.md)

## Python modules

### `__init__.py`
- **Summary:** AI/ML Tools

### `ai_enhanced_data_models.py`
- **Summary:** Backwards-compatibility shim.

### `ai_enhanced_orchestrator.py`
- **Summary:** AI-Enhanced Universal Binary Analysis Engine
- **Classes:**
  - `EnhancedAnalysisConfig` — Configuration for enhanced analysis modules
  - `AIEnhancedAnalyzer` — AI-Enhanced Universal Binary Analysis Engine
- **Functions / coroutines:**
  - `def main()` — Main function for AI-Enhanced Analyzer

### `ai_provider_registry.py`
- **Summary:** REVENG Enhanced AI Analyzer
- **Classes:**
  - `EnhancedAIAnalyzer` — Enhanced AI analyzer with Ollama support
- **Functions / coroutines:**
  - `def get_analyzer()` — Return an analyzer instance for the given provider.

### `anthropic_analyzer.py`
- **Summary:** REVENG Anthropic Claude Integration
- **Classes:**
  - `AnthropicAnalyzer` — Anthropic Claude-powered code analysis.
- **Functions / coroutines:**
  - `def _import_anthropic()` — Lazy-import anthropic and raise a clear error when absent.
  - `def _extract_code_block()` — Extract the first code block from a markdown-fenced response, or return as-is.

### `claude_cli_analyzer.py`
- **Summary:** LLM provider that calls the Claude Code CLI (``claude -p``) as a subprocess.
- **Classes:**
  - `_Usage` — Lightweight usage object exposing ``input_tokens`` / ``output_tokens``.
  - `ClaudeCLIResult` — Result of a single ``claude -p`` invocation.
  - `ClaudeCodeCLIAnalyzer` — OAuth-based LLM provider that shells out to the ``claude`` CLI.

### `ollama_analyzer.py`
- **Summary:** REVENG Ollama Integration
- **Classes:**
  - `OllamaModel` — Ollama model information
  - `AnalysisResult` — LLM analysis result
  - `_OllamaTextResult` — Minimal LLM result exposing ``.content`` for the refiner contract.
  - `OllamaAnalyzer` — Ollama-powered code analysis

### `ollama_preflight.py`
- **Summary:** REVENG Ollama Preflight Checker
- **Classes:**
  - `OllamaPreflightChecker` — Preflight checker for Ollama AI integration

### `openai_analyzer.py`
- **Summary:** REVENG OpenAI Integration
- **Classes:**
  - `OpenAIAnalyzer` — OpenAI GPT-powered code analysis.
- **Functions / coroutines:**
  - `def _extract_code_block()` — Extract the first code block from a markdown-fenced response, or return as-is.
  - `def _import_openai()` — Lazy-import openai and raise a clear error when absent.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
