# `claude.md` — `ai`

**Repository path:** `src/reveng/ai/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `ai_assistant.py`
- **Summary:** REVENG AI Assistant
- **Classes:**
  - `REVENGAIAssistant` — Unified AI Assistant for REVENG
- **Functions / coroutines:**
  - `async def analyze_binary()` — Convenience function for AI binary analysis
  - `async def ask_about_binary()` — Convenience function for asking questions about a binary
  - `async def suggest_analysis_workflow()` — Convenience function for workflow suggestions

### `analysis_models.py`
- **Summary:** REVENG Analysis Models
- **Classes:**
  - `AnalysisType` — Types of analysis that can be performed
  - `ThreatLevel` — Threat level classifications
  - `ConfidenceLevel` — Confidence levels for analysis results
  - `BinaryInfo` — Information about the binary being analyzed
  - `FunctionAnalysis` — Analysis result for a single function
  - `Vulnerability` — Vulnerability information
  - `ThreatIndicator` — Threat intelligence indicator
  - `Recommendation` — Analysis recommendation
  - `AnalysisMetadata` — Metadata about the analysis process
  - `AIAnalysisResult` — Comprehensive AI analysis result optimized for AI consumption
  - `AIAnalysisRequest` — Request for AI analysis
  - `WorkflowSuggestion` — Suggested analysis workflow
- **Functions / coroutines:**
  - `def create_binary_info()` — Create BinaryInfo with default values
  - `def create_function_analysis()` — Create FunctionAnalysis with default values
  - `def create_vulnerability()` — Create Vulnerability with default values
  - `def create_threat_indicator()` — Create ThreatIndicator with default values
  - `def create_recommendation()` — Create Recommendation with default values
  - `def create_analysis_metadata()` — Create AnalysisMetadata with calculated values

### `angr_cfg_preprocessor.py`
- **Summary:** angr-based CFG preprocessing for binary recompilation context.
- **Classes:**
  - `CFGExtractionError` — Raised when CFG extraction cannot produce a usable payload.
  - `AngrCFGPreprocessor` — Extract and serialize a structured control-flow graph with angr.

### `gemini_engine.py`
- **Summary:** Gemini AI Engine - Advanced Reasoning and Code Analysis
- **Classes:**
  - `GeminiEngine` — Google Gemini integration for advanced AI-powered analysis.
- **Functions / coroutines:**
  - `async def reconstruct_code()` — Quick function to reconstruct code using Gemini.
  - `async def find_vulnerabilities()` — Quick function to find vulnerabilities using Gemini.

### `gemini_feedback_loop.py`
- **Summary:** Gemini Continuous Feedback Loop
- **Classes:**
  - `GeminiFeedbackLoop` — Continuous improvement system using Gemini.
- **Functions / coroutines:**
  - `async def run_feedback_loop()` — Run the Gemini feedback loop from CLI.
  - `def run_feedback_loop_sync()` — Synchronous wrapper for the feedback loop.

### `llm4decompile_engine.py`
- **Summary:** LLM4Decompile Integration - Specialized Decompilation Models
- **Classes:**
  - `DecompilationResult` — Result from LLM4Decompile
  - `LLM4DecompileEngine` — Specialized decompilation models trained on Decompile-Bench dataset
  - `MultiModelEnsemble` — Ensemble of specialized and general models for optimal results

### `recompilation_engine.py`
- **Summary:** Binary Recompilation Engine - Prove Vulnerabilities Through Working Code
- **Classes:**
  - `CompilationError` — Raised when code compilation fails.
  - `BinaryRecompilationEngine` — Advanced engine for binary → source → binary reconstruction.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
