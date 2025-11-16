# Directory: src/reveng/ai

## Overview
This directory contains AI-powered analysis components that enable natural language interaction, intelligent analysis orchestration, and advanced code analysis using large language models. It provides a unified AI assistant interface that combines all REVENG capabilities for AI-driven reverse engineering.

## Files in This Directory

### ai_assistant.py
- **Purpose**: Unified AI assistant that orchestrates all REVENG AI capabilities
- **Key Classes**:
  - `REVENGAIAssistant`: Main AI assistant class combining all analysis capabilities
- **Key Functions**:
  - `analyze_binary_ai()`: AI-powered binary analysis with natural language interaction (async)
  - `ask_question()`: Ask questions about analysis results (async)
  - `explain_code()`: Natural language code explanation
  - `suggest_improvements()`: Code improvement suggestions
  - `find_similar_samples()`: Find similar binaries in database
- **Dependencies**:
  - `..analyzer.REVENGAnalyzer`
  - `..ghidra.scripting_engine.GhidraScriptingEngine`
  - `..tools.ai.ollama_analyzer.OllamaAnalyzer`
  - `..tools.ai.ai_enhanced_analyzer.AIEnhancedAnalyzer`
  - `..tools.security.*` (Vulnerability and threat engines)
  - `.analysis_models` (Structured data models)
- **Used By**: CLI (ai command), API, web interface

### analysis_models.py
- **Purpose**: Structured data models for AI-optimized analysis results
- **Key Classes**:
  - `AIAnalysisRequest`: Request for AI analysis
  - `AIAnalysisResult`: Complete analysis results
  - `BinaryInfo`: Binary metadata
  - `FunctionAnalysis`: Per-function analysis results
  - `Vulnerability`: Vulnerability information
  - `ThreatIndicator`: Threat intelligence indicators
  - `Recommendation`: Analysis recommendations
  - `AnalysisMetadata`: Analysis execution metadata
  - `AnalysisType`: Enum (COMPREHENSIVE, SECURITY, TRIAGE, PERFORMANCE, CUSTOM)
  - `ThreatLevel`: Enum (LOW, MEDIUM, HIGH, CRITICAL, UNKNOWN)
  - `ConfidenceLevel`: Enum (VERY_LOW to VERY_HIGH)
- **Key Functions**: Factory functions for creating model instances
- **Dependencies**: Standard library (dataclasses, enum)
- **Used By**: `ai_assistant.py`, API layer, all AI components

### gemini_engine.py
- **Purpose**: Integration with Google Gemini AI for advanced code analysis
- **Key Classes**: `GeminiEngine`
- **Key Functions**:
  - Code analysis using Gemini models
  - Multi-modal analysis (code + diagrams)
  - Advanced reasoning for complex code
- **Dependencies**: Google Gemini API
- **Used By**: AI assistant, advanced analysis workflows

### gemini_feedback_loop.py
- **Purpose**: Implements feedback loop for improving Gemini-based analysis
- **Key Classes**: `GeminiFeedbackLoop`
- **Key Functions**:
  - Collect analysis feedback
  - Improve prompts based on results
  - Adaptive analysis strategies
- **Dependencies**: `gemini_engine.py`
- **Used By**: AI assistant for continuous improvement

### llm4decompile_engine.py
- **Purpose**: Specialized LLM engine for decompilation using LLM4Decompile models
- **Key Classes**: `LLM4DecompileEngine`
- **Key Functions**:
  - Assembly-to-C decompilation
  - Code optimization and cleanup
  - Variable name recovery
- **Dependencies**: LLM4Decompile models, transformers library
- **Used By**: Decompilation pipeline, code reconstruction

### recompilation_engine.py
- **Purpose**: AI-powered code recompilation and optimization
- **Key Classes**: `RecompilationEngine`
- **Key Functions**:
  - Decompiled code improvement
  - Code reconstruction
  - Build system generation
- **Dependencies**: AI models, compiler toolchains
- **Used By**: Binary reconstruction pipeline

## Architecture

```
┌─────────────────────────────────────┐
│   REVENGAIAssistant                 │
│   (Unified AI Interface)            │
├─────────────────────────────────────┤
│ • Natural language interaction      │
│ • Analysis orchestration            │
│ • Context management                │
│ • Multi-model ensemble              │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────────────────┐
       │   AI Engines               │
       ├────────────────────────────┤
       │ • GeminiEngine             │
       │ • LLM4DecompileEngine      │
       │ • OllamaAnalyzer           │
       │ • RecompilationEngine      │
       └───────┬────────────────────┘
               │
       ┌───────┴────────────────────┐
       │   Analysis Models          │
       ├────────────────────────────┤
       │ • Structured data models   │
       │ • Type-safe interfaces     │
       │ • JSON serialization       │
       └────────────────────────────┘
```

## Key Concepts

### AI-Powered Analysis Workflow
1. **Request Analysis**: User submits binary with analysis goals
2. **Intelligent Routing**: AI determines optimal analysis strategy
3. **Multi-Stage Analysis**: Orchestrates various tools and techniques
4. **Result Synthesis**: Combines results into coherent narrative
5. **Natural Language Output**: Presents findings in human-readable format

### Supported Analysis Types
- **COMPREHENSIVE**: Full analysis with all modules
- **SECURITY**: Focus on vulnerabilities and threats
- **TRIAGE**: Quick assessment for incident response
- **PERFORMANCE**: Performance bottleneck analysis
- **CUSTOM**: User-defined analysis goals

### AI Model Integration
- **Ollama**: Local LLM for code analysis
- **Gemini**: Google's advanced AI for complex reasoning
- **LLM4Decompile**: Specialized decompilation models
- **Ensemble**: Combines multiple models for best results

## Usage Examples

### Basic AI Assistant Usage
```python
from reveng.ai.ai_assistant import REVENGAIAssistant
from reveng.ai.analysis_models import AIAnalysisRequest, AnalysisType
import asyncio

# Create AI assistant
assistant = REVENGAIAssistant()

# Create analysis request
request = AIAnalysisRequest(
    binary_path="malware.exe",
    analysis_type=AnalysisType.SECURITY,
    goals=["find_vulnerabilities", "assess_threats", "extract_iocs"]
)

# Run analysis (async)
result = asyncio.run(assistant.analyze_binary_ai(request))

# Access results
print(f"Binary: {result.binary_info.name}")
print(f"Vulnerabilities: {len(result.vulnerabilities)}")
print(f"Threat Level: {result.threat_level}")
print(f"\nSummary:\n{result.natural_language_summary}")
```

### Using Structured Models
```python
from reveng.ai.analysis_models import (
    create_binary_info,
    create_vulnerability,
    ThreatLevel
)

# Create binary info
binary = create_binary_info(
    name="suspicious.exe",
    path="/path/to/suspicious.exe",
    size=1024000,
    file_type="PE32",
    architecture="x86-64"
)

# Create vulnerability
vuln = create_vulnerability(
    vuln_type="buffer_overflow",
    severity="HIGH",
    description="Unbounded strcpy in process_input",
    location="0x401000",
    cwe_id="CWE-120"
)

# Convert to JSON
print(vuln.to_json())
```

### Natural Language Queries
```python
import asyncio

async def analyze():
    assistant = REVENGAIAssistant()

    # Ask questions about binary
    answer = await assistant.ask_question(
        "What does this binary do?",
        binary_path="unknown.exe"
    )

    print(f"Answer: {answer}")

    # Get code explanation
    explanation = await assistant.explain_code(
        code="<decompiled code>",
        context="main function"
    )

    print(f"Explanation: {explanation}")

asyncio.run(analyze())
```

## Configuration

### AI Model Selection
```python
config = {
    "ai_provider": "ollama",  # or "gemini", "ensemble"
    "ollama_model": "codellama",
    "gemini_model": "gemini-pro",
    "max_tokens": 4096,
    "temperature": 0.7
}

assistant = REVENGAIAssistant(config=config)
```

### Analysis Goals
Common analysis goals for AI assistant:
- `understand_functionality`
- `find_vulnerabilities`
- `assess_threats`
- `extract_iocs`
- `identify_malware_family`
- `reverse_algorithm`
- `find_crypto`
- `analyze_network_behavior`

## Testing

### Unit Tests
```bash
pytest tests/ai/test_ai_assistant.py
pytest tests/ai/test_analysis_models.py
```

### Integration Tests
```bash
pytest tests/ai/test_ai_integration.py
```

## Related Modules

### Dependencies
- `src/reveng/analyzer.py`: Core analyzer
- `src/reveng/tools/ai/*`: AI-enhanced tools
- `src/reveng/security/*`: Security analysis engines
- `src/reveng/ghidra/*`: Ghidra integration

### Used By
- `src/reveng/cli.py`: CLI ai command
- `src/reveng/api.py`: API endpoints
- Web interface

## Notes

### Async Design
Most AI operations are async to support:
- Long-running analysis
- Real-time streaming results
- Concurrent operations
- Web interface integration

### Model Requirements
- Ollama: Requires local Ollama server
- Gemini: Requires Google API key
- LLM4Decompile: Requires transformers library

### Best Practices
1. Use structured models for type safety
2. Implement proper error handling for AI operations
3. Set appropriate timeouts for LLM calls
4. Cache results when possible
5. Use ensemble for critical analysis
6. Validate AI outputs before trusting them

### Performance
- Ollama: Fastest, local inference
- Gemini: Best quality, cloud-based
- Ensemble: Highest accuracy, slowest
- Average analysis time: 2-10 minutes depending on mode
