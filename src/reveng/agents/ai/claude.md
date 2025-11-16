# Directory: src/reveng/agents/ai

## Overview
This directory contains AI-enhanced analysis agents that use machine learning and large language models to automate and improve reverse engineering tasks. Key components include instant triage, natural language interfaces, and Ollama-based analysis.

## Files in This Directory

### __init__.py
- **Purpose**: Package initialization
- **Dependencies**: None

### ollama_preflight.py
- **Purpose**: Preflight check for Ollama availability and model selection
- **Key Classes**: `OllamaPreflightChecker`
- **Key Functions**:
  - `check_all()`: Comprehensive Ollama availability check
  - `get_recommended_model()`: Selects best available model
  - `check_server()`: Verify Ollama server is running
  - `check_models()`: List available models
- **Dependencies**: Ollama server (http://localhost:11434)
- **Used By**: Analyzer initialization, AI components

### ollama_analyzer.py
- **Purpose**: Ollama-based binary analysis using local LLM
- **Key Classes**: `OllamaAnalyzer`
- **Key Functions**:
  - `analyze_binary()`: Full binary analysis
  - `analyze_function()`: Single function analysis
  - `explain_code()`: Natural language code explanation
- **Dependencies**: Ollama, local LLM models
- **Used By**: AI assistant, enhanced analyzer

### ai_enhanced_analyzer.py
- **Purpose**: AI-enhanced binary analyzer with ML capabilities
- **Key Classes**: `AIEnhancedAnalyzer`
- **Key Functions**:
  - Intelligent feature extraction
  - Pattern recognition
  - Anomaly detection
  - Predictive analysis
- **Dependencies**: ML models, analyzers
- **Used By**: Main analyzer, AI assistant

### ai_enhanced_data_models.py
- **Purpose**: Data models for AI-enhanced analysis
- **Key Classes**: Various dataclasses for structured AI results
- **Dependencies**: Standard library
- **Used By**: AI-enhanced components

### ai_analyzer_enhanced.py
- **Purpose**: Enhanced AI analyzer with advanced capabilities
- **Key Classes**: `AIAnalyzerEnhanced`
- **Dependencies**: AI models, analysis engines
- **Used By**: Advanced analysis workflows

### ai_enhanced/ (subdirectory)

#### nl_interface.py
- **Purpose**: Natural language interface for querying binaries
- **Key Classes**: `NaturalLanguageInterface`, `NLResponse`
- **Key Functions**:
  - `query()`: Ask questions about binaries in natural language
  - `explain()`: Get explanations of binary behavior
  - `find()`: Search for specific features
- **Dependencies**: Ollama, NLP models
- **Used By**: AI API, CLI ask command

#### instant_triage.py
- **Purpose**: Rapid threat assessment (<30 seconds)
- **Key Classes**: `InstantTriageEngine`, `ThreatLevel`
- **Key Functions**:
  - `triage()`: Fast binary triage
  - `batch_triage()`: Batch processing
  - `generate_report()`: Triage reports
- **Dependencies**: ML models, heuristics
- **Used By**: CLI triage command, incident response

## Architecture

```
┌─────────────────────────────────────┐
│   AI Agents Layer                   │
├─────────────────────────────────────┤
│ • Ollama Integration                │
│ • AI-Enhanced Analysis              │
│ • Natural Language Interface        │
│ • Instant Triage                    │
└──────────────┬──────────────────────┘
               │
       ┌───────┴────────────────┐
       │   AI Engines           │
       ├────────────────────────┤
       │ • Ollama (local LLM)   │
       │ • ML models            │
       │ • NLP processors       │
       └────────────────────────┘
```

## Key Concepts

### Ollama Integration
- Local LLM inference
- No cloud dependencies
- Privacy-preserving analysis
- Multiple model support (codellama, mistral, etc.)

### Instant Triage
Fast (<30 second) analysis for:
- Threat level assessment
- Malware capability detection
- IOC extraction
- Incident response prioritization

### Natural Language Interface
Ask questions like:
- "What does this binary do?"
- "Is this malware?"
- "Find all network communication"
- "Extract crypto functions"

## Usage Examples

### Ollama Preflight
```python
from reveng.agents.ai.ollama_preflight import OllamaPreflightChecker

checker = OllamaPreflightChecker()
success, results = checker.check_all()

if success:
    print(f"Ollama available with {len(results['models_available'])} models")
    recommended = checker.get_recommended_model()
    print(f"Recommended model: {recommended}")
else:
    print("Ollama not available")
    for error in results['errors']:
        print(f"  - {error}")
```

### Instant Triage
```python
from reveng.agents.ai.ai_enhanced.instant_triage import InstantTriageEngine

engine = InstantTriageEngine()

# Single file triage
result = engine.triage("suspicious.exe")
print(f"Threat level: {result.threat_level}")
print(f"Threat score: {result.threat_score}/100")
print(f"Malicious: {result.is_malicious}")
print(f"Capabilities: {result.detected_capabilities}")

# Batch triage
results = engine.batch_triage(["file1.exe", "file2.exe", "file3.exe"])
```

### Natural Language Interface
```python
from reveng.agents.ai.ai_enhanced.nl_interface import NaturalLanguageInterface

nl = NaturalLanguageInterface()

# Ask questions
response = nl.query(
    question="What does this binary do?",
    binary_path="malware.exe"
)

print(f"Answer: {response.answer}")
print(f"Confidence: {response.confidence}")
```

### Ollama Analysis
```python
from reveng.agents.ai.ollama_analyzer import OllamaAnalyzer

analyzer = OllamaAnalyzer(model="codellama")

# Analyze binary
result = analyzer.analyze_binary("app.exe")

# Explain code
explanation = analyzer.explain_code(
    code="<decompiled code>",
    context="authentication function"
)
```

## Configuration

### Ollama Setup
```bash
# Install Ollama
curl https://ollama.ai/install.sh | sh

# Pull models
ollama pull codellama
ollama pull mistral
ollama pull llama3

# Start server (usually auto-starts)
ollama serve
```

### Configuration File
```python
config = {
    "ollama_host": "http://localhost:11434",
    "ollama_model": "codellama",  # or "auto"
    "triage_timeout": 30,
    "nl_max_tokens": 2048
}
```

## Testing

### Unit Tests
```bash
pytest tests/agents/ai/test_ollama_preflight.py
pytest tests/agents/ai/test_instant_triage.py
pytest tests/agents/ai/test_nl_interface.py
```

### Integration Tests
```bash
pytest tests/agents/ai/test_ollama_integration.py
```

## Related Modules

### Dependencies
- `src/reveng/ai/`: AI components
- `src/reveng/tools/ai/`: AI tools
- Ollama server (external)

### Used By
- `src/reveng/analyzer.py`: Uses for enhanced analysis
- `src/reveng/ai/ai_assistant.py`: Orchestrates AI agents
- `src/reveng/cli.py`: CLI commands (ask, triage, ai)

## Notes

### Ollama Models
Supported models:
- **codellama**: Best for code analysis (recommended)
- **mistral**: Fast general-purpose
- **llama3**: Highest quality, slower
- **deepseek-coder**: Code-specialized

### Performance
- Instant triage: <30 seconds
- Natural language query: 5-10 seconds
- Full analysis: 2-5 minutes
- Depends on model size and hardware

### Best Practices
1. Run preflight check before using Ollama features
2. Use codellama for code analysis
3. Use instant triage for rapid assessment
4. Cache NL responses when possible
5. Set appropriate timeouts
6. Monitor Ollama server resource usage

### Hardware Requirements
- Minimum: 8GB RAM
- Recommended: 16GB RAM, GPU
- Codellama 7B: ~4GB VRAM
- Llama3 70B: ~40GB VRAM
