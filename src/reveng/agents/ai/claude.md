# `claude.md` — `agents/ai`

**Repository path:** `src/reveng/agents/ai/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `ai_enhanced/` — [`claude.md`](ai_enhanced/claude.md)

## Python modules

### `__init__.py`
- **Summary:** AI/ML Tools

### `ai_analyzer_enhanced.py`
- **Summary:** REVENG Enhanced AI Analyzer
- **Classes:**
  - `EnhancedAIAnalyzer` — Enhanced AI analyzer with Ollama support

### `ai_enhanced_analyzer.py`
- **Summary:** AI-Enhanced Universal Binary Analysis Engine
- **Classes:**
  - `EnhancedAnalysisConfig` — Configuration for enhanced analysis modules
  - `AIEnhancedAnalyzer` — AI-Enhanced Universal Binary Analysis Engine
- **Functions / coroutines:**
  - `def main()` — Main function for AI-Enhanced Analyzer

### `ai_enhanced_data_models.py`
- **Summary:** AI-Enhanced Universal Analysis Data Models
- **Classes:**
  - `RiskLevel` — Risk level enumeration
  - `Severity` — Vulnerability severity enumeration
  - `ConfidenceLevel` — Confidence level enumeration
  - `Evidence` — Evidence item with confidence scoring
  - `FileInfo` — File information and metadata
  - `CredentialExposure` — Exposed credential information
  - `BusinessLogicExposure` — Exposed business logic information
  - `APIEndpoint` — Discovered API endpoint
  - `CompetitiveIntel` — Competitive intelligence finding
  - `CorporateExposureReport` — Corporate data exposure analysis report
  - `MemoryVulnerability` — Memory-related vulnerability
  - `InjectionVulnerability` — Injection vulnerability
  - `AuthenticationIssue` — Authentication/authorization issue
  - `CryptographicWeakness` — Cryptographic implementation weakness
  - `VulnerabilityReport` — Comprehensive vulnerability analysis report
  - `IOC` — Indicator of Compromise
  - `APTAttribution` — APT group attribution analysis
  - `AttackChain` — Attack chain representation for MITRE ATT&CK analysis
  - `MITREMapping` — MITRE ATT&CK framework mapping
  - `MalwareClassification` — Malware classification result
  - `CampaignCorrelation` — Campaign correlation analysis
  - `ThreatIntelligenceReport` — Threat intelligence correlation report
  - `ReconstructionDemo` — Binary reconstruction demonstration
  - `ExecutiveSummary` — Executive-level summary
  - `UniversalAnalysisResult` — Universal analysis result containing all findings
  - `ExecutiveReport` — Executive-level report for CISOs and leadership
  - `DemonstrationComponent` — Component of a security demonstration
  - `DemonstrationPackage` — Security demonstration package
  - `CorporateRiskAssessment` — Corporate risk assessment result
  - `UniversalAnalysisSerializer` — Serialization utilities for analysis results
  - `EvidenceTracker` — Evidence tracking and confidence scoring system
  - `VulnerabilityPrediction` — ML-based vulnerability prediction result
  - `MLModelResult` — Result from machine learning model
  - `FeatureVector` — Feature vector for ML models
  - `BehavioralPattern` — Behavioral pattern detected in malware
  - `ThreatFamily` — Malware family information
  - `MLMalwareClassificationResult` — ML-based malware classification result (advanced version)
  - `CodeSummary` — NLP-generated code summary
  - `SemanticAnalysis` — Semantic analysis of code using NLP
  - `DocumentationSuggestion` — Suggestion for improving code documentation
  - `MLTrainingData` — Training data for ML models
  - `ModelPerformanceMetrics` — Performance metrics for ML models
  - `NeuralNetworkArchitecture` — Neural network architecture description
  - `DeepLearningResult` — Result from deep learning model
  - `EmbeddingVector` — Vector embedding for similarity analysis
  - `SimilarityAnalysis` — Code/malware similarity analysis using embeddings
  - `MLPipelineResult` — Complete ML pipeline execution result
  - `EnhancedUniversalAnalysisResult` — Enhanced universal analysis result with ML capabilities
- **Functions / coroutines:**
  - `def create_file_info_from_path()` — Create FileInfo from file path
  - `def merge_confidence_scores()` — Merge multiple confidence scores with optional weights

### `ollama_analyzer.py`
- **Summary:** REVENG Ollama Integration
- **Classes:**
  - `OllamaModel` — Ollama model information
  - `AnalysisResult` — LLM analysis result
  - `OllamaAnalyzer` — Ollama-powered code analysis

### `ollama_preflight.py`
- **Summary:** REVENG Ollama Preflight Checker
- **Classes:**
  - `OllamaPreflightChecker` — Preflight checker for Ollama AI integration

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
