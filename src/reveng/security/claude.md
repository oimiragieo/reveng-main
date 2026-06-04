# `claude.md` — `security`

**Repository path:** `src/reveng/security/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Security analysis tool exports with defensive optional dependency handling.
- **Functions / coroutines:**
  - `def _optional_import()`
  - `def __getattr__()` — Lazy import security tools on demand with graceful degradation.

### `complexity_scorer.py`
- **Summary:** REVENG Function Complexity Scorer
- **Classes:**
  - `ComplexityMetrics` — Complexity metrics for a function
  - `ComplexityScorer` — Analyze and score function complexity

### `corporate_exposure_detector.py`
- **Summary:** Corporate Data Exposure Detection Engine
- **Classes:**
  - `ExposureType` — Types of corporate data exposure
  - `SeverityLevel` — Severity levels for exposure findings
  - `ExposureEvidence` — Evidence supporting an exposure finding
  - `CorporateExposure` — Represents a detected corporate data exposure
  - `CredentialDetector` — Detects various types of credentials and secrets in code
  - `BusinessLogicAnalyzer` — Analyzes decompiled code for business logic and proprietary algorithms
  - `NetworkTopologyAnalyzer` — Analyzes network communication code for API endpoints and topology
  - `CorporateExposureDetector` — Main class for detecting corporate data exposure in binaries
- **Functions / coroutines:**
  - `def main()` — Example usage of the Corporate Exposure Detector

### `mitre_attack_mapper.py`
- **Summary:** MITRE ATT&CK Mapping Engine
- **Classes:**
  - `MITRETechnique` — MITRE ATT&CK technique information
  - `MITREAttackMapper` — Enhanced MITRE ATT&CK mapping engine
- **Functions / coroutines:**
  - `def main()` — Test function

### `ml_malware_classifier.py`
- **Summary:** ML-Based Malware Family Classifier
- **Classes:**
  - `MalwareFeatures` — Feature vector for malware classification
  - `MalwareFeatureExtractor` — Extract features from malware samples for classification
  - `MalwareFamilyDatabase` — Database of known malware families and their characteristics
  - `MLMalwareClassifier` — Advanced machine learning-based malware family classifier with deep learning
- **Functions / coroutines:**
  - `def main()` — Main function for testing advanced ML malware classifier

### `ml_vulnerability_predictor.py`
- **Summary:** ML-Based Vulnerability Predictor
- **Classes:**
  - `VulnerabilityFeatures` — Feature vector for vulnerability prediction
  - `VulnerabilityFeatureExtractor` — Extract features from code for vulnerability prediction
  - `MLVulnerabilityPredictor` — Machine learning-based vulnerability predictor
- **Functions / coroutines:**
  - `def main()` — Main function for testing ML vulnerability predictor

### `nlp_code_analyzer.py`
- **Summary:** NLP Code Analyzer
- **Classes:**
  - `CodeSemantics` — Semantic information extracted from code
  - `CodeTokenizer` — Tokenize and preprocess code for NLP analysis
  - `SemanticAnalyzer` — Analyze semantic meaning of code using NLP techniques
  - `DocumentationGenerator` — Generate automated documentation and suggestions
- **Functions / coroutines:**
  - `def main()` — Main function for testing NLP code analyzer

### `symbolic_execution_engine.py`
- **Summary:** Advanced Symbolic Execution Engine - Automatic Vulnerability Discovery
- **Classes:**
  - `VulnerabilityType` — Types of vulnerabilities that can be detected
  - `Severity` — Vulnerability severity
  - `Vulnerability` — Detected vulnerability
  - `ExploitTemplate` — Generated exploit template
  - `ExploitInput` — Generated exploit input for compatibility symbolic path exploration APIs.
  - `SymbolicVulnerability` — Vulnerability discovered through symbolic path exploration.
  - `PathExplorationResult` — Results from compatibility symbolic path exploration.
  - `SymbolicExecutionEngine` — Advanced symbolic execution for automatic vulnerability discovery

### `threat_intelligence_correlator.py`
- **Summary:** Threat Intelligence Correlator
- **Classes:**
  - `ThreatIntelligenceCorrelator` — Main threat intelligence correlation engine that extracts IOCs,
- **Functions / coroutines:**
  - `def defang_ioc()` — Defang IOC for safe sharing
  - `def create_yara_rule()` — Generate YARA rule from IOCs

### `vulnerability_discovery_engine.py`
- **Summary:** Vulnerability Discovery Engine
- **Classes:**
  - `MemoryVulnerabilityScanner` — Scanner for memory-related vulnerabilities in C/C++ code
  - `InjectionVulnerabilityScanner` — Scanner for injection vulnerabilities (SQL, XSS, Command)
  - `AuthenticationBypassScanner` — Scanner for authentication and authorization bypass vulnerabilities
  - `VulnerabilityDiscoveryEngine` — Main vulnerability discovery engine coordinating all scanners

### `yara_scanner.py`
- **Summary:** Built-in YARA scanning and malware classification support for REVENG.
- **Classes:**
  - `YARAMatch` — Normalized YARA match result used across REVENG.
  - `YARAScanner` — Scan binaries with built-in YARA signatures and lightweight ML heuristics.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
