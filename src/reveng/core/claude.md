# `claude.md` — `core`

**Repository path:** `src/reveng/core/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `ai_models.py`
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

### `dependency_manager.py`
- **Summary:** REVENG Dependency Management System
- **Classes:**
  - `Platform` — Supported platforms
  - `ToolStatus` — Installation status of a tool
  - `ToolInfo` — Information about an analysis tool
  - `InstallationResult` — Result of tool installation
  - `BaseInstaller` — Base class for tool installers
  - `GhidraInstaller` — Installer for Ghidra reverse engineering tool (cross-platform)
  - `ILSpyInstaller` — Installer for ILSpy .NET decompiler (Windows-only, use dotnet-ilspy on Linux/macOS)
  - `CFRInstaller` — Installer for CFR Java decompiler
  - `DIEInstaller` — Installer for Detect It Easy (Windows/Linux/macOS)
  - `ScyllaInstaller` — Installer for Scylla unpacker (Windows-only PE tool)
  - `HxDInstaller` — Installer for HxD hex editor (Windows-only, use 'hexdump' or 'xxd' on Unix)
  - `ResourceHackerInstaller` — Installer for Resource Hacker (Windows-only PE resource editor)
  - `DependencyManager` — Comprehensive dependency management system
- **Functions / coroutines:**
  - `def get_platform()` — Detect current platform
  - `def get_architecture()` — Get system architecture (x86_64, arm64, etc.)
  - `def get_executable_name()` — Get platform-specific executable name
  - `def get_script_name()` — Get platform-specific script name
  - `def load_checksums()` — Load checksums from checksums.yaml file
  - `def calculate_sha256()` — Calculate SHA256 hash of a file
  - `def validate_checksum()` — Validate file checksum against expected SHA256 hash
  - `def create_retry_session()` — Create a requests session with retry logic and exponential backoff
  - `def download_with_retry()` — Download a file with retry logic and exponential backoff

### `error_codes.py`
- **Summary:** REVENG Error Code System
- **Classes:**
  - `ErrorCode` — Standardized error codes for REVENG
  - `REVENGError` — Base exception for REVENG with structured error information

### `errors.py`
- **Summary:** REVENG Enhanced Error Handling System
- **Classes:**
  - `ErrorSeverity` — Error severity levels
  - `ErrorContext` — Context information for errors
  - `RecoverySuggestion` — Recovery suggestion for errors
  - `REVENGError` — Base exception with context and recovery suggestions
  - `MissingDependencyError` — Missing tool dependency error
  - `PluginError` — Plugin subsystem error.
  - `AnalysisFailureError` — Analysis operation failed
  - `BinaryFormatError` — Unsupported binary format
  - `PackedBinaryError` — Binary is packed/obfuscated
  - `MemoryAnalysisError` — Memory forensics failed
  - `ScriptExecutionError` — Ghidra/IDA script execution failed
  - `PipelineExecutionError` — Pipeline execution failed
  - `ConfigurationError` — Configuration error
- **Functions / coroutines:**
  - `def create_error_context()` — Create error context
  - `def handle_exception()` — Convert generic exception to REVENG error
  - `def log_error()` — Log REVENG error with context

### `exceptions.py`
- **Summary:** REVENG Core Exceptions
- **Classes:**
  - `REVENGException` — Base exception for all REVENG errors.
  - `AnalysisError` — Raised when analysis operations fail.
  - `DependencyError` — Raised when required dependencies are missing or incompatible.
  - `ValidationError` — Raised when input validation fails.
  - `SecurityError` — Raised when security constraints are violated.
  - `ConfigurationError` — Raised when configuration is invalid.
  - `ToolError` — Raised when external tools fail.
  - `MLModelError` — Raised when ML model operations fail.
  - `BinaryFormatError` — Raised when binary format is unsupported or corrupted.
  - `TimeoutError` — Raised when operations exceed timeout.
  - `InsufficientPermissionsError` — Raised when insufficient permissions for operation.
  - `ResourceError` — Raised when system resources are insufficient.
- **Functions / coroutines:**
  - `def raise_analysis_error()` — Raise an AnalysisError with optional step information.
  - `def raise_dependency_error()` — Raise a DependencyError with optional dependency information.
  - `def raise_validation_error()` — Raise a ValidationError with optional field information.
  - `def raise_security_error()` — Raise a SecurityError with optional issue information.
  - `def raise_tool_error()` — Raise a ToolError with optional tool and exit code information.

### `ir.py`
- **Summary:** REVENG Intermediate Representation (IR) -- v2.
- **Classes:**
  - `NodeKind`
  - `EdgeKind`
  - `Provenance` — Traceability record linking an IR node back to its binary origin.
  - `IRNode` — A typed vertex in the IR graph.
  - `IREdge` — A directed, typed edge between two IRNode vertices.
  - `IRProgram` — Top-level IR container for one analyzed target.
  - `_REProjectIRCompat` — Thin compatibility subclass that re-exposes the legacy REProjectIR

### `logger.py`
- **Summary:** REVENG Enhanced Logging System
- **Classes:**
  - `LogLevel` — Log levels
  - `LogContext` — Context information for logging
  - `ProgressInfo` — Progress information
  - `StructuredFormatter` — Structured log formatter
  - `ProgressTracker` — Progress tracking for long operations
  - `LogAggregator` — Log aggregation for analysis pipelines
  - `REVENGLogger` — Enhanced REVENG logger with context and progress tracking
- **Functions / coroutines:**
  - `def setup_logging()` — Setup REVENG logging system
  - `def get_logger()` — Get REVENG logger instance.
  - `def log_context()` — Context manager for logging with automatic context
  - `def progress_tracking()` — Context manager for progress tracking
  - `def log_analysis_start()` — Log analysis start
  - `def log_analysis_complete()` — Log analysis completion
  - `def log_tool_execution()` — Log tool execution
  - `def log_error_with_context()` — Log error with context
  - `def get_global_aggregator()` — Get global log aggregator

### `progress_tracker.py`
- **Summary:** Progress tracking for REVENG analysis operations
- **Classes:**
  - `AnalysisStatus` — Analysis status
  - `AnalysisStage` — Analysis stage information
  - `ToolExecution` — Tool execution information
  - `ProgressTracker` — Track progress of analysis operations

### `result_contracts.py`
- **Summary:** Versioned result contracts for public analyzer and API outputs.
- **Classes:**
  - `ResultContract` — Base class for public result contracts.
  - `AnalysisResultContract`
  - `ReconstructionResultContract`
  - `MalwareDetectionResultContract`
  - `AnalyzerCapabilitiesContract`
  - `AIBinaryAnalysisContract`
- **Functions / coroutines:**
  - `def make_trace_reference()` — Create a normalized trace reference for provenance chains.
  - `def make_evidence_item()` — Create a normalized provenance entity.
  - `def build_mcp_tool_response()` — Build a versioned MCP tool response while preserving top-level payload fields.
  - `def build_mcp_resource_result()` — Build a versioned MCP resource payload for resource-read responses.

### `validation.py`
- **Summary:** REVENG Security Validation Module
- **Functions / coroutines:**
  - `def validate_file_path()` — Validate file path for security.
  - `def secure_hash_file()` — Securely hash a file using the specified algorithm.
  - `def secure_temp_file()` — Create a secure temporary file.
  - `def validate_binary_content()` — Validate binary file content for security.
  - `def calculate_entropy()` — Calculate Shannon entropy of data.
  - `def sanitize_filename()` — Sanitize filename for safe storage.
  - `def validate_analysis_config()` — Validate analysis configuration for security.

## Other files in this folder

- `checksums.yaml`

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
