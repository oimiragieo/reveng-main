# `claude.md` — `tools/utils`

**Repository path:** `src/reveng/tools/utils/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Utility modules with lazy loading to avoid heavy imports at module import time.
- **Functions / coroutines:**
  - `def __getattr__()`

### `comprehensive_reporting_system.py`
- **Summary:** Comprehensive Reporting and Visualization System
- **Classes:**
  - `ReportType` — Types of reports that can be generated
  - `ReportConfiguration` — Configuration for report generation
  - `ComprehensiveReportingSystem` — Unified reporting system that orchestrates executive reporting,

### `demonstration_generator.py`
- **Summary:** Demonstration and Presentation Generator
- **Classes:**
  - `DemoType` — Types of demonstrations
  - `RiskLevel` — Risk levels for visualizations
  - `DemoConfig` — Configuration for demonstration generation
  - `AnalysisEvidence` — Evidence from binary analysis
  - `DemonstrationPackage` — Complete demonstration package
  - `DemonstrationGenerator` — Main class for generating security demonstrations and presentations
- **Functions / coroutines:**
  - `def main()` — Main function for command-line usage

### `educational_content_generator.py`
- **Summary:** Educational Content and Awareness Campaign Generator
- **Classes:**
  - `SocialMediaPost` — Represents a social media post for security awareness
  - `BlogPost` — Represents a blog post for security awareness
  - `ConferencePresentation` — Represents a conference presentation template
  - `EducationalContentGenerator` — Generates educational content and awareness campaigns
- **Functions / coroutines:**
  - `def main()` — Main function for testing the educational content generator

### `educational_content_generator_simple.py`
- **Summary:** Educational Content and Awareness Campaign Generator
- **Classes:**
  - `SocialMediaPost`
  - `EducationalContentGenerator`
- **Functions / coroutines:**
  - `def main()`

### `enhanced_code_generator.py`
- **Summary:** Enhanced Code Generator
- **Classes:**
  - `EnhancedCodeGenerator` — Generate real C implementations from AI analysis and Ghidra data
- **Functions / coroutines:**
  - `def main()` — Main entry point

### `export_formats.py`
- **Summary:** REVENG Export Formats
- **Classes:**
  - `ExportFormats` — Export analysis to multiple formats

### `export_integration_engine.py`
- **Summary:** Multi-Format Export and Integration Engine
- **Classes:**
  - `ExportFormat` — Supported export formats
  - `TLPLevel` — Traffic Light Protocol levels
  - `SIEMType` — Supported SIEM systems
  - `IOCData` — Indicator of Compromise data structure
  - `ThreatIntelligence` — Threat intelligence data structure
  - `CustomBranding` — Custom branding configuration
  - `ExportIntegrationEngine` — Multi-format export and integration engine for threat intelligence sharing,

### `functional_code_generator.py`
- **Summary:** REVENG Functional Code Generator
- **Classes:**
  - `FunctionalCodeGenerator` — Generate functional C code from disassembly and analysis

### `interactive_mode.py`
- **Summary:** REVENG Interactive Mode
- **Classes:**
  - `REVENGShell` — Interactive REVENG shell
- **Functions / coroutines:**
  - `def main()` — Run REVENG interactive shell

### `java_ai_analyzer.py`
- **Summary:** REVENG AI-Enhanced Java Analyzer
- **Classes:**
  - `JavaAIAnalysisResult` — Result from AI analysis of Java code
  - `JavaAIAnalyzer` — AI-enhanced analyzer for decompiled Java code
- **Functions / coroutines:**
  - `def main()` — Test AI analyzer

### `live_demonstration_engine.py`
- **Summary:** Live Demonstration and Assessment Engine
- **Classes:**
  - `DemonstrationStep` — Represents a single step in a live demonstration
  - `LiveDemonstration` — Represents a complete live demonstration workflow
  - `AssessmentMetric` — Represents a security assessment metric
  - `PortfolioAnalysis` — Represents analysis of an organization's software portfolio
  - `LiveDemonstrationEngine` — Manages live demonstrations and real-time assessments
- **Functions / coroutines:**
  - `def main()` — Main function for testing the live demonstration engine

### `ml_pipeline_orchestrator.py`
- **Summary:** ML Pipeline Orchestrator
- **Classes:**
  - `MLPipelineOrchestrator` — Orchestrates machine learning pipeline for enhanced binary analysis
- **Functions / coroutines:**
  - `def main()` — Main function for testing ML pipeline orchestrator

### `progress_reporter.py`
- **Summary:** REVENG Progress Reporter
- **Classes:**
  - `ProgressReporter` — Progress reporting with tqdm
  - `ProgressBar` — Manual progress bar wrapper
  - `PipelineProgress` — Pipeline-specific progress tracking
  - `NoOpProgressBar` — No-op progress bar for when tqdm is disabled
  - `NoOpPipelineProgress` — No-op pipeline progress for when tqdm is disabled
- **Functions / coroutines:**
  - `def get_progress_reporter()` — Get global progress reporter instance
  - `def track_progress()` — Convenience function for tracking progress
  - `def create_progress_bar()` — Convenience function for creating manual progress bar

### `proguard_mapper.py`
- **Summary:** REVENG ProGuard Mapping File Parser
- **Classes:**
  - `ClassMapping` — Mapping for a single class
  - `ProGuardMapper` — Parse and apply ProGuard mapping files
- **Functions / coroutines:**
  - `def main()` — Test ProGuard mapper

### `purge_stubs.py`
- **Summary:** Stub Purge Tool
- **Classes:**
  - `StubPurger` — Purge narrative stubs from C source files
- **Functions / coroutines:**
  - `def main()` — Main entry point

### `reconstruction_comparator.py`
- **Summary:** Reconstruction Comparison and Validation Engine
- **Classes:**
  - `ComparisonType` — Types of comparison analysis
  - `AccuracyLevel` — Reconstruction accuracy levels
  - `ComparisonMetrics` — Metrics for comparing original vs reconstructed binary
  - `BehavioralTest` — Individual behavioral test case
  - `ComparisonResult` — Complete comparison analysis result
  - `ReconstructionComparator` — Main class for comparing original and reconstructed binaries
- **Functions / coroutines:**
  - `def main()` — Main function for command-line usage

### `training_material_generator.py`
- **Summary:** Training Material and Case Study Generator
- **Classes:**
  - `TrainingModule` — Represents a training module with content and exercises
  - `CaseStudy` — Represents a security case study with analysis and lessons
  - `InteractiveLearningModule` — Represents an interactive learning module with hands-on components
  - `TrainingContentGenerator` — Generates automated security training content
- **Functions / coroutines:**
  - `def main()` — Main function for testing the training material generator

### `vulnerability_dataset_loader.py`
- **Summary:** Vulnerability Dataset Loader
- **Classes:**
  - `VulnerabilityRecord` — Represents a vulnerability record for training
  - `VulnerabilityDatasetLoader` — Loads vulnerability datasets from various sources
- **Functions / coroutines:**
  - `def main()` — Test the vulnerability dataset loader

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
