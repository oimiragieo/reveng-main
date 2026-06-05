# `claude.md` — `reporting/visualization`

**Repository path:** `src/reveng/reporting/visualization/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Visualization Tools

### `code_visualizer.py`
- **Classes:**
  - `CallGraphNode` — Node in call graph (function/method)
  - `DependencyNode` — Node in dependency graph (module/class)
  - `CallGraphBuilder` — Builds call graphs from source code analysis
  - `DependencyGraphBuilder` — Builds dependency graphs from code analysis
  - `GraphVisualizer` — Generates visualizations from NetworkX graphs
- **Functions / coroutines:**
  - `def main()` — CLI interface for code visualization

### `executive_reporting_engine.py`
- **Summary:** Executive Reporting and Risk Visualization Engine
- **Classes:**
  - `RiskLevel` — Risk severity levels
  - `BusinessImpact` — Business impact categories
  - `RiskMetric` — Individual risk metric
  - `ExecutiveSummary` — Executive summary data structure
  - `RemediationRoadmap` — Remediation roadmap item
  - `ExecutiveReportingEngine` — Executive reporting and risk visualization engine for creating

### `technical_reporting_engine.py`
- **Summary:** Technical Documentation and Research Reporting Engine
- **Classes:**
  - `EvidenceType` — Types of evidence
  - `ReportFormat` — Report output formats
  - `Evidence` — Evidence item for technical reports
  - `Finding` — Technical finding with evidence chain
  - `Methodology` — Research methodology documentation
  - `Dataset` — Research dataset information
  - `TechnicalReportingEngine` — Technical documentation and research reporting engine for creating

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
