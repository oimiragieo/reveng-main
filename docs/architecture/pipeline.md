# Pipeline

The enhanced pipeline executes deterministic stages so that CLI users, services, and automation agents observe the same behaviour. Each stage writes structured results to `REVENGAnalyzer.enhanced_results`.

| Step | Description | Implementation |
| --- | --- | --- |
| 1–7 | Core REVENG analysis (disassembly, metadata extraction, reconstruction prep). | `reveng.analyzer.REVENGAnalyzer._run_reveng_pipeline` |
| 8–9 | Corporate exposure assessment and reporting. | `reveng.analyzer._analyze_corporate_exposure` |
| 10 | Automated vulnerability discovery using ML + Ghidra context. | `reveng.pipeline.steps.vulnerability.run_vulnerability_discovery` |
| 11 | Threat intelligence correlation and IOC enrichment. | `reveng.pipeline.steps.threat_intel.run_threat_intelligence` |
| 12 | Enhanced reconstruction (optional). | `reveng.analyzer._step12_enhanced_reconstruction` |
| 13 | Demonstration generation / reporting. | `reveng.analyzer._step13_security_demonstrations` |

## Adding a New Step

1. Create a module under `reveng/pipeline/steps/` exporting a function that accepts the analyzer instance.
2. Register the function in `reveng/pipeline/steps/__init__.py` or invoke it directly from the orchestrator.
3. Update the analyzer to call the new function and populate `enhanced_results` with a serialisable payload.
4. Document the step in this table and add focused unit tests under `tests/unit`.

## Context Object

Steps can access the following attributes through the analyzer:

- `binary_path`, `binary_name`, `analysis_folder`
- `ghidra_extractor` (if the Ghidra integration is enabled)
- `enhanced_results` (dict that feeds downstream reporting)
- `vulnerability_discovery_engine`, `threat_intelligence_correlator`, etc. — lazy-instantiated dependencies.

When steps depend on optional modules, catch `ImportError` and record a `{ "status": "skipped", "error": "module_not_found" }` payload so callers understand the capability was unavailable rather than failing unexpectedly.
