# `claude.md` — `tools/anti_analysis`

**Repository path:** `src/reveng/tools/anti_analysis/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** Anti-Analysis Tools

### `bun_extractor.py`
- **Summary:** Bun executable detection and JavaScript extraction helpers.
- **Classes:**
  - `BunExecutableInfo` — Detection result for a Bun-compiled executable.
  - `BunExtractionResult` — Result of extracting bundled JavaScript from a Bun executable.
  - `BunModuleEntry` — Single Bun module entry parsed from the embedded module graph.
  - `BunModuleGraph` — Parsed Bun module graph metadata.
  - `BunRecoveryResult` — Result of reconstructing the Bun virtual filesystem.
  - `BunNormalizationResult` — Result of normalizing recovered Bun JavaScript into a project workspace.
  - `BunDependencyAnalysis` — Recovered dependency information for a normalized Bun workspace.
  - `BunSeaBuildResult` — Result of packaging a normalized Bun workspace with Node SEA.
  - `BunSeaWorkflowResult` — End-to-end Bun rebuild workflow state for higher-level surfaces.
  - `BunSourcemapProvenance` — Structured provenance and validation metadata for recovered sourcemaps.
  - `BunPostprocessingHook` — Recommended post-processing step for recovered JavaScript artifacts.
  - `BunSemanticCheck` — Structured semantic normalization check for recovered JS/TS workspaces.
  - `PEStubAnalysis` — Summary of the native PE stub that hosts an embedded Bun bundle.
  - `PETLSCallback` — Resolved TLS callback metadata.
  - `PEInstructionPreview` — Small disassembly preview for startup-path triage.
  - `PEStartupTarget` — Deduplicated first-hop startup target summary.
  - `PEStartupGraphNode` — Bounded startup-graph node used for triage output.
  - `PEStartupGraphEdge` — Bounded startup-graph edge used for triage output.
  - `PEStartupGraph` — Compact bounded startup graph rooted at entrypoint/TLS callbacks.
  - `PEHandoffSignal` — Strong signal that startup flow is converging toward Bun/JS runtime handoff.
  - `PECrossReference` — Cross-linked PE clue surfaced from resources, manifests, or string evidence.
  - `PERuntimeObservationPoint` — Recommended runtime observation point for debugging or dumping.
  - `PERuntimeReadiness` — Structured runtime-observation guidance when static analysis stalls.
  - `PEDumpGuidanceAction` — Escalation action for runtime-unpacked or dynamically resolved startup paths.
  - `PEDumpGuidance` — Structured escalation guidance for dump/import reconstruction workflows.
  - `BunExecutableExtractor` — Detect and extract JavaScript from Bun single-file executables.
- **Functions / coroutines:**
  - `def select_bun_recompilation_input()` — Choose the cleanest recovered Bun artifact for downstream recompilation.
  - `def build_bun_report_severity_summary()` — Build a compact reconstruction-risk ranking for Bun analysis/rebuild reports.
  - `def build_bun_runtime_escalation_summary()` — Build a compact analyst-facing escalation plan from Bun static/rebuild evidence.
  - `def build_bun_equivalence_validation_summary()` — Build a compact equivalence-confidence summary for rebuilt Bun artifacts.
  - `def _serialize_bun_normalization()`
  - `def _serialize_bun_recovery()`
  - `def _serialize_bun_build_result()`
  - `def run_bun_sea_workflow()` — Recover, normalize, and package a Bun executable through the Node SEA path.

### `packer_detector.py`
- **Summary:** Packer Detection for REVENG
- **Classes:**
  - `PackerInfo` — Information about detected packer
  - `PackerDetector` — Detects packing/compression in binaries.
- **Functions / coroutines:**
  - `def quick_detect()` — Quick packer detection

### `universal_unpacker.py`
- **Summary:** Universal Unpacker for REVENG
- **Classes:**
  - `UnpackResult` — Result of unpacking operation
  - `UniversalUnpacker` — Universal unpacker for packed binaries.
- **Functions / coroutines:**
  - `def quick_unpack()` — Quick unpacking of a packed binary

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
