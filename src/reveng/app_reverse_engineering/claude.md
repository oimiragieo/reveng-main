# `claude.md` — `app_reverse_engineering`

**Repository path:** `src/reveng/app_reverse_engineering/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Subpackages / subfolders (see each `claude.md`)

- `adapters/` — [`claude.md`](adapters/claude.md)
- `js_recovery_toolkit/` — [`claude.md`](js_recovery_toolkit/claude.md)

## Python modules

### `__init__.py`
- **Summary:** Shared app reverse-engineering framework with language adapters.
- **Functions / coroutines:**
  - `def create_default_framework()` — Create the default framework with built-in adapters.

### `capability_report.py`
- **Summary:** Structured capability dimensions for app reverse-engineering results.
- **Functions / coroutines:**
  - `def project_tree_stats()` — Count files and bytes under a reconstructed project (skips node_modules).
  - `def resolve_javascript_probe_timeout_sec()` — Pick a subprocess timeout from tree size unless the caller set ``explicit``.
  - `def _safe_float()`
  - `def _extract_oracle_alignment()`
  - `def _artifact_presence()`
  - `def _collect_js_syntax_candidates()`
  - `def _resolve_package_cli_entry()` — Pick a Node entry for ``node <entry> --help``: ``bin``, then ``main``, then
  - `def _resolve_typescript_cli_entry()` — Pick a TypeScript entry (``bin`` / ``main``) when no JS entry resolves.
  - `def run_javascript_behavior_probe()` — Run ``node <entry> --help`` from the project root (npm-style CLI smoke).
  - `def run_javascript_npm_lifecycle_probe()` — Optional ``npm pack --dry-run`` smoke for reconstructed Node projects (P3-BP-2).
  - `def _run_node_check()`
  - `def analyze_js_reconstructed_project()` — Best-effort smoke metrics for a recovered JavaScript/TypeScript project tree.
  - `def build_capability_report()` — Assemble the `capability_report` object persisted into app analysis.json.

### `cli.py`
- **Summary:** Generic CLI for app-level reverse engineering across languages.
- **Functions / coroutines:**
  - `def create_parser()` — Create the generic app reverse-engineering CLI parser.
  - `async def main()` — Async entrypoint for the generic app reverse-engineering CLI.
  - `def console_main()` — Synchronous console entrypoint.

### `contracts.py`
- **Summary:** Shared contract helpers for app-level reverse-engineering outputs.
- **Functions / coroutines:**
  - `def enrich_app_analysis_payload()` — Attach shared schema, validation, evidence, and provenance fields.
  - `def promote_grade_from_capability()` — Promote a validation grade using JS behavior evidence without overclaiming.
  - `def build_validation_summary()` — Build a compact analyst-facing validation summary.
  - `def build_app_provenance()` — Build shared provenance for app-level reverse-engineering output.
  - `def build_app_evidence()` — Create evidence references for major analyst-facing artifacts.
  - `def rewrite_analysis_file()` — Rewrite the machine-readable analysis summary with normalized formatting.

### `corpus.py`
- **Summary:** Corpus runner for app reverse-engineering workflows.
- **Classes:**
  - `AppCorpusEntry` — One app reverse-engineering corpus row.
- **Functions / coroutines:**
  - `def _utc_timestamp()`
  - `def select_app_corpus_entries()` — Filter corpus entries by name while preserving manifest order.
  - `async def run_app_corpus()` — Run a corpus of app reverse-engineering entries and write a rollup report.
  - `def run_app_corpus_sync()` — Synchronous wrapper for the async corpus runner.

### `framework.py`
- **Summary:** Language-agnostic app reverse-engineering framework.
- **Classes:**
  - `AppAdapter` — Protocol implemented by language-specific app adapters.
  - `AppReverseEngineeringFramework` — Registry and dispatch layer for app reverse-engineering adapters.

### `js_oracle_scorecard.py`
- **Summary:** Filename-set JS oracle scorecard (honest reconstruction metrics).
- **Functions / coroutines:**
  - `def _basename_tokens()`
  - `def _iter_oracle_relpaths()`
  - `def _dedupe_existing()`
  - `def _recovered_rel_or_none()`
  - `def compute_js_project_file_scorecard()` — Compute filename-set recall/precision and aggregate scores.

### `js_project_materialize.py`
- **Summary:** Materialize ``output_dir/project`` for JS oracle scorecards (Wave 4).
- **Classes:**
  - `ProjectMaterializeResult`
- **Functions / coroutines:**
  - `def _wipe_project()`
  - `def _sanitize_relpath()`
  - `def _write_text()`
  - `def _find_sibling_map()`
  - `def _materialize_from_sourcemap()`
  - `def _materialize_from_bun_vfs()`
  - `def materialize_js_project_tree()` — Create ``output_dir/project`` for filename-set oracle scoring.

### `js_stale_map_transfer.py`
- **Summary:** Stale-map fingerprint transfer (Wave 5 Tier A) — attribution evidence only.
- **Classes:**
  - `FingerprintIndex` — In-memory index: digest → first-party source path (unique digests only).
  - `ConfirmedAttribution`
  - `TransferResult`
- **Functions / coroutines:**
  - `def _is_vendor_path()`
  - `def _normalize_source_path()`
  - `def _digest()`
  - `def _extract_signals()` — Return list of (kind, value) signal candidates from source or bundle text.
  - `def build_index_from_sourcemap()`
  - `def build_index_from_sources()` — Index unique-to-one-source signals. Vendor paths skipped.
  - `def scan_bundle()` — Scan bundle for hashed fingerprint hits; confirm paths with ≥ min_signals.
  - `def index_has_raw_secret_literals()` — Honesty helper: serialized index must not contain plaintext secret fixtures.
  - `def _sourcemap_content_by_path()` — Map normalized source path → sourcesContent body (first wins).
  - `def apply_fingerprint_backed_missing()` — Write map ``sourcesContent`` for fingerprint-confirmed paths missing under project.

### `js_structural_identifiers.py`
- **Summary:** Collect generic structural identifier *hints* from JS/TS text (Wave 4).
- **Functions / coroutines:**
  - `def collect_structural_identifier_hints()` — Return a JSON-serializable hint payload for ``source_path``.

### `models.py`
- **Summary:** Shared models for app-level reverse engineering workflows.
- **Classes:**
  - `AppReverseEngineeringResult` — Normalized result returned by language-specific app adapters.

### `ralph_js_loop.py`
- **Summary:** Ralph-style outer loop for JavaScript oracle scoring (execute → measure → retry with variants).
- **Functions / coroutines:**
  - `def load_js_ralph_variants_from_json()` — Load variant profiles from a JSON array of objects.
  - `def oracle_recall_precision()` — Read project_file_recall / project_file_precision from enriched analysis metadata.
  - `def js_behavior_probe_tier()` — Return 0–2 from ``capability_report.dimensions.javascript_behavior_probe``.
  - `def ralph_score_key()` — Lexicographic ranking: recall, precision, JS behavior-probe tier, then F1-like product.
  - `def default_js_ralph_variants()` — Built-in attempt profiles. Each dict is merged into framework.reverse_engineer kwargs.
  - `def heavy_js_ralph_variants()` — Optional slow / external-tool profiles appended after defaults.
  - `def compose_ralph_variants()` — Build the variant list: optional defaults, optional JSON-loaded profiles, optional heavy tools.
  - `async def run_ralph_js_oracle_loop()` — Run up to ``max_attempts`` attempts, cycling ``variants``, keeping the best oracle recall.

### `spec_library.py`
- **Summary:** Helpers for writing app reverse-engineering spec libraries.
- **Classes:**
  - `TopicDefinition` — Definition of one spec-library topic.
- **Functions / coroutines:**
  - `def normalize_skip_patterns()` — Normalize comma-separated or repeated skip patterns.
  - `def should_skip_text()` — Return whether a snippet should be omitted based on skip patterns.
  - `def build_directory_tree()` — Render a bounded directory tree for documentation.
  - `def segment_text()` — Split dense text into bounded pseudo-lines.
  - `def collect_keyword_matches()` — Collect top-scoring evidence snippets across multiple sources.
  - `def render_directory_structure_doc()` — Render the directory structure document.
  - `def render_specs_index()` — Render the main SPECS index.
  - `def render_topic_spec()` — Render one topic specification document.
  - `def render_domain_file()` — Render the domain evidence split file.
  - `def top_values()` — Return a stable limited list of unique values.

### `tracked_bundle_manifest.py`
- **Summary:** Tracked, reproducible JavaScript bundle artifacts — manifest and integrity proofs.
- **Classes:**
  - `TrackedBundleVerifyResult` — Result of comparing on-disk bytes to a committed manifest.
- **Functions / coroutines:**
  - `def load_tracked_js_bundle_manifest()`
  - `def _sha256_file()`
  - `def verify_tracked_js_bundle_artifact()` — Return ok=True when every listed file exists and matches manifest SHA-256.
  - `def compute_files_sha256()` — Compute lowercase SHA-256 hex digests for files under artifact_dir.
  - `def write_build_manifest()` — Write build_manifest.json (used by scripts/build_tracked_js_bundle.py).
  - `async def benchmark_tracked_js_bundle_row()` — Run the JavaScript app adapter on a tracked bundle + oracle; return summary dict for tests/reports.

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
