# `claude.md` — `app_reverse_engineering/js_recovery_toolkit`

**Repository path:** `src/reveng/app_reverse_engineering/js_recovery_toolkit/`

Breadcrumb for AI navigation: this folder’s files, top-level Python symbols, and one-line intent.

## Python modules

### `__init__.py`
- **Summary:** JS recovery toolkit — multi-strategy climb toward higher attribution coverage.

### `behavior_probe.py`
- **Summary:** Behavior overlap probe — string/flag CUJ similarity (not file recall).
- **Classes:**
  - `BehaviorOverlap`
- **Functions / coroutines:**
  - `def behavior_token_overlap()`

### `bun_serialized_sourcemap.py`
- **Summary:** Decode Bun ``SerializedSourceMap`` blobs (standalone compile sourcemaps).
- **Classes:**
  - `BunSerializedSourceMap`
- **Functions / coroutines:**
  - `def _read_ptr()`
  - `def _slice()`
  - `def _zstd_decompress()`
  - `def parse_serialized_sourcemap()` — Parse a Bun SerializedSourceMap blob; decompress zstd sourcesContent.
  - `def build_serialized_sourcemap_fixture()` — Build a minimal SerializedSourceMap blob for hermetic tests.
  - `def materialize_serialized_sources()` — Write recovered sources under output_dir; return files written.

### `coverage_union.py`
- **Summary:** Singleton high-confidence attribution + coverage union toward 100% of survivors.
- **Classes:**
  - `CoverageReport`
- **Functions / coroutines:**
  - `def _norm_path()`
  - `def _digest()`
  - `def load_map_sources()`
  - `def singleton_literal_hits()` — Confirm paths with a unique ≥20-char literal that appears in the bundle.
  - `def union_coverage()` — attributed: path -> method name.

### `ensemble_index.py`
- **Summary:** Ensemble fingerprint index/scan using expanded signal kinds.
- **Classes:**
  - `EnsembleIndex`
  - `EnsembleHit`
- **Functions / coroutines:**
  - `def _is_vendor()`
  - `def _normalize()`
  - `def _digest()`
  - `def build_ensemble_index_from_sourcemap()`
  - `def scan_ensemble()`

### `ensemble_signals.py`
- **Summary:** Expanded signal extractors for fingerprint transfer (ensemble).
- **Functions / coroutines:**
  - `def extract_ensemble_signals()` — Return ``(kind, value)`` candidates from source or bundle text.

### `external_tools.py`
- **Summary:** Optional external CLI adapters (Exa-discovered tools). Never hard-required.
- **Classes:**
  - `ExternalToolResult`
- **Functions / coroutines:**
  - `def _which()`
  - `def probe_external_tools()`
  - `def try_webcrack()` — Unpack/unminify via ``npx webcrack`` when Node is available.
  - `def try_wakaru()` — Unpack via ``npx @wakaru/cli`` when available.
  - `def try_bun_extract_in_tree()` — Use REVENG in-tree Bun extractor (inspired by unbun / bun-demincer research).
  - `def write_tool_probe_json()`

### `graph_complete.py`
- **Summary:** Soft import-graph completion after fingerprint confirms.
- **Classes:**
  - `GraphHint`
- **Functions / coroutines:**
  - `def _imports_of()`
  - `def suggest_graph_completions()` — Suggest anonymous→path links when import sets uniquely identify a confirm.

### `iterative_defrag.py`
- **Summary:** Iterative 'disk defrag' unlock loop for stale-map → bundle attribution.
- **Classes:**
  - `DefragRound`
  - `DefragResult`
- **Functions / coroutines:**
  - `def _oracle()`
  - `def _unique_tokens()`
  - `def _build_global_owners()` — token -> path if unique to exactly one source.
  - `def _rel_imports()`
  - `def _resolve_rel_candidates()`
  - `def _graph_unlock()`
  - `def _cooccur_unlock()`
  - `def _word_map_unlock()`
  - `def _soft_assign_unlock()`
  - `def run_iterative_defrag()`

### `llm_digest.py`
- **Summary:** Optional AST-chunked LLM summarize (non-hermetic).
- **Classes:**
  - `LlmModuleDigest`
- **Functions / coroutines:**
  - `def tags_from_summary()`
  - `def summarize_unlocked_modules()` — Run LLM summarize on a bounded set of unlocked module bodies.
  - `def heuristic_summarize_fn()` — Hermetic stand-in for an LLM: describe features without a model.

### `pipeline.py`
- **Summary:** End-to-end JS recovery toolkit pipeline (Waves 7–10; Option C climb).
- **Classes:**
  - `ToolkitReport`
- **Functions / coroutines:**
  - `def run_recovery_toolkit()` — Run materialize → fingerprint → ensemble → graph → behavior (+ optional externals).

### `provider_summarize.py`
- **Summary:** Real LLM summarize providers for AST-chunked module digests.
- **Functions / coroutines:**
  - `def _http_json()`
  - `def _prompt()`
  - `def openai_compat_summarize()`
  - `def ollama_summarize()`
  - `def anthropic_summarize()`
  - `def build_summarize_fn()` — Return (fn, notes). Prefer: openai_compat | ollama | anthropic | heuristic.
  - `def probe_providers()` — Lightweight reachability probe (no model generate).

### `readable_normalize.py`
- **Summary:** Hermetic readable-normalize (beautify-lite) for minified JS.
- **Classes:**
  - `ReadableNormalizeResult`
- **Functions / coroutines:**
  - `def readable_normalize()` — Beautify-lite: minifier idioms + line breaks. Caps output size.

### `semantic_digest.py`
- **Summary:** Semantic feature digests — deterministic 'what does this chunk do' anchors.
- **Classes:**
  - `SemanticDigest`
- **Functions / coroutines:**
  - `def extract_semantic_features()` — Return sorted unique semantic feature tags for a code body.
  - `def digest_sources()`
  - `def semantic_overlap_unlock()` — Unlock unattributed sources whose semantic feature set uniquely matches

### `soft_assignment.py`
- **Summary:** Soft bipartite source↔chunk assignment (Hungarian / linear sum).
- **Classes:**
  - `SoftAssignResult`
- **Functions / coroutines:**
  - `def hungarian_unique_assignments()` — Global max-weight unique path↔chunk matching with margin gate.
  - `def _char_ngram_topk()` — Char n-gram TF-IDF cosine (unsupervised clone feature channel).
  - `def _blend_scores()`
  - `def soft_assign_sources_to_bundle()`

### `structural_match.py`
- **Summary:** Structural MinHash matching (astdiff-inspired, pure Python, hermetic).
- **Classes:**
  - `StructuralMatch`
- **Functions / coroutines:**
  - `def normalize_tokens()`
  - `def shingles()`
  - `def _hash_shingle()`
  - `def minhash_signature()`
  - `def jaccard_from_sigs()`
  - `def file_signature()`
  - `def chunk_bundle()` — Sliding windows over large bundles (Claude-scale).
  - `def match_sources_to_bundle()` — Greedy unique structural matches of map sources onto bundle chunks.

### `tag_boost.py`
- **Summary:** Reinject LLM digest tags into a second defrag unlock pass.
- **Classes:**
  - `TagBoostResult`
- **Functions / coroutines:**
  - `def _bundle_has_tag()`
  - `def inject_digest_tags_as_pseudo_signals()` — Append LLM tags as comment tokens into a copy of source bodies for word_map/cooccur.
  - `def unlock_by_llm_tags()` — Attribute unattributed sources when ≥min_tags unique digest tags appear in bundle.
  - `def run_tag_boost_defrag()` — Merge llm_tag unlocks then continue iterative defrag from the expanded seed.

### `tombstone.py`
- **Summary:** Tombstone / recoverable-oracle metrics for stale-map → bundle climbs.
- **Classes:**
  - `TombstoneReport`
- **Functions / coroutines:**
  - `def classify_tombstones()` — Partition oracle sources by whether salient tokens hit the bundle.
  - `def recoverable_oracle_coverage()`

### `word_map.py`
- **Summary:** TF-IDF / cosine word-mapping (embedding-nearest-neighbor without neural nets).
- **Classes:**
  - `WordMapResult`
- **Functions / coroutines:**
  - `def tokenize_code()`
  - `def _vectorizer()`
  - `def chunk_text()`
  - `def cosine_topk()` — Return path → [(chunk_idx, cosine), ...] sorted descending.
  - `def best_unique_assignments()` — Greedy unique path↔chunk matching (precision-first).
  - `def word_map_sources_to_bundle()`

---
*Generated or maintained for Claude / AI agents. Primary package: `src/reveng`.*
