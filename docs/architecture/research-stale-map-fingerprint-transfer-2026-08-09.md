# Research bank — stale-map transfer / fingerprint demangle (2026-08-09)

Exa MCP research for the RE framing: **old map is close but VLQ-dead; recover the rest via fingerprints + optional LLM token mapping.**  
Operator-local Claude trees stay out of git. Tracked micro-bundle remains the ship gate.

## Problem restated (industry already named it)

Sentry: mismatched compiled file ↔ source map is a known failure mode (“files incorrectly versioned”). Wrong map produces **plausible but wrong** line bindings — worse than no map.  
→ Do **not** VLQ-apply `cli.js.map@2.1.88` to Bun `cli.js@2.1.226`.

What *does* survive across versions: strings, API names, structural AST shape, export/object keys (our probe: ~69% unique long literals still in new bundle).

## Tooling / papers (adopt vs defer)

### A. Deterministic fingerprint transfer (ADOPT — Wave 5 candidate)

| Source | URL | Role |
| --- | --- | --- |
| 0xdevalias AST fingerprint / minified-lib notes | https://gist.github.com/0xdevalias/31c6574891db3e36f15069b859065267 | Canonical link dump: normalize AST → fingerprint → match |
| poc-ast-tools (diff-minimiser, text_similarity, rename-chunk) | https://github.com/0xdevalias/poc-ast-tools | Normalize identifiers; compare builds ignoring minify noise |
| humanify issue #97 (deterministic renames across versions) | https://github.com/jehna/humanify/issues/97 | Exact recipe: normalize → hash chunks → reuse prior name map → LLM only on deltas |
| bun-demincer export-key rename | https://github.com/vicnaum/bun-demincer | Pattern: string keys as rename hints (already Wave 4 hints class) |

**REVENG shape:** `js_stale_map_transfer` index from map `sourcesContent` / oracle `src/`:
`(unique_literal | export_name | string_key) → source_path`  
Scan new bundle → hit table → confidence scores. Brute-forceable; no LLM required for tier A.

### B. Structural align old↔new minified (ADOPT concepts — optional hard dep later)

| Source | URL | Role |
| --- | --- | --- |
| **astdiff** (MinHash + structural hash + string fingerprints) | https://github.com/shcv/astdiff | Match renamed functions across minified versions; can consume maps for names |
| smartdiff / sem (entity-level AST match) | https://github.com/opensensor/smartdiff · https://github.com/ataraxy-labs/sem | Same idea family |
| tdiff (Zhang–Shasha tree edit) | https://github.com/blendmaster/tdiff | Classic AST diff; smaller files |

**REVENG shape:** split old map-era materialized modules vs new chunks (if/when Bun unpack yields multi-module); MinHash match → copy path labels. Reference astdiff; don’t vendor unless dogfood proves need.

### C. LLM token / identifier mapping (ADOPT as **residual only**)

| Source | URL | Role |
| --- | --- | --- |
| **humanify** (LLM suggests names; oxc AST renames) | https://github.com/jehna/humanify | Production pattern: LLM proposes, AST applies |
| CASCADE (Google) — LLM finds prelude, IR transforms | https://arxiv.org/html/2507.17691 | Hybrid LLM+compiler IR |
| JsDeObsBench / JSIMPLIFIER | https://arxiv.org/html/2506.20170v1 · NDSS 2026 JSIMPLIFIER | LLM rename benchmarks |
| reverse-machine | https://github.com/mariolqn/reverse-machine | webcrack + Babel + LLM rename |
| JSNaughty / Autonym (FSE 2017) | https://cmustrudel.github.io/papers/fse17jsnaughty.pdf · https://github.com/bvasiles/jsnaughty | SMT name recovery; train on clear↔minified pairs |

**REVENG shape:** after tier A/B freeze high-confidence map, LLM only on unmatched bindings; prefer ollama; never claim GA from LLM rename alone. Cache suggestions keyed by normalized AST hash (humanify #97).

### D. Same-build map compose (NOT our problem)

| Source | URL | Role |
| --- | --- | --- |
| ampproject/remapping | https://github.com/ampproject/remapping | Chain babel→webpack→minify maps for **one** build |
| recover-source / unmapjs / sourcemap-extract | various | Need a **matching** `.map` |

Useful elsewhere in REVENG; **does not** fix stale map ↔ new Bun PE.

## Measured local priors (this session)

- Old map VLQ line fit vs old `cli.js`: **~1.0**; vs new Bun extract: **~0.31**
- Unique long literals from map `src/` present in new: **~69%**
- Unique export-name tokens present in new: **~29%**
- Materialize old map → Ralph vs `src/`: **recall 1.0** (map-era surface only)

## Proposed REVENG pipeline (“puzzle pieces”)

```text
[stale map + sourcesContent] ──► Fingerprint index (A)
[new cli.js / Bun VFS] ─────────► Hit scan + confidence (A)
        │
        ├─ high confidence ──► hints JSON / optional AST rename
        ├─ medium ──► structural MinHash align if multi-module (B)
        └─ residual ──► LLM name suggest + AST apply + cache (C)
        │
        └──► Ralph score vs operator-local oracle (honesty gate)
```

**Honesty gates:** tier A alone must beat untreated baseline on a discriminating control; LLM optional; no Anthropic IP in repo; R-RALPH-2 stays open until 0.8 on authorized large surface.

## Thinktank + Fable (2026-08-09)

**Verdict:** unanimous **APPROVE_WITH_NITS** (claude, dedicated Fable headless, codex, agy, copilot; droid EMPTY / cursor MISSING_CLI = non-votes).

Full synthesis: [`thinktank-stale-map-fingerprint-transfer-2026-08-09.md`](thinktank-stale-map-fingerprint-transfer-2026-08-09.md).

Must-fix before coding: hashed fingerprints; uniqueness+IDF+≥2-signal confidence; bidirectional mismatch control; split provenance vs name metrics; hermetic-only ship gate; Tier B demoted pending Bun-unpack spike; machine-checked “≠ decoded exe” honesty.

## Out of scope / do not build

- “Run old `.map` VLQ on new `.exe` extract” as a product claim  
- Committing Claude recovered trees  
- Hard-dep Moses/JSNaughty stack without hermetic CI story  
- Enterprise GA from fingerprint transfer alone
