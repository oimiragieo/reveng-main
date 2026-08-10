# Research — Wave 10 soft bipartite assignment + tombstones (2026-08-10)

**Goal:** climb Claude stale→Bun oracle coverage past ~55% by replacing greedy unique TF-IDF matching with **global linear assignment** + multi-feature scores, and by reporting **tombstone / recoverable** coverage so deleted modules stop looking like failures.

**Ship bar (option C):** unlockable/survivor **100%** (unchanged). Full-oracle remains aspirational.

## Exa → arXiv prior art

| Paper | Idea we reuse | Hermetic ship? |
|-------|---------------|----------------|
| [Sinkhorn for Lifted Assignment](https://arxiv.org/abs/1707.07285) | Entropic OT / Softassign for large matching; JA relaxation for QAP | **Inspiration** — we use exact `scipy.optimize.linear_sum_assignment` (Hungarian) on the bipartite source↔chunk graph (smaller, precision-first). Sinkhorn reserved if we add quadratic co-occur terms later. |
| [Unsupervised clone similarity measures](https://arxiv.org/abs/2401.09885) | Ensemble of unsupervised similarity features beats single measure | **Yes** — blend word TF-IDF (0.6) + char n-gram TF-IDF 3–5 (0.4) before assignment |
| [GraphCodeBERT + extra features](https://arxiv.org/html/2408.08903) | Multi-channel features improve clone detection | **Partial** — feature blend only; no neural weights in CI |
| [CASCADE](https://arxiv.org/html/2507.17691) / [JSIMPLIFIER](https://arxiv.org/html/2512.14070) | LLM+IR iterative deobfuscation | Already Wave 9b optional lane; not CI ship bar |
| [SAFE-DEOBS](https://arxiv.org/abs/2009.09170) | Compiler-style static peels | Inspiration for normalize lane (Wave 9) |
| [CoE SBOM / clone search for JS bundles](https://arxiv.org/html/2512.14070) (related clone-search family) | Present-vs-absent component classification | **Yes** — tombstone classifier on token residue |

**Deliberate non-deps for this wave:** CodeBERT/GraphCodeBERT weights, Sinkhorn GPU stacks, Moses.

## Algorithms

### Soft assignment
```
for remaining sources:
  scores_word  = TFIDF_cosine(source, bundle_chunks)
  scores_char  = char_ngram_TFIDF_cosine(source, bundle_chunks)
  scores       = 0.6*word + 0.4*char
  assign       = Hungarian(max weight, threshold)
  keep edge iff margin(best − second) ≥ min_margin
```

Fixes the greedy trap: path A locks the only good chunk for path B even when A has a near-equal alternate.

### Tombstones
```
for src/ path:
  hits = count(salient tokens present in bundle)
  if hits < min_hits → tombstone (deleted/rewritten)
recoverable_oracle = |attr| / |oracle − tombstones|
```

## Modules
- `soft_assignment.py` — Hungarian + blend + margin
- `tombstone.py` — classify + recoverable coverage
- `iterative_defrag.py` — `soft_assign` unlock stage
- `pipeline.py` — `tombstone` stage artifact

## Measured (operator-local Claude)

Seed = Wave 9b attributed set (1053). Soft-assign on unique-residue remaining:

| Metric | Value |
|--------|------:|
| soft_new | +34 |
| oracle_coverage | **0.5715 (~57%)** |
| unique-residue survivors | 1028 |
| tombstones | 874 |
| recoverable_oracle_coverage | **0.8191 (~82%)** |

Naïve (any-token) tombstones falsely mark all 1902 as survivors on a 24MB bundle — unique-owner tokens are required.

## Honesty
- Fixture ≠ Claude oracle 100%
- Soft assign can still mis-attribute under heavy shared tokens — margin gate + unique-residue filter prefer precision
- `decoded_exe_claim=false`; R-RALPH-2 stays open
