# Design — Iterative defrag + word-map unlock (Wave 8.5, option C)

**CEO choice:** report both metrics; **ship bar = survivor/unlockable coverage 100%**; full-oracle coverage is aspirational dogfood.

**Metaphor:** stale-map sources vs Bun bundle ≈ fragmented disk. Seed high-confidence sectors → propagate constraints → unlock neighbors → repeat to fixed point.

## Exa prior art (build-on, not vendor)

| Source | Idea we reuse | Hermetic? |
|--------|---------------|-----------|
| [astdiff](https://github.com/shcv/astdiff) | MinHash / structural match (already Wave 8) | pure Py port |
| [jsNaughty / Autonym](https://github.com/bvasiles/jsNaughty) | SMT / language-model “next name” — **inspiration only** | Moses = non-hermetic |
| [CASCADE](https://arxiv.org/abs/2507.17691) | LLM+IR iterative unlock — inspiration; we use deterministic IR substitutes | Gemini = non-hermetic |
| TF-IDF + cosine (sklearn plagiarism tools, code-embeddings doc2vec) | **Word mapping** ≈ embedding nearest-neighbor without neural weights | yes (`sklearn` already in requirements) |
| Import-graph completion (in-tree `graph_complete`) | Neighbor unlock from confirmed requires | yes |
| Co-occurrence near confirmed tokens | Soft “same sector” evidence | yes |
| 0xdevalias fingerprint gists | Stable salient tokens for library ID | yes |

**Deliberate non-deps:** Moses, Gemini, CodeBERT, gensim doc2vec weights — optional later lanes, not CI ship bar.

## Algorithm

```
seed = ensemble ∪ singleton ∪ fingerprint ∪ structural
unlockable = seed
loop rounds ≤ N until no new attributions:
  graph_unlock   # relative imports from confirmed bodies
  cooccur_unlock # unique weak token near confirmed unique token in bundle
  word_map_unlock # TF-IDF cosine source↔bundle-window, greedy unique
  unlockable |= new
attributed grows; survivor_coverage = |attr∩unlockable|/|unlockable| → 1.0 by construction
oracle_coverage = |attr|/|oracle_src|  # report; climb
```

## Measured results

### Hermetic fixture

- Neighbor file has only a weak short token (not ensemble ≥2); unlocked via graph/cooccur.
- After defrag: `survivor_coverage=1.0`, `oracle_coverage=1.0`.

### Operator-local Claude (stale map → Bun `stable/cli.js`)

| Stage | attributed | oracle_coverage | survivor/unlockable |
|-------|-----------:|----------------:|--------------------:|
| Seed (ensemble+singleton) | 621 | 0.3265 | 1.0 |
| After iterative defrag | **990** | **0.5205** | **1.0** |
| Round unlocks | +311, +55, +2, +1 | | cooccur / word_map / graph |

Methods on final set: ensemble 553, singleton 68, cooccur 278, word_map 73, graph_unlock 18.

**Not** 100% of old oracle (deleted/rewritten modules). **Is** 100% of unlockable set at fixed point for this run.


## Modules

- `word_map.py` — TF-IDF / cosine / unique assignment
- `iterative_defrag.py` — fixed-point loop
- Pipeline stage `iterative_defrag`
- Fixture: neighbor only unlockable via graph/cooccur (not ensemble ≥2)

## Honesty

Fixture 100% ≠ Claude oracle 100%. Deleted modules never unlock. Option C reports both.
