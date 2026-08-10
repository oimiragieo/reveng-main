# CEO update — 2026-08-10 (Wave 8.5: iterative defrag + word-map)

## Verdict

Option **C**: report both metrics; ship bar = unlockable/survivor **100%**.

Wave 8.5 adds an iterative “disk defrag” loop: seed fingerprints → unlock via **import graph**, **co-occurrence**, and **TF-IDF cosine word-mapping** (AI-nearest-neighbor math without shipping neural nets / Moses / Gemini).

| Gate | Result |
|------|--------|
| Hermetic fixture (incl. weak neighbor) | **oracle + survivor 1.0** after defrag |
| Claude stale→Bun **survivor/unlockable** | **1.0** |
| Claude **oracle** coverage | **0.5205 (990/1902)** — was ~0.33 seed-only |
| New unlocks beyond seed | **+369** |
| `decoded_exe_claim` | false |
| R-RALPH-2 / Phase 6 / GA | **still open** |

## Exa build-ons

astdiff MinHash · jsNaughty/SMT *inspiration* · CASCADE iterative *inspiration* · sklearn TF-IDF/cosine · in-tree graph_complete.

## Next

Tighten cooccur precision controls; more rounds / signal kinds; re-measure when Bun embeds SerializedSourceMap.

Research: `docs/architecture/research-wave85-iterative-defrag-wordmap-2026-08-10.md`
