"""Soft bipartite source↔chunk assignment (Hungarian / linear sum).

Prior art (Exa → arXiv, Wave 10)::

- Sinkhorn / lifted assignment (arXiv:1707.07285) — entropic OT for large
  QAP-scale problems. We use exact linear assignment via scipy for our
  source×chunk bipartite graph (smaller, precision-first).
- Unsupervised clone measures (arXiv:2401.09885) — ensemble of similarity
  features; we blend word TF-IDF + char n-gram TF-IDF cosines.
- Softassign / margin gating — reject ambiguous best≈second pairs to avoid
  fingerprint collisions that dominate the Claude Bun residual.

Does **not** claim exe decode or R-RALPH-2 close.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from .word_map import chunk_text, cosine_topk


@dataclass
class SoftAssignResult:
    assignments: Dict[str, Tuple[int, float]] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)
    decoded_exe_claim: bool = False

    def to_serializable(self) -> dict:
        return {
            "schema_version": "1.0",
            "result_type": "soft_assignment",
            "assignment_count": len(self.assignments),
            "assignments": {
                p: {"chunk_idx": idx, "score": score}
                for p, (idx, score) in self.assignments.items()
            },
            "notes": list(self.notes),
            "decoded_exe_claim": False,
        }


def hungarian_unique_assignments(
    scores: Dict[str, List[Tuple[int, float]]],
    *,
    threshold: float = 0.35,
    min_margin: float = 0.03,
) -> Dict[str, Tuple[int, float]]:
    """Global max-weight unique path↔chunk matching with margin gate.

    Cost matrix is negated similarity so ``linear_sum_assignment`` minimizes
    cost ≡ maximizes cosine. Paths/chunks with no edge above ``threshold`` are
    left unmatched. After assignment, drop pairs whose (best − second) margin
    on that path is below ``min_margin`` (collision guard).
    """
    if not scores:
        return {}
    paths = sorted(scores.keys())
    chunk_ids = sorted({idx for ranked in scores.values() for idx, _ in ranked})
    if not chunk_ids:
        return {}
    chunk_pos = {c: i for i, c in enumerate(chunk_ids)}
    n_p, n_c = len(paths), len(chunk_ids)

    try:
        import numpy as np
        from scipy.optimize import linear_sum_assignment
    except ImportError:
        # Fallback: greedy unique (same as word_map) if scipy absent
        from .word_map import best_unique_assignments

        return best_unique_assignments(scores, threshold=threshold)

    # Large finite pad so unmatched rows/cols stay cheap to leave empty via
    # rectangular assignment (scipy pads automatically for rectangular).
    BIG = 10.0
    cost = np.full((n_p, n_c), BIG, dtype=float)
    sim_lookup: Dict[Tuple[int, int], float] = {}
    for pi, path in enumerate(paths):
        for idx, score in scores[path]:
            if score < threshold:
                continue
            cj = chunk_pos[idx]
            # minimize negative similarity
            cost[pi, cj] = -float(score)
            sim_lookup[(pi, cj)] = float(score)

    row_ind, col_ind = linear_sum_assignment(cost)
    assigned: Dict[str, Tuple[int, float]] = {}
    for pi, cj in zip(row_ind, col_ind):
        if cost[pi, cj] >= BIG - 1e-9:
            continue
        score = sim_lookup.get((pi, cj))
        if score is None or score < threshold:
            continue
        path = paths[pi]
        ranked = sorted(scores[path], key=lambda t: float(t[1]), reverse=True)
        best = float(ranked[0][1]) if ranked else 0.0
        second = float(ranked[1][1]) if len(ranked) > 1 else 0.0
        # Margin vs runner-up on THIS path (not vs global)
        if best - second < min_margin and second > 0:
            continue
        # Also require the chosen edge is near the path's best
        if best - score > max(min_margin, 0.05) and min_margin > 0:
            continue
        assigned[path] = (chunk_ids[cj], score)
    return assigned


def _char_ngram_topk(
    query_texts: Dict[str, str],
    corpus_chunks: Sequence[str],
    *,
    top_k: int = 3,
) -> Dict[str, List[Tuple[int, float]]]:
    """Char n-gram TF-IDF cosine (unsupervised clone feature channel)."""
    if not query_texts or not corpus_chunks:
        return {}
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.metrics.pairwise import cosine_similarity
    except ImportError:
        return {}
    paths = list(query_texts.keys())
    docs = [query_texts[p] for p in paths] + list(corpus_chunks)
    vec = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        lowercase=False,
        min_df=1,
        max_features=80000,
    )
    try:
        matrix = vec.fit_transform(docs)
    except ValueError:
        return {}
    n_q = len(paths)
    sims = cosine_similarity(matrix[:n_q], matrix[n_q:])
    out: Dict[str, List[Tuple[int, float]]] = {}
    for i, path in enumerate(paths):
        ranked = sorted(enumerate(sims[i]), key=lambda t: float(t[1]), reverse=True)[:top_k]
        out[path] = [(int(idx), float(score)) for idx, score in ranked]
    return out


def _blend_scores(
    channels: Sequence[Dict[str, List[Tuple[int, float]]]],
    *,
    weights: Optional[Sequence[float]] = None,
) -> Dict[str, List[Tuple[int, float]]]:
    if not channels:
        return {}
    w = list(weights) if weights is not None else [1.0] * len(channels)
    s = sum(w) or 1.0
    w = [x / s for x in w]
    accum: Dict[str, Dict[int, float]] = {}
    for ch, weight in zip(channels, w):
        for path, ranked in ch.items():
            bucket = accum.setdefault(path, {})
            for idx, score in ranked:
                bucket[idx] = bucket.get(idx, 0.0) + weight * float(score)
    out: Dict[str, List[Tuple[int, float]]] = {}
    for path, bucket in accum.items():
        out[path] = sorted(bucket.items(), key=lambda t: t[1], reverse=True)[:5]
    return out


def soft_assign_sources_to_bundle(
    sources: Dict[str, str],
    bundle_text: str,
    *,
    threshold: float = 0.28,
    min_margin: float = 0.03,
    max_sources: int = 800,
    chunk_chars: int = 8000,
    step: int = 6000,
    enable_char_channel: bool = True,
) -> SoftAssignResult:
    result = SoftAssignResult(notes=["soft_assignment_hungarian", "blend_word_char_tfidf"])
    items = sorted(sources.items(), key=lambda kv: len(kv[1]), reverse=True)[:max_sources]
    if not items:
        result.notes.append("no_sources")
        return result
    chunks = chunk_text(bundle_text, chunk_chars=chunk_chars, step=step)
    if not chunks:
        result.notes.append("empty_bundle")
        return result
    q = dict(items)
    word = cosine_topk(q, chunks, top_k=5)
    # Char n-grams explode memory on multi-MB bundles — keep for fixtures / small inputs.
    use_char = bool(enable_char_channel) and len(bundle_text) <= 2_000_000 and len(chunks) <= 400
    char = _char_ngram_topk(q, chunks, top_k=5) if use_char else {}
    if not use_char:
        result.notes.append("char_channel_skipped_large_bundle")
    blended = _blend_scores([word, char], weights=[0.6, 0.4]) if char else word
    if not blended:
        result.notes.append("no_scores")
        return result
    result.assignments = hungarian_unique_assignments(
        blended, threshold=threshold, min_margin=min_margin
    )
    return result
