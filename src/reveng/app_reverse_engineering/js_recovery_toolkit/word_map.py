"""TF-IDF / cosine word-mapping (embedding-nearest-neighbor without neural nets).

Inspired by code-embeddings / plagiarism TF-IDF pipelines and jsNaughty's
\"next best name in context\" idea — hermetic via sklearn (already a REVENG dep).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")


def tokenize_code(text: str) -> List[str]:
    return _TOKEN_RE.findall(text or "")


@dataclass
class WordMapResult:
    assignments: Dict[str, Tuple[int, float]] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_serializable(self) -> dict:
        return {
            "schema_version": "1.0",
            "result_type": "word_map",
            "assignment_count": len(self.assignments),
            "assignments": {
                p: {"chunk_idx": idx, "score": score}
                for p, (idx, score) in self.assignments.items()
            },
            "notes": list(self.notes),
            "decoded_exe_claim": False,
        }


def _vectorizer():
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
    except ImportError:
        return None
    return TfidfVectorizer(
        analyzer="word",
        token_pattern=r"[A-Za-z_][A-Za-z0-9_]{2,}",
        lowercase=False,
        min_df=1,
        max_features=50000,
    )


def chunk_text(text: str, *, chunk_chars: int = 8000, step: int = 6000) -> List[str]:
    if not text:
        return []
    if len(text) <= chunk_chars:
        return [text]
    out: List[str] = []
    for i in range(0, len(text), max(1, step)):
        out.append(text[i : i + chunk_chars])
        if i + chunk_chars >= len(text):
            break
        if len(out) >= 4000:  # Claude-scale safety cap
            break
    return out


def cosine_topk(
    query_texts: Dict[str, str],
    corpus_chunks: Sequence[str],
    *,
    top_k: int = 3,
) -> Dict[str, List[Tuple[int, float]]]:
    """Return path → [(chunk_idx, cosine), ...] sorted descending."""
    if not query_texts or not corpus_chunks:
        return {}
    vec = _vectorizer()
    if vec is None:
        return {}
    from sklearn.metrics.pairwise import cosine_similarity

    paths = list(query_texts.keys())
    docs = [query_texts[p] for p in paths] + list(corpus_chunks)
    try:
        matrix = vec.fit_transform(docs)
    except ValueError:
        return {}
    n_q = len(paths)
    q = matrix[:n_q]
    c = matrix[n_q:]
    if c.shape[0] == 0:
        return {}
    sims = cosine_similarity(q, c)
    out: Dict[str, List[Tuple[int, float]]] = {}
    for i, path in enumerate(paths):
        row = sims[i]
        ranked = sorted(enumerate(row), key=lambda t: float(t[1]), reverse=True)[:top_k]
        out[path] = [(int(idx), float(score)) for idx, score in ranked]
    return out


def best_unique_assignments(
    scores: Dict[str, List[Tuple[int, float]]],
    *,
    threshold: float = 0.35,
) -> Dict[str, Tuple[int, float]]:
    """Greedy unique path↔chunk matching (precision-first)."""
    candidates: List[Tuple[float, str, int]] = []
    for path, ranked in scores.items():
        for idx, score in ranked:
            if score >= threshold:
                candidates.append((float(score), path, int(idx)))
    candidates.sort(reverse=True)
    used_paths: set = set()
    used_chunks: set = set()
    assigned: Dict[str, Tuple[int, float]] = {}
    for score, path, idx in candidates:
        if path in used_paths or idx in used_chunks:
            continue
        assigned[path] = (idx, score)
        used_paths.add(path)
        used_chunks.add(idx)
    return assigned


def word_map_sources_to_bundle(
    sources: Dict[str, str],
    bundle_text: str,
    *,
    threshold: float = 0.35,
    max_sources: int = 800,
    chunk_chars: int = 8000,
    step: int = 6000,
) -> WordMapResult:
    result = WordMapResult()
    if _vectorizer() is None:
        result.notes.append("sklearn_absent")
        return result
    items = sorted(sources.items(), key=lambda kv: len(kv[1]), reverse=True)[:max_sources]
    if not items:
        result.notes.append("no_sources")
        return result
    chunks = chunk_text(bundle_text, chunk_chars=chunk_chars, step=step)
    if not chunks:
        result.notes.append("empty_bundle")
        return result
    top = cosine_topk(dict(items), chunks, top_k=3)
    result.assignments = best_unique_assignments(top, threshold=threshold)
    result.notes.append("tfidf_cosine_unique")
    return result
