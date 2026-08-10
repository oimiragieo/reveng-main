"""Structural MinHash matching (astdiff-inspired, pure Python, hermetic).

Identifier-blind token shingles + MinHash Jaccard to attribute map sources
to bundle chunks when string fingerprints are thin.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

_TOKEN_RE = re.compile(r"[A-Za-z_$][\w$]*|\d+|[{}()\[\];,.<>]=*|['\"][^'\"]{0,40}['\"]")
_KEYWORDS = {
    "if",
    "else",
    "for",
    "while",
    "function",
    "return",
    "const",
    "let",
    "var",
    "class",
    "export",
    "import",
    "from",
    "async",
    "await",
    "throw",
    "try",
    "catch",
    "new",
    "typeof",
    "switch",
    "case",
    "break",
    "continue",
    "default",
    "true",
    "false",
    "null",
    "undefined",
}


def normalize_tokens(text: str) -> List[str]:
    out: List[str] = []
    for tok in _TOKEN_RE.findall(text or ""):
        if tok.startswith(("'", '"')):
            # keep short string shapes; long strings handled by fingerprint lane
            if len(tok) <= 24:
                out.append("STR")
            else:
                out.append("STR_LONG")
            continue
        if tok.isdigit():
            out.append("NUM")
            continue
        if tok in _KEYWORDS or tok in "{}()[];,.":
            out.append(tok)
            continue
        out.append("VAR")
    return out


def shingles(tokens: Sequence[str], k: int = 5) -> Set[str]:
    if len(tokens) < k:
        return {"|".join(tokens)} if tokens else set()
    return {"|".join(tokens[i : i + k]) for i in range(len(tokens) - k + 1)}


def _hash_shingle(s: str, seed: int) -> int:
    h = hashlib.sha1(f"{seed}:{s}".encode("utf-8")).digest()
    return int.from_bytes(h[:8], "little")


def minhash_signature(shingle_set: Set[str], num_perm: int = 64) -> Tuple[int, ...]:
    if not shingle_set:
        return tuple(0 for _ in range(num_perm))
    sig: List[int] = []
    for seed in range(num_perm):
        sig.append(min(_hash_shingle(s, seed) for s in shingle_set))
    return tuple(sig)


def jaccard_from_sigs(a: Tuple[int, ...], b: Tuple[int, ...]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    equal = sum(1 for x, y in zip(a, b) if x == y)
    return equal / len(a)


def file_signature(text: str, *, num_perm: int = 64) -> Tuple[int, ...]:
    return minhash_signature(shingles(normalize_tokens(text)), num_perm=num_perm)


@dataclass
class StructuralMatch:
    source_path: str
    score: float
    method: str


def chunk_bundle(text: str, *, chunk_chars: int = 12000, overlap: int = 2000) -> List[str]:
    """Sliding windows over large bundles (Claude-scale)."""
    if len(text) <= chunk_chars:
        return [text]
    chunks: List[str] = []
    step = max(1000, chunk_chars - overlap)
    for i in range(0, len(text), step):
        chunks.append(text[i : i + chunk_chars])
        if i + chunk_chars >= len(text):
            break
    return chunks


def match_sources_to_bundle(
    sources: Dict[str, str],
    bundle_text: str,
    *,
    threshold: float = 0.55,
    already_confirmed: Optional[Set[str]] = None,
    max_sources: int = 5000,
) -> List[StructuralMatch]:
    """Greedy unique structural matches of map sources onto bundle chunks."""
    confirmed = set(already_confirmed or [])
    # Precompute chunk signatures
    chunks = chunk_bundle(bundle_text)
    chunk_sigs = [file_signature(c) for c in chunks]
    matches: List[StructuralMatch] = []
    used_chunks: Set[int] = set()
    items = [(p, b) for p, b in sources.items() if p not in confirmed]
    # Prefer larger bodies first (more structural signal)
    items.sort(key=lambda pb: len(pb[1]), reverse=True)
    for path, body in items[:max_sources]:
        if len(body) < 80:
            continue
        sig = file_signature(body)
        best_i = -1
        best = 0.0
        for i, cs in enumerate(chunk_sigs):
            if i in used_chunks:
                continue
            score = jaccard_from_sigs(sig, cs)
            if score > best:
                best = score
                best_i = i
        if best_i >= 0 and best >= threshold:
            used_chunks.add(best_i)
            matches.append(
                StructuralMatch(source_path=path, score=round(best, 4), method="minhash_chunk")
            )
            confirmed.add(path)
    return matches
