"""Semantic feature digests — deterministic 'what does this chunk do' anchors.

LLM summarization is optional and non-hermetic. This module extracts the same
*kinds* of anchors an LLM would lean on (API calls, HTTP verbs, DOM, crypto)
as stable tokens for fingerprint / cooccur / word-map — without a model call.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

# High-signal API / platform anchors (minified code often keeps these strings/idents)
_API_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("api_fetch", re.compile(r"\bfetch\s*\(")),
    ("api_xhr", re.compile(r"\bXMLHttpRequest\b")),
    ("api_ws", re.compile(r"\bWebSocket\b")),
    ("api_local_storage", re.compile(r"\blocalStorage\b")),
    ("api_session_storage", re.compile(r"\bsessionStorage\b")),
    ("api_indexed_db", re.compile(r"\bindexedDB\b")),
    ("api_crypto", re.compile(r"\bcrypto\.subtle\b|\bcreateHash\b|\bcreateHmac\b")),
    ("api_child_process", re.compile(r"\bchild_process\b|\bspawn\s*\(|\bexecFile\s*\(")),
    ("api_fs", re.compile(r"\bfs\.promises\b|\breadFileSync\b|\bwriteFileSync\b")),
    ("api_path", re.compile(r"\bpath\.join\b|\bpath\.resolve\b")),
    ("api_process_env", re.compile(r"\bprocess\.env\b")),
    ("api_buffer", re.compile(r"\bBuffer\.(?:from|alloc|concat)\b")),
    ("dom_query", re.compile(r"\bquerySelector(?:All)?\s*\(")),
    ("dom_add_listener", re.compile(r"\baddEventListener\s*\(")),
    ("http_authorization", re.compile(r"Authorization", re.I)),
    ("http_bearer", re.compile(r"Bearer\s+", re.I)),
    ("mime_json", re.compile(r"application/json")),
    (
        "cff_dispatcher",
        re.compile(r"while\s*\(\s*!!\s*\[\s*\]\s*\)|while\s*\(\s*true\s*\)\s*\{[^}]*switch\s*\("),
    ),
    (
        "string_array_decoder",
        re.compile(r"function\s+_0x[a-f0-9]+\s*\(|var\s+_0x[a-f0-9]+\s*=\s*\["),
    ),
]

_HTTP_VERB = re.compile(r"""['"](GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)['"]""")
_URLISH = re.compile(r"""['"](https?://[^'"]{8,120}|/[a-z][a-z0-9_\-/]{4,80})['"]""")


@dataclass
class SemanticDigest:
    path: str
    features: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_serializable(self) -> dict:
        return {
            "path": self.path,
            "features": list(self.features),
            "notes": list(self.notes),
        }


def extract_semantic_features(text: str) -> List[str]:
    """Return sorted unique semantic feature tags for a code body."""
    body = text or ""
    found: Set[str] = set()
    for name, pat in _API_PATTERNS:
        if pat.search(body):
            found.add(name)
    for verb in _HTTP_VERB.findall(body):
        found.add(f"http_verb_{verb.lower()}")
    for url in _URLISH.findall(body):
        # Keep short stable shape, not full URL (privacy + uniqueness)
        if url.startswith("http"):
            found.add("url_absolute")
        else:
            found.add(f"path_{url[:40]}")
    return sorted(found)


def digest_sources(sources: Dict[str, str]) -> Dict[str, SemanticDigest]:
    out: Dict[str, SemanticDigest] = {}
    for path, body in sources.items():
        feats = extract_semantic_features(body)
        out[path] = SemanticDigest(
            path=path,
            features=feats,
            notes=["deterministic_semantic_digest", "not_llm"],
        )
    return out


def semantic_overlap_unlock(
    *,
    sources: Dict[str, str],
    bundle_text: str,
    attributed: Dict[str, str],
    min_shared: int = 3,
) -> Dict[str, str]:
    """Unlock unattributed sources whose semantic feature set uniquely matches
    a subset of features observed in the (readable) bundle and overlaps a
    confirmed neighbor's features — precision-first unique match.
    """
    bundle_feats = set(extract_semantic_features(bundle_text))
    digests = digest_sources(sources)
    confirmed_feats: Dict[str, Set[str]] = {
        p: set(digests[p].features) for p in attributed if p in digests
    }
    # Candidate: unattributed with ≥min_shared features present in bundle
    candidates: List[Tuple[str, Set[str]]] = []
    for path, dig in digests.items():
        if path in attributed or not path.startswith("src/"):
            continue
        feats = set(dig.features) & bundle_feats
        if len(feats) >= min_shared:
            candidates.append((path, feats))
    new: Dict[str, str] = {}
    # Unique feature signature among remaining
    sig_owners: Dict[frozenset, List[str]] = {}
    for path, feats in candidates:
        sig_owners.setdefault(frozenset(feats), []).append(path)
    for sig, paths in sig_owners.items():
        if len(paths) != 1:
            continue
        path = paths[0]
        # Prefer candidates that share features with some confirmed module
        if confirmed_feats:
            if not any(sig & cf for cf in confirmed_feats.values()):
                # still allow unique-in-bundle semantic islands
                if len(sig) < min_shared + 1:
                    continue
        new[path] = "semantic_digest"
    return new
