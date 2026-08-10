"""Optional AST-chunked LLM summarize (non-hermetic).

Industry pattern (humanify / re-Script / deobfuscate-mcp): never dump the whole
bundle — summarize **one unlocked module body** (from map sourcesContent) at a
time and emit short semantic tags back into the defrag vocabulary.

Default OFF. Enable with ``enable_llm=True`` and a callable ``summarize_fn``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

_TAG_RE = re.compile(r"[a-z][a-z0-9_]{2,40}")


@dataclass
class LlmModuleDigest:
    path: str
    summary: str
    tags: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def to_serializable(self) -> dict:
        return {
            "path": self.path,
            "summary": self.summary[:500],
            "tags": list(self.tags),
            "notes": list(self.notes),
        }


SummarizeFn = Callable[[str, str], str]  # (path, body) -> summary text


def tags_from_summary(summary: str, *, limit: int = 12) -> List[str]:
    words = _TAG_RE.findall((summary or "").lower())
    # Prefer content words
    stop = {
        "the",
        "and",
        "for",
        "with",
        "this",
        "that",
        "from",
        "function",
        "module",
        "code",
        "returns",
        "using",
    }
    out: List[str] = []
    seen = set()
    for w in words:
        if w in stop or w in seen:
            continue
        seen.add(w)
        out.append(w)
        if len(out) >= limit:
            break
    return out


def summarize_unlocked_modules(
    *,
    path_to_body: Dict[str, str],
    unlocked_paths: List[str],
    summarize_fn: SummarizeFn,
    max_modules: int = 20,
    max_body_chars: int = 6000,
) -> List[LlmModuleDigest]:
    """Run LLM summarize on a bounded set of unlocked module bodies."""
    digests: List[LlmModuleDigest] = []
    for path in unlocked_paths[:max_modules]:
        body = path_to_body.get(path) or ""
        if not body:
            continue
        clip = body[:max_body_chars]
        try:
            summary = summarize_fn(path, clip)
        except Exception as exc:  # pragma: no cover
            digests.append(
                LlmModuleDigest(
                    path=path,
                    summary="",
                    notes=[f"llm_failed:{type(exc).__name__}"],
                )
            )
            continue
        digests.append(
            LlmModuleDigest(
                path=path,
                summary=summary or "",
                tags=tags_from_summary(summary or ""),
                notes=["llm_module_digest", "ast_chunked_not_full_bundle"],
            )
        )
    return digests


def heuristic_summarize_fn(path: str, body: str) -> str:
    """Hermetic stand-in for an LLM: describe features without a model.

    Used in tests and offline runs; real providers plug in via summarize_fn.
    """
    from .semantic_digest import extract_semantic_features

    feats = extract_semantic_features(body)
    base = path.rsplit("/", 1)[-1]
    if feats:
        return f"module {base} involves " + ", ".join(feats[:8])
    return f"module {base} utility logic"
