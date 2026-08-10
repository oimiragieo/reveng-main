"""Reinject LLM digest tags into a second defrag unlock pass."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from .iterative_defrag import DefragResult, run_iterative_defrag
from .llm_digest import LlmModuleDigest

_TAG_TOKEN = re.compile(r"[a-z][a-z0-9_]{3,40}")


@dataclass
class TagBoostResult:
    seed_count: int
    after_count: int
    new_paths: Dict[str, str] = field(default_factory=dict)
    tag_hits_in_bundle: int = 0
    notes: List[str] = field(default_factory=list)
    defrag: Optional[DefragResult] = None

    def to_serializable(self) -> dict:
        return {
            "schema_version": "1.0",
            "result_type": "llm_tag_boost_defrag",
            "seed_count": self.seed_count,
            "after_count": self.after_count,
            "new_count": len(self.new_paths),
            "new_paths": dict(self.new_paths),
            "tag_hits_in_bundle": self.tag_hits_in_bundle,
            "oracle_coverage": self.defrag.oracle_coverage if self.defrag else 0.0,
            "survivor_coverage": self.defrag.survivor_coverage if self.defrag else 0.0,
            "notes": list(self.notes) + ["not_decoded_exe"],
            "decoded_exe_claim": False,
            "defrag": self.defrag.to_serializable() if self.defrag else None,
        }


def _bundle_has_tag(bundle_lower: str, tag: str) -> bool:
    # Accept tag as substring or split snake parts
    if tag in bundle_lower:
        return True
    parts = [p for p in tag.split("_") if len(p) >= 4]
    return bool(parts) and all(p in bundle_lower for p in parts[:3])


def inject_digest_tags_as_pseudo_signals(
    *,
    sources: Dict[str, str],
    digests: List[LlmModuleDigest],
) -> Dict[str, str]:
    """Append LLM tags as comment tokens into a copy of source bodies for word_map/cooccur."""
    enriched = dict(sources)
    by_path = {d.path: d for d in digests}
    for path, dig in by_path.items():
        if path not in enriched or not dig.tags:
            continue
        tag_line = "/* LLM_TAGS " + " ".join(dig.tags) + " */\n"
        enriched[path] = tag_line + enriched[path]
    return enriched


def unlock_by_llm_tags(
    *,
    sources: Dict[str, str],
    bundle_text: str,
    attributed: Dict[str, str],
    digests: List[LlmModuleDigest],
    min_tags: int = 2,
) -> Dict[str, str]:
    """Attribute unattributed sources when ≥min_tags unique digest tags appear in bundle.

    Only considers digests for paths not yet attributed — those digests come from
    *already unlocked* modules normally; for boost we also allow synthesizing tags
    for unattributed by running summarize on them separately. Here we use digests
    keyed by path: if an unattributed path was summarized, unlock when tags hit.
    """
    bundle_lower = (bundle_text or "").lower()
    new: Dict[str, str] = {}
    for dig in digests:
        path = dig.path
        if path in attributed or path in new or not path.startswith("src/"):
            continue
        tags = [t for t in dig.tags if _TAG_TOKEN.fullmatch(t)]
        if len(tags) < min_tags:
            continue
        hits = [t for t in tags if _bundle_has_tag(bundle_lower, t)]
        if len(hits) >= min_tags:
            new[path] = "llm_tag"
    return new


def run_tag_boost_defrag(
    *,
    sources: Dict[str, str],
    bundle_text: str,
    seed_attributed: Dict[str, str],
    digests: List[LlmModuleDigest],
    max_rounds: int = 4,
) -> TagBoostResult:
    """Merge llm_tag unlocks then continue iterative defrag from the expanded seed."""
    notes = ["llm_tag_boost"]
    attributed = dict(seed_attributed)
    seed_n = len(attributed)
    direct = unlock_by_llm_tags(
        sources=sources,
        bundle_text=bundle_text,
        attributed=attributed,
        digests=digests,
        min_tags=2,
    )
    # Also: tags from unlocked digests that uniquely point at unattributed paths
    # via shared topic words in unattributed source text
    bundle_lower = bundle_text.lower()
    tag_hits = 0
    for dig in digests:
        for t in dig.tags:
            if _bundle_has_tag(bundle_lower, t):
                tag_hits += 1
    attributed.update(direct)
    enriched = inject_digest_tags_as_pseudo_signals(sources=sources, digests=digests)
    defrag = run_iterative_defrag(
        sources=enriched,
        bundle_text=bundle_text,
        seed_attributed=attributed,
        max_rounds=max_rounds,
    )
    new_paths = {p: m for p, m in defrag.attributed.items() if p not in seed_attributed}
    for p, m in direct.items():
        new_paths.setdefault(p, m)
    notes.append(f"direct_llm_tag:{len(direct)}")
    return TagBoostResult(
        seed_count=seed_n,
        after_count=len(defrag.attributed),
        new_paths=new_paths,
        tag_hits_in_bundle=tag_hits,
        notes=notes,
        defrag=defrag,
    )
