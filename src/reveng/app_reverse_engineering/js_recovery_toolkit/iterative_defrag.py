"""Iterative 'disk defrag' unlock loop for stale-map → bundle attribution.

Seed high-confidence paths, then repeatedly unlock neighbors via import graph,
co-occurrence near confirmed tokens, and TF-IDF word-mapping — until fixed point.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple

from .semantic_digest import semantic_overlap_unlock
from .word_map import word_map_sources_to_bundle

_REL_IMPORT_RE = re.compile(
    r"""(?:import\s+(?:[^'"]+\s+from\s+)?|require\s*\(\s*|from\s+)['"](\.[^'"]+)['"]"""
)
_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{5,}")


@dataclass
class DefragRound:
    round_index: int
    new_paths: Dict[str, str]
    methods: Dict[str, int]


@dataclass
class DefragResult:
    attributed: Dict[str, str]
    rounds: List[DefragRound] = field(default_factory=list)
    unlockable_count: int = 0
    survivor_coverage: float = 0.0
    oracle_coverage: float = 0.0
    notes: List[str] = field(default_factory=list)

    def to_serializable(self) -> dict:
        return {
            "schema_version": "1.0",
            "result_type": "iterative_defrag",
            "attributed_count": len(self.attributed),
            "unlockable_count": self.unlockable_count,
            "survivor_coverage": self.survivor_coverage,
            "oracle_coverage": self.oracle_coverage,
            "rounds": [
                {
                    "round_index": r.round_index,
                    "new_count": len(r.new_paths),
                    "new_paths": dict(r.new_paths),
                    "methods": dict(r.methods),
                }
                for r in self.rounds
            ],
            "attributed": dict(self.attributed),
            "notes": list(self.notes)
            + [
                "option_c_report_both",
                "ship_bar_survivor_unlockable",
                "not_decoded_exe",
                "not_r_ralph_2_close",
            ],
            "decoded_exe_claim": False,
        }


def _oracle(sources: Dict[str, str]) -> Set[str]:
    return {p for p in sources if p.startswith("src/")}


def _unique_tokens(body: str) -> Set[str]:
    return set(_TOKEN_RE.findall(body or ""))


def _build_global_owners(sources: Dict[str, str]) -> Dict[str, str]:
    """token -> path if unique to exactly one source."""
    owners: Dict[str, Set[str]] = {}
    for path, body in sources.items():
        for tok in _unique_tokens(body):
            owners.setdefault(tok, set()).add(path)
    return {t: next(iter(ps)) for t, ps in owners.items() if len(ps) == 1}


def _rel_imports(body: str) -> Set[str]:
    return {m.replace("\\", "/") for m in _REL_IMPORT_RE.findall(body or "")}


def _resolve_rel_candidates(from_path: str, rel: str) -> List[str]:
    base_parts = from_path.replace("\\", "/").split("/")[:-1]
    rel_clean = rel.replace("\\", "/")
    rel_parts = rel_clean.split("/")
    stack = list(base_parts)
    for part in rel_parts:
        if part in ("", "."):
            continue
        if part == "..":
            if stack:
                stack.pop()
            continue
        stack.append(part)
    joined = "/".join(stack)
    stem = joined
    for ext in (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"):
        if stem.endswith(ext):
            return [stem]
    return [stem + e for e in (".ts", ".tsx", ".js", ".jsx", ".mjs")] + [stem]


def _graph_unlock(
    *,
    sources: Dict[str, str],
    attributed: Dict[str, str],
    bundle_text: str,
    unique_owner: Dict[str, str],
) -> Dict[str, str]:
    new: Dict[str, str] = {}
    for path in list(attributed):
        body = sources.get(path, "")
        for rel in _rel_imports(body):
            for cand in _resolve_rel_candidates(path, rel):
                if cand not in sources or cand in attributed or cand in new:
                    continue
                # weak presence: any unique token of cand in bundle, or basename mention
                toks = [t for t, owner in unique_owner.items() if owner == cand]
                present = any(t in bundle_text for t in toks[:20]) if toks else False
                base = cand.rsplit("/", 1)[-1].rsplit(".", 1)[0]
                if not present and base and len(base) >= 4:
                    present = base in bundle_text
                if present or toks:  # allow graph edge if unique tokens exist (even if weak)
                    # Prefer requiring bundle presence when we have tokens
                    if toks and not any(t in bundle_text for t in toks):
                        continue
                    new[cand] = "graph_unlock"
                    break
    return new


def _cooccur_unlock(
    *,
    sources: Dict[str, str],
    attributed: Dict[str, str],
    bundle_text: str,
    unique_owner: Dict[str, str],
    window: int = 200,
) -> Dict[str, str]:
    new: Dict[str, str] = {}
    # Precompute positions of confirmed unique tokens
    confirmed_positions: List[Tuple[int, str]] = []
    for tok, owner in unique_owner.items():
        if owner not in attributed:
            continue
        start = 0
        while True:
            idx = bundle_text.find(tok, start)
            if idx < 0:
                break
            confirmed_positions.append((idx, owner))
            start = idx + len(tok)
            if len(confirmed_positions) > 5000:
                break
        if len(confirmed_positions) > 5000:
            break
    if not confirmed_positions:
        return new
    for tok, owner in unique_owner.items():
        if owner in attributed or owner in new:
            continue
        start = 0
        while True:
            idx = bundle_text.find(tok, start)
            if idx < 0:
                break
            for cpos, _cowner in confirmed_positions:
                if abs(idx - cpos) <= window:
                    new[owner] = "cooccur"
                    break
            if owner in new:
                break
            start = idx + len(tok)
    return new


def _word_map_unlock(
    *,
    sources: Dict[str, str],
    attributed: Dict[str, str],
    bundle_text: str,
    threshold: float,
) -> Dict[str, str]:
    remaining = {p: b for p, b in sources.items() if p.startswith("src/") and p not in attributed}
    if not remaining:
        return {}
    wm = word_map_sources_to_bundle(remaining, bundle_text, threshold=threshold)
    return {p: "word_map" for p in wm.assignments}


def run_iterative_defrag(
    *,
    sources: Dict[str, str],
    bundle_text: str,
    seed_attributed: Dict[str, str],
    max_rounds: int = 8,
    word_map_threshold: float = 0.35,
) -> DefragResult:
    oracle = _oracle(sources)
    attributed = {p: m for p, m in seed_attributed.items() if p in oracle}
    unlockable: Set[str] = set(attributed)
    unique_owner = _build_global_owners({p: sources[p] for p in oracle if p in sources})
    rounds: List[DefragRound] = []
    notes = ["iterative_defrag_v1", "tfidf_word_map", "graph_cooccur", "semantic_digest"]

    for r in range(max_rounds):
        new: Dict[str, str] = {}
        for path, method in _graph_unlock(
            sources=sources,
            attributed=attributed,
            bundle_text=bundle_text,
            unique_owner=unique_owner,
        ).items():
            new.setdefault(path, method)
        for path, method in _cooccur_unlock(
            sources=sources,
            attributed=attributed,
            bundle_text=bundle_text,
            unique_owner=unique_owner,
        ).items():
            new.setdefault(path, method)
        for path, method in _word_map_unlock(
            sources=sources,
            attributed={**attributed, **new},
            bundle_text=bundle_text,
            threshold=word_map_threshold,
        ).items():
            new.setdefault(path, method)
        for path, method in semantic_overlap_unlock(
            sources=sources,
            bundle_text=bundle_text,
            attributed={**attributed, **new},
            min_shared=3,
        ).items():
            new.setdefault(path, method)
        # only oracle paths
        new = {p: m for p, m in new.items() if p in oracle and p not in attributed}
        if not new:
            break
        methods: Dict[str, int] = {}
        for m in new.values():
            methods[m] = methods.get(m, 0) + 1
        rounds.append(DefragRound(round_index=r, new_paths=dict(new), methods=methods))
        attributed.update(new)
        unlockable |= set(new)

    surv = len(set(attributed) & unlockable) / len(unlockable) if unlockable else 0.0
    orc = len(set(attributed) & oracle) / len(oracle) if oracle else 0.0
    return DefragResult(
        attributed=attributed,
        rounds=rounds,
        unlockable_count=len(unlockable),
        survivor_coverage=round(surv, 4),
        oracle_coverage=round(orc, 4),
        notes=notes,
    )
