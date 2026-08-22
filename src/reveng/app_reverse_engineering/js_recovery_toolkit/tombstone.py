"""Tombstone / recoverable-oracle metrics for stale-map → bundle climbs.

Modules with essentially no residue in the bundle are treated as deleted or
rewritten (tombstones). Option C then reports::

- oracle_coverage = |attributed| / |oracle|          # aspirational
- recoverable_oracle_coverage = |attr| / |oracle − tombstones|
- survivor/unlockable coverage                      # ship bar

Inspired by clone-search residual analysis and SBOM chain-of-experts style
\"present vs absent\" classification — hermetic, no LLM required.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{5,}")


@dataclass
class TombstoneReport:
    tombstones: Set[str] = field(default_factory=set)
    survivors: Set[str] = field(default_factory=set)
    weak_residue: Set[str] = field(default_factory=set)
    hit_counts: Dict[str, int] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_serializable(self) -> dict:
        return {
            "schema_version": "1.0",
            "result_type": "tombstone",
            "tombstone_count": len(self.tombstones),
            "survivor_count": len(self.survivors),
            "weak_residue_count": len(self.weak_residue),
            "tombstones": sorted(self.tombstones),
            "survivors": sorted(self.survivors),
            "weak_residue": sorted(self.weak_residue),
            "hit_counts": dict(self.hit_counts),
            "notes": list(self.notes)
            + [
                "option_c_report_both",
                "tombstones_not_unlockable",
                "not_decoded_exe",
            ],
            "decoded_exe_claim": False,
        }


def classify_tombstones(
    sources: Dict[str, str],
    bundle_text: str,
    *,
    min_hits: int = 1,
    token_min_len: int = 6,
    unique_tokens_only: bool = True,
) -> TombstoneReport:
    """Partition oracle sources by whether salient tokens hit the bundle.

    When ``unique_tokens_only`` (default), only tokens owned by exactly one
    source count — shared boilerplate in a mega-bundle otherwise makes every
    path look like a survivor.
    """
    report = TombstoneReport(
        notes=["tombstone_v1", f"min_hits={min_hits}", f"unique_tokens_only={unique_tokens_only}"]
    )
    tok_re = re.compile(rf"[A-Za-z_][A-Za-z0-9_]{{{token_min_len - 1},}}")
    bundle_toks = set(tok_re.findall(bundle_text or ""))
    report.notes.append(f"bundle_token_count={len(bundle_toks)}")

    owners: Dict[str, Set[str]] = {}
    path_toks: Dict[str, Set[str]] = {}
    for path, body in sources.items():
        if not path.startswith("src/"):
            continue
        toks = set(tok_re.findall(body or ""))
        path_toks[path] = toks
        for t in toks:
            owners.setdefault(t, set()).add(path)
    unique_owner = {t: next(iter(ps)) for t, ps in owners.items() if len(ps) == 1}

    for path, toks in path_toks.items():
        if unique_tokens_only:
            candidates = {t for t in toks if unique_owner.get(t) == path}
        else:
            candidates = toks
        hits = sum(1 for t in candidates if t in bundle_toks)
        report.hit_counts[path] = hits
        if hits >= max(1, min_hits):
            report.survivors.add(path)
            if hits < 3:
                report.weak_residue.add(path)
        else:
            report.tombstones.add(path)
    return report


def recoverable_oracle_coverage(
    *,
    oracle_paths: Set[str],
    attributed: Dict[str, str],
    tombstones: Set[str],
) -> float:
    recoverable = oracle_paths - set(tombstones)
    if not recoverable:
        return 0.0
    return round(len(set(attributed) & recoverable) / len(recoverable), 4)
