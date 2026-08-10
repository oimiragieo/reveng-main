"""Behavior overlap probe — string/flag CUJ similarity (not file recall)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Set

_TOKEN_RE = re.compile(r"""(?:--[a-z][a-z0-9\-]{2,}|/[a-z][a-z0-9_\-/]{2,}|[A-Z][A-Z0-9_]{5,})""")


@dataclass
class BehaviorOverlap:
    oracle_token_count: int
    target_token_count: int
    intersection: int
    recall: float
    precision: float
    notes: str


def behavior_token_overlap(oracle_text: str, target_text: str) -> BehaviorOverlap:
    o: Set[str] = set(_TOKEN_RE.findall(oracle_text or ""))
    t: Set[str] = set(_TOKEN_RE.findall(target_text or ""))
    inter = o & t
    recall = (len(inter) / len(o)) if o else 0.0
    precision = (len(inter) / len(t)) if t else 0.0
    return BehaviorOverlap(
        oracle_token_count=len(o),
        target_token_count=len(t),
        intersection=len(inter),
        recall=round(recall, 4),
        precision=round(precision, 4),
        notes="cli_flag_slash_and_SHOUTY_token_overlap",
    )
