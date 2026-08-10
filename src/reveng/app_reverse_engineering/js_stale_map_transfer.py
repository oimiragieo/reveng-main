"""Stale-map fingerprint transfer (Wave 5 Tier A) — attribution evidence only.

Builds a salted-hash fingerprint index from map ``sourcesContent`` (or a
source tree), scans a target bundle, and emits first-party confirmations
when ≥2 independent unique signals co-occur.

This does **not** decode / decompile a new executable. LLM rename is out of
scope for the hermetic ship path (``llm_used`` always false here).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

_LITERAL_RE = re.compile(r"""['"]([A-Za-z][A-Za-z0-9_./:-]{15,120})['"]""")
_EXPORT_RE = re.compile(
    r"\bexport\s+(?:async\s+)?(?:function|class|const|let|var)\s+([A-Za-z_$][\w$]{4,})"
)
_VENDOR_MARKERS = ("node_modules/", "/vendor/", "\\node_modules\\")
_DEFAULT_SALT = "reveng-wave5-stale-map-v1"
_MIN_LITERAL_LEN = 16
_MIN_SIGNALS_CONFIRMED = 2


def _is_vendor_path(path: str) -> bool:
    text = path.replace("\\", "/")
    return any(m in text for m in _VENDOR_MARKERS)


def _normalize_source_path(raw: str) -> Optional[str]:
    text = (raw or "").strip().replace("\\", "/")
    if not text or _is_vendor_path(text):
        return None
    # Prefer path under src/ when present
    if "src/" in text:
        text = text[text.index("src/") :]
    if text.startswith("../"):
        parts = [p for p in text.split("/") if p not in ("", ".")]
        while parts and parts[0] == "..":
            parts.pop(0)
        text = "/".join(parts)
    if _is_vendor_path(text) or not text:
        return None
    return text


def _digest(salt: str, kind: str, value: str) -> str:
    payload = f"{salt}|{kind}|{value}".encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _extract_signals(text: str) -> List[Tuple[str, str]]:
    """Return list of (kind, value) signal candidates from source or bundle text."""
    out: List[Tuple[str, str]] = []
    for lit in _LITERAL_RE.findall(text or ""):
        if lit.startswith("http") or "node_modules" in lit:
            continue
        if len(lit) < _MIN_LITERAL_LEN:
            continue
        # Skip ultra-common boilerplate
        if lit.lower() in {"application/json", "text/plain", "content-type"}:
            continue
        out.append(("literal", lit))
    for name in _EXPORT_RE.findall(text or ""):
        out.append(("export_name", name))
    return out


@dataclass
class FingerprintIndex:
    """In-memory index: digest → first-party source path (unique digests only)."""

    salt: str
    digest_to_path: Dict[str, str] = field(default_factory=dict)
    digest_to_kind: Dict[str, str] = field(default_factory=dict)
    notes: List[str] = field(default_factory=list)

    def to_serializable(self) -> Dict[str, Any]:
        """Serialize without raw literal/export values (hashes only)."""
        entries = []
        for digest, path in sorted(self.digest_to_path.items()):
            entries.append(
                {
                    "digest": digest,
                    "kind": self.digest_to_kind.get(digest, "unknown"),
                    "source_path": path,
                }
            )
        return {
            "schema_version": "1.0",
            "index_type": "stale_map_fingerprint_index",
            "salt_id": self.salt,
            "entry_count": len(entries),
            "entries": entries,
            "notes": list(self.notes)
            + ["raw_values_omitted", "hashed_fingerprints_only"],
        }


@dataclass
class ConfirmedAttribution:
    source_path: str
    signal_count: int
    provenance_confidence: float
    kinds: List[str]


@dataclass
class TransferResult:
    confirmed: List[ConfirmedAttribution]
    abstained_paths: List[str]
    metrics: Dict[str, Any]
    notes: List[str]
    llm_used: bool = False

    def to_serializable(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "result_type": "stale_map_fingerprint_transfer",
            "attribution_mode": "fingerprint_transfer",
            "llm_used": self.llm_used,
            "decoded_exe_claim": False,
            "confirmed": [
                {
                    "source_path": c.source_path,
                    "signal_count": c.signal_count,
                    "provenance_confidence": c.provenance_confidence,
                    "name_recovery_confidence": 0.0,
                    "kinds": c.kinds,
                }
                for c in self.confirmed
            ],
            "abstained_paths": list(self.abstained_paths),
            "metrics": dict(self.metrics),
            "notes": list(self.notes),
        }


def build_index_from_sourcemap(
    map_path: Path,
    *,
    salt: str = _DEFAULT_SALT,
) -> FingerprintIndex:
    data = json.loads(Path(map_path).read_text(encoding="utf-8"))
    sources = data.get("sources") or []
    contents = data.get("sourcesContent") or []
    if not isinstance(sources, list) or not isinstance(contents, list):
        return FingerprintIndex(salt=salt, notes=["invalid_sourcemap_shape"])
    pairs: List[Tuple[str, str]] = []
    for src, body in zip(sources, contents):
        if body is None:
            continue
        path = _normalize_source_path(str(src))
        if path is None:
            continue
        pairs.append((path, str(body)))
    return build_index_from_sources(pairs, salt=salt)


def build_index_from_sources(
    sources: Sequence[Tuple[str, str]],
    *,
    salt: str = _DEFAULT_SALT,
) -> FingerprintIndex:
    """Index unique-to-one-source signals. Vendor paths skipped."""
    # value_key -> set of source paths
    owners: Dict[Tuple[str, str], Set[str]] = {}
    notes: List[str] = ["unique_to_one_source", "vendor_excluded", f"min_literal_len:{_MIN_LITERAL_LEN}"]
    for path, body in sources:
        if _is_vendor_path(path):
            notes.append(f"skip_vendor:{path}")
            continue
        norm = _normalize_source_path(path) or path
        if _is_vendor_path(norm):
            continue
        for kind, value in _extract_signals(body):
            owners.setdefault((kind, value), set()).add(norm)

    digest_to_path: Dict[str, str] = {}
    digest_to_kind: Dict[str, str] = {}
    skipped_shared = 0
    for (kind, value), paths in owners.items():
        if len(paths) != 1:
            skipped_shared += 1
            continue
        path = next(iter(paths))
        digest = _digest(salt, kind, value)
        # Collision on digest across different values is astronomically rare; last-write would be wrong —
        # refuse if digest already mapped to a different path.
        if digest in digest_to_path and digest_to_path[digest] != path:
            notes.append(f"digest_collision_abstain:{digest[:12]}")
            digest_to_path.pop(digest, None)
            digest_to_kind.pop(digest, None)
            continue
        digest_to_path[digest] = path
        digest_to_kind[digest] = kind
    notes.append(f"skipped_non_unique:{skipped_shared}")
    notes.append(f"indexed:{len(digest_to_path)}")
    return FingerprintIndex(
        salt=salt,
        digest_to_path=digest_to_path,
        digest_to_kind=digest_to_kind,
        notes=notes,
    )


def scan_bundle(
    index: FingerprintIndex,
    bundle_text: str,
    *,
    min_signals: int = _MIN_SIGNALS_CONFIRMED,
) -> TransferResult:
    """Scan bundle for hashed fingerprint hits; confirm paths with ≥ min_signals."""
    notes = [
        "fingerprint_attribution_only",
        "not_decoded_exe",
        "not_decompiled_exe",
        "name_recovery_not_applied",
        f"min_signals_confirmed:{min_signals}",
    ]
    # Collect hits: path -> list of (digest, kind)
    hits: Dict[str, List[Tuple[str, str]]] = {}
    seen_digests: Set[str] = set()
    for kind, value in _extract_signals(bundle_text):
        digest = _digest(index.salt, kind, value)
        path = index.digest_to_path.get(digest)
        if path is None:
            continue
        if digest in seen_digests:
            continue
        seen_digests.add(digest)
        hits.setdefault(path, []).append((digest, index.digest_to_kind.get(digest, kind)))

    confirmed: List[ConfirmedAttribution] = []
    abstained: List[str] = []
    for path, pairs in sorted(hits.items()):
        kinds = sorted({k for _d, k in pairs})
        count = len(pairs)
        if count < min_signals:
            abstained.append(path)
            continue
        # provenance confidence: saturating in signal count (precision-first, capped)
        provenance = min(1.0, 0.5 + 0.25 * (count - min_signals + 1))
        confirmed.append(
            ConfirmedAttribution(
                source_path=path,
                signal_count=count,
                provenance_confidence=round(provenance, 4),
                kinds=kinds,
            )
        )

    fp_confirmed = len(confirmed)
    mean_prov = (
        sum(c.provenance_confidence for c in confirmed) / fp_confirmed if fp_confirmed else 0.0
    )
    metrics = {
        "first_party_confirmed_count": fp_confirmed,
        "first_party_abstained_count": len(abstained),
        "provenance_confidence_mean": round(mean_prov, 4),
        "name_recovery_confidence_mean": 0.0,
        "hit_digest_count": len(seen_digests),
        "index_entry_count": len(index.digest_to_path),
    }
    return TransferResult(
        confirmed=confirmed,
        abstained_paths=abstained,
        metrics=metrics,
        notes=notes,
        llm_used=False,
    )


def index_has_raw_secret_literals(serialized: Mapping[str, Any], secrets: Iterable[str]) -> bool:
    """Honesty helper: serialized index must not contain plaintext secret fixtures."""
    blob = json.dumps(serialized, sort_keys=True)
    return any(secret in blob for secret in secrets)


__all__ = [
    "FingerprintIndex",
    "TransferResult",
    "ConfirmedAttribution",
    "build_index_from_sourcemap",
    "build_index_from_sources",
    "scan_bundle",
    "index_has_raw_secret_literals",
]
