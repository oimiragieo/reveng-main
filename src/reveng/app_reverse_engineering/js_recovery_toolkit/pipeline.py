"""End-to-end JS recovery toolkit pipeline (Wave 7–8)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from reveng.app_reverse_engineering.js_project_materialize import materialize_js_project_tree
from reveng.app_reverse_engineering.js_stale_map_transfer import (
    _normalize_source_path,
    apply_fingerprint_backed_missing,
)

from .behavior_probe import behavior_token_overlap
from .bun_serialized_sourcemap import materialize_serialized_sources, parse_serialized_sourcemap
from .coverage_union import singleton_literal_hits, union_coverage
from .ensemble_index import build_ensemble_index_from_sourcemap, scan_ensemble
from .external_tools import (
    probe_external_tools,
    try_bun_extract_in_tree,
    try_wakaru,
    try_webcrack,
    write_tool_probe_json,
)
from .graph_complete import suggest_graph_completions
from .iterative_defrag import run_iterative_defrag
from .llm_digest import heuristic_summarize_fn, summarize_unlocked_modules
from .provider_summarize import build_summarize_fn, probe_providers
from .readable_normalize import readable_normalize
from .structural_match import match_sources_to_bundle
from .tag_boost import run_tag_boost_defrag
from .tombstone import classify_tombstones, recoverable_oracle_coverage


@dataclass
class ToolkitReport:
    output_dir: Path
    stages: Dict[str, Any] = field(default_factory=dict)
    decoded_exe_claim: bool = False
    llm_used: bool = False
    notes: List[str] = field(default_factory=list)

    def to_serializable(self) -> Dict[str, Any]:
        return {
            "schema_version": "1.0",
            "result_type": "js_recovery_toolkit",
            "decoded_exe_claim": self.decoded_exe_claim,
            "llm_used": self.llm_used,
            "output_dir": str(self.output_dir),
            "stages": self.stages,
            "notes": list(self.notes)
            + [
                "not_decoded_exe",
                "not_r_ralph_2_close",
                "not_enterprise_ga",
            ],
        }


def run_recovery_toolkit(
    *,
    output_dir: Path,
    bundle: Optional[Path] = None,
    sourcemap: Optional[Path] = None,
    oracle_dir: Optional[Path] = None,
    bun_binary: Optional[Path] = None,
    run_external: bool = False,
    enable_llm_digest: bool = False,
    llm_prefer: Optional[str] = None,
    llm_max_modules: int = 40,
    llm_tag_boost: bool = True,
) -> ToolkitReport:
    """Run materialize → fingerprint → ensemble → graph → behavior (+ optional externals)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = ToolkitReport(output_dir=output_dir)
    report.notes.append("toolkit_wave8")

    tools_probe = write_tool_probe_json(output_dir / "tool_probe.json")
    report.stages["tool_probe"] = tools_probe

    # Optional Bun binary extract (+ SerializedSourceMap when present)
    if bun_binary is not None and Path(bun_binary).is_file():
        bun_out = output_dir / "bun_extract"
        bun_res = try_bun_extract_in_tree(Path(bun_binary), bun_out)
        report.stages["bun_extract"] = {
            "available": bun_res.available,
            "ran": bun_res.ran,
            "exit_code": bun_res.exit_code,
            "notes": bun_res.notes,
            "error": bun_res.error,
            "output_dir": bun_res.output_dir,
        }
        # Prefer freshly extracted bundle if present
        candidates = list(bun_out.rglob("*.js")) if bun_out.exists() else []
        if candidates and bundle is None:
            bundle = max(candidates, key=lambda p: p.stat().st_size)
        # Decode any adjacent .bunmap SerializedSourceMap blobs
        sm_recovered = 0
        sm_notes: List[str] = []
        for sm_path in bun_out.rglob("*.bunmap") if bun_out.exists() else []:
            parsed = parse_serialized_sourcemap(sm_path.read_bytes())
            sm_notes.extend(parsed.notes)
            if parsed.sources:
                sm_recovered += materialize_serialized_sources(
                    parsed, bun_out / "from_serialized_map"
                )
        report.stages["bun_serialized_sourcemap"] = {
            "blobs_seen": (len(list(bun_out.rglob("*.bunmap"))) if bun_out.exists() else 0),
            "files_recovered": sm_recovered,
            "notes": sm_notes[:20],
        }

    if bundle is None or not Path(bundle).is_file():
        report.notes.append("bundle_absent")
        (output_dir / "toolkit_report.json").write_text(
            json.dumps(report.to_serializable(), indent=2) + "\n", encoding="utf-8"
        )
        return report

    bundle = Path(bundle)
    raw_bundle_text = bundle.read_text(encoding="utf-8", errors="replace")
    # Wave 9: beautify-lite before fingerprint/defrag (not CFF/string-array undo)
    norm = readable_normalize(raw_bundle_text)
    bundle_text = norm.text or raw_bundle_text
    report.stages["readable_normalize"] = norm.to_serializable()
    (output_dir / "artifacts").mkdir(parents=True, exist_ok=True)
    (output_dir / "artifacts" / "bundle.readable.js").write_text(bundle_text, encoding="utf-8")
    report.notes.append("toolkit_wave9_readable")

    # Materialize from sibling map
    mat = materialize_js_project_tree(
        output_dir=output_dir,
        input_path=bundle,
        normalized_bundle=bundle,
    )
    report.stages["materialize"] = {
        "mode": mat.mode,
        "files_written": mat.files_written,
        "notes": list(mat.notes),
    }

    map_path = Path(sourcemap) if sourcemap else Path(str(bundle) + ".map")
    if not map_path.is_file():
        # try classic
        alt = bundle.with_suffix(bundle.suffix + ".map")
        if alt.is_file():
            map_path = alt

    if map_path.is_file():
        # Wave 5 fingerprint + content-backed fill
        transfer, written, fp_notes = apply_fingerprint_backed_missing(
            map_path=map_path,
            bundle_text=bundle_text,
            project_dir=output_dir / "project",
        )
        report.stages["fingerprint_v5"] = {
            "confirmed": transfer.metrics.get("first_party_confirmed_count"),
            "files_written": written,
            "notes": fp_notes,
            "metrics": transfer.metrics,
        }
        (output_dir / "artifacts").mkdir(parents=True, exist_ok=True)
        (output_dir / "artifacts" / "fingerprint_v5.json").write_text(
            json.dumps(transfer.to_serializable(), indent=2) + "\n", encoding="utf-8"
        )

        # Ensemble fingerprint
        eindex = build_ensemble_index_from_sourcemap(map_path)
        ehits = scan_ensemble(eindex, bundle_text)
        report.stages["fingerprint_ensemble"] = {
            "index_entries": len(eindex.digest_to_path),
            "confirmed": len(ehits),
            "paths": [h.source_path for h in ehits],
            "notes": list(eindex.notes),
        }
        (output_dir / "artifacts" / "fingerprint_ensemble.json").write_text(
            json.dumps(
                {
                    "confirmed": [
                        {
                            "source_path": h.source_path,
                            "signal_count": h.signal_count,
                            "kinds": h.kinds,
                            "provenance_confidence": h.provenance_confidence,
                        }
                        for h in ehits
                    ],
                    "index": eindex.to_serializable(),
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        # Graph completion using map bodies for confirmed ensemble paths
        data = json.loads(map_path.read_text(encoding="utf-8"))
        sources = data.get("sources") or []
        contents = data.get("sourcesContent") or []
        path_bodies: Dict[str, str] = {}
        for src, body in zip(sources, contents):
            if body is None:
                continue
            p = _normalize_source_path(str(src))
            if p and p not in path_bodies:
                path_bodies[p] = str(body)
        confirmed_bodies = {
            h.source_path: path_bodies[h.source_path] for h in ehits if h.source_path in path_bodies
        }
        # Hermetic anonymous modules: leftover map sources not confirmed
        anonymous = {
            f"anon:{p}": body
            for p, body in path_bodies.items()
            if p not in confirmed_bodies and not p.startswith("src/")
        }
        # Also try splitting project leftovers as anonymous ids by relative path
        project = output_dir / "project"
        if project.is_dir():
            for fp in project.rglob("*.js"):
                rel = fp.relative_to(project).as_posix()
                if rel not in confirmed_bodies:
                    anonymous[f"file:{rel}"] = fp.read_text(encoding="utf-8", errors="replace")
        hints = suggest_graph_completions(
            confirmed_path_to_body=confirmed_bodies,
            anonymous_modules=anonymous,
            min_shared=2,
        )
        report.stages["graph_complete"] = {
            "hint_count": len(hints),
            "hints": [
                {
                    "anonymous_id": h.anonymous_id,
                    "inferred_path": h.inferred_path,
                    "shared_imports": h.shared_imports,
                    "note": h.note,
                }
                for h in hints
            ],
        }

        # Wave 8: singleton literals + structural MinHash + coverage union
        attributed: Dict[str, str] = {}
        for h in ehits:
            attributed[h.source_path] = "ensemble"
        # Fingerprint paths (if serialized on transfer)
        fp_paths = transfer.metrics.get("first_party_confirmed_paths") or []
        if isinstance(fp_paths, list):
            for p in fp_paths:
                attributed.setdefault(str(p), "fingerprint_v5")
        single_hits, survivors = singleton_literal_hits(path_bodies, bundle_text)
        for p in single_hits:
            attributed.setdefault(p, "singleton_literal")
        remaining = {
            p: body
            for p, body in path_bodies.items()
            if p.startswith("src/") and p not in attributed
        }
        structural = match_sources_to_bundle(
            remaining,
            bundle_text,
            threshold=0.55,
            already_confirmed=set(attributed),
            max_sources=min(400, len(remaining)),
        )
        for m in structural:
            attributed.setdefault(m.source_path, "structural_minhash")
        # Survivors = independent presence evidence (literals / ensemble / fp), not structural
        survivors |= {h.source_path for h in ehits}
        if isinstance(fp_paths, list):
            survivors |= {str(p) for p in fp_paths}
        oracle_paths: Set[str] = {p for p in path_bodies if p.startswith("src/")}
        cov = union_coverage(
            oracle_paths=oracle_paths,
            attributed={p: m for p, m in attributed.items() if p in oracle_paths},
            survivor_paths={p for p in survivors if p in oracle_paths},
        )
        report.stages["coverage_union"] = cov.to_serializable()
        report.stages["structural_match"] = {
            "confirmed": len(structural),
            "paths": [m.source_path for m in structural],
            "scores": {m.source_path: m.score for m in structural},
        }
        report.stages["singleton_literal"] = {
            "confirmed": len(single_hits & oracle_paths),
            "survivor_detection": len(survivors & oracle_paths),
        }
        (output_dir / "artifacts" / "coverage_union.json").write_text(
            json.dumps(cov.to_serializable(), indent=2) + "\n", encoding="utf-8"
        )
        if cov.survivor_coverage >= 1.0 and cov.survivor_count > 0:
            report.notes.append("survivor_coverage_100pct")
        if cov.oracle_coverage >= 1.0 and cov.oracle_count > 0:
            report.notes.append("oracle_coverage_100pct")

        # Wave 8.5: iterative defrag + TF-IDF word-map (option C)
        defrag = run_iterative_defrag(
            sources=path_bodies,
            bundle_text=bundle_text,
            seed_attributed={p: m for p, m in attributed.items() if p in oracle_paths},
            max_rounds=8,
        )
        for path, method in defrag.attributed.items():
            attributed.setdefault(path, method)
        report.stages["iterative_defrag"] = defrag.to_serializable()
        report.notes.append("toolkit_wave85")
        report.notes.append("toolkit_wave10")
        # Wave 10: tombstone / recoverable-oracle (deleted vs weak residue)
        tomb = classify_tombstones(
            {p: path_bodies[p] for p in oracle_paths},
            bundle_text,
            min_hits=1,
        )
        rec_cov = recoverable_oracle_coverage(
            oracle_paths=oracle_paths,
            attributed={p: m for p, m in attributed.items() if p in oracle_paths},
            tombstones=tomb.tombstones,
        )
        tomb_ser = tomb.to_serializable()
        tomb_ser["recoverable_oracle_coverage"] = rec_cov
        tomb_ser["oracle_coverage"] = defrag.oracle_coverage
        report.stages["tombstone"] = tomb_ser
        (output_dir / "artifacts" / "tombstone.json").write_text(
            json.dumps(tomb_ser, indent=2) + "\n", encoding="utf-8"
        )
        final_cov = union_coverage(
            oracle_paths=oracle_paths,
            attributed={p: m for p, m in attributed.items() if p in oracle_paths},
            survivor_paths=set(defrag.attributed.keys())
            | set(tomb.survivors)
            | {p for p in survivors if p in oracle_paths},
        )
        report.stages["coverage_union_final"] = final_cov.to_serializable()
        (output_dir / "artifacts" / "iterative_defrag.json").write_text(
            json.dumps(defrag.to_serializable(), indent=2) + "\n", encoding="utf-8"
        )
        if defrag.survivor_coverage >= 1.0 and defrag.unlockable_count > 0:
            report.notes.append("defrag_survivor_coverage_100pct")
        if defrag.oracle_coverage >= 1.0 and defrag.unlockable_count > 0:
            report.notes.append("defrag_oracle_coverage_100pct")
        if rec_cov >= 1.0 and (oracle_paths - tomb.tombstones):
            report.notes.append("recoverable_oracle_coverage_100pct")

        # Wave 9/9b: AST-chunked LLM digest + tag-boost defrag (optional)
        if enable_llm_digest:
            summarize_fn, provider_notes = build_summarize_fn(prefer=llm_prefer)
            # Prefer diverse unlocked paths (largest first) for richer tags
            unlocked = sorted(
                defrag.attributed.keys(),
                key=lambda p: len(path_bodies.get(p, "")),
                reverse=True,
            )
            # Also probe a few unattributed neighbors for tag unlock
            remaining = [
                p
                for p in sorted(
                    oracle_paths, key=lambda x: len(path_bodies.get(x, "")), reverse=True
                )
                if p not in defrag.attributed
            ][: max(0, llm_max_modules // 2)]
            probe_paths = unlocked[: max(1, llm_max_modules - len(remaining))] + remaining
            digests = summarize_unlocked_modules(
                path_to_body=path_bodies,
                unlocked_paths=probe_paths,
                summarize_fn=summarize_fn,
                max_modules=llm_max_modules,
            )
            report.stages["llm_digest"] = {
                "enabled": True,
                "provider_probe": probe_providers(),
                "provider_notes": provider_notes,
                "module_count": len(digests),
                "digests": [d.to_serializable() for d in digests],
                "notes": [
                    "not_full_bundle_dump",
                    "ast_chunked_modules",
                    "humanify_pattern",
                ],
            }
            report.llm_used = True
            report.notes.append("llm_digest_enabled")
            if llm_tag_boost and digests:
                boost = run_tag_boost_defrag(
                    sources=path_bodies,
                    bundle_text=bundle_text,
                    seed_attributed={p: m for p, m in attributed.items() if p in oracle_paths},
                    digests=digests,
                    max_rounds=4,
                )
                for path, method in boost.defrag.attributed.items() if boost.defrag else []:
                    attributed.setdefault(path, method)
                report.stages["llm_tag_boost"] = boost.to_serializable()
                report.notes.append("llm_tag_boost")
                if boost.defrag and boost.defrag.oracle_coverage >= 1.0:
                    report.notes.append("tag_boost_oracle_coverage_100pct")
    else:
        report.notes.append("sourcemap_absent")

    # Behavior overlap vs oracle tree text
    if oracle_dir is not None and Path(oracle_dir).is_dir():
        oracle_blob = []
        for p in Path(oracle_dir).rglob("*"):
            if p.suffix.lower() in {".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs"}:
                try:
                    oracle_blob.append(p.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
        overlap = behavior_token_overlap("\n".join(oracle_blob), bundle_text)
        report.stages["behavior"] = {
            "oracle_token_count": overlap.oracle_token_count,
            "target_token_count": overlap.target_token_count,
            "intersection": overlap.intersection,
            "recall": overlap.recall,
            "precision": overlap.precision,
            "notes": overlap.notes,
        }

    # Optional externals: webcrack FIRST (CFF/string-array), then wakaru (unminify)
    if run_external:
        wc_out = output_dir / "external" / "webcrack"
        report.stages["external_webcrack"] = try_webcrack(bundle, wc_out).__dict__
        report.stages["external_wakaru"] = try_wakaru(
            bundle, output_dir / "external" / "wakaru"
        ).__dict__
        report.notes.append("external_chain_webcrack_then_wakaru")

    (output_dir / "toolkit_report.json").write_text(
        json.dumps(report.to_serializable(), indent=2) + "\n", encoding="utf-8"
    )
    return report
