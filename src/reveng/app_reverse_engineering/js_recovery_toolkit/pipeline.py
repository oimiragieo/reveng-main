"""End-to-end JS recovery toolkit pipeline (Wave 7)."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from reveng.app_reverse_engineering.js_project_materialize import materialize_js_project_tree
from reveng.app_reverse_engineering.js_stale_map_transfer import (
    _normalize_source_path,
    apply_fingerprint_backed_missing,
)

from .behavior_probe import behavior_token_overlap
from .ensemble_index import build_ensemble_index_from_sourcemap, scan_ensemble
from .external_tools import (
    probe_external_tools,
    try_bun_extract_in_tree,
    try_wakaru,
    try_webcrack,
    write_tool_probe_json,
)
from .graph_complete import suggest_graph_completions


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
) -> ToolkitReport:
    """Run materialize → fingerprint → ensemble → graph → behavior (+ optional externals)."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    report = ToolkitReport(output_dir=output_dir)
    report.notes.append("toolkit_wave7")

    tools_probe = write_tool_probe_json(output_dir / "tool_probe.json")
    report.stages["tool_probe"] = tools_probe

    # Optional Bun binary extract
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

    if bundle is None or not Path(bundle).is_file():
        report.notes.append("bundle_absent")
        (output_dir / "toolkit_report.json").write_text(
            json.dumps(report.to_serializable(), indent=2) + "\n", encoding="utf-8"
        )
        return report

    bundle = Path(bundle)
    bundle_text = bundle.read_text(encoding="utf-8", errors="replace")

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

    # Optional externals (off by default for hermetic CI)
    if run_external:
        report.stages["external_webcrack"] = try_webcrack(
            bundle, output_dir / "external" / "webcrack"
        ).__dict__
        report.stages["external_wakaru"] = try_wakaru(
            bundle, output_dir / "external" / "wakaru"
        ).__dict__

    (output_dir / "toolkit_report.json").write_text(
        json.dumps(report.to_serializable(), indent=2) + "\n", encoding="utf-8"
    )
    return report
