"""Shared contract helpers for app-level reverse-engineering outputs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Sequence

from reveng.result_contracts import RESULT_SCHEMA_VERSION, make_evidence_item, make_trace_reference

APP_RESULT_TYPE = "app_reverse_engineering_result"


def enrich_app_analysis_payload(
    payload: MutableMapping[str, Any],
    *,
    language: str,
    adapter_name: str,
    input_path: Path,
    input_root: Path,
    output_dir: Path,
    analysis_file: Path,
    topic_files: Mapping[str, Path],
    domain_files: Mapping[str, Path],
    primary_artifacts: Mapping[str, Path],
    source_count: int,
    warnings: Sequence[str],
) -> Dict[str, Any]:
    """Attach shared schema, validation, evidence, and provenance fields."""
    topic_match_counts = payload.get("topic_match_counts", {})
    evidence = build_app_evidence(
        input_path=input_path,
        analysis_file=analysis_file,
        topic_files=topic_files,
        domain_files=domain_files,
        primary_artifacts=primary_artifacts,
        topic_match_counts=topic_match_counts if isinstance(topic_match_counts, Mapping) else {},
        source_count=source_count,
    )
    provenance = build_app_provenance(
        language=language,
        adapter_name=adapter_name,
        input_path=input_path,
        input_root=input_root,
        output_dir=output_dir,
        analysis_file=analysis_file,
        topic_files=topic_files,
        domain_files=domain_files,
        primary_artifacts=primary_artifacts,
    )
    validation = build_validation_summary(
        source_count=source_count,
        warnings=warnings,
        topic_match_counts=topic_match_counts if isinstance(topic_match_counts, Mapping) else {},
        primary_artifacts=primary_artifacts,
        evidence_count=len(evidence),
    )

    enriched = dict(payload)
    enriched.update(
        {
            "schema_version": RESULT_SCHEMA_VERSION,
            "result_type": APP_RESULT_TYPE,
            "validation": validation,
            "evidence": evidence,
            "provenance": provenance,
        }
    )
    return enriched


def build_validation_summary(
    *,
    source_count: int,
    warnings: Sequence[str],
    topic_match_counts: Mapping[str, Any],
    primary_artifacts: Mapping[str, Path],
    evidence_count: int,
) -> Dict[str, Any]:
    """Build a compact analyst-facing validation summary."""
    topic_evidence = 0
    for value in topic_match_counts.values():
        if isinstance(value, int):
            topic_evidence += value

    artifact_count = len(primary_artifacts)
    warning_count = len(warnings)
    if source_count > 0 and topic_evidence >= 5 and warning_count == 0:
        grade = "evidence_backed"
    elif source_count > 0 and topic_evidence >= 1:
        grade = "partial_recovery"
    elif artifact_count > 0 or topic_evidence > 0:
        grade = "structure_only"
    else:
        grade = "packaging_only"

    summary = (
        f"Recovered {source_count} source artifact(s), {topic_evidence} topic evidence snippet(s), "
        f"and {artifact_count} primary artifact(s); warnings={warning_count}."
    )
    return {
        "grade": grade,
        "summary": summary,
        "evidence_count": evidence_count,
        "topic_evidence_count": topic_evidence,
        "artifact_count": artifact_count,
        "warning_count": warning_count,
    }


def build_app_provenance(
    *,
    language: str,
    adapter_name: str,
    input_path: Path,
    input_root: Path,
    output_dir: Path,
    analysis_file: Path,
    topic_files: Mapping[str, Path],
    domain_files: Mapping[str, Path],
    primary_artifacts: Mapping[str, Path],
) -> Dict[str, Any]:
    """Build shared provenance for app-level reverse-engineering output."""
    trace_id = f"app-re::{language}::{analysis_file.stem}"
    artifacts = [
        make_evidence_item(
            "analysis_summary",
            path=str(analysis_file),
            trace_id=trace_id,
            evidence_kind="analysis_summary",
        )
    ]
    for topic_key, path in topic_files.items():
        artifacts.append(
            make_evidence_item(
                "spec_topic",
                path=str(path),
                trace_id=trace_id,
                evidence_kind="spec_topic",
                metadata={"topic_key": topic_key},
            )
        )
    for topic_key, path in domain_files.items():
        artifacts.append(
            make_evidence_item(
                "domain_evidence",
                path=str(path),
                trace_id=trace_id,
                evidence_kind="domain_evidence",
                metadata={"topic_key": topic_key},
            )
        )
    for artifact_name, path in primary_artifacts.items():
        artifacts.append(
            make_evidence_item(
                "primary_artifact",
                path=str(path),
                trace_id=trace_id,
                evidence_kind="primary_artifact",
                metadata={"artifact_name": artifact_name},
            )
        )

    references = [
        make_trace_reference(
            "analyzed_under",
            str(output_dir),
            trace_id=trace_id,
            metadata={"adapter_name": adapter_name},
        )
    ]
    if input_root != input_path.parent:
        references.append(
            make_trace_reference(
                "scoped_from_root",
                str(input_root),
                trace_id=trace_id,
            )
        )

    return {
        "inputs": [
            make_evidence_item(
                "app_input",
                path=str(input_path),
                trace_id=trace_id,
                evidence_kind="input_app",
                metadata={"input_root": str(input_root)},
            )
        ],
        "artifacts": artifacts,
        "stages": [
            "input_inventory",
            "spec_generation",
            "domain_split",
            "analysis_summary_serialization",
        ],
        "references": references,
        "tools": [adapter_name],
    }


def build_app_evidence(
    *,
    input_path: Path,
    analysis_file: Path,
    topic_files: Mapping[str, Path],
    domain_files: Mapping[str, Path],
    primary_artifacts: Mapping[str, Path],
    topic_match_counts: Mapping[str, Any],
    source_count: int,
) -> List[Dict[str, Any]]:
    """Create evidence references for major analyst-facing artifacts."""
    trace_id = f"app-re::{analysis_file.stem}"
    evidence: List[Dict[str, Any]] = [
        make_evidence_item(
            "input_sample",
            path=str(input_path),
            trace_id=trace_id,
            evidence_kind="input_app",
        ),
        make_evidence_item(
            "analysis_summary",
            path=str(analysis_file),
            trace_id=trace_id,
            evidence_kind="analysis_summary",
            metadata={"source_count": source_count},
        ),
    ]
    for topic_key, path in topic_files.items():
        evidence.append(
            make_evidence_item(
                "spec_topic",
                path=str(path),
                trace_id=trace_id,
                evidence_kind="spec_topic",
                metadata={
                    "topic_key": topic_key,
                    "match_count": int(topic_match_counts.get(topic_key, 0) or 0),
                },
            )
        )
    for topic_key, path in domain_files.items():
        evidence.append(
            make_evidence_item(
                "domain_evidence",
                path=str(path),
                trace_id=trace_id,
                evidence_kind="domain_evidence",
                metadata={"topic_key": topic_key},
            )
        )
    for artifact_name, path in primary_artifacts.items():
        evidence.append(
            make_evidence_item(
                "primary_artifact",
                path=str(path),
                trace_id=trace_id,
                evidence_kind="primary_artifact",
                metadata={"artifact_name": artifact_name},
            )
        )
    return evidence


def rewrite_analysis_file(analysis_file: Path, payload: Mapping[str, Any]) -> None:
    """Rewrite the machine-readable analysis summary with normalized formatting."""
    analysis_file.write_text(json.dumps(dict(payload), indent=2), encoding="utf-8")
