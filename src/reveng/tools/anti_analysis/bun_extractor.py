"""
Bun executable detection and JavaScript extraction helpers.

Focused on Bun single-file Windows executables that embed a `.bun` PE section.
"""

from __future__ import annotations

import base64
import json
import hashlib
import logging
import re
import shutil
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional
from urllib.parse import unquote_to_bytes

logger = logging.getLogger(__name__)

try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs
    from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP

    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False

try:
    import pefile

    _PEFILE_AVAILABLE = True
except ImportError:
    _PEFILE_AVAILABLE = False

_TEXT_BYTES = {9, 10, 13} | set(range(32, 127))
_NODE_BUILTIN_MODULES = {
    "assert",
    "buffer",
    "child_process",
    "cluster",
    "console",
    "constants",
    "crypto",
    "dgram",
    "diagnostics_channel",
    "dns",
    "domain",
    "events",
    "fs",
    "http",
    "http2",
    "https",
    "inspector",
    "module",
    "net",
    "os",
    "path",
    "perf_hooks",
    "process",
    "punycode",
    "querystring",
    "readline",
    "repl",
    "stream",
    "string_decoder",
    "timers",
    "tls",
    "tty",
    "url",
    "util",
    "v8",
    "vm",
    "worker_threads",
    "zlib",
}


@dataclass
class BunExecutableInfo:
    """Detection result for a Bun-compiled executable."""

    is_bun_executable: bool
    container: Optional[str]
    section_name: Optional[str]
    bundle_offset: Optional[int]
    bundle_size: Optional[int]
    javascript_start_offset: Optional[int]
    indicators: List[str]


@dataclass
class BunExtractionResult:
    """Result of extracting bundled JavaScript from a Bun executable."""

    success: bool
    output_path: Optional[str]
    extracted_hash: Optional[str]
    javascript_size: int
    error_message: Optional[str]
    info: BunExecutableInfo


@dataclass
class BunModuleEntry:
    """Single Bun module entry parsed from the embedded module graph."""

    virtual_path: str
    recovered_path: str
    loader_id: int
    content_offset: int
    content_size: int
    sourcemap_offset: int
    sourcemap_size: int


@dataclass
class BunModuleGraph:
    """Parsed Bun module graph metadata."""

    entry_point_id: int
    compile_exec_argv: str
    modules: List[BunModuleEntry]
    module_layout: str = "full"


@dataclass
class BunRecoveryResult:
    """Result of reconstructing the Bun virtual filesystem."""

    success: bool
    output_dir: Optional[str]
    manifest_path: Optional[str]
    recovered_files: List[str]
    error_message: Optional[str]
    graph: Optional[BunModuleGraph]
    recovery_mode: str = "module_graph"


@dataclass
class BunNormalizationResult:
    """Result of normalizing recovered Bun JavaScript into a project workspace."""

    success: bool
    output_dir: Optional[str]
    entrypoint_path: Optional[str]
    sea_entrypoint_path: Optional[str]
    sea_config_path: Optional[str]
    package_json_path: Optional[str]
    manifest_path: Optional[str]
    inferred_dependencies: List[str]
    runtime_features: List[str]
    shims_applied: List[str]
    semantic_checks: List[Dict[str, str]]
    postprocessing_hooks: List[Dict[str, str]]
    warnings: List[str]
    error_message: Optional[str]


@dataclass
class BunDependencyAnalysis:
    """Recovered dependency information for a normalized Bun workspace."""

    required_packages: List[str]
    builtin_modules: List[str]
    ignored_package_strings: List[str]


@dataclass
class BunSeaBuildResult:
    """Result of packaging a normalized Bun workspace with Node SEA."""

    success: bool
    normalized_project_dir: Optional[str]
    output_path: Optional[str]
    sea_blob_path: Optional[str]
    installed_dependencies: List[str]
    commands_run: List[str]
    verification: Optional[Dict[str, Any]]
    error_message: Optional[str]


@dataclass
class BunSeaWorkflowResult:
    """End-to-end Bun rebuild workflow state for higher-level surfaces."""

    status: str
    message: Optional[str]
    reason: Optional[str]
    info: BunExecutableInfo
    extraction: Optional[BunExtractionResult]
    recovery: Optional[BunRecoveryResult]
    normalization: Optional[BunNormalizationResult]
    build_result: Optional[BunSeaBuildResult]
    differential_validation: Optional[Dict[str, Any]]
    canonical_input: Optional[str]
    canonical_reason: Optional[str]
    report_path: Optional[str]
    report_data: Optional[Dict[str, Any]]


@dataclass
class BunSourcemapProvenance:
    """Structured provenance and validation metadata for recovered sourcemaps."""

    origin: str
    byte_size: int
    sha256: str
    parse_status: str
    file_field: Optional[str]
    source_count: int
    file_matches_source_name: Optional[bool]


@dataclass
class BunPostprocessingHook:
    """Recommended post-processing step for recovered JavaScript artifacts."""

    tool: str
    category: str
    reason: str
    suggested_input: str
    command_template: str


@dataclass
class BunSemanticCheck:
    """Structured semantic normalization check for recovered JS/TS workspaces."""

    check: str
    severity: str
    message: str


@dataclass
class PEStubAnalysis:
    """Summary of the native PE stub that hosts an embedded Bun bundle."""

    container: str
    machine: Optional[str]
    entry_point_rva: Optional[int]
    image_base: Optional[int]
    entry_point_section: Optional[str]
    entry_point_preview: List["PEInstructionPreview"]
    section_names: List[str]
    tls_directory_rva: Optional[int]
    tls_callback_vas: List[int]
    tls_callbacks: List["PETLSCallback"]
    import_dlls: List[str]
    imported_functions: List[str]
    suspicious_imports: List[str]
    startup_classification: str
    startup_reasons: List[str]
    runtime_readiness: "PERuntimeReadiness"
    dump_guidance: "PEDumpGuidance"
    cross_references: List["PECrossReference"]
    handoff_signals: List["PEHandoffSignal"]
    startup_targets: List["PEStartupTarget"]
    startup_graph: "PEStartupGraph"
    indicators: List[str]


@dataclass
class PETLSCallback:
    """Resolved TLS callback metadata."""

    virtual_address: int
    rva: int
    section_name: Optional[str]
    file_offset: Optional[int]
    instruction_preview: List["PEInstructionPreview"]


@dataclass
class PEInstructionPreview:
    """Small disassembly preview for startup-path triage."""

    address: int
    mnemonic: str
    op_str: str
    target_address: Optional[int]
    target_rva: Optional[int]
    target_section: Optional[str]
    import_target: Optional[str]
    rip_relative_address: Optional[int]
    rip_relative_section: Optional[str]


@dataclass
class PEStartupTarget:
    """Deduplicated first-hop startup target summary."""

    source: str
    instruction_address: int
    instruction_mnemonic: str
    target_address: Optional[int]
    target_rva: Optional[int]
    target_section: Optional[str]
    symbolic_label: str
    target_resolution: str
    import_target: Optional[str]
    target_preview: List["PEInstructionPreview"]


@dataclass
class PEStartupGraphNode:
    """Bounded startup-graph node used for triage output."""

    label: str
    node_type: str
    address: Optional[int]
    rva: Optional[int]
    section: Optional[str]
    source: Optional[str]
    target_resolution: Optional[str]
    import_target: Optional[str]


@dataclass
class PEStartupGraphEdge:
    """Bounded startup-graph edge used for triage output."""

    source_label: str
    target_label: str
    instruction_mnemonic: str
    instruction_address: int
    depth: int
    target_resolution: str
    import_target: Optional[str]


@dataclass
class PEStartupGraph:
    """Compact bounded startup graph rooted at entrypoint/TLS callbacks."""

    roots: List[str]
    nodes: List["PEStartupGraphNode"]
    edges: List["PEStartupGraphEdge"]
    truncated: bool


@dataclass
class PEHandoffSignal:
    """Strong signal that startup flow is converging toward Bun/JS runtime handoff."""

    kind: str
    source: str
    message: str
    confidence: str


@dataclass
class PECrossReference:
    """Cross-linked PE clue surfaced from resources, manifests, or string evidence."""

    kind: str
    value: str
    section: Optional[str]
    file_offset: Optional[int]
    source: str


@dataclass
class PERuntimeObservationPoint:
    """Recommended runtime observation point for debugging or dumping."""

    label: str
    kind: str
    address: Optional[int]
    section: Optional[str]
    reason: str


@dataclass
class PERuntimeReadiness:
    """Structured runtime-observation guidance when static analysis stalls."""

    breakpoints: List["PERuntimeObservationPoint"]
    dump_points: List["PERuntimeObservationPoint"]
    notes: List[str]


@dataclass
class PEDumpGuidanceAction:
    """Escalation action for runtime-unpacked or dynamically resolved startup paths."""

    kind: str
    summary: str
    trigger: str


@dataclass
class PEDumpGuidance:
    """Structured escalation guidance for dump/import reconstruction workflows."""

    recommended: bool
    actions: List["PEDumpGuidanceAction"]


def select_bun_recompilation_input(
    bundle_output: Optional[str], recovery: Optional[BunRecoveryResult]
) -> tuple[Optional[str], str]:
    """Choose the cleanest recovered Bun artifact for downstream recompilation."""
    if recovery and recovery.success:
        for recovered_file in recovery.recovered_files:
            recovered_path = Path(recovered_file)
            if recovered_path.name == "module_graph.json":
                continue
            if recovered_path.suffix == ".bunmap":
                continue
            if recovered_path.name in {"bundle_tail.bin", "module_records.bin", "discovered_paths.txt"}:
                continue
            try:
                prefix = recovered_path.read_text(encoding="utf-8", errors="replace")[:32]
            except Exception:
                prefix = ""
            if prefix.startswith("// @bun"):
                return str(recovered_path), "Recovered Bun virtual file excludes appended bundle metadata"

    return bundle_output, "Extracted bundle is the best available Bun source artifact"


def build_bun_report_severity_summary(
    native_stub: Optional[PEStubAnalysis] = None,
    normalization: Optional[BunNormalizationResult] = None,
    differential_validation: Optional[Dict[str, Any]] = None,
    verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a compact reconstruction-risk ranking for Bun analysis/rebuild reports."""
    severity_weights = {"info": 0, "low": 10, "medium": 25, "high": 50, "critical": 75}
    factors: List[Dict[str, str]] = []

    def add_factor(level: str, source: str, message: str) -> None:
        factors.append({"level": level, "source": source, "message": message})

    if native_stub:
        if native_stub.startup_classification == "runtime_bootstrap_likely":
            add_factor(
                "high",
                "native_stub",
                "Native startup looks runtime-driven and may require dynamic observation or staged dumping.",
            )
        if native_stub.suspicious_imports:
            add_factor(
                "medium",
                "native_stub",
                "Loader-style imports are present in the startup profile: "
                + ", ".join(native_stub.suspicious_imports[:4]),
            )
        if native_stub.dump_guidance.recommended:
            add_factor(
                "high",
                "dump_guidance",
                "Static recovery alone may be incomplete; dump/import reconstruction guidance was triggered.",
            )
        if native_stub.startup_graph.truncated:
            add_factor(
                "medium",
                "startup_graph",
                "Bounded startup graph truncated before fully exploring startup fan-out.",
            )

    if normalization:
        for check in normalization.semantic_checks:
            if check["severity"] == "warning":
                add_factor("medium", "semantic_checks", check["message"])

    if differential_validation:
        for check in differential_validation.get("checks", []):
            if check["status"] == "fail":
                add_factor("high", "differential_validation", check["message"])
            elif check["status"] == "warn":
                add_factor("medium", "differential_validation", check["message"])

    if verification:
        for check in verification.get("checks", []):
            if check["status"] == "fail":
                add_factor("critical", "sea_build_verification", check["message"])
            elif check["status"] == "warn":
                add_factor("medium", "sea_build_verification", check["message"])

    if not factors:
        return {
            "dimension": "reconstruction_risk",
            "level": "low",
            "score": 0,
            "summary": "Low reconstruction risk; no elevated attention factors were detected.",
            "factors": [],
        }

    score = min(100, sum(severity_weights[factor["level"]] for factor in factors))
    level = max(factors, key=lambda factor: severity_weights[factor["level"]])["level"]
    summary = (
        f"{level.title()} reconstruction risk; {len(factors)} attention factor"
        f"{'' if len(factors) == 1 else 's'} detected."
    )
    return {
        "dimension": "reconstruction_risk",
        "level": level,
        "score": score,
        "summary": summary,
        "factors": factors,
    }


def build_bun_runtime_escalation_summary(
    native_stub: Optional[PEStubAnalysis] = None,
    report_severity: Optional[Dict[str, Any]] = None,
    differential_validation: Optional[Dict[str, Any]] = None,
    verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a compact analyst-facing escalation plan from Bun static/rebuild evidence."""

    severity_level = (report_severity or {}).get("level", "low")
    severity_score = (report_severity or {}).get("score", 0)
    differential_status = (differential_validation or {}).get("status")
    verification_status = (verification or {}).get("status")

    evidence = {
        "report_severity_level": severity_level,
        "report_severity_score": severity_score,
        "dump_guidance_recommended": (
            native_stub.dump_guidance.recommended if native_stub else False
        ),
        "breakpoint_count": (
            len(native_stub.runtime_readiness.breakpoints) if native_stub else 0
        ),
        "dump_point_count": (
            len(native_stub.runtime_readiness.dump_points) if native_stub else 0
        ),
        "differential_status": differential_status,
        "verification_status": verification_status,
    }
    reasons: List[str] = []
    next_steps: List[Dict[str, Any]] = []
    seen_kinds: set[str] = set()

    def add_step(priority: int, kind: str, title: str, summary: str, evidence_items: List[str]) -> None:
        if kind in seen_kinds:
            return
        seen_kinds.add(kind)
        next_steps.append(
            {
                "priority": priority,
                "kind": kind,
                "title": title,
                "summary": summary,
                "evidence": evidence_items,
            }
        )

    if native_stub:
        if native_stub.startup_classification == "runtime_bootstrap_likely":
            reasons.append(
                "Native startup looks runtime-driven, so static recovery may miss late materialization."
            )
        if native_stub.dump_guidance.recommended:
            reasons.append(
                "Dump/import-reconstruction guidance was triggered by Bun handoff or loader-style startup evidence."
            )
        if native_stub.startup_graph.truncated:
            reasons.append(
                "Startup graph exploration truncated before the startup fan-out was fully resolved."
            )

    if severity_level in {"high", "critical"}:
        reasons.append(
            f"Overall reconstruction risk is {severity_level}, which justifies runtime validation before overclaiming fidelity."
        )
    if differential_status in {"warn", "fail"}:
        reasons.append(
            f"Differential validation returned {differential_status}, so normalized output should be checked against runtime behavior."
        )
    if verification_status in {"warn", "fail", "pass_with_warnings"}:
        reasons.append(
            f"SEA build verification returned {verification_status}, so rebuild-side assumptions should be reviewed alongside static recovery."
        )

    if native_stub and native_stub.runtime_readiness.breakpoints:
        top_labels = ", ".join(
            point.label for point in native_stub.runtime_readiness.breakpoints[:3]
        )
        add_step(
            1,
            "set_breakpoints",
            "Set targeted startup breakpoints",
            "Use the recommended entrypoint/TLS/callsite breakpoints before later startup stages hide useful evidence.",
            [f"breakpoints:{top_labels}"],
        )

    if native_stub and any(action.kind == "memory_dump" for action in native_stub.dump_guidance.actions):
        dump_labels = ", ".join(
            point.label for point in native_stub.runtime_readiness.dump_points[:3]
        )
        add_step(
            2,
            "capture_memory_dump",
            "Capture memory near Bun handoff",
            "Dump process memory after control flow reaches Bun-linked regions to recover runtime-materialized payload state.",
            [f"dump_points:{dump_labels}" if dump_labels else "dump_guidance:memory_dump"],
        )

    if native_stub and any(
        action.kind == "import_reconstruction" for action in native_stub.dump_guidance.actions
    ):
        add_step(
            3,
            "reconstruct_imports",
            "Trace and reconstruct dynamic imports",
            "Instrument import-resolution callsites when loader-style APIs dominate the startup path.",
            ["dump_guidance:import_reconstruction"],
        )

    if differential_status in {"warn", "fail"} or verification_status in {
        "warn",
        "fail",
        "pass_with_warnings",
    }:
        add_step(
            4,
            "review_diff_and_verification",
            "Review diff and rebuild evidence",
            "Compare differential validation with SEA verification before treating the normalized workspace as behaviorally complete.",
            [
                f"differential_validation:{differential_status or 'unknown'}",
                f"sea_build_verification:{verification_status or 'unknown'}",
            ],
        )

    recommended = bool(
        evidence["dump_guidance_recommended"]
        or severity_level in {"high", "critical"}
        or differential_status in {"warn", "fail"}
        or verification_status in {"warn", "fail", "pass_with_warnings"}
    )
    if not next_steps:
        add_step(
            1,
            "continue_static_analysis",
            "Continue static recovery",
            "Static recovery signals are coherent enough to keep working from the normalized workspace and report surfaces.",
            [f"report_severity:{severity_level}"],
        )

    next_steps.sort(key=lambda step: step["priority"])
    if not reasons:
        reasons.append(
            "Static recovery and rebuild evidence currently look coherent enough to avoid immediate runtime escalation."
        )

    if not recommended:
        status = "static_sufficient"
        confidence = "high"
        summary = "Static recovery appears sufficient; runtime escalation is not currently recommended."
    elif evidence["dump_guidance_recommended"] and evidence["dump_point_count"] > 0:
        status = "runtime_dump_recommended"
        confidence = "high"
        summary = "Runtime dumping is recommended because Bun handoff and startup evidence suggest static recovery may be incomplete."
    elif evidence["breakpoint_count"] > 0:
        status = "targeted_runtime_observation"
        confidence = "medium"
        summary = "Targeted runtime observation is recommended before making stronger fidelity claims."
    else:
        status = "manual_review_required"
        confidence = "medium"
        summary = "Manual review is recommended because report-side warnings outpace the available runtime guidance."

    return {
        "dimension": "runtime_escalation",
        "recommended": recommended,
        "status": status,
        "confidence": confidence,
        "summary": summary,
        "reasons": reasons,
        "next_steps": next_steps,
        "evidence": evidence,
    }


def build_bun_equivalence_validation_summary(
    differential_validation: Optional[Dict[str, Any]] = None,
    verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build a compact equivalence-confidence summary for rebuilt Bun artifacts."""

    if not differential_validation or not verification:
        return {
            "dimension": "equivalence_validation",
            "status": "insufficient_evidence",
            "equivalence_level": "insufficient_evidence",
            "confidence": "low",
            "summary": "Equivalence evidence is incomplete because differential validation or rebuild verification is missing.",
            "reasons": [
                "Both differential validation and rebuild verification are required before making an equivalence claim."
            ],
            "recommended_validations": [
                {
                    "priority": 1,
                    "kind": "complete_build_validation",
                    "title": "Complete build-side validation",
                    "summary": "Run the Bun rebuild workflow far enough to emit both differential validation and SEA verification evidence.",
                    "evidence": ["missing_equivalence_inputs"],
                }
            ],
            "evidence": {
                "differential_status": differential_validation.get("status") if differential_validation else None,
                "verification_status": verification.get("status") if verification else None,
            },
        }

    differential_status = differential_validation.get("status")
    verification_status = verification.get("status")
    diff_checks = differential_validation.get("checks", [])
    verification_checks = verification.get("checks", [])
    diff_failures = [check for check in diff_checks if check.get("status") == "fail"]
    diff_warnings = [check for check in diff_checks if check.get("status") == "warn"]
    verification_failures = [check for check in verification_checks if check.get("status") == "fail"]
    verification_warnings = [check for check in verification_checks if check.get("status") == "warn"]
    content_changed = bool(differential_validation.get("content_changed"))
    expected_rewrites = differential_validation.get("expected_rewrites", [])
    missing_features = differential_validation.get("missing_runtime_features", [])
    added_features = differential_validation.get("added_runtime_features", [])

    reasons: List[str] = []
    recommended_validations: List[Dict[str, Any]] = []
    seen_kinds: set[str] = set()

    def add_validation(
        priority: int,
        kind: str,
        title: str,
        summary: str,
        evidence_items: List[str],
    ) -> None:
        if kind in seen_kinds:
            return
        seen_kinds.add(kind)
        recommended_validations.append(
            {
                "priority": priority,
                "kind": kind,
                "title": title,
                "summary": summary,
                "evidence": evidence_items,
            }
        )

    if diff_failures or verification_failures:
        status = "divergent"
        equivalence_level = "not_equivalent"
        confidence = "high"
        reasons.append("One or more differential or rebuild verification checks failed.")
    elif diff_warnings or verification_warnings:
        status = "candidate_with_warnings"
        equivalence_level = "structural_candidate"
        confidence = "medium"
        reasons.append("No hard failures were found, but warnings still limit confidence in behavioral equivalence.")
    elif not content_changed:
        status = "candidate"
        equivalence_level = "artifact_identity_candidate"
        confidence = "high"
        reasons.append("Normalized source matches the canonical input byte-for-byte while rebuild verification is clean.")
    else:
        status = "candidate"
        equivalence_level = "semantic_candidate"
        confidence = "medium"
        reasons.append("Content changed, but only within a verification-clean normalization path, so semantic equivalence is the strongest current claim.")

    if expected_rewrites:
        reasons.append(
            "Known Bun-to-Node rewrites were applied: " + ", ".join(expected_rewrites)
        )
    if missing_features:
        reasons.append(
            "Preserved runtime features were lost during normalization: " + ", ".join(missing_features)
        )
    if added_features:
        reasons.append(
            "Normalization introduced additional runtime features that should be reviewed: " + ", ".join(added_features)
        )

    add_validation(
        1,
        "characterization_smoke_test",
        "Run black-box characterization checks",
        "Exercise representative CLI or runtime behaviors against the original and rebuilt artifacts to confirm externally visible behavior is preserved.",
        [
            f"differential_validation:{differential_status}",
            f"sea_build_verification:{verification_status}",
        ],
    )
    if content_changed or expected_rewrites or diff_warnings or verification_warnings:
        add_validation(
            2,
            "structural_diff_review",
            "Review structural differences",
            "Inspect transformed source and rebuild evidence to confirm changes are limited to expected rewrites and packaging differences.",
            [
                f"content_changed:{content_changed}",
                f"expected_rewrite_count:{len(expected_rewrites)}",
            ],
        )
    if diff_failures or missing_features or added_features:
        add_validation(
            3,
            "runtime_compare",
            "Compare runtime behavior directly",
            "Use targeted runtime comparison when semantic continuity checks found dropped or newly introduced runtime behavior.",
            [
                f"missing_runtime_feature_count:{len(missing_features)}",
                f"added_runtime_feature_count:{len(added_features)}",
            ],
        )

    recommended_validations.sort(key=lambda item: item["priority"])
    evidence = {
        "differential_status": differential_status,
        "verification_status": verification_status,
        "content_changed": content_changed,
        "expected_rewrite_count": len(expected_rewrites),
        "missing_runtime_feature_count": len(missing_features),
        "added_runtime_feature_count": len(added_features),
        "differential_fail_count": len(diff_failures),
        "differential_warn_count": len(diff_warnings),
        "verification_fail_count": len(verification_failures),
        "verification_warn_count": len(verification_warnings),
    }
    summary = (
        f"{equivalence_level.replace('_', ' ').title()} with {confidence} confidence "
        f"based on differential validation={differential_status} and rebuild verification={verification_status}."
    )
    return {
        "dimension": "equivalence_validation",
        "status": status,
        "equivalence_level": equivalence_level,
        "confidence": confidence,
        "summary": summary,
        "reasons": reasons,
        "recommended_validations": recommended_validations,
        "evidence": evidence,
    }


def _serialize_bun_normalization(normalization: Optional[BunNormalizationResult]) -> Optional[Dict[str, Any]]:
    if not normalization:
        return None
    return {
        "success": normalization.success,
        "output_dir": normalization.output_dir,
        "entrypoint_path": normalization.entrypoint_path,
        "sea_entrypoint_path": normalization.sea_entrypoint_path,
        "sea_config_path": normalization.sea_config_path,
        "package_json_path": normalization.package_json_path,
        "manifest_path": normalization.manifest_path,
        "inferred_dependencies": normalization.inferred_dependencies,
        "runtime_features": normalization.runtime_features,
        "shims_applied": normalization.shims_applied,
        "warnings": normalization.warnings,
        "error_message": normalization.error_message,
    }


def _serialize_bun_recovery(recovery: Optional[BunRecoveryResult]) -> Optional[Dict[str, Any]]:
    if not recovery:
        return None
    return {
        "success": recovery.success,
        "mode": recovery.recovery_mode,
        "module_layout": recovery.graph.module_layout if recovery.graph else None,
        "output_dir": recovery.output_dir,
        "manifest_path": recovery.manifest_path,
        "recovered_files": recovery.recovered_files,
        "error_message": recovery.error_message,
    }


def _serialize_bun_build_result(build_result: Optional[BunSeaBuildResult]) -> Optional[Dict[str, Any]]:
    if not build_result:
        return None
    return {
        "success": build_result.success,
        "normalized_project_dir": build_result.normalized_project_dir,
        "output_path": build_result.output_path,
        "sea_blob_path": build_result.sea_blob_path,
        "installed_dependencies": build_result.installed_dependencies,
        "commands_run": build_result.commands_run,
        "verification": build_result.verification,
        "error_message": build_result.error_message,
    }


def run_bun_sea_workflow(
    binary_path: str,
    output_dir: str | None = None,
    output_path: str | None = None,
    skip_install: bool = False,
) -> BunSeaWorkflowResult:
    """Recover, normalize, and package a Bun executable through the Node SEA path."""
    extractor = BunExecutableExtractor()
    info = extractor.detect(binary_path)
    if not info.is_bun_executable:
        return BunSeaWorkflowResult(
            status="not_bun",
            message="Binary is not recognized as a Bun executable",
            reason=None,
            info=info,
            extraction=None,
            recovery=None,
            normalization=None,
            build_result=None,
            differential_validation=None,
            canonical_input=None,
            canonical_reason=None,
            report_path=None,
            report_data=None,
        )

    output_root = Path(output_dir or f"analysis_{Path(binary_path).stem}")
    output_root.mkdir(parents=True, exist_ok=True)

    bundle_output = output_root / f"{Path(binary_path).stem}_bundle.js"
    bunfs_dir = output_root / f"{Path(binary_path).stem}_bunfs"

    extraction = extractor.extract_javascript(binary_path, str(bundle_output))
    if not extraction.success or not extraction.output_path:
        return BunSeaWorkflowResult(
            status="error",
            message="Bun JavaScript extraction failed",
            reason=extraction.error_message,
            info=info,
            extraction=extraction,
            recovery=None,
            normalization=None,
            build_result=None,
            differential_validation=None,
            canonical_input=None,
            canonical_reason=None,
            report_path=None,
            report_data=None,
        )

    recovery = extractor.recover_virtual_files(binary_path, str(bunfs_dir))
    canonical_input, canonical_reason = select_bun_recompilation_input(extraction.output_path, recovery)
    normalization = (
        extractor.normalize_project(canonical_input, str(output_root / "normalized_project"))
        if canonical_input
        else None
    )
    native_stub = extractor.analyze_pe_stub(binary_path)
    if not normalization or not normalization.success or not normalization.output_dir:
        return BunSeaWorkflowResult(
            status="error",
            message="Bun normalization failed",
            reason=normalization.error_message if normalization else None,
            info=info,
            extraction=extraction,
            recovery=recovery,
            normalization=normalization,
            build_result=None,
            differential_validation=None,
            canonical_input=canonical_input,
            canonical_reason=canonical_reason,
            report_path=None,
            report_data=None,
        )

    differential_validation = extractor._build_differential_validation(canonical_input, normalization)

    build_result = extractor.build_node_sea(
        normalization.output_dir,
        output_path=output_path,
        install_dependencies=not skip_install,
    )
    report_severity = build_bun_report_severity_summary(
        native_stub=native_stub,
        normalization=normalization,
        differential_validation=differential_validation,
        verification=build_result.verification,
    )
    runtime_escalation = build_bun_runtime_escalation_summary(
        native_stub=native_stub,
        report_severity=report_severity,
        differential_validation=differential_validation,
        verification=build_result.verification,
    )
    equivalence_validation = build_bun_equivalence_validation_summary(
        differential_validation=differential_validation,
        verification=build_result.verification,
    )

    report_path = output_root / "bun_sea_build.json"
    report_data = {
        "binary_path": binary_path,
        "route": "bun_node_sea",
        "canonical_recompilation_input": canonical_input,
        "canonical_recompilation_reason": canonical_reason,
        "bundle_info": {
            "section_name": info.section_name,
            "bundle_size": info.bundle_size,
            "javascript_start_offset": info.javascript_start_offset,
            "indicators": info.indicators,
        },
        "bunfs_recovery": _serialize_bun_recovery(recovery),
        "normalized_project": _serialize_bun_normalization(normalization),
        "report_severity": report_severity,
        "runtime_escalation": runtime_escalation,
        "equivalence_validation": equivalence_validation,
        "differential_validation": differential_validation,
        "sea_build": _serialize_bun_build_result(build_result),
    }
    report_path.write_text(json.dumps(report_data, indent=2), encoding="utf-8")

    return BunSeaWorkflowResult(
        status="success" if build_result.success else "error",
        message=None if build_result.success else "Node SEA build failed",
        reason=build_result.error_message,
        info=info,
        extraction=extraction,
        recovery=recovery,
        normalization=normalization,
        build_result=build_result,
        differential_validation=differential_validation,
        canonical_input=canonical_input,
        canonical_reason=canonical_reason,
        report_path=str(report_path),
        report_data=report_data,
    )


class BunExecutableExtractor:
    """Detect and extract JavaScript from Bun single-file executables."""

    JS_START_MARKERS = (b"// @bun",)
    JS_END_MARKERS = (
        b"\n//# sourceMappingURL=",
        b"\n//# debugId=",
        b"\n})();",
    )
    TRAILER = b"\n---- Bun! ----\n"
    SOURCE_MAPPING_URL_PATTERN = re.compile(r"//# sourceMappingURL=([^\r\n]+)")
    FALLBACK_TEXT_ARTIFACT_SUFFIXES = (
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".css",
        ".html",
        ".yml",
        ".yaml",
        ".toml",
        ".env",
        ".txt",
    )
    FALLBACK_BINARY_ARTIFACT_SUFFIXES = (".wasm",)
    WASM_MAGIC = b"\x00asm"
    WASM_VERSION = b"\x01\x00\x00\x00"
    MODULE_ENTRY_STRUCT = struct.Struct("<IIIIIIIIIIII4B")
    SHORT_MODULE_ENTRY_STRUCT = struct.Struct("<IIIIIIII4B")
    SHORT_EXT_MODULE_ENTRY_STRUCT = struct.Struct("<IIIIIIIII4B")
    OFFSETS_STRUCT = struct.Struct("<QIIIIII")
    VIRTUAL_PATH_PATTERNS = (
        re.compile(rb"B:/~BUN/[A-Za-z0-9][A-Za-z0-9._/@\-]{0,260}"),
        re.compile(rb"B:\\~BUN\\[A-Za-z0-9][A-Za-z0-9._@\\\-]{0,260}"),
        re.compile(rb"/\$bunfs/[A-Za-z0-9][A-Za-z0-9._/@\-]{0,260}"),
    )
    IMPORT_PATTERNS = (
        re.compile(r'(?<!["\'`])\bimport\s+(?:[^;"\'`]+?\s+from\s*)?["\']([^"\']+)["\']'),
        re.compile(
            r'(?<!["\'`])\b(?:import\.meta\.require|createRequire\(import\.meta\.url\)|require)\(["\']([^"\']+)["\']\)'
        ),
    )
    BUN_FFI_SHIM_FILENAME = "reveng-bun-ffi-shim.mjs"
    BUN_GLOBAL_SHIM_FILENAME = "reveng-bun-global-shim.mjs"
    STRING_LITERAL_PATTERNS = (
        re.compile(r'"([^"\r\n]+)"'),
        re.compile(r"'([^'\r\n]+)'"),
        re.compile(r"`([^`\r\n]+)`"),
    )
    EMBEDDED_REQUIRE_PATTERN = re.compile(
        r'(?:import\.meta\.require|createRequire\(import\.meta\.url\)|require|import)\(["\']([^"\']+)["\']\)'
    )
    PE_SECTION_HEADER_SIZE = 40
    PE_IMPORT_DIRECTORY_INDEX = 1
    PE_TLS_DIRECTORY_INDEX = 9
    PE_PREVIEW_INSTRUCTION_COUNT = 8
    PE_STARTUP_GRAPH_NODE_LIMIT = 24
    PE_STARTUP_GRAPH_EDGE_LIMIT = 32
    _SUSPICIOUS_STUB_IMPORTS = {
        "LoadLibraryA",
        "LoadLibraryW",
        "GetProcAddress",
        "VirtualAlloc",
        "VirtualAllocEx",
        "VirtualProtect",
        "VirtualProtectEx",
        "CreateProcessA",
        "CreateProcessW",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "ResumeThread",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
    }

    def detect(self, file_path: str) -> BunExecutableInfo:
        binary_path = Path(file_path)
        try:
            data = binary_path.read_bytes()
            section = self._find_bun_section(data)
            if section is None:
                return BunExecutableInfo(
                    is_bun_executable=False,
                    container="pe" if data[:2] == b"MZ" else None,
                    section_name=None,
                    bundle_offset=None,
                    bundle_size=None,
                    javascript_start_offset=None,
                    indicators=[],
                )

            section_name, section_offset, section_size = section
            bundle_data, bundle_prefix_size = self._strip_bundle_prefix(
                data[section_offset : section_offset + section_size]
            )
            js_start = self._find_js_start(bundle_data)
            indicators = [f"Bun PE section detected: {section_name}"]
            if bundle_prefix_size:
                indicators.append(f"Bun bundle size prefix detected: {bundle_prefix_size} bytes")
            if js_start is not None:
                indicators.append("Bun JavaScript marker detected")

            return BunExecutableInfo(
                is_bun_executable=js_start is not None,
                container="pe",
                section_name=section_name,
                bundle_offset=section_offset,
                bundle_size=len(bundle_data),
                javascript_start_offset=js_start,
                indicators=indicators,
            )
        except Exception as exc:
            logger.error("Bun detection failed for %s: %s", file_path, exc)
            return BunExecutableInfo(
                is_bun_executable=False,
                container=None,
                section_name=None,
                bundle_offset=None,
                bundle_size=None,
                javascript_start_offset=None,
                indicators=[f"Bun detection failed: {exc}"],
            )

    def extract_javascript(
        self,
        file_path: str,
        output_path: Optional[str] = None,
    ) -> BunExtractionResult:
        info = self.detect(file_path)
        if not info.is_bun_executable:
            return BunExtractionResult(
                success=False,
                output_path=None,
                extracted_hash=None,
                javascript_size=0,
                error_message="Binary does not contain a recognizable Bun bundle",
                info=info,
            )

        binary_path = Path(file_path)
        data = binary_path.read_bytes()
        assert info.bundle_offset is not None
        bundle_size = info.bundle_size or 0
        section_data = data[info.bundle_offset : info.bundle_offset + bundle_size + 8]
        bundle_data, _ = self._strip_bundle_prefix(section_data)
        js_start = info.javascript_start_offset
        assert js_start is not None
        js_end = self._find_js_end(bundle_data, js_start)
        js_bytes = bundle_data[js_start:js_end].rstrip(b"\x00")
        js_text = js_bytes.decode("utf-8", errors="replace").strip()

        if not js_text:
            return BunExtractionResult(
                success=False,
                output_path=None,
                extracted_hash=None,
                javascript_size=0,
                error_message="Bun bundle found, but no JavaScript payload could be extracted",
                info=info,
            )

        target_path = Path(output_path) if output_path else binary_path.with_suffix(".js")
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(js_text + "\n", encoding="utf-8")

        return BunExtractionResult(
            success=True,
            output_path=str(target_path),
            extracted_hash=self._calculate_hash(target_path),
            javascript_size=len(js_text.encode("utf-8")),
            error_message=None,
            info=info,
        )

    def analyze_pe_stub(self, file_path: str) -> Optional[PEStubAnalysis]:
        """Summarize the native PE wrapper around a Bun bundle."""
        binary_path = Path(file_path)
        try:
            data = binary_path.read_bytes()
            pe_header = self._parse_pe_metadata(data)
            if pe_header is None:
                return None
            import_address_map = self._build_import_address_map(binary_path)

            sections = pe_header["sections"]
            section_names = [section["name"] for section in sections]
            entry_point_rva = pe_header["entry_point_rva"]
            entry_point_section = self._find_section_name_for_rva(sections, entry_point_rva)
            entry_point_preview = self._disassemble_preview(
                data, pe_header, entry_point_rva, import_address_map
            )
            tls_callbacks = self._parse_tls_callbacks(data, pe_header)
            tls_callback_vas = [callback.virtual_address for callback in tls_callbacks]
            import_dlls, imported_functions = self._parse_imports(data, pe_header)
            suspicious_imports = sorted(
                {name for name in imported_functions if name in self._SUSPICIOUS_STUB_IMPORTS}
            )
            startup_classification, startup_reasons = self._classify_startup_profile(
                entry_point_section=entry_point_section,
                entry_point_preview=entry_point_preview,
                tls_callbacks=tls_callbacks,
                suspicious_imports=suspicious_imports,
            )
            startup_targets = self._collect_startup_targets(
                data=data,
                pe_header=pe_header,
                import_address_map=import_address_map,
                entry_point_preview=entry_point_preview,
                tls_callbacks=tls_callbacks,
            )
            startup_graph = self._build_startup_graph(
                pe_header=pe_header,
                entry_point_preview=entry_point_preview,
                tls_callbacks=tls_callbacks,
                startup_targets=startup_targets,
            )
            cross_references = self._collect_pe_cross_references(
                data=data,
                pe_header=pe_header,
                section_names=section_names,
            )
            handoff_signals = self._detect_bun_handoff_signals(
                data=data,
                section_names=section_names,
                entry_point_preview=entry_point_preview,
                tls_callbacks=tls_callbacks,
                startup_targets=startup_targets,
                startup_graph=startup_graph,
            )
            runtime_readiness = self._build_runtime_readiness(
                pe_header=pe_header,
                entry_point_section=entry_point_section,
                tls_callbacks=tls_callbacks,
                startup_targets=startup_targets,
                startup_graph=startup_graph,
                handoff_signals=handoff_signals,
            )
            dump_guidance = self._build_dump_guidance(
                startup_classification=startup_classification,
                suspicious_imports=suspicious_imports,
                runtime_readiness=runtime_readiness,
                handoff_signals=handoff_signals,
            )

            indicators: List[str] = []
            if ".bun" in section_names:
                indicators.append("Embedded Bun payload section present")
            if entry_point_section:
                indicators.append(f"Entrypoint located in PE section {entry_point_section}")
            if tls_callback_vas:
                indicators.append(f"TLS callbacks present: {len(tls_callback_vas)}")
            if suspicious_imports:
                indicators.append(
                    "Stub imports include loader-style APIs: "
                    + ", ".join(suspicious_imports[:6])
                )
            if startup_graph.nodes:
                indicators.append(
                    "Startup graph summarized: "
                    f"{len(startup_graph.nodes)} nodes / {len(startup_graph.edges)} edges"
                )
            if cross_references:
                indicators.append(
                    f"Cross-linked PE clues: {len(cross_references)}"
                )
            if runtime_readiness.breakpoints or runtime_readiness.dump_points:
                indicators.append(
                    "Runtime observation guidance available: "
                    f"{len(runtime_readiness.breakpoints)} breakpoints / "
                    f"{len(runtime_readiness.dump_points)} dump points"
                )
            if dump_guidance.recommended:
                indicators.append(
                    "Escalation guidance available: "
                    + ", ".join(action.kind for action in dump_guidance.actions[:3])
                )
            if handoff_signals:
                indicators.append(
                    "Bun handoff signals detected: "
                    + ", ".join(signal.kind for signal in handoff_signals[:4])
                )
            indicators.append(f"Startup classification: {startup_classification}")

            return PEStubAnalysis(
                container="pe",
                machine=pe_header["machine"],
                entry_point_rva=entry_point_rva,
                image_base=pe_header["image_base"],
                entry_point_section=entry_point_section,
                entry_point_preview=entry_point_preview,
                section_names=section_names,
                tls_directory_rva=pe_header["tls_directory_rva"],
                tls_callback_vas=tls_callback_vas,
                tls_callbacks=tls_callbacks,
                import_dlls=import_dlls,
                imported_functions=imported_functions,
                suspicious_imports=suspicious_imports,
                startup_classification=startup_classification,
                startup_reasons=startup_reasons,
                runtime_readiness=runtime_readiness,
                dump_guidance=dump_guidance,
                cross_references=cross_references,
                handoff_signals=handoff_signals,
                startup_targets=startup_targets,
                startup_graph=startup_graph,
                indicators=indicators,
            )
        except Exception as exc:
            logger.warning("PE stub analysis failed for %s: %s", file_path, exc)
            return None

    def parse_module_graph(self, file_path: str) -> Optional[BunModuleGraph]:
        bundle_data = self._read_bundle_data(Path(file_path))
        if bundle_data is None:
            return None

        trailer_offset = bundle_data.rfind(self.TRAILER)
        if trailer_offset < self.OFFSETS_STRUCT.size:
            return None

        offsets_start = trailer_offset - self.OFFSETS_STRUCT.size
        (
            byte_count,
            modules_offset,
            modules_length,
            entry_point_id,
            compile_argv_offset,
            compile_argv_length,
            _flags,
        ) = self.OFFSETS_STRUCT.unpack(bundle_data[offsets_start:trailer_offset])

        if byte_count <= 0 or byte_count > len(bundle_data):
            return None

        raw_bytes = bundle_data[:byte_count]
        modules_bytes = self._slice_bytes(raw_bytes, modules_offset, modules_length)
        if modules_bytes is None:
            return None

        compile_exec_argv_bytes = self._slice_bytes(raw_bytes, compile_argv_offset, compile_argv_length)
        compile_exec_argv = (
            compile_exec_argv_bytes.decode("utf-8", errors="replace")
            if compile_exec_argv_bytes
            else ""
        )

        parse_result = self._parse_module_entries(raw_bytes, modules_bytes)
        if parse_result is None:
            return None
        modules, module_layout = parse_result

        return BunModuleGraph(
            entry_point_id=entry_point_id,
            compile_exec_argv=compile_exec_argv,
            modules=modules,
            module_layout=module_layout,
        )

    def recover_virtual_files(self, file_path: str, output_dir: str) -> BunRecoveryResult:
        bundle_path = Path(file_path)
        bundle_data = self._read_bundle_data(bundle_path)
        if bundle_data is None:
            return BunRecoveryResult(
                success=False,
                output_dir=None,
                manifest_path=None,
                recovered_files=[],
                error_message="Bun bundle data could not be loaded",
                graph=None,
            )

        graph = self.parse_module_graph(str(bundle_path))
        if graph is None:
            return self._recover_from_path_scan(
                file_path=str(bundle_path),
                bundle_data=bundle_data,
                output_dir=output_dir,
            )

        trailer_offset = bundle_data.rfind(self.TRAILER)
        offsets_start = trailer_offset - self.OFFSETS_STRUCT.size
        (
            byte_count,
            modules_offset,
            modules_length,
            _entry_point_id,
            _compile_argv_offset,
            _compile_argv_length,
            _flags,
        ) = self.OFFSETS_STRUCT.unpack(bundle_data[offsets_start:trailer_offset])
        raw_bytes = bundle_data[:byte_count]

        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        recovered_files: List[str] = []
        manifest_modules = []

        for module in graph.modules:
            module_bytes = (
                self._slice_bytes(raw_bytes, module.content_offset, module.content_size) or b""
            )
            module_output = target_dir / Path(module.recovered_path)
            module_output.parent.mkdir(parents=True, exist_ok=True)
            module_output.write_bytes(module_bytes)
            recovered_files.append(str(module_output))

            sourcemap_output = None
            sourcemap_provenance = None
            if module.sourcemap_size > 0:
                sourcemap_bytes = (
                    self._slice_bytes(raw_bytes, module.sourcemap_offset, module.sourcemap_size) or b""
                )
                sourcemap_output = module_output.with_name(module_output.name + ".bunmap")
                sourcemap_output.write_bytes(sourcemap_bytes)
                sourcemap_provenance = self._analyze_sourcemap_provenance(
                    sourcemap_bytes=sourcemap_bytes,
                    source_output=module_output,
                    origin="module_graph_embedded",
                )
                recovered_files.append(str(sourcemap_output))

            manifest_modules.append(
                {
                        "virtual_path": module.virtual_path,
                        "recovered_path": module.recovered_path,
                        "loader_id": module.loader_id,
                        "content_offset": module.content_offset,
                        "content_size": module.content_size,
                        "sourcemap_offset": module.sourcemap_offset,
                        "sourcemap_size": module.sourcemap_size,
                        "output_path": str(module_output),
                        "sourcemap_output_path": str(sourcemap_output) if sourcemap_output else None,
                        "sourcemap_provenance": (
                            self._serialize_sourcemap_provenance(sourcemap_provenance)
                            if sourcemap_provenance
                            else None
                        ),
                    }
                )

        manifest_path = target_dir / "module_graph.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "entry_point_id": graph.entry_point_id,
                    "compile_exec_argv": graph.compile_exec_argv,
                    "module_layout": graph.module_layout,
                    "module_count": len(graph.modules),
                    "modules": manifest_modules,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        recovered_files.append(str(manifest_path))

        return BunRecoveryResult(
            success=True,
            output_dir=str(target_dir),
            manifest_path=str(manifest_path),
            recovered_files=recovered_files,
            error_message=None,
            graph=graph,
            recovery_mode="module_graph",
        )

    def normalize_project(self, source_path: str, output_dir: str) -> BunNormalizationResult:
        """Create a reproducible Node-compatible project workspace from recovered Bun JS."""
        source = Path(source_path)
        if not source.exists():
            return BunNormalizationResult(
                success=False,
                output_dir=None,
                entrypoint_path=None,
                sea_entrypoint_path=None,
                sea_config_path=None,
                package_json_path=None,
                manifest_path=None,
                inferred_dependencies=[],
                runtime_features=[],
                shims_applied=[],
                semantic_checks=[],
                postprocessing_hooks=[],
                warnings=[],
                error_message=f"Recovered Bun source not found: {source_path}",
            )

        try:
            source_text = source.read_text(encoding="utf-8", errors="replace")
            dependency_analysis = self._analyze_dependencies(source_text)
            inferred_dependencies = dependency_analysis.required_packages
            runtime_features = self._detect_runtime_features(source_text)
            normalized_text, shims_applied = self._normalize_source_text(source_text)
            semantic_checks = self._build_semantic_checks(
                dependency_analysis=dependency_analysis,
                runtime_features=runtime_features,
                shims_applied=shims_applied,
            )
            sourcemap_provenance = self._load_adjacent_sourcemap_provenance(source)
            postprocessing_hooks = self._recommend_postprocessing_hooks(
                source_text=source_text,
                runtime_features=runtime_features,
                shims_applied=shims_applied,
                sourcemap_provenance=sourcemap_provenance,
            )

            warnings = [
                check["message"]
                for check in semantic_checks
                if check["severity"] == "warning"
            ]

            target_dir = Path(output_dir)
            target_dir.mkdir(parents=True, exist_ok=True)

            entrypoint_name = f"{source.stem}.mjs"
            entrypoint_path = target_dir / entrypoint_name
            entrypoint_path.write_text(normalized_text.rstrip() + "\n", encoding="utf-8")

            companion_files = [entrypoint_name]

            if "bun global bootstrap" in shims_applied:
                bun_global_shim_path = target_dir / self.BUN_GLOBAL_SHIM_FILENAME
                bun_global_shim_path.write_text(
                    self._build_bun_global_shim_source(), encoding="utf-8"
                )
                companion_files.append(self.BUN_GLOBAL_SHIM_FILENAME)

            if "bun:ffi replacement" in shims_applied:
                bun_ffi_shim_path = target_dir / self.BUN_FFI_SHIM_FILENAME
                bun_ffi_shim_path.write_text(
                    self._build_bun_ffi_shim_source(), encoding="utf-8"
                )
                companion_files.append(self.BUN_FFI_SHIM_FILENAME)

            sea_entrypoint_path = target_dir / "sea-entry.cjs"
            sea_entrypoint_path.write_text(
                self._build_sea_entrypoint_source(entrypoint_name),
                encoding="utf-8",
            )

            sea_config_path = target_dir / "sea-config.json"
            sea_config_path.write_text(
                json.dumps(
                    {
                        "main": f"./{sea_entrypoint_path.name}",
                        "output": "./sea-prep.blob",
                        "disableExperimentalSEAWarning": True,
                        "useCodeCache": False,
                        "assets": {},
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            package_json_path = target_dir / "package.json"
            package_json = {
                "name": self._slugify_name(source.stem),
                "version": "0.0.0-recovered",
                "private": True,
                "type": "module",
                "scripts": {
                    "start": f"node ./{entrypoint_name}",
                    "start:bun": f"bun ./{entrypoint_name}",
                },
                "engines": {"node": ">=22"},
                "reveng": {
                    "normalized_from": str(source),
                    "inferred_dependencies": inferred_dependencies,
                    "dependency_analysis": {
                        "required_packages": dependency_analysis.required_packages,
                        "builtin_modules": dependency_analysis.builtin_modules,
                        "ignored_package_strings": dependency_analysis.ignored_package_strings,
                    },
                    "runtime_features": runtime_features,
                    "shims_applied": shims_applied,
                    "sea_companion_files": companion_files,
                    "semantic_checks": semantic_checks,
                    "postprocessing_hooks": postprocessing_hooks,
                    "sea_entrypoint_path": str(sea_entrypoint_path),
                    "sea_config_path": str(sea_config_path),
                    "warnings": warnings,
                    "suggested_install_command": (
                        f"npm install {' '.join(inferred_dependencies)}"
                        if inferred_dependencies
                        else None
                    ),
                    "suggested_postject_install_command": "npm install --save-dev postject",
                },
            }
            if inferred_dependencies:
                package_json["dependencies"] = {dependency: "*" for dependency in inferred_dependencies}
            package_json_path.write_text(json.dumps(package_json, indent=2), encoding="utf-8")

            manifest_path = target_dir / "normalization_manifest.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "source_path": str(source),
                        "entrypoint_path": str(entrypoint_path),
                        "sea_entrypoint_path": str(sea_entrypoint_path),
                        "sea_config_path": str(sea_config_path),
                        "package_json_path": str(package_json_path),
                        "inferred_dependencies": inferred_dependencies,
                        "dependency_analysis": {
                            "required_packages": dependency_analysis.required_packages,
                            "builtin_modules": dependency_analysis.builtin_modules,
                            "ignored_package_strings": dependency_analysis.ignored_package_strings,
                        },
                        "runtime_features": runtime_features,
                        "shims_applied": shims_applied,
                        "sea_companion_files": companion_files,
                        "semantic_checks": semantic_checks,
                        "postprocessing_hooks": postprocessing_hooks,
                        "warnings": warnings,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

            return BunNormalizationResult(
                success=True,
                output_dir=str(target_dir),
                entrypoint_path=str(entrypoint_path),
                sea_entrypoint_path=str(sea_entrypoint_path),
                sea_config_path=str(sea_config_path),
                package_json_path=str(package_json_path),
                manifest_path=str(manifest_path),
                inferred_dependencies=inferred_dependencies,
                runtime_features=runtime_features,
                shims_applied=shims_applied,
                semantic_checks=semantic_checks,
                postprocessing_hooks=postprocessing_hooks,
                warnings=warnings,
                error_message=None,
            )
        except Exception as exc:
            logger.error("Bun normalization failed for %s: %s", source_path, exc)
            return BunNormalizationResult(
                success=False,
                output_dir=None,
                entrypoint_path=None,
                sea_entrypoint_path=None,
                sea_config_path=None,
                package_json_path=None,
                manifest_path=None,
                inferred_dependencies=[],
                runtime_features=[],
                shims_applied=[],
                semantic_checks=[],
                postprocessing_hooks=[],
                warnings=[],
                error_message=str(exc),
            )

    def _find_bun_section(self, data: bytes) -> Optional[tuple[str, int, int]]:
        if data[:2] != b"MZ" or len(data) < 0x40:
            return None

        pe_offset = struct.unpack("<I", data[0x3C:0x40])[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return None

        num_sections = struct.unpack("<H", data[pe_offset + 6 : pe_offset + 8])[0]
        optional_header_size = struct.unpack("<H", data[pe_offset + 20 : pe_offset + 22])[0]
        section_table_offset = pe_offset + 24 + optional_header_size

        for index in range(num_sections):
            header_offset = section_table_offset + index * 40
            if header_offset + 40 > len(data):
                break

            name = data[header_offset : header_offset + 8].rstrip(b"\x00").decode(
                "ascii", errors="ignore"
            )
            raw_size = struct.unpack("<I", data[header_offset + 16 : header_offset + 20])[0]
            raw_offset = struct.unpack("<I", data[header_offset + 20 : header_offset + 24])[0]

            if name == ".bun" and raw_offset < len(data):
                bounded_size = min(raw_size, len(data) - raw_offset)
                return (name, raw_offset, bounded_size)

        return None

    def _read_bundle_data(self, binary_path: Path) -> Optional[bytes]:
        data = binary_path.read_bytes()
        section = self._find_bun_section(data)
        if section is None:
            return None
        _, section_offset, section_size = section
        section_data = data[section_offset : section_offset + section_size]
        bundle_data, _ = self._strip_bundle_prefix(section_data)
        return bundle_data

    def _parse_pe_metadata(self, data: bytes) -> Optional[Dict[str, Any]]:
        if data[:2] != b"MZ" or len(data) < 0x40:
            return None
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 24 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            return None

        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
        optional_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        optional_header_offset = pe_offset + 24
        optional_header_end = optional_header_offset + optional_header_size
        if optional_header_end > len(data) or optional_header_size < 96:
            return None

        magic = struct.unpack_from("<H", data, optional_header_offset)[0]
        if magic == 0x10B:
            entry_point_rva = struct.unpack_from("<I", data, optional_header_offset + 16)[0]
            image_base = struct.unpack_from("<I", data, optional_header_offset + 28)[0]
            data_directory_offset = optional_header_offset + 96
        elif magic == 0x20B:
            entry_point_rva = struct.unpack_from("<I", data, optional_header_offset + 16)[0]
            image_base = struct.unpack_from("<Q", data, optional_header_offset + 24)[0]
            data_directory_offset = optional_header_offset + 112
        else:
            return None

        section_table_offset = optional_header_end
        sections: List[Dict[str, Any]] = []
        for index in range(section_count):
            header_offset = section_table_offset + index * self.PE_SECTION_HEADER_SIZE
            if header_offset + self.PE_SECTION_HEADER_SIZE > len(data):
                break
            name = (
                data[header_offset : header_offset + 8]
                .rstrip(b"\x00")
                .decode("ascii", errors="replace")
            )
            virtual_size, virtual_address, raw_size, raw_address = struct.unpack_from(
                "<IIII", data, header_offset + 8
            )
            sections.append(
                {
                    "name": name,
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_address": raw_address,
                }
            )

        import_directory_offset = data_directory_offset + self.PE_IMPORT_DIRECTORY_INDEX * 8
        import_table_rva = None
        import_table_size = 0
        if import_directory_offset + 8 <= optional_header_end:
            import_table_rva, import_table_size = struct.unpack_from(
                "<II", data, import_directory_offset
            )

        tls_directory_offset = data_directory_offset + self.PE_TLS_DIRECTORY_INDEX * 8
        tls_directory_rva = None
        tls_directory_size = 0
        if tls_directory_offset + 8 <= optional_header_end:
            tls_directory_rva, tls_directory_size = struct.unpack_from(
                "<II", data, tls_directory_offset
            )
        if tls_directory_rva == 0:
            tls_directory_rva = None

        return {
            "pe_magic": magic,
            "machine": f"0x{machine:04x}",
            "entry_point_rva": entry_point_rva,
            "image_base": image_base,
            "sections": sections,
            "import_table_rva": import_table_rva,
            "import_table_size": import_table_size,
            "tls_directory_rva": tls_directory_rva,
            "tls_directory_size": tls_directory_size,
        }

    def _find_section_name_for_rva(self, sections: List[Dict[str, Any]], rva: int) -> Optional[str]:
        for section in sections:
            size = max(section["virtual_size"], section["raw_size"])
            if section["virtual_address"] <= rva < section["virtual_address"] + size:
                return section["name"]
        return None

    def _rva_to_file_offset(self, sections: List[Dict[str, Any]], rva: int) -> Optional[int]:
        for section in sections:
            size = max(section["virtual_size"], section["raw_size"])
            start = section["virtual_address"]
            if start <= rva < start + size:
                return section["raw_address"] + (rva - start)
        return None

    def _read_c_string(self, data: bytes, offset: int) -> str:
        if offset < 0 or offset >= len(data):
            return ""
        end = data.find(b"\x00", offset)
        if end == -1:
            end = len(data)
        return data[offset:end].decode("ascii", errors="replace")

    def _parse_imports(
        self, data: bytes, pe_header: Dict[str, Any]
    ) -> tuple[List[str], List[str]]:
        import_table_rva = pe_header.get("import_table_rva")
        if not import_table_rva:
            return [], []

        sections = pe_header["sections"]
        descriptor_offset = self._rva_to_file_offset(sections, import_table_rva)
        if descriptor_offset is None:
            return [], []

        dlls: List[str] = []
        functions: List[str] = []
        seen_dlls = set()
        seen_functions = set()

        while descriptor_offset + 20 <= len(data):
            original_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from(
                "<IIIII", data, descriptor_offset
            )
            if not any((original_first_thunk, name_rva, first_thunk)):
                break

            dll_name_offset = self._rva_to_file_offset(sections, name_rva)
            dll_name = self._read_c_string(data, dll_name_offset) if dll_name_offset is not None else ""
            if dll_name and dll_name not in seen_dlls:
                seen_dlls.add(dll_name)
                dlls.append(dll_name)

            thunk_rva = original_first_thunk or first_thunk
            thunk_offset = self._rva_to_file_offset(sections, thunk_rva)
            if thunk_offset is not None:
                thunk_size = 8
                ordinal_flag = 1 << 63
                while thunk_offset + thunk_size <= len(data):
                    thunk_value = struct.unpack_from("<Q", data, thunk_offset)[0]
                    if thunk_value == 0:
                        break
                    if not (thunk_value & ordinal_flag):
                        hint_name_offset = self._rva_to_file_offset(
                            sections, thunk_value & 0x7FFFFFFFFFFFFFFF
                        )
                        if hint_name_offset is not None and hint_name_offset + 2 <= len(data):
                            function_name = self._read_c_string(data, hint_name_offset + 2)
                            if function_name and function_name not in seen_functions:
                                seen_functions.add(function_name)
                                functions.append(function_name)
                    thunk_offset += thunk_size

            descriptor_offset += 20

        return dlls, functions

    def _parse_tls_callbacks(self, data: bytes, pe_header: Dict[str, Any]) -> List[PETLSCallback]:
        tls_directory_rva = pe_header.get("tls_directory_rva")
        if not tls_directory_rva:
            return []

        sections = pe_header["sections"]
        tls_offset = self._rva_to_file_offset(sections, tls_directory_rva)
        if tls_offset is None:
            return []

        is_pe32_plus = pe_header.get("pe_magic") == 0x20B
        if is_pe32_plus:
            if tls_offset + 40 > len(data):
                return []
            callbacks_va = struct.unpack_from("<Q", data, tls_offset + 24)[0]
            stride = 8
            unpack_format = "<Q"
        else:
            if tls_offset + 24 > len(data):
                return []
            callbacks_va = struct.unpack_from("<I", data, tls_offset + 12)[0]
            stride = 4
            unpack_format = "<I"

        if not callbacks_va:
            return []

        callbacks_rva = callbacks_va - pe_header["image_base"]
        callbacks_offset = self._rva_to_file_offset(sections, callbacks_rva)
        if callbacks_offset is None:
            return []

        import_address_map = self._build_import_address_map(None, pe_header, data)
        callbacks: List[PETLSCallback] = []
        for index in range(32):
            offset = callbacks_offset + index * stride
            if offset + stride > len(data):
                break
            callback_va = struct.unpack_from(unpack_format, data, offset)[0]
            if callback_va == 0:
                break
            callback_rva = callback_va - pe_header["image_base"]
            callback_offset = self._rva_to_file_offset(sections, callback_rva)
            callbacks.append(
                PETLSCallback(
                    virtual_address=callback_va,
                    rva=callback_rva,
                    section_name=self._find_section_name_for_rva(sections, callback_rva),
                    file_offset=callback_offset,
                    instruction_preview=self._disassemble_preview(
                        data, pe_header, callback_rva, import_address_map
                    ),
                )
            )
        return callbacks

    def _disassemble_preview(
        self,
        data: bytes,
        pe_header: Dict[str, Any],
        rva: Optional[int],
        import_address_map: Optional[Dict[int, str]] = None,
    ) -> List[PEInstructionPreview]:
        if not _CAPSTONE_AVAILABLE or rva is None:
            return []

        file_offset = self._rva_to_file_offset(pe_header["sections"], rva)
        if file_offset is None or file_offset >= len(data):
            return []

        mode = CS_MODE_64 if pe_header.get("pe_magic") == 0x20B else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = True
        preview: List[PEInstructionPreview] = []
        start_va = pe_header["image_base"] + rva
        code = data[file_offset : file_offset + 64]
        for index, insn in enumerate(md.disasm(code, start_va)):
            target_address = None
            target_rva = None
            target_section = None
            import_target = None
            rip_relative_address = None
            rip_relative_section = None
            if (
                insn.operands
                and (insn.mnemonic == "call" or insn.mnemonic.startswith("j"))
                and insn.operands[0].type == X86_OP_IMM
            ):
                target_address = int(insn.operands[0].imm)
                target_rva = target_address - pe_header["image_base"]
                target_section = self._find_section_name_for_rva(
                    pe_header["sections"], target_rva
                )
            for operand in insn.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    rip_relative_address = insn.address + insn.size + operand.mem.disp
                    rip_relative_rva = rip_relative_address - pe_header["image_base"]
                    rip_relative_section = self._find_section_name_for_rva(
                        pe_header["sections"], rip_relative_rva
                    )
                    if import_address_map:
                        import_target = import_address_map.get(rip_relative_address)
                    break
            preview.append(
                PEInstructionPreview(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    target_address=target_address,
                    target_rva=target_rva,
                    target_section=target_section,
                    import_target=import_target,
                    rip_relative_address=rip_relative_address,
                    rip_relative_section=rip_relative_section,
                )
            )
            if index + 1 >= self.PE_PREVIEW_INSTRUCTION_COUNT:
                break
        return preview

    def _build_import_address_map(
        self,
        binary_path: Optional[Path],
        pe_header: Optional[Dict[str, Any]] = None,
        data: Optional[bytes] = None,
    ) -> Dict[int, str]:
        if not _PEFILE_AVAILABLE:
            return {}
        try:
            if binary_path is not None:
                pe = pefile.PE(str(binary_path))
            else:
                if data is None:
                    return {}
                pe = pefile.PE(data=data)
            imports: Dict[int, str] = {}
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="replace")
                    for imp in entry.imports:
                        function_name = (
                            imp.name.decode("utf-8", errors="replace")
                            if imp.name
                            else f"Ordinal_{imp.ordinal}"
                        )
                        imports[imp.address] = f"{dll_name}!{function_name}"
            return imports
        except Exception:
            return {}

    def _classify_startup_profile(
        self,
        entry_point_section: Optional[str],
        entry_point_preview: List[PEInstructionPreview],
        tls_callbacks: List[PETLSCallback],
        suspicious_imports: List[str],
    ) -> tuple[str, List[str]]:
        reasons: List[str] = []
        runtime_score = 0

        if entry_point_section == ".text":
            runtime_score += 1
            reasons.append("Entrypoint is located in the executable .text section")
        if tls_callbacks:
            runtime_score += 2
            reasons.append(f"TLS callbacks are present ({len(tls_callbacks)})")
        if self._looks_like_entrypoint_thunk(entry_point_preview):
            runtime_score += 2
            reasons.append("Entrypoint preview matches a thin thunk pattern")
        if suspicious_imports:
            runtime_score += 1
            reasons.append("Loader-style imports are present in the import table")

        if runtime_score >= 4:
            return "runtime_bootstrap_likely", reasons
        return "mixed_or_unknown", reasons

    def _looks_like_entrypoint_thunk(
        self, entry_point_preview: List[PEInstructionPreview]
    ) -> bool:
        if len(entry_point_preview) < 4:
            return False
        return (
            entry_point_preview[0].mnemonic == "sub"
            and entry_point_preview[1].mnemonic == "call"
            and entry_point_preview[1].target_section == ".text"
            and entry_point_preview[2].mnemonic == "add"
            and entry_point_preview[3].mnemonic == "jmp"
            and entry_point_preview[3].target_section == ".text"
        )

    def _collect_startup_targets(
        self,
        data: bytes,
        pe_header: Dict[str, Any],
        import_address_map: Dict[int, str],
        entry_point_preview: List[PEInstructionPreview],
        tls_callbacks: List[PETLSCallback],
    ) -> List[PEStartupTarget]:
        targets: List[PEStartupTarget] = []
        seen: set[tuple[str, int, Optional[int], Optional[str]]] = set()

        def add_targets(source: str, preview: List[PEInstructionPreview]) -> None:
            for instruction in preview:
                target_address = instruction.target_address
                target_rva = instruction.target_rva
                target_section = instruction.target_section
                target_preview: List[PEInstructionPreview] = []
                target_resolution = "direct"
                if target_address is None:
                    if instruction.import_target is None and instruction.rip_relative_address is None:
                        continue
                    target_address = instruction.rip_relative_address
                    if target_address is not None:
                        target_rva = target_address - pe_header["image_base"]
                    else:
                        target_rva = None
                    target_section = instruction.rip_relative_section
                    target_resolution = "import_iat" if instruction.import_target else "rip_relative"
                else:
                    target_preview = self._disassemble_preview(
                        data, pe_header, instruction.target_rva, import_address_map
                    )

                if (
                    target_address is None
                    and target_rva is None
                    and target_section is None
                    and instruction.import_target is None
                ):
                    continue
                key = (source, instruction.address, target_address, instruction.import_target)
                if key in seen:
                    continue
                seen.add(key)
                target = PEStartupTarget(
                    source=source,
                    instruction_address=instruction.address,
                    instruction_mnemonic=instruction.mnemonic,
                    target_address=target_address,
                    target_rva=target_rva,
                    target_section=target_section,
                    symbolic_label="",
                    target_resolution=target_resolution,
                    import_target=instruction.import_target,
                    target_preview=target_preview,
                )
                target.symbolic_label = self._build_startup_symbolic_label(target)
                targets.append(
                    target
                )

        add_targets("entrypoint", entry_point_preview)
        for index, callback in enumerate(tls_callbacks):
            add_targets(f"tls_callback[{index}]", callback.instruction_preview)

        return targets

    def _build_startup_symbolic_label(self, target: PEStartupTarget) -> str:
        if target.import_target:
            return re.sub(r"[^A-Za-z0-9]+", "_", target.import_target).strip("_").lower()
        section = target.target_section or ""
        sanitized_section = re.sub(r"[^A-Za-z0-9]+", "_", section).strip("_").lower()
        if target.target_rva is not None:
            if sanitized_section:
                return f"{sanitized_section}_rva_{target.target_rva:08x}"
            return f"rva_{target.target_rva:08x}"
        return f"va_{target.target_address:016x}"

    def _build_startup_graph(
        self,
        pe_header: Dict[str, Any],
        entry_point_preview: List[PEInstructionPreview],
        tls_callbacks: List[PETLSCallback],
        startup_targets: List[PEStartupTarget],
    ) -> PEStartupGraph:
        nodes: List[PEStartupGraphNode] = []
        edges: List[PEStartupGraphEdge] = []
        node_keys: set[str] = set()
        edge_keys: set[tuple[str, str, int, int]] = set()
        truncated = False

        def add_node(node: PEStartupGraphNode) -> None:
            nonlocal truncated
            if node.label in node_keys:
                return
            if len(nodes) >= self.PE_STARTUP_GRAPH_NODE_LIMIT:
                truncated = True
                return
            node_keys.add(node.label)
            nodes.append(node)

        def add_edge(edge: PEStartupGraphEdge) -> None:
            nonlocal truncated
            key = (edge.source_label, edge.target_label, edge.instruction_address, edge.depth)
            if key in edge_keys:
                return
            if len(edges) >= self.PE_STARTUP_GRAPH_EDGE_LIMIT:
                truncated = True
                return
            edge_keys.add(key)
            edges.append(edge)

        roots = ["entrypoint"]
        add_node(
            PEStartupGraphNode(
                label="entrypoint",
                node_type="root",
                address=(
                    pe_header["image_base"] + pe_header["entry_point_rva"]
                    if pe_header.get("image_base") is not None
                    and pe_header.get("entry_point_rva") is not None
                    else None
                ),
                rva=pe_header.get("entry_point_rva"),
                section=self._first_preview_section(entry_point_preview),
                source="entrypoint",
                target_resolution="root",
                import_target=None,
            )
        )

        for index, callback in enumerate(tls_callbacks):
            label = f"tls_callback[{index}]"
            roots.append(label)
            add_node(
                PEStartupGraphNode(
                    label=label,
                    node_type="root",
                    address=callback.virtual_address,
                    rva=callback.rva,
                    section=callback.section_name,
                    source=label,
                    target_resolution="root",
                    import_target=None,
                )
            )

        def add_target_node(label_source: str, target: PEStartupTarget, depth: int) -> None:
            add_node(
                PEStartupGraphNode(
                    label=target.symbolic_label,
                    node_type="target",
                    address=target.target_address,
                    rva=target.target_rva,
                    section=target.target_section,
                    source=label_source,
                    target_resolution=target.target_resolution,
                    import_target=target.import_target,
                )
            )
            add_edge(
                PEStartupGraphEdge(
                    source_label=label_source,
                    target_label=target.symbolic_label,
                    instruction_mnemonic=target.instruction_mnemonic,
                    instruction_address=target.instruction_address,
                    depth=depth,
                    target_resolution=target.target_resolution,
                    import_target=target.import_target,
                )
            )

        for target in startup_targets:
            add_target_node(target.source, target, depth=1)
            if truncated:
                break
            second_hop_targets = self._build_startup_targets_from_preview(
                pe_header=pe_header,
                source_label=target.symbolic_label,
                preview=target.target_preview,
            )
            for nested_target in second_hop_targets:
                add_target_node(target.symbolic_label, nested_target, depth=2)
                if truncated:
                    break
            if truncated:
                break

        return PEStartupGraph(roots=roots, nodes=nodes, edges=edges, truncated=truncated)

    def _detect_bun_handoff_signals(
        self,
        data: bytes,
        section_names: List[str],
        entry_point_preview: List[PEInstructionPreview],
        tls_callbacks: List[PETLSCallback],
        startup_targets: List[PEStartupTarget],
        startup_graph: PEStartupGraph,
    ) -> List[PEHandoffSignal]:
        signals: List[PEHandoffSignal] = []
        seen: set[tuple[str, str]] = set()

        def add_signal(kind: str, source: str, message: str, confidence: str) -> None:
            key = (kind, source)
            if key in seen:
                return
            seen.add(key)
            signals.append(
                PEHandoffSignal(
                    kind=kind,
                    source=source,
                    message=message,
                    confidence=confidence,
                )
            )

        if ".bun" in section_names:
            add_signal(
                "embedded_bun_section",
                "section_table",
                "PE section table exposes an embedded .bun payload section",
                "high",
            )
        if self.TRAILER in data:
            add_signal(
                "bun_bundle_trailer",
                "bundle_bytes",
                "Embedded Bun trailer marker is present in the payload bytes",
                "high",
            )

        matched_virtual_paths = self._scan_virtual_paths(data)
        if matched_virtual_paths:
            add_signal(
                "bun_virtual_path_marker",
                "bundle_strings",
                f"Recovered Bun virtual-path marker {matched_virtual_paths[0]}",
                "high",
            )

        if b"// @bun" in data or b"sourceMappingURL=" in data:
            add_signal(
                "bundled_javascript_marker",
                "bundle_strings",
                "Embedded payload contains Bun/JavaScript source markers",
                "high",
            )

        if any(target.target_section == ".bun" for target in startup_targets):
            add_signal(
                "startup_target_into_bun_section",
                "startup_targets",
                "Startup control-flow reaches code or data that resolves into the .bun section",
                "medium",
            )

        if any(
            instruction.rip_relative_section == ".bun"
            for instruction in entry_point_preview
        ) or any(
            instruction.rip_relative_section == ".bun"
            for callback in tls_callbacks
            for instruction in callback.instruction_preview
        ):
            add_signal(
                "rip_relative_bun_reference",
                "startup_preview",
                "Startup instructions reference RIP-relative data inside the .bun section",
                "medium",
            )

        if any(
            node.section == ".bun" and node.node_type == "target"
            for node in startup_graph.nodes
        ):
            add_signal(
                "startup_graph_bun_node",
                "startup_graph",
                "Bounded startup graph includes nodes that land in the .bun section",
                "medium",
            )

        return signals

    def _collect_pe_cross_references(
        self,
        data: bytes,
        pe_header: Dict[str, Any],
        section_names: List[str],
    ) -> List[PECrossReference]:
        references: List[PECrossReference] = []
        seen: set[tuple[str, int]] = set()

        def add_reference(kind: str, value: str, offset: Optional[int], source: str) -> None:
            key = (kind, offset if offset is not None else -1)
            if key in seen:
                return
            seen.add(key)
            references.append(
                PECrossReference(
                    kind=kind,
                    value=value,
                    section=self._find_section_name_for_file_offset(
                        pe_header["sections"], offset
                    ),
                    file_offset=offset,
                    source=source,
                )
            )

        if ".rsrc" in section_names:
            resource_offset = self._find_section_file_offset_by_name(pe_header["sections"], ".rsrc")
            add_reference("resource_section", ".rsrc", resource_offset, "section_table")

        marker_patterns = (
            ("manifest_xml", b"<assembly", "manifest string fragment", "string_scan"),
            (
                "requested_execution_level",
                b"requestedExecutionLevel",
                "requestedExecutionLevel",
                "string_scan",
            ),
            ("bun_virtual_path", b"B:/~BUN/", "B:/~BUN/", "string_scan"),
            ("bunfs_virtual_path", b"/$bunfs/", "/$bunfs/", "string_scan"),
            ("source_map_marker", b"sourceMappingURL=", "sourceMappingURL=", "string_scan"),
            ("compile_argv", b"--compile", "--compile", "string_scan"),
            ("bundled_javascript", b"// @bun", "// @bun", "string_scan"),
        )
        for kind, marker, value, source in marker_patterns:
            offset = data.find(marker)
            if offset >= 0:
                add_reference(kind, value, offset, source)

        return references

    def _build_runtime_readiness(
        self,
        pe_header: Dict[str, Any],
        entry_point_section: Optional[str],
        tls_callbacks: List[PETLSCallback],
        startup_targets: List[PEStartupTarget],
        startup_graph: PEStartupGraph,
        handoff_signals: List[PEHandoffSignal],
    ) -> PERuntimeReadiness:
        breakpoints: List[PERuntimeObservationPoint] = []
        dump_points: List[PERuntimeObservationPoint] = []
        notes: List[str] = []
        seen_breakpoints: set[str] = set()
        seen_dump_points: set[str] = set()

        def add_breakpoint(
            label: str, kind: str, address: Optional[int], section: Optional[str], reason: str
        ) -> None:
            if label in seen_breakpoints:
                return
            seen_breakpoints.add(label)
            breakpoints.append(
                PERuntimeObservationPoint(
                    label=label,
                    kind=kind,
                    address=address,
                    section=section,
                    reason=reason,
                )
            )

        def add_dump_point(
            label: str, kind: str, address: Optional[int], section: Optional[str], reason: str
        ) -> None:
            if label in seen_dump_points:
                return
            seen_dump_points.add(label)
            dump_points.append(
                PERuntimeObservationPoint(
                    label=label,
                    kind=kind,
                    address=address,
                    section=section,
                    reason=reason,
                )
            )

        image_base = pe_header.get("image_base")
        entry_point_rva = pe_header.get("entry_point_rva")
        entrypoint_address = (
            image_base + entry_point_rva
            if image_base is not None and entry_point_rva is not None
            else None
        )
        add_breakpoint(
            "entrypoint",
            "breakpoint",
            entrypoint_address,
            entry_point_section,
            "Catch the earliest native stub execution before loader/runtime fan-out",
        )

        for index, callback in enumerate(tls_callbacks):
            add_breakpoint(
                f"tls_callback[{index}]",
                "breakpoint",
                callback.virtual_address,
                callback.section_name,
                "Observe loader-triggered TLS initialization before process startup settles",
            )

        for target in startup_targets:
            if target.target_resolution == "import_iat":
                add_breakpoint(
                    f"callsite_{target.symbolic_label}",
                    "callsite",
                    target.instruction_address,
                    self._find_section_name_for_rva(
                        pe_header["sections"], target.instruction_address - image_base
                    )
                    if image_base is not None
                    else None,
                    "Trace dynamic import resolution at the callsite before the import target is invoked",
                )
                continue
            if target.target_section in {".text", ".bun"}:
                add_breakpoint(
                    target.symbolic_label,
                    "breakpoint",
                    target.target_address,
                    target.target_section,
                    "Observe first-hop startup target execution when static control-flow becomes ambiguous",
                )

        for node in startup_graph.nodes:
            if node.section == ".bun" and node.node_type == "target":
                add_dump_point(
                    node.label,
                    "dump_point",
                    node.address,
                    node.section,
                    "Capture process memory after control-flow reaches the embedded Bun payload region",
                )

        if tls_callbacks:
            notes.append(
                "TLS callbacks are present; attach before normal process resume if you need the earliest loader-triggered state."
            )
        if any(signal.kind.startswith("bun_") or signal.kind.endswith("_bun_section") for signal in handoff_signals):
            notes.append(
                "Strong Bun handoff evidence is present; prioritize breakpoints that transition into .bun-backed targets."
            )
        if any(target.target_resolution == "import_iat" for target in startup_targets):
            notes.append(
                "Import/IAT startup edges are present; callsite breakpoints can reveal dynamically resolved APIs when direct targets are absent."
            )

        return PERuntimeReadiness(
            breakpoints=breakpoints,
            dump_points=dump_points,
            notes=notes,
        )

    def _build_dump_guidance(
        self,
        startup_classification: str,
        suspicious_imports: List[str],
        runtime_readiness: PERuntimeReadiness,
        handoff_signals: List[PEHandoffSignal],
    ) -> PEDumpGuidance:
        actions: List[PEDumpGuidanceAction] = []

        if runtime_readiness.dump_points and handoff_signals:
            actions.append(
                PEDumpGuidanceAction(
                    kind="memory_dump",
                    summary="Capture process memory after execution reaches a Bun-linked dump point.",
                    trigger="Bun handoff evidence and dump-point guidance are both present.",
                )
            )

        dynamic_imports = {"GetProcAddress", "LoadLibraryA", "LoadLibraryW", "VirtualProtect", "VirtualAlloc"}
        if any(name in dynamic_imports for name in suspicious_imports) or any(
            point.kind == "callsite" for point in runtime_readiness.breakpoints
        ):
            actions.append(
                PEDumpGuidanceAction(
                    kind="import_reconstruction",
                    summary="Trace dynamic import resolution and reconstruct imports from runtime callsites if the stub stays opaque.",
                    trigger="Dynamic import-resolution signals are present in the startup path.",
                )
            )

        if startup_classification == "runtime_bootstrap_likely" and runtime_readiness.breakpoints:
            actions.append(
                PEDumpGuidanceAction(
                    kind="early_attach",
                    summary="Attach at entrypoint/TLS breakpoints before later startup stages overwrite useful evidence.",
                    trigger="The startup profile looks dominated by runtime/bootstrap behavior.",
                )
            )

        return PEDumpGuidance(recommended=bool(actions), actions=actions)

    def _find_section_name_for_file_offset(
        self, sections: List[Dict[str, Any]], file_offset: Optional[int]
    ) -> Optional[str]:
        if file_offset is None:
            return None
        for section in sections:
            start = section["raw_address"]
            size = section["raw_size"]
            if start <= file_offset < start + size:
                return section["name"]
        return None

    def _find_section_file_offset_by_name(
        self, sections: List[Dict[str, Any]], section_name: str
    ) -> Optional[int]:
        for section in sections:
            if section["name"] == section_name:
                return section["raw_address"]
        return None

    def _build_startup_targets_from_preview(
        self,
        pe_header: Dict[str, Any],
        source_label: str,
        preview: List[PEInstructionPreview],
    ) -> List[PEStartupTarget]:
        targets: List[PEStartupTarget] = []
        seen: set[tuple[int, Optional[int], Optional[str]]] = set()
        for instruction in preview:
            target_address = instruction.target_address
            target_rva = instruction.target_rva
            target_section = instruction.target_section
            target_resolution = "direct"
            if target_address is None:
                if instruction.import_target is None and instruction.rip_relative_address is None:
                    continue
                target_address = instruction.rip_relative_address
                if target_address is not None:
                    target_rva = target_address - pe_header["image_base"]
                else:
                    target_rva = None
                target_section = instruction.rip_relative_section
                target_resolution = "import_iat" if instruction.import_target else "rip_relative"
            key = (instruction.address, target_address, instruction.import_target)
            if key in seen:
                continue
            seen.add(key)
            target = PEStartupTarget(
                source=source_label,
                instruction_address=instruction.address,
                instruction_mnemonic=instruction.mnemonic,
                target_address=target_address,
                target_rva=target_rva,
                target_section=target_section,
                symbolic_label="",
                target_resolution=target_resolution,
                import_target=instruction.import_target,
                target_preview=[],
            )
            target.symbolic_label = self._build_startup_symbolic_label(target)
            targets.append(target)
        return targets

    def _first_preview_section(self, preview: List[PEInstructionPreview]) -> Optional[str]:
        for instruction in preview:
            if instruction.target_section:
                return instruction.target_section
        return None

    def _strip_bundle_prefix(self, section_data: bytes) -> tuple[bytes, int]:
        for prefix_size, fmt in ((8, "<Q"), (4, "<I")):
            if len(section_data) <= prefix_size:
                continue
            declared_size = struct.unpack(fmt, section_data[:prefix_size])[0]
            available = len(section_data) - prefix_size
            if 0 < declared_size <= available:
                return (section_data[prefix_size : prefix_size + declared_size], prefix_size)
        return (section_data, 0)

    def _find_js_start(self, bundle_data: bytes) -> Optional[int]:
        positions = [bundle_data.find(marker) for marker in self.JS_START_MARKERS]
        positions = [position for position in positions if position >= 0]
        return min(positions) if positions else None

    def _find_js_end(self, bundle_data: bytes, start_offset: int) -> int:
        best_end = None
        for marker in self.JS_END_MARKERS:
            marker_offset = bundle_data.rfind(marker, start_offset)
            if marker_offset < 0:
                continue
            line_end = bundle_data.find(b"\n", marker_offset + len(marker))
            end_offset = len(bundle_data) if line_end < 0 else line_end + 1
            if best_end is None or end_offset > best_end:
                best_end = end_offset

        if best_end is not None:
            return best_end

        chunk_size = 4096
        position = start_offset
        last_text_end = len(bundle_data)
        while position < len(bundle_data):
            end = min(len(bundle_data), position + chunk_size)
            chunk = bundle_data[position:end]
            if chunk:
                non_text_ratio = sum(1 for byte in chunk if byte not in _TEXT_BYTES) / len(chunk)
                if non_text_ratio > 0.20:
                    return max(start_offset, position)
            position = end
            last_text_end = end

        return last_text_end

    def _slice_bytes(self, data: bytes, offset: int, length: int) -> Optional[bytes]:
        if offset < 0 or length < 0 or offset + length > len(data):
            return None
        return data[offset : offset + length]

    def _normalize_virtual_path(self, virtual_path: str) -> str:
        normalized = virtual_path.replace("\\", "/")
        for prefix in ("B:/~BUN/", "B:~BUN/", "/$bunfs/"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
                break
        normalized = normalized.lstrip("/")
        parts = [part for part in Path(normalized).parts if part not in ("", ".", "..")]
        return str(Path(*parts)) if parts else "module.bin"

    def _calculate_hash(self, file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(4096), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def _analyze_dependencies(self, source_text: str) -> BunDependencyAnalysis:
        analysis_text = self._strip_dependency_analysis_noise(source_text)
        required_packages: List[str] = []
        builtin_modules: List[str] = []
        seen_required = set()
        seen_builtin = set()

        def record_package(specifier: str) -> None:
            package_name = self._package_name_from_specifier(
                specifier, allow_node_builtin=True
            )
            if not package_name:
                return
            if package_name in _NODE_BUILTIN_MODULES:
                if package_name not in seen_builtin:
                    seen_builtin.add(package_name)
                    builtin_modules.append(package_name)
                return
            if package_name not in seen_required:
                seen_required.add(package_name)
                required_packages.append(package_name)

        for pattern in self.IMPORT_PATTERNS:
            for match in pattern.finditer(analysis_text):
                record_package(match.group(1))

        for alias in self._iter_require_aliases(analysis_text):
            alias_pattern = re.compile(rf"\b{re.escape(alias)}\([\"']([^\"']+)[\"']\)")
            for match in alias_pattern.finditer(analysis_text):
                record_package(match.group(1))

        ignored_package_strings: List[str] = []
        seen_ignored = set()
        for string_pattern in self.STRING_LITERAL_PATTERNS:
            for literal_content in string_pattern.findall(analysis_text):
                for candidate in self._iter_embedded_package_candidates(literal_content):
                    package_name = self._package_name_from_specifier(
                        candidate, allow_node_builtin=True
                    )
                    if not package_name:
                        continue
                    if (
                        package_name in seen_required
                        or package_name in seen_builtin
                        or package_name in seen_ignored
                    ):
                        continue
                    seen_ignored.add(package_name)
                    ignored_package_strings.append(package_name)

        return BunDependencyAnalysis(
            required_packages=required_packages,
            builtin_modules=builtin_modules,
            ignored_package_strings=ignored_package_strings,
        )

    def _strip_dependency_analysis_noise(self, source_text: str) -> str:
        fenced_block_pattern = r"```(?:[A-Za-z0-9_-]+)?\r?\n[\s\S]{0,20000}?\r?\n```"
        escaped_fenced_block_pattern = (
            r"\\`\\`\\`(?:[A-Za-z0-9_-]+)?\r?\n[\s\S]{0,20000}?\r?\n\\`\\`\\`"
        )
        sanitized = re.sub(fenced_block_pattern, " ", source_text)
        sanitized = re.sub(escaped_fenced_block_pattern, " ", sanitized)
        return sanitized

    def _infer_external_dependencies(self, source_text: str) -> List[str]:
        return self._analyze_dependencies(source_text).required_packages

    def _iter_embedded_package_candidates(self, literal_content: str) -> List[str]:
        candidates: List[str] = []
        for match in self.EMBEDDED_REQUIRE_PATTERN.finditer(literal_content):
            candidates.append(match.group(1))
        return candidates

    def _iter_require_aliases(self, source_text: str) -> List[str]:
        aliases = set()
        alias_pattern = re.compile(
            r"(?:^|[;,\n])\s*(?:(?:var|let|const)\s+)?([A-Za-z_$][\w$]*)\s*=\s*(?:createRequire\(import\.meta\.url\)|import\.meta\.require)",
            re.MULTILINE,
        )
        for match in alias_pattern.finditer(source_text):
            aliases.add(match.group(1))
        return sorted(aliases)

    def _detect_runtime_features(self, source_text: str) -> List[str]:
        features: List[str] = []
        if "import.meta.require" in source_text:
            features.append("bun_import_meta_require")
        if "import.meta.url" in source_text:
            features.append("import_meta_url")
        if "await " in source_text:
            features.append("await_usage")
        if "Bun." in source_text or "globalThis.Bun" in source_text:
            features.append("bun_global_usage")
        return features

    def _normalize_source_text(self, source_text: str) -> tuple[str, List[str]]:
        normalized = source_text
        shims_applied: List[str] = []
        if "Bun." in normalized or "globalThis.Bun" in normalized:
            normalized = self._ensure_module_import(
                normalized, f'import "./{self.BUN_GLOBAL_SHIM_FILENAME}";'
            )
            shims_applied.append("bun global bootstrap")
        if "import.meta.require" in normalized:
            normalized = self._ensure_module_import(
                normalized, 'import { createRequire } from "module";'
            )
            normalized = normalized.replace(
                "import.meta.require", "createRequire(import.meta.url)"
            )
            shims_applied.extend(["createRequire import", "import.meta.require replacement"])
        normalized, bun_ffi_rewritten = self._rewrite_runtime_import_specifier(
            normalized,
            "bun:ffi",
            f"./{self.BUN_FFI_SHIM_FILENAME}",
        )
        if bun_ffi_rewritten:
            shims_applied.append("bun:ffi replacement")
        return normalized, shims_applied

    def _rewrite_runtime_import_specifier(
        self, source_text: str, original: str, replacement: str
    ) -> tuple[str, bool]:
        static_pattern = re.compile(
            rf'(\bimport\s*(?:[^;"\'`]+?\s*from\s*)?)(["\']){re.escape(original)}\2'
        )
        dynamic_pattern = re.compile(
            rf'(\b(?:import\.meta\.require|createRequire\(import\.meta\.url\)|require|import)\()(["\']){re.escape(original)}\2(\))'
        )
        rewritten = static_pattern.sub(rf"\1\2{replacement}\2", source_text)
        rewritten = dynamic_pattern.sub(rf"\1\2{replacement}\2\3", rewritten)
        return rewritten, rewritten != source_text

    def _build_bun_ffi_shim_source(self) -> str:
        return (
            "const unsupported = (api) => (...args) => {\n"
            "  throw new Error(\n"
            "    `${api} from bun:ffi is not supported in the Node rebuild. "
            "This code path requires manual porting or a Bun runtime.`\n"
            "  );\n"
            "};\n"
            "export const dlopen = unsupported(\"dlopen\");\n"
            "export const ptr = unsupported(\"ptr\");\n"
            "export const FFIType = new Proxy(Object.create(null), {\n"
            "  get(_target, prop) {\n"
            "    return String(prop);\n"
            "  },\n"
            "});\n"
            "export default {\n"
            "  dlopen,\n"
            "  ptr,\n"
            "  FFIType,\n"
            "};\n"
        )

    def _build_bun_global_shim_source(self) -> str:
        return (
            'import { fileURLToPath } from "url";\n'
            'import { spawnSync } from "child_process";\n'
            "\n"
            "const existingBun = globalThis.Bun ?? {};\n"
            "\n"
            "function runShellCommand(command) {\n"
            '  const shell = process.platform === "win32" ? "cmd.exe" : "/bin/sh";\n'
            '  const shellArgs = process.platform === "win32" ? ["/d", "/s", "/c", command] : ["-lc", command];\n'
            "  const result = spawnSync(shell, shellArgs, { encoding: null });\n"
            "  return {\n"
            '    stdout: Buffer.from(result.stdout ?? []),\n'
            '    stderr: Buffer.from(result.stderr ?? []),\n'
            "    exitCode: result.status ?? 1,\n"
            "  };\n"
            "}\n"
            "\n"
            "function dollar(strings, ...values) {\n"
            "  const command = String.raw({ raw: strings }, ...values);\n"
            "  return {\n"
            "    quiet() {\n"
            "      return Promise.resolve(runShellCommand(command));\n"
            "    },\n"
            "  };\n"
            "}\n"
            "\n"
            "function locateCommand(command) {\n"
            '  const locator = process.platform === "win32" ? "where" : "which";\n'
            "  const result = spawnSync(locator, [command], { encoding: \"utf8\" });\n"
            "  if (result.status !== 0) {\n"
            "    return null;\n"
            "  }\n"
            "  const firstLine = result.stdout.split(/\\r?\\n/, 1)[0]?.trim();\n"
            "  return firstLine || null;\n"
            "}\n"
            "\n"
            "const bunShim = {\n"
            "  ...existingBun,\n"
            "  $: existingBun.$ ?? dollar,\n"
            "  env: existingBun.env ?? process.env,\n"
            "  fileURLToPath: existingBun.fileURLToPath ?? fileURLToPath,\n"
            "  which: existingBun.which ?? locateCommand,\n"
            "};\n"
            "\n"
            "globalThis.Bun = bunShim;\n"
            "export default bunShim;\n"
            "export const $ = bunShim.$;\n"
            "export const env = bunShim.env;\n"
            "export const which = bunShim.which;\n"
            "export const bunFileURLToPath = bunShim.fileURLToPath;\n"
        )

    def _build_sea_entrypoint_source(self, entrypoint_name: str) -> str:
        return (
            'const { pathToFileURL } = require("url");\n'
            'const path = require("path");\n'
            'const fs = require("fs");\n'
            'const os = require("os");\n'
            'const crypto = require("crypto");\n'
            "\n"
            "function resolveRuntimeRoot() {\n"
            "  let sea;\n"
            "  try {\n"
            '    sea = require("node:sea");\n'
            "  } catch (_error) {\n"
            "    return __dirname;\n"
            "  }\n"
            "  let assetKeys;\n"
            "  try {\n"
            '    assetKeys = typeof sea.getAssetKeys === "function" ? sea.getAssetKeys() : [];\n'
            "  } catch (_error) {\n"
            "    return __dirname;\n"
            "  }\n"
            "  if (!assetKeys.length) {\n"
            "    return __dirname;\n"
            "  }\n"
            "  const runtimeId = crypto\n"
            '    .createHash("sha256")\n'
            "    .update(process.execPath)\n"
            '    .digest("hex")\n'
            "    .slice(0, 16);\n"
            '  const runtimeRoot = path.join(os.tmpdir(), "reveng-sea-runtime", runtimeId);\n'
            "  for (const assetKey of assetKeys) {\n"
            '    const targetPath = path.join(runtimeRoot, ...assetKey.split("/"));\n'
            "    fs.mkdirSync(path.dirname(targetPath), { recursive: true });\n"
            "    fs.writeFileSync(targetPath, Buffer.from(sea.getAsset(assetKey)));\n"
            "  }\n"
            "  return runtimeRoot;\n"
            "}\n"
            "\n"
            "(async () => {\n"
            "  const runtimeRoot = resolveRuntimeRoot();\n"
            f'  await import(pathToFileURL(path.join(runtimeRoot, "{entrypoint_name}")).href);\n'
            "})();\n"
        )

    def _collect_runtime_asset_map(
        self, project_dir: Path, manifest_data: Dict[str, Any]
    ) -> Dict[str, str]:
        asset_paths: List[Path] = []
        for relative_name in manifest_data.get("sea_companion_files", []):
            candidate = project_dir / relative_name
            if candidate.exists() and candidate.is_file():
                asset_paths.append(candidate)

        package_json_path = project_dir / "package.json"
        if package_json_path.exists():
            asset_paths.append(package_json_path)

        node_modules_dir = project_dir / "node_modules"
        if node_modules_dir.exists():
            for candidate in node_modules_dir.rglob("*"):
                if candidate.is_file():
                    asset_paths.append(candidate)

        runtime_assets: Dict[str, str] = {}
        for candidate in asset_paths:
            relative_path = candidate.relative_to(project_dir)
            runtime_assets[PurePosixPath(relative_path.as_posix()).as_posix()] = (
                relative_path.as_posix()
            )
        return runtime_assets

    def _update_sea_config_assets(
        self, sea_config_path: Path, asset_map: Dict[str, str]
    ) -> Dict[str, Any]:
        sea_config = json.loads(sea_config_path.read_text(encoding="utf-8"))
        sea_config["assets"] = asset_map
        sea_config_path.write_text(json.dumps(sea_config, indent=2), encoding="utf-8")
        return sea_config

    def _probe_standalone_output(self, output_exe: Path) -> Dict[str, Any]:
        probe_dir = Path(tempfile.mkdtemp(prefix="reveng_bun_sea_probe_"))
        probe_exe = probe_dir / output_exe.name
        try:
            shutil.copy2(output_exe, probe_exe)
            result = subprocess.run(
                [str(probe_exe), "--version"],
                cwd=probe_dir,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            combined_output = ((result.stdout or "") + (result.stderr or "")).strip()
            return {
                "passed": result.returncode == 0,
                "returncode": result.returncode,
                "output_tail": combined_output[-800:],
            }
        except subprocess.TimeoutExpired as exc:
            stdout = getattr(exc, "stdout", "") or ""
            stderr = getattr(exc, "stderr", "") or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            combined_output = (stdout + stderr).strip()
            return {
                "passed": False,
                "returncode": None,
                "output_tail": combined_output[-800:],
                "error": "Timeout after 5s",
            }
        except Exception as exc:
            return {
                "passed": False,
                "returncode": None,
                "output_tail": "",
                "error": str(exc),
            }

    def _ensure_module_import(self, source_text: str, import_line: str) -> str:
        if import_line in source_text:
            return source_text

        lines = source_text.splitlines(keepends=True)
        if lines and lines[0].strip() == "// @bun":
            newline = "\r\n" if lines[0].endswith("\r\n") else "\n"
            return f"{lines[0]}{import_line}{newline}{''.join(lines[1:])}"
        return f"{import_line}\n{source_text}"

    def _package_name_from_specifier(
        self, specifier: str, allow_node_builtin: bool = False
    ) -> Optional[str]:
        candidate = specifier.strip()
        if not candidate or candidate.startswith((".", "/", "\\")):
            return None
        if candidate.startswith("node:"):
            candidate = candidate[5:]
        if not re.fullmatch(r"(?:@[\w.-]+/)?[\w.-]+(?:/[\w./-]+)?", candidate):
            return None
        package_name = self._root_package_name(candidate)
        if not allow_node_builtin and package_name in _NODE_BUILTIN_MODULES:
            return None
        return package_name

    def _root_package_name(self, specifier: str) -> str:
        if specifier.startswith("@"):
            parts = specifier.split("/")
            return "/".join(parts[:2]) if len(parts) >= 2 else specifier
        return specifier.split("/")[0]

    def _slugify_name(self, value: str) -> str:
        slug = re.sub(r"[^A-Za-z0-9._-]+", "-", value.strip().lower()).strip("-")
        return slug or "bun-recovered-app"

    def _build_rebuild_verification_check(
        self, check: str, severity: str, status: str, message: str
    ) -> Dict[str, str]:
        return {
            "check": check,
            "severity": severity,
            "status": status,
            "message": message,
        }

    def _describe_validation_artifact(self, artifact_path: Path) -> Dict[str, Any]:
        return {
            "path": str(artifact_path),
            "byte_size": artifact_path.stat().st_size,
            "sha256": self._calculate_hash(artifact_path),
        }

    def _build_differential_validation(
        self,
        canonical_input: Optional[str],
        normalization: Optional[BunNormalizationResult],
    ) -> Optional[Dict[str, Any]]:
        if not canonical_input or not normalization or not normalization.entrypoint_path:
            return None

        checks: List[Dict[str, str]] = []
        expected_rewrites: List[str] = []
        canonical_path = Path(canonical_input)
        normalized_entrypoint = Path(normalization.entrypoint_path)

        if canonical_path.exists():
            checks.append(
                self._build_rebuild_verification_check(
                    "canonical_input_present",
                    "info",
                    "pass",
                    f"Canonical Bun input exists at {canonical_path}",
                )
            )
            canonical_text = canonical_path.read_text(encoding="utf-8", errors="replace")
        else:
            canonical_text = ""
            checks.append(
                self._build_rebuild_verification_check(
                    "canonical_input_present",
                    "error",
                    "fail",
                    "Canonical Bun input is missing before differential validation",
                )
            )

        if normalized_entrypoint.exists():
            checks.append(
                self._build_rebuild_verification_check(
                    "normalized_entrypoint_present",
                    "info",
                    "pass",
                    f"Normalized entrypoint exists at {normalized_entrypoint}",
                )
            )
            normalized_text = normalized_entrypoint.read_text(encoding="utf-8", errors="replace")
        else:
            normalized_text = ""
            checks.append(
                self._build_rebuild_verification_check(
                    "normalized_entrypoint_present",
                    "error",
                    "fail",
                    "Normalized entrypoint is missing before differential validation",
                )
            )

        canonical_dependencies = self._analyze_dependencies(canonical_text)
        normalized_dependencies = self._analyze_dependencies(normalized_text)
        if canonical_dependencies.required_packages == normalized_dependencies.required_packages:
            checks.append(
                self._build_rebuild_verification_check(
                    "dependency_runtime_parity",
                    "info",
                    "pass",
                    "Normalized entrypoint preserves the original external runtime dependency set",
                )
            )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "dependency_runtime_parity",
                    "error",
                    "fail",
                    "Runtime dependency set changed during normalization: "
                    + f"original={canonical_dependencies.required_packages}, "
                    + f"normalized={normalized_dependencies.required_packages}",
                )
            )

        canonical_features = set(self._detect_runtime_features(canonical_text))
        normalized_features = set(self._detect_runtime_features(normalized_text))
        expected_feature_drops = {"bun_import_meta_require"} if "bun_import_meta_require" in canonical_features else set()
        missing_features = sorted((canonical_features - expected_feature_drops) - normalized_features)
        preserved_features = sorted((canonical_features - expected_feature_drops) & normalized_features)
        added_features = sorted(normalized_features - canonical_features)
        if missing_features:
            checks.append(
                self._build_rebuild_verification_check(
                    "runtime_feature_continuity",
                    "error",
                    "fail",
                    "Normalization dropped preserved runtime features: " + ", ".join(missing_features),
                )
            )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "runtime_feature_continuity",
                    "info",
                    "pass",
                    "Normalized entrypoint preserves the runtime features that should survive normalization",
                )
            )

        if canonical_text.startswith("// @bun") and normalized_text.startswith("// @bun"):
            checks.append(
                self._build_rebuild_verification_check(
                    "bun_marker_continuity",
                    "info",
                    "pass",
                    "Normalized entrypoint preserves the Bun source marker header",
                )
            )
        elif canonical_text.startswith("// @bun"):
            checks.append(
                self._build_rebuild_verification_check(
                    "bun_marker_continuity",
                    "warning",
                    "warn",
                    "Normalized entrypoint no longer starts with the Bun source marker header",
                )
            )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "bun_marker_continuity",
                    "info",
                    "pass",
                    "No Bun source marker continuity check was needed for this canonical input",
                )
            )

        if "bun_import_meta_require" in canonical_features:
            expected_rewrites.append("import.meta.require -> createRequire(import.meta.url)")
            shim_present = "createRequire(import.meta.url)" in normalized_text
            shim_import_present = 'import { createRequire } from "module";' in normalized_text
            if shim_present and shim_import_present:
                checks.append(
                    self._build_rebuild_verification_check(
                        "bun_require_rewrite_coverage",
                        "info",
                        "pass",
                        "Normalized entrypoint rewrites Bun require usage through createRequire(import.meta.url)",
                    )
                )
            else:
                checks.append(
                    self._build_rebuild_verification_check(
                        "bun_require_rewrite_coverage",
                        "error",
                        "fail",
                        "Expected Bun require rewrite is missing from the normalized entrypoint",
                    )
                )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "bun_require_rewrite_coverage",
                    "info",
                    "pass",
                    "No Bun require rewrite was needed for this canonical input",
                    )
                )

        if "bun_global_usage" in canonical_features:
            expected_rewrites.append(
                f"Bun global bootstrap -> ./{self.BUN_GLOBAL_SHIM_FILENAME}"
            )
            bun_global_bootstrap_present = (
                f'import "./{self.BUN_GLOBAL_SHIM_FILENAME}";' in normalized_text
            )
            if bun_global_bootstrap_present:
                checks.append(
                    self._build_rebuild_verification_check(
                        "bun_global_bootstrap_coverage",
                        "info",
                        "pass",
                        "Normalized entrypoint bootstraps a Node-compatible Bun global shim",
                    )
                )
            else:
                checks.append(
                    self._build_rebuild_verification_check(
                        "bun_global_bootstrap_coverage",
                        "error",
                        "fail",
                        "Expected Bun global bootstrap import is missing from the normalized entrypoint",
                    )
                )

        if '"bun:ffi"' in canonical_text or "'bun:ffi'" in canonical_text:
            expected_rewrites.append(
                f"bun:ffi -> ./{self.BUN_FFI_SHIM_FILENAME}"
            )
            ffi_shim_present = f"./{self.BUN_FFI_SHIM_FILENAME}" in normalized_text
            if ffi_shim_present:
                checks.append(
                    self._build_rebuild_verification_check(
                        "bun_ffi_rewrite_coverage",
                        "info",
                        "pass",
                        "Normalized entrypoint rewrites bun:ffi imports through a Node-compatible shim",
                    )
                )
            else:
                checks.append(
                    self._build_rebuild_verification_check(
                        "bun_ffi_rewrite_coverage",
                        "error",
                        "fail",
                        "Expected bun:ffi rewrite is missing from the normalized entrypoint",
                    )
                )

        content_changed = False
        artifacts: Dict[str, Any] = {}
        if canonical_path.exists():
            artifacts["canonical_input"] = self._describe_validation_artifact(canonical_path)
        if normalized_entrypoint.exists():
            artifacts["normalized_entrypoint"] = self._describe_validation_artifact(normalized_entrypoint)
        if "canonical_input" in artifacts and "normalized_entrypoint" in artifacts:
            content_changed = (
                artifacts["canonical_input"]["sha256"] != artifacts["normalized_entrypoint"]["sha256"]
            )
            checks.append(
                self._build_rebuild_verification_check(
                    "content_delta_recorded",
                    "info",
                    "pass",
                    "Normalization produced "
                    + ("a transformed entrypoint" if content_changed else "an identical entrypoint")
                    + " relative to the canonical Bun input",
                )
            )

        failed_checks = [check for check in checks if check["status"] == "fail"]
        warned_checks = [check for check in checks if check["status"] == "warn"]
        if failed_checks:
            status = "fail"
        elif warned_checks:
            status = "pass_with_warnings"
        else:
            status = "pass"

        return {
            "status": status,
            "artifacts": artifacts,
            "checks": checks,
            "content_changed": content_changed,
            "preserved_runtime_features": preserved_features,
            "missing_runtime_features": missing_features,
            "added_runtime_features": added_features,
            "expected_rewrites": expected_rewrites,
        }

    def _verify_bun_rebuild(
        self,
        project_dir: Path,
        output_exe: Path,
        sea_blob_path: Path,
        package_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        checks: List[Dict[str, str]] = []
        manifest_path = project_dir / "normalization_manifest.json"
        sea_config_path = project_dir / "sea-config.json"
        manifest_data: Dict[str, Any] = {}
        sea_config_data: Dict[str, Any] = {}
        if manifest_path.exists():
            try:
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                manifest_data = {}
        if sea_config_path.exists():
            try:
                sea_config_data = json.loads(sea_config_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                sea_config_data = {}

        reveng_data = package_data.get("reveng", {})
        dependency_analysis = reveng_data.get("dependency_analysis", {})
        required_packages = set(dependency_analysis.get("required_packages", []))
        declared_dependencies = set((package_data.get("dependencies") or {}).keys())
        missing_dependencies = sorted(required_packages - declared_dependencies)
        extra_dependencies = sorted(declared_dependencies - required_packages)

        entrypoint_value = manifest_data.get("entrypoint_path")
        entrypoint_path = Path(entrypoint_value) if entrypoint_value else None
        if entrypoint_path and entrypoint_path.exists():
            checks.append(
                self._build_rebuild_verification_check(
                    "normalized_entrypoint_present",
                    "info",
                    "pass",
                    f"Normalized entrypoint exists at {entrypoint_path}",
                )
            )
            entrypoint_text = entrypoint_path.read_text(encoding="utf-8", errors="replace")
        else:
            entrypoint_text = ""
            checks.append(
                self._build_rebuild_verification_check(
                    "normalized_entrypoint_present",
                    "error",
                    "fail",
                    "Normalized entrypoint is missing from the workspace manifest",
                )
            )

        if sea_blob_path.exists():
            checks.append(
                self._build_rebuild_verification_check(
                    "sea_blob_generated",
                    "info",
                    "pass",
                    f"SEA preparation blob exists at {sea_blob_path}",
                )
            )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "sea_blob_generated",
                    "error",
                    "fail",
                    "SEA preparation blob was not generated",
                )
            )

        if output_exe.exists():
            checks.append(
                self._build_rebuild_verification_check(
                    "output_binary_generated",
                    "info",
                    "pass",
                    f"SEA executable exists at {output_exe}",
                )
            )
            standalone_probe = self._probe_standalone_output(output_exe)
            if standalone_probe["passed"]:
                checks.append(
                    self._build_rebuild_verification_check(
                        "standalone_copy_probe",
                        "info",
                        "pass",
                        "Standalone copied SEA executable responds to --version outside the normalized workspace",
                    )
                )
            else:
                failure_hint = standalone_probe.get("error") or standalone_probe.get("output_tail") or "unknown runtime failure"
                checks.append(
                    self._build_rebuild_verification_check(
                        "standalone_copy_probe",
                        "warning",
                        "warn",
                        "Standalone copied SEA executable still depends on the normalized workspace bundle: "
                        + failure_hint,
                    )
                )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "output_binary_generated",
                    "error",
                    "fail",
                    "SEA executable was not generated",
                )
            )

        asset_map = sea_config_data.get("assets", {}) if isinstance(sea_config_data, dict) else {}
        companion_files = set(manifest_data.get("sea_companion_files", []))
        missing_companion_assets = sorted(
            companion_file for companion_file in companion_files if companion_file not in asset_map
        )
        node_modules_embedded = any(key.startswith("node_modules/") for key in asset_map)
        if missing_companion_assets:
            checks.append(
                self._build_rebuild_verification_check(
                    "sea_asset_bundle_coverage",
                    "error",
                    "fail",
                    "SEA asset bundle is missing runtime companion files: "
                    + ", ".join(missing_companion_assets),
                )
            )
        elif required_packages and not node_modules_embedded:
            checks.append(
                self._build_rebuild_verification_check(
                    "sea_asset_bundle_coverage",
                    "warning",
                    "warn",
                    "SEA asset bundle preserves the entrypoint shims but does not embed node_modules runtime dependencies",
                )
            )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "sea_asset_bundle_coverage",
                    "info",
                    "pass",
                    f"SEA asset bundle records {len(asset_map)} runtime file(s) for workspace-companion reconstruction",
                )
            )

        if missing_dependencies:
            checks.append(
                self._build_rebuild_verification_check(
                    "dependency_manifest_alignment",
                    "error",
                    "fail",
                    "package.json is missing inferred runtime dependencies: "
                    + ", ".join(missing_dependencies),
                )
            )
        elif extra_dependencies:
            checks.append(
                self._build_rebuild_verification_check(
                    "dependency_manifest_alignment",
                    "warning",
                    "warn",
                    "package.json declares extra dependencies beyond the inferred runtime set: "
                    + ", ".join(extra_dependencies),
                )
            )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "dependency_manifest_alignment",
                    "info",
                    "pass",
                    "package.json dependencies align with the inferred runtime dependency set",
                )
            )

        if entrypoint_text.startswith("// @bun"):
            checks.append(
                self._build_rebuild_verification_check(
                    "bun_marker_continuity",
                    "info",
                    "pass",
                    "Normalized entrypoint preserves the Bun marker header",
                )
            )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "bun_marker_continuity",
                    "warning",
                    "warn",
                    "Normalized entrypoint does not preserve the original Bun marker header",
                )
            )

        shims_applied = reveng_data.get("shims_applied", [])
        if "import.meta.require replacement" in shims_applied:
            if "createRequire(import.meta.url)" in entrypoint_text:
                checks.append(
                    self._build_rebuild_verification_check(
                        "shim_continuity",
                        "info",
                        "pass",
                        "Normalized entrypoint retains the createRequire shim for Bun require usage",
                    )
                )
            else:
                checks.append(
                    self._build_rebuild_verification_check(
                        "shim_continuity",
                        "error",
                        "fail",
                        "Expected createRequire shim is missing from the normalized entrypoint",
                    )
                )
        else:
            checks.append(
                self._build_rebuild_verification_check(
                    "shim_continuity",
                    "info",
                    "pass",
                    "No Bun require shim continuity check was needed for this workspace",
                )
            )

        failed_checks = [check for check in checks if check["status"] == "fail"]
        warned_checks = [check for check in checks if check["status"] == "warn"]
        if failed_checks:
            status = "fail"
        elif warned_checks:
            status = "pass_with_warnings"
        else:
            status = "pass"

        return {
            "status": status,
            "checks": checks,
        }

    def build_node_sea(
        self,
        normalized_project_dir: str,
        output_path: Optional[str] = None,
        install_dependencies: bool = True,
    ) -> BunSeaBuildResult:
        """Package a normalized Bun workspace into a Windows executable using Node SEA."""
        project_dir = Path(normalized_project_dir)
        project_dir_abs = project_dir.resolve()
        package_json_path = project_dir / "package.json"
        sea_config_path = project_dir / "sea-config.json"
        sea_blob_path = project_dir / "sea-prep.blob"

        if not project_dir.exists():
            return BunSeaBuildResult(
                success=False,
                normalized_project_dir=None,
                output_path=None,
                sea_blob_path=None,
                installed_dependencies=[],
                commands_run=[],
                verification=None,
                error_message=f"Normalized project directory not found: {normalized_project_dir}",
            )

        if not package_json_path.exists() or not sea_config_path.exists():
            return BunSeaBuildResult(
                success=False,
                normalized_project_dir=str(project_dir),
                output_path=None,
                sea_blob_path=None,
                installed_dependencies=[],
                commands_run=[],
                verification=None,
                error_message="Normalized project is missing package.json or sea-config.json",
            )

        package_data = json.loads(package_json_path.read_text(encoding="utf-8"))
        reveng_data = package_data.get("reveng", {})
        package_dependencies = package_data.get("dependencies", {})
        inferred_dependencies = list(package_dependencies.keys()) if isinstance(package_dependencies, dict) else []
        if not inferred_dependencies:
            dependency_analysis = reveng_data.get("dependency_analysis", {})
            inferred_dependencies = list(dependency_analysis.get("required_packages", []))
        if not inferred_dependencies:
            inferred_dependencies = list(reveng_data.get("inferred_dependencies", []))
        dependencies_to_install = inferred_dependencies + ["postject"]

        node_path = shutil.which("node")
        npm_path = shutil.which("npm") or shutil.which("npm.cmd")
        if not node_path:
            return BunSeaBuildResult(
                success=False,
                normalized_project_dir=str(project_dir),
                output_path=None,
                sea_blob_path=None,
                installed_dependencies=[],
                commands_run=[],
                verification=None,
                error_message="Node.js executable not found in PATH",
            )
        if install_dependencies and not npm_path:
            return BunSeaBuildResult(
                success=False,
                normalized_project_dir=str(project_dir),
                output_path=None,
                sea_blob_path=None,
                installed_dependencies=[],
                commands_run=[],
                verification=None,
                error_message="npm executable not found in PATH",
            )

        output_exe = Path(output_path) if output_path else project_dir / "bun-sea.exe"
        output_exe_abs = output_exe.resolve()
        sea_blob_path_abs = sea_blob_path.resolve()
        commands_run: List[str] = []

        try:
            manifest_path = project_dir / "normalization_manifest.json"
            manifest_data: Dict[str, Any] = {}
            if manifest_path.exists():
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))

            if install_dependencies and dependencies_to_install:
                install_cmd = [npm_path, "install", *dependencies_to_install, "--silent"]
                commands_run.append(" ".join(install_cmd))
                self._run_command(install_cmd, cwd=project_dir_abs)

            asset_map = self._collect_runtime_asset_map(project_dir, manifest_data)
            self._update_sea_config_assets(sea_config_path, asset_map)

            sea_cmd = [node_path, "--experimental-sea-config", sea_config_path.name]
            commands_run.append(" ".join(sea_cmd))
            self._run_command(sea_cmd, cwd=project_dir_abs)

            shutil.copy2(node_path, output_exe_abs)

            postject_cmd = self._resolve_postject_command(project_dir_abs)
            inject_cmd = [
                *postject_cmd,
                str(output_exe_abs),
                "NODE_SEA_BLOB",
                str(sea_blob_path_abs),
                "--sentinel-fuse",
                "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
            ]
            commands_run.append(" ".join(inject_cmd))
            self._run_command(inject_cmd, cwd=project_dir_abs)

            verification = self._verify_bun_rebuild(
                project_dir=project_dir,
                output_exe=output_exe,
                sea_blob_path=sea_blob_path,
                package_data=package_data,
            )
            return BunSeaBuildResult(
                success=True,
                normalized_project_dir=str(project_dir),
                output_path=str(output_exe),
                sea_blob_path=str(sea_blob_path),
                installed_dependencies=dependencies_to_install if install_dependencies else [],
                commands_run=commands_run,
                verification=verification,
                error_message=None,
            )
        except Exception as exc:
            logger.error("Node SEA build failed for %s: %s", normalized_project_dir, exc)
            verification = self._verify_bun_rebuild(
                project_dir=project_dir,
                output_exe=output_exe,
                sea_blob_path=sea_blob_path,
                package_data=package_data,
            )
            return BunSeaBuildResult(
                success=False,
                normalized_project_dir=str(project_dir),
                output_path=str(output_exe),
                sea_blob_path=str(sea_blob_path) if sea_blob_path.exists() else None,
                installed_dependencies=dependencies_to_install if install_dependencies else [],
                commands_run=commands_run,
                verification=verification,
                error_message=str(exc),
            )

    def _resolve_postject_command(self, project_dir: Path) -> List[str]:
        local_cmd = project_dir / "node_modules" / ".bin" / "postject.cmd"
        local_shell = project_dir / "node_modules" / ".bin" / "postject"
        if local_cmd.exists():
            return [str(local_cmd)]
        if local_shell.exists():
            return [str(local_shell)]
        npx_path = shutil.which("npx") or shutil.which("npx.cmd")
        return [npx_path, "postject"] if npx_path else ["npx", "postject"]

    def _run_command(self, command: List[str], cwd: Path) -> None:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            stderr = result.stderr.strip() or result.stdout.strip() or "Command failed"
            raise RuntimeError(stderr)

    def _parse_module_entries(
        self, raw_bytes: bytes, modules_bytes: bytes
    ) -> Optional[tuple[List[BunModuleEntry], str]]:
        for layout_name, entry_struct in (
            ("full", self.MODULE_ENTRY_STRUCT),
            ("short", self.SHORT_MODULE_ENTRY_STRUCT),
            ("short_ext", self.SHORT_EXT_MODULE_ENTRY_STRUCT),
        ):
            modules = self._parse_module_entries_with_layout(raw_bytes, modules_bytes, layout_name, entry_struct)
            if modules:
                return modules, layout_name
        return None

    def _parse_module_entries_with_layout(
        self,
        raw_bytes: bytes,
        modules_bytes: bytes,
        layout_name: str,
        entry_struct: struct.Struct,
    ) -> List[BunModuleEntry]:
        if len(modules_bytes) % entry_struct.size != 0:
            return []

        modules: List[BunModuleEntry] = []
        for index in range(0, len(modules_bytes), entry_struct.size):
            fields = entry_struct.unpack(modules_bytes[index : index + entry_struct.size])
            name_offset, name_length = fields[0], fields[1]
            content_offset, content_length = fields[2], fields[3]
            sourcemap_offset, sourcemap_length = fields[4], fields[5]
            if layout_name == "full":
                loader_id = fields[13]
            else:
                loader_id = fields[9] if layout_name == "short_ext" else fields[8]

            name_bytes = self._slice_bytes(raw_bytes, name_offset, name_length)
            content_bytes = self._slice_bytes(raw_bytes, content_offset, content_length)
            if not name_bytes or content_bytes is None:
                return []

            virtual_path = name_bytes.decode("utf-8", errors="replace")
            if not self._looks_like_virtual_path(virtual_path):
                return []

            modules.append(
                BunModuleEntry(
                    virtual_path=virtual_path,
                    recovered_path=self._normalize_virtual_path(virtual_path),
                    loader_id=loader_id,
                    content_offset=content_offset,
                    content_size=content_length,
                    sourcemap_offset=sourcemap_offset,
                    sourcemap_size=sourcemap_length,
                )
            )

        return modules

    def _recover_from_path_scan(
        self,
        file_path: str,
        bundle_data: bytes,
        output_dir: str,
    ) -> BunRecoveryResult:
        target_dir = Path(output_dir)
        target_dir.mkdir(parents=True, exist_ok=True)
        info = self.detect(file_path)
        trailer_offset = bundle_data.rfind(self.TRAILER)
        offsets = self._parse_offsets(bundle_data, trailer_offset)
        discovered_paths = self._scan_virtual_paths(bundle_data)
        recovered_files: List[str] = []
        primary_source_path = None
        recovered_sourcemap_path = None
        recovered_supporting_artifacts: List[str] = []

        recovered_source = self._recover_path_scan_primary_source(
            bundle_data=bundle_data,
            info=info,
            discovered_paths=discovered_paths,
            output_dir=target_dir,
        )
        if recovered_source:
            primary_source_path = recovered_source["source_path"]
            recovered_files.append(primary_source_path)
            recovered_sourcemap_path = recovered_source.get("sourcemap_path")
            recovered_sourcemap_provenance = recovered_source.get("sourcemap_provenance")
            if recovered_sourcemap_path:
                recovered_files.append(recovered_sourcemap_path)
        else:
            recovered_sourcemap_provenance = None
        recovered_supporting_artifacts = self._recover_path_scan_supporting_artifacts(
            bundle_data=bundle_data,
            discovered_paths=discovered_paths,
            output_dir=target_dir,
            excluded_outputs=[path for path in (primary_source_path, recovered_sourcemap_path) if path],
        )
        recovered_files.extend(recovered_supporting_artifacts)

        bundle_tail_path = target_dir / "bundle_tail.bin"
        bundle_tail_path.write_bytes(bundle_data[max(0, len(bundle_data) - 256) :])
        recovered_files.append(str(bundle_tail_path))

        module_records_path = None
        if offsets is not None:
            module_bytes = self._slice_bytes(
                bundle_data[: offsets["byte_count"]],
                offsets["modules_offset"],
                offsets["modules_length"],
            )
            if module_bytes:
                module_records_path = target_dir / "module_records.bin"
                module_records_path.write_bytes(module_bytes)
                recovered_files.append(str(module_records_path))

        discovered_paths_path = target_dir / "discovered_paths.txt"
        discovered_paths_path.write_text(
            "\n".join(discovered_paths) + ("\n" if discovered_paths else ""),
            encoding="utf-8",
        )
        recovered_files.append(str(discovered_paths_path))

        manifest_path = target_dir / "module_graph.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "recovery_mode": "path_scan",
                    "parse_warning": "Bun module graph could not be parsed with known layouts",
                    "bundle": {
                        "section_name": info.section_name,
                        "bundle_size": info.bundle_size,
                        "javascript_start_offset": info.javascript_start_offset,
                        "trailer_offset": trailer_offset if trailer_offset >= 0 else None,
                    },
                    "offsets": offsets,
                    "discovered_path_count": len(discovered_paths),
                    "discovered_paths": [
                        {
                            "virtual_path": path,
                            "recovered_path": self._normalize_virtual_path(path),
                        }
                        for path in discovered_paths
                    ],
                    "artifacts": {
                        "primary_source_path": primary_source_path,
                        "recovered_sourcemap_path": recovered_sourcemap_path,
                        "recovered_sourcemap_provenance": (
                            self._serialize_sourcemap_provenance(recovered_sourcemap_provenance)
                            if recovered_sourcemap_provenance
                            else None
                        ),
                        "recovered_supporting_artifacts": recovered_supporting_artifacts,
                        "bundle_tail_path": str(bundle_tail_path),
                        "module_records_path": str(module_records_path)
                        if module_records_path
                        else None,
                        "discovered_paths_path": str(discovered_paths_path),
                    },
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        recovered_files.append(str(manifest_path))

        logger.warning(
            "Recovered Bun metadata via path scan fallback for %s; discovered %d virtual paths",
            file_path,
            len(discovered_paths),
        )

        return BunRecoveryResult(
            success=True,
            output_dir=str(target_dir),
            manifest_path=str(manifest_path),
            recovered_files=recovered_files,
            error_message="Bun module graph could not be parsed; recovered metadata via path scan",
            graph=None,
            recovery_mode="path_scan",
        )

    def _recover_path_scan_primary_source(
        self,
        bundle_data: bytes,
        info: BunExecutableInfo,
        discovered_paths: List[str],
        output_dir: Path,
    ) -> Optional[Dict[str, Any]]:
        js_start = info.javascript_start_offset
        if js_start is None:
            js_start = self._find_js_start(bundle_data)
        if js_start is None:
            return None

        js_end = self._find_js_end(bundle_data, js_start)
        next_path_offset = self._find_next_virtual_path_offset(bundle_data, discovered_paths, js_start + 1)
        if next_path_offset is not None and (js_end <= js_start or next_path_offset < js_end):
            js_end = next_path_offset
        if js_end <= js_start:
            js_end = self._find_fallback_text_end(bundle_data, js_start)
        js_bytes = bundle_data[js_start:js_end].rstrip(b"\x00")
        js_text = js_bytes.decode("utf-8", errors="replace").strip()
        if not js_text:
            return None

        virtual_path = self._select_fallback_primary_path(discovered_paths)
        if not virtual_path:
            return None

        source_output = output_dir / self._normalize_virtual_path(virtual_path)
        source_output.parent.mkdir(parents=True, exist_ok=True)
        source_output.write_text(js_text + "\n", encoding="utf-8")

        result: Dict[str, Any] = {"source_path": str(source_output)}
        sourcemap_result = self._recover_inline_sourcemap(js_text, source_output)
        if not sourcemap_result:
            sourcemap_result = self._recover_referenced_sourcemap(
                source_text=js_text,
                source_virtual_path=virtual_path,
                source_output=source_output,
                bundle_data=bundle_data,
                discovered_paths=discovered_paths,
            )
        if sourcemap_result:
            result["sourcemap_path"] = sourcemap_result["path"]
            result["sourcemap_provenance"] = sourcemap_result["provenance"]
        return result

    def _recover_path_scan_supporting_artifacts(
        self,
        bundle_data: bytes,
        discovered_paths: List[str],
        output_dir: Path,
        excluded_outputs: List[str],
    ) -> List[str]:
        recovered_artifacts: List[str] = []
        excluded = {str(Path(path)) for path in excluded_outputs}
        for virtual_path in discovered_paths:
            normalized_virtual_path = virtual_path.replace("\\", "/").lower()
            output_path = output_dir / self._normalize_virtual_path(virtual_path)
            if str(output_path) in excluded or output_path.exists():
                continue
            recovered_path = None
            if normalized_virtual_path.endswith(".json"):
                recovered_path = self._recover_json_artifact_after_virtual_path(
                    bundle_data=bundle_data,
                    virtual_path=virtual_path,
                    output_path=output_path,
                )
            elif normalized_virtual_path.endswith(self.FALLBACK_TEXT_ARTIFACT_SUFFIXES):
                recovered_path = self._recover_text_artifact_after_virtual_path(
                    bundle_data=bundle_data,
                    virtual_path=virtual_path,
                    output_path=output_path,
                    discovered_paths=discovered_paths,
                )
            elif normalized_virtual_path.endswith(self.FALLBACK_BINARY_ARTIFACT_SUFFIXES):
                recovered_path = self._recover_binary_artifact_after_virtual_path(
                    bundle_data=bundle_data,
                    virtual_path=virtual_path,
                    output_path=output_path,
                    discovered_paths=discovered_paths,
                )
            if recovered_path:
                recovered_artifacts.append(recovered_path)
        return recovered_artifacts

    def _select_fallback_primary_path(self, discovered_paths: List[str]) -> Optional[str]:
        if not discovered_paths:
            return None

        primary_suffix_groups = (
            (".exe", ".js", ".mjs", ".cjs"),
            (".ts", ".tsx", ".jsx"),
        )
        for suffix_group in primary_suffix_groups:
            for candidate in discovered_paths:
                normalized = candidate.lower()
                if normalized.endswith(".map") or normalized.endswith(".json"):
                    continue
                if normalized.endswith(".env") or normalized.endswith(".txt"):
                    continue
                if normalized.endswith(suffix_group):
                    return candidate

        for candidate in discovered_paths:
            normalized = candidate.lower()
            if not normalized.endswith(".map"):
                return candidate
        return discovered_paths[0]

    def _recover_inline_sourcemap(
        self, source_text: str, source_output: Path
    ) -> Optional[Dict[str, Any]]:
        match = self.SOURCE_MAPPING_URL_PATTERN.search(source_text)
        if not match:
            return None

        source_mapping_url = match.group(1).strip()
        if not source_mapping_url.startswith("data:"):
            return None

        payload_bytes = self._decode_data_url_payload(source_mapping_url)
        if payload_bytes is None:
            return None

        sourcemap_output = source_output.with_name(source_output.name + ".bunmap")
        sourcemap_output.write_bytes(payload_bytes)
        return {
            "path": str(sourcemap_output),
            "provenance": self._analyze_sourcemap_provenance(
                sourcemap_bytes=payload_bytes,
                source_output=source_output,
                origin="inline_data_url",
            ),
        }

    def _recover_referenced_sourcemap(
        self,
        source_text: str,
        source_virtual_path: str,
        source_output: Path,
        bundle_data: bytes,
        discovered_paths: List[str],
    ) -> Optional[Dict[str, Any]]:
        match = self.SOURCE_MAPPING_URL_PATTERN.search(source_text)
        if not match:
            return None

        source_mapping_url = match.group(1).strip()
        if not source_mapping_url or source_mapping_url.startswith("data:"):
            return None

        sourcemap_virtual_path = self._match_referenced_virtual_path(
            source_virtual_path, source_mapping_url, discovered_paths
        )
        if not sourcemap_virtual_path:
            return None

        sourcemap_output = source_output.parent / PurePosixPath(source_mapping_url).name
        recovered_path = self._recover_json_artifact_after_virtual_path(
            bundle_data=bundle_data,
            virtual_path=sourcemap_virtual_path,
            output_path=sourcemap_output,
        )
        if not recovered_path:
            return None
        sourcemap_bytes = sourcemap_output.read_bytes()
        return {
            "path": recovered_path,
            "provenance": self._analyze_sourcemap_provenance(
                sourcemap_bytes=sourcemap_bytes,
                source_output=source_output,
                origin="referenced_virtual_path",
            ),
        }

    def _match_referenced_virtual_path(
        self,
        source_virtual_path: str,
        source_mapping_url: str,
        discovered_paths: List[str],
    ) -> Optional[str]:
        normalized_source = source_virtual_path.replace("\\", "/")
        normalized_mapping = source_mapping_url.replace("\\", "/").lstrip("/")
        expected_path = str(PurePosixPath(normalized_source).parent / normalized_mapping)

        for candidate in discovered_paths:
            normalized_candidate = candidate.replace("\\", "/")
            if normalized_candidate == expected_path:
                return candidate
        for candidate in discovered_paths:
            normalized_candidate = candidate.replace("\\", "/")
            if normalized_candidate.endswith("/" + PurePosixPath(normalized_mapping).name):
                return candidate
        return None

    def _recover_json_artifact_after_virtual_path(
        self,
        bundle_data: bytes,
        virtual_path: str,
        output_path: Path,
    ) -> Optional[str]:
        for candidate_bytes in self._candidate_virtual_path_bytes(virtual_path):
            marker_offset = bundle_data.find(candidate_bytes)
            if marker_offset < 0:
                continue
            start_offset = marker_offset + len(candidate_bytes)
            while start_offset < len(bundle_data) and bundle_data[start_offset] in b"\x00\r\n\t ":
                start_offset += 1
            if start_offset >= len(bundle_data) or bundle_data[start_offset] != ord("{"):
                continue
            end_offset = self._find_json_object_end(bundle_data, start_offset)
            if end_offset is None:
                continue
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(bundle_data[start_offset:end_offset])
            return str(output_path)
        return None

    def _recover_text_artifact_after_virtual_path(
        self,
        bundle_data: bytes,
        virtual_path: str,
        output_path: Path,
        discovered_paths: List[str],
    ) -> Optional[str]:
        for candidate_bytes in self._candidate_virtual_path_bytes(virtual_path):
            marker_offset = bundle_data.find(candidate_bytes)
            if marker_offset < 0:
                continue
            start_offset = marker_offset + len(candidate_bytes)
            while start_offset < len(bundle_data) and bundle_data[start_offset] in b"\x00\r\n\t ":
                start_offset += 1
            if start_offset >= len(bundle_data):
                continue
            if bundle_data[start_offset] not in _TEXT_BYTES:
                continue

            next_path_offset = self._find_next_virtual_path_offset(bundle_data, discovered_paths, start_offset)
            text_end = self._find_fallback_text_end(bundle_data, start_offset)
            candidate_end = min(text_end, next_path_offset) if next_path_offset is not None else text_end
            text_bytes = bundle_data[start_offset:candidate_end].rstrip(b"\x00\r\n\t ")
            if not text_bytes:
                continue
            if not self._looks_like_text_artifact_payload(virtual_path, text_bytes):
                continue

            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(text_bytes.decode("utf-8", errors="replace") + "\n", encoding="utf-8")
            return str(output_path)
        return None

    def _recover_binary_artifact_after_virtual_path(
        self,
        bundle_data: bytes,
        virtual_path: str,
        output_path: Path,
        discovered_paths: List[str],
    ) -> Optional[str]:
        normalized_virtual_path = virtual_path.replace("\\", "/").lower()
        if normalized_virtual_path.endswith(".wasm"):
            return self._recover_wasm_artifact_after_virtual_path(
                bundle_data=bundle_data,
                virtual_path=virtual_path,
                output_path=output_path,
                discovered_paths=discovered_paths,
            )
        return None

    def _recover_wasm_artifact_after_virtual_path(
        self,
        bundle_data: bytes,
        virtual_path: str,
        output_path: Path,
        discovered_paths: List[str],
    ) -> Optional[str]:
        for candidate_bytes in self._candidate_virtual_path_bytes(virtual_path):
            marker_offset = bundle_data.find(candidate_bytes)
            if marker_offset < 0:
                continue
            start_offset = marker_offset + len(candidate_bytes)
            if start_offset >= len(bundle_data):
                continue
            wasm_offset = bundle_data.find(self.WASM_MAGIC, start_offset, min(len(bundle_data), start_offset + 32))
            if wasm_offset < 0 or wasm_offset + 8 > len(bundle_data):
                continue
            if bundle_data[wasm_offset + 4 : wasm_offset + 8] != self.WASM_VERSION:
                continue

            next_path_offset = self._find_next_virtual_path_offset(bundle_data, discovered_paths, wasm_offset + 1)
            end_offset = next_path_offset if next_path_offset is not None else len(bundle_data)
            wasm_bytes = bundle_data[wasm_offset:end_offset].rstrip(b"\x00\r\n\t ")
            if len(wasm_bytes) < 8:
                continue

            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(wasm_bytes)
            return str(output_path)
        return None

    def _find_next_virtual_path_offset(
        self,
        bundle_data: bytes,
        discovered_paths: List[str],
        start_offset: int,
    ) -> Optional[int]:
        next_offset: Optional[int] = None
        for virtual_path in discovered_paths:
            for candidate_bytes in self._candidate_virtual_path_bytes(virtual_path):
                marker_offset = bundle_data.find(candidate_bytes, start_offset)
                if marker_offset < 0:
                    continue
                if next_offset is None or marker_offset < next_offset:
                    next_offset = marker_offset
        trailer_offset = bundle_data.rfind(self.TRAILER)
        if trailer_offset >= 0 and (next_offset is None or trailer_offset < next_offset):
            next_offset = trailer_offset
        return next_offset

    def _looks_like_text_payload(self, payload: bytes) -> bool:
        if not payload:
            return False
        non_text_ratio = sum(1 for byte in payload if byte not in _TEXT_BYTES) / len(payload)
        return non_text_ratio <= 0.05

    def _looks_like_text_artifact_payload(self, virtual_path: str, payload: bytes) -> bool:
        if not self._looks_like_text_payload(payload):
            return False

        normalized_path = virtual_path.replace("\\", "/").lower()
        text = payload.decode("utf-8", errors="replace").strip()
        if not text:
            return False

        if normalized_path.endswith(".css"):
            return "{" in text and "}" in text and ":" in text
        if normalized_path.endswith(".html"):
            lowered = text.lower()
            return "<html" in lowered or "<!doctype html" in lowered or "<body" in lowered
        if normalized_path.endswith((".yml", ".yaml")):
            return ": " in text and "\n" in text
        if normalized_path.endswith(".toml"):
            return "=" in text and ("[" in text or "\n" in text)
        return True

    def _analyze_sourcemap_provenance(
        self,
        sourcemap_bytes: bytes,
        source_output: Path,
        origin: str,
    ) -> BunSourcemapProvenance:
        parse_status = "non_json_payload"
        file_field = None
        source_count = 0
        file_matches_source_name: Optional[bool] = None
        try:
            parsed = json.loads(sourcemap_bytes.decode("utf-8"))
            if isinstance(parsed, dict):
                parse_status = "valid_json"
                file_value = parsed.get("file")
                file_field = file_value if isinstance(file_value, str) else None
                sources = parsed.get("sources")
                source_count = len(sources) if isinstance(sources, list) else 0
                if file_field:
                    source_name = source_output.name
                    bunmap_name = source_output.with_name(source_output.name + ".bunmap").name
                    map_name = source_output.with_suffix(".map").name
                    file_matches_source_name = file_field in {
                        source_name,
                        bunmap_name,
                        map_name,
                    }
                else:
                    file_matches_source_name = None
            else:
                parse_status = "json_not_object"
        except Exception:
            parse_status = "non_json_payload"
        return BunSourcemapProvenance(
            origin=origin,
            byte_size=len(sourcemap_bytes),
            sha256=hashlib.sha256(sourcemap_bytes).hexdigest(),
            parse_status=parse_status,
            file_field=file_field,
            source_count=source_count,
            file_matches_source_name=file_matches_source_name,
        )

    def _serialize_sourcemap_provenance(
        self, provenance: BunSourcemapProvenance
    ) -> Dict[str, Any]:
        return {
            "origin": provenance.origin,
            "byte_size": provenance.byte_size,
            "sha256": provenance.sha256,
            "parse_status": provenance.parse_status,
            "file_field": provenance.file_field,
            "source_count": provenance.source_count,
            "file_matches_source_name": provenance.file_matches_source_name,
        }

    def _load_adjacent_sourcemap_provenance(
        self, source_path: Path
    ) -> Optional[BunSourcemapProvenance]:
        for candidate in (
            source_path.with_name(source_path.name + ".bunmap"),
            source_path.with_suffix(".map"),
        ):
            if not candidate.exists():
                continue
            try:
                sourcemap_bytes = candidate.read_bytes()
            except Exception:
                continue
            origin = "adjacent_bunmap" if candidate.suffix == ".bunmap" else "adjacent_map"
            return self._analyze_sourcemap_provenance(
                sourcemap_bytes=sourcemap_bytes,
                source_output=source_path,
                origin=origin,
            )
        return None

    def _recommend_postprocessing_hooks(
        self,
        source_text: str,
        runtime_features: List[str],
        shims_applied: List[str],
        sourcemap_provenance: Optional[BunSourcemapProvenance],
    ) -> List[Dict[str, str]]:
        hooks: List[BunPostprocessingHook] = []
        seen_tools: set[str] = set()

        def add_hook(
            tool: str,
            category: str,
            reason: str,
            suggested_input: str,
            command_template: str,
        ) -> None:
            if tool in seen_tools:
                return
            seen_tools.add(tool)
            hooks.append(
                BunPostprocessingHook(
                    tool=tool,
                    category=category,
                    reason=reason,
                    suggested_input=suggested_input,
                    command_template=command_template,
                )
            )

        normalized_source = source_text.strip()
        suggested_input = "normalized entrypoint"
        suggested_path = "<normalized-entrypoint>"

        if sourcemap_provenance and sourcemap_provenance.parse_status == "valid_json":
            add_hook(
                "tsmap-extract",
                "sourcemap_reconstruction",
                "Recovered sourcemap metadata is valid JSON and may restore higher-level source structure.",
                suggested_input,
                f"npx tsmap-extract {suggested_path}",
            )
            add_hook(
                "recover-source",
                "sourcemap_reconstruction",
                "Recovered sourcemap can be used to reconstruct source files with better provenance than plain bundle text.",
                suggested_input,
                f"npx recover-source {suggested_path}",
            )

        bundling_hints = (
            "require(" in normalized_source
            or "import " in normalized_source
            or "exports." in normalized_source
        )
        if bundling_hints:
            add_hook(
                "webcrack",
                "debundling",
                "Recovered JavaScript shows bundling/module-wrapper patterns that may be debundled into clearer modules.",
                suggested_input,
                f"npx webcrack {suggested_path} -o <debundled-output-dir>",
            )
            add_hook(
                "bundle-breaker",
                "debundling",
                "Recovered JavaScript contains bundle-style structure that may be split into a module tree by a dedicated debundler.",
                suggested_input,
                f"npx bundle-breaker {suggested_path} --out-dir <bundle-breaker-output-dir>",
            )

        minification_hints = (
            len(normalized_source) > 200
            and normalized_source.count("\n") <= 3
            or re.search(r"function\s+[A-Za-z]\(", normalized_source) is not None
        )
        if minification_hints or shims_applied or "bun_import_meta_require" in runtime_features:
            add_hook(
                "wakaru",
                "readability_normalization",
                "Recovered JavaScript may benefit from readability-oriented deobfuscation or normalization after Bun-specific shims.",
                suggested_input,
                f"npx wakaru {suggested_path} -o <wakaru-output>",
            )
            add_hook(
                "restringer",
                "deobfuscation",
                "Recovered JavaScript shows patterns where a general JavaScript deobfuscator may recover cleaner control flow or string structure.",
                suggested_input,
                f"npx restringer {suggested_path} > <restringer-output>",
            )

        return [
            {
                "tool": hook.tool,
                "category": hook.category,
                "reason": hook.reason,
                "suggested_input": hook.suggested_input,
                "command_template": hook.command_template,
            }
            for hook in hooks
        ]

    def _build_semantic_checks(
        self,
        dependency_analysis: BunDependencyAnalysis,
        runtime_features: List[str],
        shims_applied: List[str],
    ) -> List[Dict[str, str]]:
        checks: List[BunSemanticCheck] = []

        if dependency_analysis.required_packages:
            checks.append(
                BunSemanticCheck(
                    check="dependency_import_sanity",
                    severity="warning",
                    message="Dependency versions were not inferred; install and pin recovered packages manually",
                )
            )
        else:
            checks.append(
                BunSemanticCheck(
                    check="dependency_import_sanity",
                    severity="info",
                    message="No external package imports were inferred from direct import/require sites",
                )
            )

        if dependency_analysis.ignored_package_strings:
            checks.append(
                BunSemanticCheck(
                    check="embedded_package_strings",
                    severity="warning",
                    message="Dependency inference ignored embedded package-name strings that were not used by direct import/require sites",
                )
            )

        if dependency_analysis.builtin_modules:
            checks.append(
                BunSemanticCheck(
                    check="builtin_module_usage",
                    severity="warning",
                    message="Node built-in modules were detected and excluded from package installation guidance",
                )
            )

        if "await_usage" in runtime_features:
            checks.append(
                BunSemanticCheck(
                    check="esm_await_packaging",
                    severity="warning",
                    message="Recovered source uses await semantics that may require ESM-aware packaging",
                )
            )

        if shims_applied:
            checks.append(
                BunSemanticCheck(
                    check="bun_require_shim",
                    severity="info",
                    message="Bun-specific runtime constructs were rewritten during normalization",
                )
            )

        return [
            {
                "check": check.check,
                "severity": check.severity,
                "message": check.message,
            }
            for check in checks
        ]

    def _candidate_virtual_path_bytes(self, virtual_path: str) -> List[bytes]:
        normalized = virtual_path.replace("\\", "/")
        candidates = [normalized.encode("utf-8")]
        if normalized.startswith("B:/~BUN/"):
            candidates.append(normalized.replace("/", "\\").encode("utf-8"))
        return candidates

    def _find_json_object_end(self, data: bytes, start_offset: int) -> Optional[int]:
        depth = 0
        in_string = False
        escaped = False
        for index in range(start_offset, len(data)):
            byte = data[index]
            char = chr(byte)
            if in_string:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    in_string = False
                continue
            if char == '"':
                in_string = True
            elif char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return index + 1
        return None

    def _find_fallback_text_end(self, bundle_data: bytes, start_offset: int) -> int:
        consecutive_nontext = 0
        last_text_end = start_offset
        for index in range(start_offset, len(bundle_data)):
            byte = bundle_data[index]
            if byte in _TEXT_BYTES:
                consecutive_nontext = 0
                last_text_end = index + 1
                continue
            consecutive_nontext += 1
            if consecutive_nontext >= 8:
                return last_text_end
        return last_text_end

    def _decode_data_url_payload(self, data_url: str) -> Optional[bytes]:
        try:
            metadata, payload = data_url.split(",", 1)
        except ValueError:
            return None

        try:
            if ";base64" in metadata:
                return base64.b64decode(payload)
            return unquote_to_bytes(payload)
        except Exception:
            return None

    def _parse_offsets(self, bundle_data: bytes, trailer_offset: int) -> Optional[dict[str, int]]:
        if trailer_offset < self.OFFSETS_STRUCT.size:
            return None

        offsets_start = trailer_offset - self.OFFSETS_STRUCT.size
        (
            byte_count,
            modules_offset,
            modules_length,
            entry_point_id,
            compile_argv_offset,
            compile_argv_length,
            flags,
        ) = self.OFFSETS_STRUCT.unpack(bundle_data[offsets_start:trailer_offset])

        if byte_count <= 0 or byte_count > len(bundle_data):
            return None

        return {
            "byte_count": byte_count,
            "modules_offset": modules_offset,
            "modules_length": modules_length,
            "entry_point_id": entry_point_id,
            "compile_argv_offset": compile_argv_offset,
            "compile_argv_length": compile_argv_length,
            "flags": flags,
        }

    def _scan_virtual_paths(self, bundle_data: bytes) -> List[str]:
        discovered: List[str] = []
        seen = set()
        for pattern in self.VIRTUAL_PATH_PATTERNS:
            for match in pattern.finditer(bundle_data):
                candidate = match.group(0).decode("utf-8", errors="replace")
                candidate = candidate.replace("\\", "/")
                if candidate.endswith("/"):
                    continue
                if candidate not in seen:
                    seen.add(candidate)
                    discovered.append(candidate)
        return discovered

    def _looks_like_virtual_path(self, virtual_path: str) -> bool:
        normalized = virtual_path.replace("\\", "/")
        return normalized.startswith(("B:/~BUN/", "/$bunfs/"))
