#!/usr/bin/env python3
"""
REVENG Universal Reverse Engineering Platform - CLI Interface
============================================================

Command-line interface for the REVENG platform.

Author: REVENG Development Team
Version: 4.0.0
License: MIT
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ..analysis.analyzer import EnhancedAnalysisFeatures, REVENGAnalyzer
from ..translations import get_translator
from ..version import get_version_string


def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    # Pre-parse language if specified to adjust help messages
    lang = "en"
    for i, arg in enumerate(sys.argv):
        if arg == "--lang" and i + 1 < len(sys.argv):
            lang = sys.argv[i + 1]
            break

    t = get_translator(lang)

    parser = argparse.ArgumentParser(
        prog="reveng",
        description=t["description"],
        epilog=t["epilog"],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # Language option
    parser.add_argument(
        "--lang",
        choices=["en", "pt-br"],
        default="en",
        help=t["lang_help"],
    )

    # Version information
    parser.add_argument(
        "--version",
        "-v",
        action="version",
        version=get_version_string(),
        help=t["version_help"],
    )

    # Main command
    subparsers = parser.add_subparsers(dest="command", help=t["commands_help"], metavar="COMMAND")

    # Analyze command
    analyze_parser = subparsers.add_parser(
        "analyze",
        help=t["analyze_help"],
        description=t["analyze_desc"],
    )
    analyze_parser.add_argument(
        "binary_path",
        nargs="?",
        help=t["binary_path_help"],
    )
    analyze_parser.add_argument(
        "--ghidra-timeout",
        type=int,
        default=900,
        help="Ghidra analysis stage timeout in seconds (default: 900)",
    )
    analyze_parser.add_argument(
        "--ghidra-retries",
        type=int,
        default=0,
        help="Number of retries for the Ghidra analysis stage (default: 0)",
    )

    # App reverse-engineering command
    reverse_app_parser = subparsers.add_parser(
        "reverse-engineer-app",
        help="Reverse engineer an application bundle or source package",
        description="Generate a SPECS library and recovered artifacts for supported app inputs",
    )
    reverse_app_parser.add_argument(
        "input_path",
        help="Input application entrypoint, bundle, source file, or archive",
    )
    reverse_app_parser.add_argument(
        "--language",
        default="auto",
        choices=["auto", "javascript", "jvm", "python", "dotnet"],
        help="Language adapter to use; defaults to auto inference",
    )
    reverse_app_parser.add_argument(
        "--input-root",
        help="Root directory to inventory before analysis",
    )
    reverse_app_parser.add_argument(
        "--skip-pattern",
        action="append",
        default=[],
        help="Case-insensitive pattern to exclude from generated excerpts; repeat as needed",
    )
    reverse_app_parser.add_argument(
        "--max-snippets",
        type=int,
        default=12,
        help="Maximum excerpts to keep per topic",
    )
    reverse_app_parser.add_argument(
        "--snippet-context",
        type=int,
        default=2,
        help="Neighboring pseudo-lines to keep around a match",
    )
    reverse_app_parser.add_argument(
        "--run-deobfuscator",
        action="store_true",
        help="Attempt deeper deobfuscation when the selected adapter supports it",
    )

    # Serve command (web interface)
    serve_parser = subparsers.add_parser(
        "serve",
        help=t["serve_help"],
        description=t["serve_desc"],
    )
    serve_parser.add_argument(
        "--host",
        default="localhost",
        help=t["host_help"],
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=3000,
        help=t["port_help"],
    )
    serve_parser.add_argument("--reload", action="store_true", help=t["reload_help"])

    # Ask command (Natural Language Interface)
    ask_parser = subparsers.add_parser(
        "ask",
        help=t["ask_help"],
        description=t["ask_desc"],
    )
    ask_parser.add_argument("question", help=t["question_help"])
    ask_parser.add_argument(
        "binary_path",
        nargs="?",
        help=t["binary_path_opt_help"],
    )
    ask_parser.add_argument("--analysis-results", help=t["results_help"])
    ask_parser.add_argument(
        "--conversational",
        action="store_true",
        help=t["conversational_help"],
    )

    # AI Assistant command (New)
    ai_parser = subparsers.add_parser(
        "ai",
        help=t["ai_help"],
        description=t["ai_desc"],
    )
    ai_parser.add_argument("binary_path", help=t["binary_path_help"])
    ai_parser.add_argument(
        "--analysis-type",
        choices=["comprehensive", "security", "triage", "custom"],
        default="comprehensive",
        help=t["analysis_type_help"],
    )
    ai_parser.add_argument(
        "--goals",
        nargs="+",
        help=t["goals_help"],
    )
    ai_parser.add_argument(
        "--interactive",
        action="store_true",
        help=t["interactive_help"],
    )

    # Triage command (Instant Triage)
    triage_parser = subparsers.add_parser(
        "triage",
        help=t["triage_help"],
        description=t["triage_desc"],
    )
    triage_parser.add_argument("binary_path", help=t["binary_path_help"])
    triage_parser.add_argument("--bulk", nargs="+", help=t["bulk_help"])
    triage_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help=t["format_help"],
    )

    # VirusTotal lookup command
    vt_lookup_parser = subparsers.add_parser(
        "vt-lookup",
        help=t["vt_lookup_help"],
        description=t["vt_lookup_desc"],
    )
    vt_lookup_parser.add_argument("binary_path", help=t["binary_path_help"])
    vt_lookup_parser.add_argument("--api-key", help=t["api_key_help"])

    # VirusTotal submit command
    vt_submit_parser = subparsers.add_parser(
        "vt-submit",
        help=t["vt_submit_help"],
        description=t["vt_submit_desc"],
    )
    vt_submit_parser.add_argument("binary_path", help=t["binary_path_help"])
    vt_submit_parser.add_argument("--api-key", help=t["api_key_help"])
    vt_submit_parser.add_argument("--wait", action="store_true", help=t["wait_help"])

    # YARA rule generation command
    yara_gen_parser = subparsers.add_parser(
        "generate-yara",
        help=t["yara_gen_help"],
        description=t["yara_gen_desc"],
    )
    yara_gen_parser.add_argument("binary_path", help=t["binary_path_help"])
    yara_gen_parser.add_argument("--rule-name", help=t["rule_name_help"])
    yara_gen_parser.add_argument("--output", help=t["output_help"])
    yara_gen_parser.add_argument(
        "--analysis-results",
        help=t["results_help"],
    )

    # YARA scanning command
    yara_scan_parser = subparsers.add_parser(
        "scan-yara",
        help=t["yara_scan_help"],
        description=t["yara_scan_desc"],
    )
    yara_scan_parser.add_argument("binary_path", help=t["binary_path_help"])
    yara_scan_parser.add_argument("--rules-dir", help=t["rules_dir_help"])
    yara_scan_parser.add_argument("--rule-file", help=t["rule_file_help"])

    # Binary diffing command
    diff_parser = subparsers.add_parser(
        "diff",
        help=t["diff_help"],
        description=t["diff_desc"],
    )
    diff_parser.add_argument("binary_v1", help=t["binary_path_help"])
    diff_parser.add_argument("binary_v2", help=t["binary_path_help"])
    diff_parser.add_argument(
        "--deep",
        action="store_true",
        help=t["deep_help"],
    )
    diff_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help=t["format_help"],
    )

    # Patch analysis command
    patch_parser = subparsers.add_parser(
        "patch-analysis",
        help=t["patch_help"],
        description=t["patch_desc"],
    )
    patch_parser.add_argument("unpatched_binary", help=t["binary_path_help"])
    patch_parser.add_argument("patched_binary", help=t["binary_path_help"])
    patch_parser.add_argument("--cve", help=t["cve_help"])
    patch_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="markdown",
        help=t["format_help"],
    )

    # Packer detection command
    detect_packer_parser = subparsers.add_parser(
        "detect-packer",
        help=t["packer_help"],
        description=t["packer_desc"],
    )
    detect_packer_parser.add_argument("binary_path", help=t["binary_path_help"])
    detect_packer_parser.add_argument(
        "--format",
        choices=["text", "json", "markdown"],
        default="text",
        help=t["format_help"],
    )

    # Unpacking command
    unpack_parser = subparsers.add_parser(
        "unpack",
        help=t["unpack_help"],
        description=t["unpack_desc"],
    )
    unpack_parser.add_argument("binary_path", help=t["binary_path_help"])
    unpack_parser.add_argument("--output", help=t["output_help"])
    unpack_parser.add_argument(
        "--method",
        choices=["auto", "specialized", "generic"],
        default="auto",
        help=t["method_help"],
    )

    # Code enhancement command
    enhance_parser = subparsers.add_parser(
        "enhance-code",
        help=t["enhance_help"],
        description=t["enhance_desc"],
    )
    enhance_parser.add_argument("code_file", help=t["binary_path_help"])
    enhance_parser.add_argument("--function-name", default="unknown", help=t["func_name_help"])
    enhance_parser.add_argument("--output", help=t["output_help"])

    # Recompile command (Binary -> Source -> Binary pipeline)
    recompile_parser = subparsers.add_parser(
        "recompile",
        help=t["recompile_help"],
        description=t["recompile_desc"],
    )
    recompile_parser.add_argument("binary_path", help=t["binary_path_help"])
    recompile_parser.add_argument(
        "--output-dir",
        help=t["out_dir_help"],
    )
    recompile_parser.add_argument(
        "--ghidra-url",
        default="http://127.0.0.1:13370",
        help=t["ghidra_url_help"],
    )
    recompile_parser.add_argument(
        "--ghidra-timeout",
        type=int,
        default=900,
        help="Ghidra request timeout in seconds for recompilation (default: 900)",
    )
    recompile_parser.add_argument(
        "--no-gemini",
        action="store_true",
        help=t["no_gemini_help"],
    )
    recompile_parser.add_argument(
        "--no-exploits",
        action="store_true",
        help=t["no_exploits_help"],
    )

    build_bun_sea_parser = subparsers.add_parser(
        "build-bun-sea",
        help="Build a Bun executable via Node SEA",
        description="Recover, normalize, and package a Bun executable into a Windows executable using Node SEA",
    )
    build_bun_sea_parser.add_argument("binary_path", help="Path to Bun executable")
    build_bun_sea_parser.add_argument(
        "--output-dir",
        help="Output directory for recovered and normalized Bun artifacts (default: analysis_<binary_name>)",
    )
    build_bun_sea_parser.add_argument(
        "--output",
        help="Output path for the generated SEA executable (default: <output-dir>\\normalized_project\\bun-sea.exe)",
    )
    build_bun_sea_parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Skip npm dependency installation before building the SEA executable",
    )

    # Decompile command
    decompile_parser = subparsers.add_parser(
        "decompile",
        help=t["decompile_help"],
        description=t["decompile_desc"],
    )
    decompile_parser.add_argument("binary_path", help=t["binary_path_help"])
    decompile_parser.add_argument(
        "--output",
        help=t["output_help"],
    )
    decompile_parser.add_argument(
        "--language",
        choices=["c", "python", "pseudo"],
        default="c",
        help=t["lang_out_help"],
    )
    decompile_parser.add_argument(
        "--enhance",
        action="store_true",
        help=t["enhance_opt_help"],
    )
    decompile_parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Ghidra request timeout in seconds (default: 120)",
    )

    # Generate exploit command
    generate_exploit_parser = subparsers.add_parser(
        "generate-exploit",
        help="[EXPERIMENTAL/non-GA] " + t["exploit_help"],
        description="EXPERIMENTAL (non-GA). " + t["exploit_desc"],
    )
    generate_exploit_parser.add_argument("binary_path", help=t["binary_path_help"])
    generate_exploit_parser.add_argument(
        "--vulnerability",
        help=t["vuln_help"],
    )
    generate_exploit_parser.add_argument(
        "--output",
        help=t["output_help"],
    )
    generate_exploit_parser.add_argument(
        "--language",
        choices=["python", "c", "shellcode"],
        default="python",
        help=t["lang_out_help"],
    )
    generate_exploit_parser.add_argument(
        "--analysis-results",
        help=t["results_help"],
    )

    # Enhanced analysis options
    enhanced_group = parser.add_argument_group(t["enhanced_group"], t["enhanced_group_desc"])
    enhanced_group.add_argument(
        "--no-enhanced",
        action="store_true",
        help=t["no_enhanced_help"],
    )
    enhanced_group.add_argument(
        "--no-corporate",
        action="store_true",
        help=t["no_corporate_help"],
    )
    enhanced_group.add_argument("--no-vuln", action="store_true", help=t["no_vuln_help"])
    enhanced_group.add_argument(
        "--no-threat",
        action="store_true",
        help=t["no_threat_help"],
    )
    enhanced_group.add_argument(
        "--no-reconstruction",
        action="store_true",
        help=t["no_recon_help"],
    )
    enhanced_group.add_argument("--no-demo", action="store_true", help=t["no_demo_help"])

    # Configuration options
    config_group = parser.add_argument_group(t["config_group"], t["config_group_desc"])
    config_group.add_argument("--config", help=t["config_help"])
    config_group.add_argument("--no-ollama-check", action="store_true", help=t["no_ollama_help"])
    config_group.add_argument(
        "--output-dir",
        help=t["out_dir_help"],
    )

    # Logging options
    logging_group = parser.add_argument_group(t["logging_group"], t["logging_group_desc"])
    logging_group.add_argument("--verbose", "-V", action="store_true", help=t["verbose_help"])
    logging_group.add_argument("--quiet", "-q", action="store_true", help=t["quiet_help"])
    logging_group.add_argument("--log-file", help=t["log_file_help"])

    return parser


def create_enhanced_features(args) -> EnhancedAnalysisFeatures:
    """Create enhanced analysis features from command line arguments."""
    features = EnhancedAnalysisFeatures()

    # Apply command line overrides
    if args.no_enhanced:
        features.enable_enhanced_analysis = False
    if args.no_corporate:
        features.enable_corporate_exposure = False
    if args.no_vuln:
        features.enable_vulnerability_discovery = False
    if args.no_threat:
        features.enable_threat_intelligence = False
    if args.no_reconstruction:
        features.enable_enhanced_reconstruction = False
    if args.no_demo:
        features.enable_demonstration_generation = False

    # Load configuration file if provided
    if args.config and Path(args.config).exists():
        try:
            with open(args.config, "r", encoding="utf-8") as f:
                config_data = json.load(f)
            features.from_config(config_data.get("enhanced_analysis", {}))
            print(f"Loaded configuration from {args.config}")
        except Exception as e:
            print(f"Warning: Error loading configuration file: {e}")

    return features


def _detect_bun_executable(binary_path: str):
    """Return a Bun extractor and detection info for the given binary."""
    from ..tools.anti_analysis.bun_extractor import BunExecutableExtractor

    extractor = BunExecutableExtractor()
    return extractor, extractor.detect(binary_path)


def _maybe_handle_bun_analysis(binary_path: str, output_dir: str) -> int | None:
    """Route Bun executables to bundle extraction instead of native analysis."""
    from ..tools.anti_analysis.bun_extractor import (
        build_bun_report_severity_summary,
        build_bun_runtime_escalation_summary,
    )

    extractor, info = _detect_bun_executable(binary_path)
    if not info.is_bun_executable:
        return None

    output_root = Path(output_dir)
    output_root.mkdir(parents=True, exist_ok=True)
    binary_name = Path(binary_path).stem
    bundle_output = output_root / f"{binary_name}_bundle.js"
    bunfs_dir = output_root / f"{binary_name}_bunfs"
    report_path = output_root / "bun_analysis.json"

    extraction = extractor.extract_javascript(binary_path, str(bundle_output))
    if not extraction.success:
        print("Error: Bun executable detected, but JavaScript extraction failed")
        if extraction.error_message:
            print(f"Reason: {extraction.error_message}")
        return 1

    recovery = extractor.recover_virtual_files(binary_path, str(bunfs_dir))
    canonical_input, canonical_reason = _select_bun_recompilation_input(
        extraction.output_path, recovery
    )
    normalization = _normalize_bun_workspace(extractor, canonical_input, output_root)
    native_stub = extractor.analyze_pe_stub(binary_path)
    report_severity = build_bun_report_severity_summary(
        native_stub=native_stub,
        normalization=normalization,
    )
    runtime_escalation = build_bun_runtime_escalation_summary(
        native_stub=native_stub,
        report_severity=report_severity,
    )
    summary = {
        "route": "bun",
        "binary_path": binary_path,
        "bundle_output": extraction.output_path,
        "bundle_hash": extraction.extracted_hash,
        "javascript_size": extraction.javascript_size,
        "canonical_recompilation_input": canonical_input,
        "canonical_recompilation_reason": canonical_reason,
        "report_severity": report_severity,
        "runtime_escalation": runtime_escalation,
        "bundle_info": {
            "section_name": info.section_name,
            "bundle_size": info.bundle_size,
            "javascript_start_offset": info.javascript_start_offset,
            "indicators": info.indicators,
        },
        "bunfs_recovery": {
            "success": recovery.success,
            "mode": recovery.recovery_mode,
            "module_layout": recovery.graph.module_layout if recovery.graph else None,
            "output_dir": recovery.output_dir,
            "manifest_path": recovery.manifest_path,
            "recovered_files": recovery.recovered_files,
            "error_message": recovery.error_message,
        },
        "normalized_project": (
            {
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
                "semantic_checks": normalization.semantic_checks,
                "postprocessing_hooks": normalization.postprocessing_hooks,
                "warnings": normalization.warnings,
                "error_message": normalization.error_message,
            }
            if normalization
            else None
        ),
        "native_stub": (
            {
                "container": native_stub.container,
                "machine": native_stub.machine,
                "entry_point_rva": native_stub.entry_point_rva,
                "image_base": native_stub.image_base,
                "entry_point_section": native_stub.entry_point_section,
                "entry_point_preview": [
                    {
                        "address": instruction.address,
                        "mnemonic": instruction.mnemonic,
                        "op_str": instruction.op_str,
                        "target_address": instruction.target_address,
                        "target_rva": instruction.target_rva,
                        "target_section": instruction.target_section,
                        "import_target": instruction.import_target,
                        "rip_relative_address": instruction.rip_relative_address,
                        "rip_relative_section": instruction.rip_relative_section,
                    }
                    for instruction in native_stub.entry_point_preview
                ],
                "section_names": native_stub.section_names,
                "tls_directory_rva": native_stub.tls_directory_rva,
                "tls_callback_vas": native_stub.tls_callback_vas,
                "tls_callbacks": [
                    {
                        "virtual_address": callback.virtual_address,
                        "rva": callback.rva,
                        "section_name": callback.section_name,
                        "file_offset": callback.file_offset,
                        "instruction_preview": [
                            {
                                "address": instruction.address,
                                "mnemonic": instruction.mnemonic,
                                "op_str": instruction.op_str,
                                "target_address": instruction.target_address,
                                "target_rva": instruction.target_rva,
                                "target_section": instruction.target_section,
                                "import_target": instruction.import_target,
                                "rip_relative_address": instruction.rip_relative_address,
                                "rip_relative_section": instruction.rip_relative_section,
                            }
                            for instruction in callback.instruction_preview
                        ],
                    }
                    for callback in native_stub.tls_callbacks
                ],
                "import_dlls": native_stub.import_dlls,
                "imported_functions": native_stub.imported_functions,
                "suspicious_imports": native_stub.suspicious_imports,
                "startup_classification": native_stub.startup_classification,
                "startup_reasons": native_stub.startup_reasons,
                "runtime_readiness": {
                    "breakpoints": [
                        {
                            "label": point.label,
                            "kind": point.kind,
                            "address": point.address,
                            "section": point.section,
                            "reason": point.reason,
                        }
                        for point in native_stub.runtime_readiness.breakpoints
                    ],
                    "dump_points": [
                        {
                            "label": point.label,
                            "kind": point.kind,
                            "address": point.address,
                            "section": point.section,
                            "reason": point.reason,
                        }
                        for point in native_stub.runtime_readiness.dump_points
                    ],
                    "notes": native_stub.runtime_readiness.notes,
                },
                "dump_guidance": {
                    "recommended": native_stub.dump_guidance.recommended,
                    "actions": [
                        {
                            "kind": action.kind,
                            "summary": action.summary,
                            "trigger": action.trigger,
                        }
                        for action in native_stub.dump_guidance.actions
                    ],
                },
                "cross_references": [
                    {
                        "kind": reference.kind,
                        "value": reference.value,
                        "section": reference.section,
                        "file_offset": reference.file_offset,
                        "source": reference.source,
                    }
                    for reference in native_stub.cross_references
                ],
                "handoff_signals": [
                    {
                        "kind": signal.kind,
                        "source": signal.source,
                        "message": signal.message,
                        "confidence": signal.confidence,
                    }
                    for signal in native_stub.handoff_signals
                ],
                "startup_targets": [
                    {
                        "source": target.source,
                        "instruction_address": target.instruction_address,
                        "instruction_mnemonic": target.instruction_mnemonic,
                        "target_address": target.target_address,
                        "target_rva": target.target_rva,
                        "target_section": target.target_section,
                        "symbolic_label": target.symbolic_label,
                        "target_resolution": target.target_resolution,
                        "import_target": target.import_target,
                        "target_preview": [
                            {
                                "address": instruction.address,
                                "mnemonic": instruction.mnemonic,
                                "op_str": instruction.op_str,
                                "target_address": instruction.target_address,
                                "target_rva": instruction.target_rva,
                                "target_section": instruction.target_section,
                                "import_target": instruction.import_target,
                                "rip_relative_address": instruction.rip_relative_address,
                                "rip_relative_section": instruction.rip_relative_section,
                            }
                            for instruction in target.target_preview
                        ],
                    }
                    for target in native_stub.startup_targets
                ],
                "startup_graph": {
                    "roots": native_stub.startup_graph.roots,
                    "nodes": [
                        {
                            "label": node.label,
                            "node_type": node.node_type,
                            "address": node.address,
                            "rva": node.rva,
                            "section": node.section,
                            "source": node.source,
                            "target_resolution": node.target_resolution,
                            "import_target": node.import_target,
                        }
                        for node in native_stub.startup_graph.nodes
                    ],
                    "edges": [
                        {
                            "source_label": edge.source_label,
                            "target_label": edge.target_label,
                            "instruction_mnemonic": edge.instruction_mnemonic,
                            "instruction_address": edge.instruction_address,
                            "depth": edge.depth,
                            "target_resolution": edge.target_resolution,
                            "import_target": edge.import_target,
                        }
                        for edge in native_stub.startup_graph.edges
                    ],
                    "truncated": native_stub.startup_graph.truncated,
                },
                "indicators": native_stub.indicators,
            }
            if native_stub
            else None
        ),
    }
    report_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")

    print("Detected Bun executable; routing analyze to Bun bundle extraction.")
    print(f"Bundled JavaScript: {extraction.output_path}")
    if recovery.success:
        print(f"Bun virtual filesystem: {recovery.output_dir}")
        print(f"Bun recovery mode: {recovery.recovery_mode}")
    elif recovery.error_message:
        print(f"Warning: Bun recovery incomplete: {recovery.error_message}")
    if canonical_input:
        print(f"Preferred recompilation input: {canonical_input}")
        print(f"Reason: {canonical_reason}")
    if normalization and normalization.success:
        print(f"Normalized project workspace: {normalization.output_dir}")
        print(f"Normalized entrypoint: {normalization.entrypoint_path}")
        print(f"Normalized SEA entrypoint: {normalization.sea_entrypoint_path}")
    print(f"Bun analysis report: {report_path}")
    return 0


def _default_bun_decompile_output(binary_path: str) -> str:
    return f"{Path(binary_path).stem}_bundle.js"


def _select_bun_recompilation_input(bundle_output: str | None, recovery) -> tuple[str | None, str]:
    """Choose the cleanest recovered Bun artifact for downstream recompilation."""
    from ..tools.anti_analysis.bun_extractor import select_bun_recompilation_input

    return select_bun_recompilation_input(bundle_output, recovery)


def _normalize_bun_workspace(extractor, canonical_input: str | None, output_root: Path):
    """Create a normalized Node-compatible workspace from the preferred Bun source artifact."""
    if not canonical_input:
        return None

    normalized_dir = output_root / "normalized_project"
    return extractor.normalize_project(canonical_input, str(normalized_dir))


def _run_bun_sea_build(
    binary_path: str, output_dir: str | None, output_path: str | None, skip_install: bool
):
    """Shared Bun SEA build workflow used by dedicated and delegated CLI paths."""
    from ..tools.anti_analysis.bun_extractor import run_bun_sea_workflow

    workflow = run_bun_sea_workflow(
        binary_path=binary_path,
        output_dir=output_dir,
        output_path=output_path,
        skip_install=skip_install,
    )
    return {
        "status": workflow.status,
        "message": workflow.message,
        "reason": workflow.reason,
        "canonical_input": workflow.canonical_input,
        "canonical_reason": workflow.canonical_reason,
        "normalization": workflow.normalization,
        "build_result": workflow.build_result,
        "differential_validation": workflow.differential_validation,
        "report_path": workflow.report_path,
    }


def _maybe_handle_bun_decompile(args) -> int | None:
    """Route Bun executables to JS extraction instead of native decompilation."""
    extractor, info = _detect_bun_executable(args.binary_path)
    if not info.is_bun_executable:
        return None

    output_path = args.output or _default_bun_decompile_output(args.binary_path)
    print("Detected Bun executable; routing decompile to Bun bundle extraction.")
    extraction = extractor.extract_javascript(args.binary_path, output_path)
    if not extraction.success or not extraction.output_path:
        print("Error: Bun executable detected, but JavaScript extraction failed")
        if extraction.error_message:
            print(f"Reason: {extraction.error_message}")
        return 1

    decompiled_code = Path(extraction.output_path).read_text(encoding="utf-8", errors="replace")
    if args.enhance and decompiled_code:
        print("Applying AI enhancement...")
        try:
            from ..agents.ai.ai_enhanced import AICodeQualityEnhancer

            enhancer = AICodeQualityEnhancer()
            enhanced = enhancer.enhance_function(
                function_code=decompiled_code, function_name=Path(args.binary_path).stem
            )
            decompiled_code = enhanced.enhanced_code
            Path(extraction.output_path).write_text(decompiled_code, encoding="utf-8")
            print("✓ AI enhancement applied")
        except Exception as e:
            print(f"Warning: AI enhancement failed: {e}")

    bunfs_dir = Path(extraction.output_path).parent / f"{Path(extraction.output_path).stem}_bunfs"
    recovery = extractor.recover_virtual_files(args.binary_path, str(bunfs_dir))
    canonical_input, canonical_reason = _select_bun_recompilation_input(
        extraction.output_path, recovery
    )
    normalization = _normalize_bun_workspace(
        extractor, canonical_input, Path(extraction.output_path).parent
    )

    print(f"\n✓ Decompiled code saved to: {extraction.output_path}")
    print("  Route: bun")
    print("  Language: javascript")
    if recovery.success:
        print(f"  Bun virtual filesystem: {recovery.output_dir}")
        print(f"  Bun recovery mode: {recovery.recovery_mode}")
    if canonical_input:
        print(f"  Preferred recompilation input: {canonical_input}")
        print(f"  Reason: {canonical_reason}")
    if normalization and normalization.success:
        print(f"  Normalized project workspace: {normalization.output_dir}")
        print(f"  Normalized entrypoint: {normalization.entrypoint_path}")
        print(f"  Normalized SEA entrypoint: {normalization.sea_entrypoint_path}")

    return 0


def run_end_to_end_analysis(
    *,
    binary_path: str,
    output_dir: str,
    enhanced_features: EnhancedAnalysisFeatures,
    ghidra_timeout_seconds: int,
    ghidra_retry_count: int,
) -> dict:
    """Run the integrated async CLI analysis lifecycle."""
    from ..pipeline.e2e_integration import EndToEndPipelineRunner

    runner = EndToEndPipelineRunner(
        output_dir=output_dir,
        use_gemini=enhanced_features.enable_enhanced_analysis,
        enable_recompilation=enhanced_features.enable_enhanced_reconstruction,
        enable_forensics=enhanced_features.enable_threat_intelligence,
        ghidra_timeout_seconds=ghidra_timeout_seconds,
        ghidra_retry_count=ghidra_retry_count,
    )
    return runner.run(binary_path)


def handle_analyze_command(args):
    """Handle the analyze command."""
    t = get_translator(getattr(args, "lang", "en"))

    # Create enhanced analysis features
    enhanced_features = create_enhanced_features(args)

    # Create analyzer for path resolution, validation, and consistent output-folder handling.
    analyzer = REVENGAnalyzer(
        binary_path=args.binary_path,
        check_ollama=not args.no_ollama_check,
        enhanced_features=enhanced_features,
        analysis_folder=args.output_dir,
    )

    # Check if binary exists
    if not Path(analyzer.binary_path).exists():
        print(f"{t['bin_not_found']}: {analyzer.binary_path}")
        print(f"\n{t['usage']}: reveng analyze [binary_path] [options]")
        print("Or place a binary file in the current directory")
        print(f"\n{t['enhanced_group']}:")
        print(f"  --no-enhanced        {t['no_enhanced_help']}")
        print(f"  --no-corporate       {t['no_corporate_help']}")
        print(f"  --no-vuln           {t['no_vuln_help']}")
        print(f"  --no-threat         {t['no_threat_help']}")
        print(f"  --no-reconstruction {t['no_recon_help']}")
        print(f"  --no-demo           {t['no_demo_help']}")
        print(f"  --config FILE       {t['config_help']}")
        return 1

    bun_result = _maybe_handle_bun_analysis(
        binary_path=analyzer.binary_path,
        output_dir=str(analyzer.analysis_folder),
    )
    if bun_result is not None:
        return bun_result

    try:
        print("Running end-to-end pipeline...")
        print(f"Ghidra stage timeout: {args.ghidra_timeout}s (retries: {args.ghidra_retries})")
        analysis = run_end_to_end_analysis(
            binary_path=analyzer.binary_path,
            output_dir=str(analyzer.analysis_folder),
            enhanced_features=enhanced_features,
            ghidra_timeout_seconds=max(60, int(args.ghidra_timeout)),
            ghidra_retry_count=max(0, int(args.ghidra_retries)),
        )
    except Exception as exc:
        print(f"\n{t['error']}")
        print(f"Reason: {exc}")
        return 1

    status = analysis.get("status", "failed")
    report_path = analysis.get("report_path")
    summary = analysis.get("summary", {})

    if status in {"success", "partial_success"}:
        print(f"\n{t['success']}")
        print(f"Pipeline status: {status}")
        print(f"Results stored in: {analysis.get('output_dir', analyzer.analysis_folder)}")
        if report_path:
            print(f"Unified report: {report_path}")

        behavioral_score = summary.get("behavioral_anomaly_score")
        memory_score = summary.get("memory_anomaly_score")
        if behavioral_score is not None:
            print(f"Behavioral anomaly score: {behavioral_score}")
        if memory_score is not None:
            print(f"Memory anomaly score: {memory_score}")

        return 0

    print(f"\n{t['error']}")
    if report_path:
        print(f"Partial report: {report_path}")
    print(f"Pipeline status: {status}")
    return 1


def handle_reverse_engineer_app_command(args):
    """Handle the language-agnostic app reverse-engineering command."""
    import asyncio

    from ..app_reverse_engineering import create_default_framework

    input_path = Path(args.input_path).expanduser().resolve()
    if not input_path.exists():
        print(f"Error: Input not found: {input_path}")
        print("\nUsage: reveng reverse-engineer-app [input_path] [options]")
        return 1

    output_dir = args.output_dir
    if not output_dir:
        output_dir = f"analysis_{input_path.stem}"

    framework = create_default_framework()
    try:
        result = asyncio.run(
            framework.reverse_engineer(
                str(input_path),
                output_dir,
                language=args.language,
                input_root=args.input_root,
                skip_patterns=args.skip_pattern,
                max_snippets=args.max_snippets,
                snippet_context=args.snippet_context,
                run_deobfuscator=args.run_deobfuscator,
            )
        )
    except Exception as exc:
        print("\n[ERROR] App reverse engineering failed!")
        print(f"Reason: {exc}")
        return 1

    print("\n[SUCCESS] App reverse engineering completed successfully!")
    print(f"Language: {result.language}")
    print(f"Adapter: {result.adapter_name}")
    print(f"Specs root: {result.specs_dir}")
    print(f"Analysis summary: {result.analysis_file}")
    print(f"Recovered source files: {result.source_count}")
    print(f"Validation: {result.validation_grade}")
    if result.validation_summary:
        print(f"Validation summary: {result.validation_summary}")
    print(f"Evidence items: {len(result.evidence)}")
    if result.primary_artifacts:
        print("Primary artifacts:")
        for name, artifact in result.primary_artifacts.items():
            print(f"  - {name}: {artifact}")
    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")
    return 0


def handle_serve_command(args):
    """Handle the serve command (web interface)."""
    try:
        # Import web interface components
        from ..web_interface.server import start_server

        print("Starting REVENG Web Interface...")
        print(f"Server will be available at: http://{args.host}:{args.port}")
        print("Press Ctrl+C to stop the server")

        # Start the web server
        start_server(host=args.host, port=args.port, reload=args.reload)

    except ImportError as e:
        print(f"Error: Web interface not available: {e}")
        print("Please ensure the web interface dependencies are installed:")
        print("  pip install -e .[web]")
        return 1
    except Exception as e:
        print(f"Error starting web interface: {e}")
        return 1

    return 0


def handle_ask_command(args):
    """Handle the ask command (Natural Language Interface)."""
    try:
        import asyncio

        from ..ai.ai_assistant import ask_about_binary

        # Run async function
        answer = asyncio.run(ask_about_binary(args.question, args.binary_path))

        print("\n" + "=" * 60)
        print(f"Question: {args.question}")
        print("=" * 60)
        print(answer)
        print("=" * 60 + "\n")

        # Handle conversational mode
        if args.conversational:
            print("Conversational mode enabled. Ask follow-up questions (type 'quit' to exit):")
            while True:
                try:
                    follow_up = input("\nFollow-up question: ").strip()
                    if follow_up.lower() in ["quit", "exit", "q"]:
                        break
                    if follow_up:
                        answer = asyncio.run(ask_about_binary(follow_up, args.binary_path))
                        print(f"\nAnswer: {answer}")
                except KeyboardInterrupt:
                    print("\nExiting conversational mode...")
                    break

        return 0

    except ImportError as e:
        print(f"Error: AI Assistant not available: {e}")
        print("Install dependencies: pip install ollama")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_ai_command(args):
    """Handle the ai command (AI Assistant)."""
    try:
        import asyncio

        from ..ai.ai_assistant import AIAnalysisRequest, REVENGAIAssistant

        # Create AI assistant
        assistant = REVENGAIAssistant()

        # Create analysis request
        from ..ai.analysis_models import AnalysisType

        analysis_type = (
            AnalysisType(args.analysis_type)
            if hasattr(AnalysisType, args.analysis_type.upper())
            else AnalysisType.COMPREHENSIVE
        )

        request = AIAnalysisRequest(
            binary_path=args.binary_path,
            analysis_type=analysis_type,
            goals=args.goals
            or ["understand_functionality", "find_vulnerabilities", "assess_threats"],
        )

        print("\n🤖 REVENG AI Assistant")
        print(f"📁 Analyzing: {args.binary_path}")
        print(f"🔍 Analysis Type: {args.analysis_type}")
        print(f"🎯 Goals: {', '.join(request.goals)}")
        print("=" * 60)

        # Run analysis
        result = asyncio.run(assistant.analyze_binary_ai(request))

        # Display results
        print("\n📊 Analysis Results:")
        print("-" * 40)
        print(f"Binary: {result.binary_info.name}")
        print(f"Size: {result.binary_info.size} bytes")
        print(f"Type: {result.binary_info.file_type}")
        print(f"Architecture: {result.binary_info.architecture or 'Unknown'}")
        print(f"Functions: {len(result.functions)}")
        print(f"Vulnerabilities: {len(result.vulnerabilities)}")
        print(f"Threat Indicators: {len(result.threat_indicators)}")
        print(f"Analysis Time: {result.metadata.duration:.2f} seconds")
        print(f"Overall Confidence: {result.metadata.confidence_overall:.2f}")

        # Display natural language summary
        print("\n🤖 AI Summary:")
        print("-" * 40)
        print(result.natural_language_summary)

        # Display recommendations
        if result.recommendations:
            print("\n💡 Recommendations:")
            print("-" * 40)
            for i, rec in enumerate(result.recommendations, 1):
                print(f"{i}. {rec.title}")
                print(f"   Priority: {rec.priority}")
                print(f"   Description: {rec.description}")
                if rec.implementation:
                    print(f"   Implementation: {rec.implementation}")
                print()

        # Interactive mode
        if args.interactive:
            print("\n💬 Interactive Mode (type 'quit' to exit):")
            while True:
                try:
                    question = input("\nAsk a question: ").strip()
                    if question.lower() in ["quit", "exit", "q"]:
                        break
                    if question:
                        answer = asyncio.run(
                            assistant.ask_question(question, args.binary_path, result)
                        )
                        print(f"\n🤖 {answer}")
                except KeyboardInterrupt:
                    print("\nExiting interactive mode...")
                    break

        return 0

    except ImportError as e:
        print(f"Error: AI Assistant not available: {e}")
        print("Install dependencies: pip install ollama")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_triage_command(args):
    """Handle the triage command (Instant Triage)."""
    try:
        from ..agents.ai.ai_enhanced import InstantTriageEngine

        engine = InstantTriageEngine()

        # Bulk triage
        if args.bulk:
            results = engine.batch_triage(args.bulk)

            for result in results:
                if args.format == "json":
                    print(json.dumps(result.__dict__, indent=2))
                else:
                    report = engine.generate_report(result, format=args.format)
                    print(report)
                    print("\n" + "=" * 60 + "\n")
        else:
            # Single triage
            result = engine.triage(args.binary_path)

            if args.format == "json":
                print(json.dumps(result.__dict__, indent=2, default=str))
            else:
                report = engine.generate_report(result, format=args.format)
                print(report)

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_vt_lookup_command(args):
    """Handle the vt-lookup command."""
    try:
        import os

        from ..tools.threat_intel import VirusTotalConnector

        api_key = args.api_key or os.getenv("VT_API_KEY")
        if not api_key:
            print("Error: VirusTotal API key required")
            print("Set VT_API_KEY environment variable or use --api-key")
            return 1

        vt = VirusTotalConnector(api_key=api_key)

        # Check if input is hash or file
        if len(args.binary_path) == 64 and all(
            c in "0123456789abcdef" for c in args.binary_path.lower()
        ):
            # It's a hash
            result = vt.lookup_hash(args.binary_path)
        else:
            # It's a file path
            import hashlib

            with open(args.binary_path, "rb") as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            result = vt.lookup_hash(sha256)

        if result:
            report = vt.generate_report(result, format="markdown")
            print(report)
        else:
            print("No results found on VirusTotal")

        return 0

    except ImportError:
        print("Error: VirusTotal connector not available")
        print("Install dependencies: pip install vt-py")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_vt_submit_command(args):
    """Handle the vt-submit command."""
    try:
        import os

        from ..tools.threat_intel import VirusTotalConnector

        api_key = args.api_key or os.getenv("VT_API_KEY")
        if not api_key:
            print("Error: VirusTotal API key required")
            print("Set VT_API_KEY environment variable or use --api-key")
            return 1

        vt = VirusTotalConnector(api_key=api_key)

        print(f"Submitting {args.binary_path} to VirusTotal...")
        analysis_id = vt.submit_file(args.binary_path, wait_for_analysis=args.wait)

        print("Submission successful!")
        print(f"Analysis ID: {analysis_id}")

        if not args.wait:
            print("\nCheck results later with:")
            print(f"  reveng vt-lookup {args.binary_path}")

        return 0

    except ImportError:
        print("Error: VirusTotal connector not available")
        print("Install dependencies: pip install vt-py")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_generate_yara_command(args):
    """Handle the generate-yara command."""
    try:
        from ..tools.threat_intel import YARAGenerator

        # Load analysis results if provided
        analysis_results = None
        if args.analysis_results:
            with open(args.analysis_results, "r") as f:
                analysis_results = json.load(f)

        generator = YARAGenerator()
        rule = generator.generate_rule(
            file_path=args.binary_path,
            analysis_results=analysis_results,
            rule_name=args.rule_name,
        )

        # Save or print
        if args.output:
            with open(args.output, "w") as f:
                f.write(rule.yara_rule)
            print(f"YARA rule saved to: {args.output}")
        else:
            print(rule.yara_rule)

        return 0

    except ImportError:
        print("Error: YARA generator not available")
        print("Install dependencies: pip install yara-python")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_scan_yara_command(args):
    """Handle the scan-yara command."""
    try:
        from ..tools.threat_intel import YARAScanner

        scanner = YARAScanner(rules_dir=args.rules_dir, rule_file=args.rule_file)

        matches = scanner.scan_file(args.binary_path)

        if matches:
            print(f"Found {len(matches)} YARA rule matches:\n")
            for match in matches:
                print(f"Rule: {match.rule_name}")
                print(f"  Tags: {', '.join(match.tags)}")
                print(f"  Strings matched: {len(match.strings_matched)}")
                if match.metadata:
                    print(f"  Metadata: {match.metadata}")
                print()
        else:
            print("No YARA rule matches found")

        return 0

    except ImportError:
        print("Error: YARA scanner not available")
        print("Install dependencies: pip install yara-python")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_diff_command(args):
    """Handle the diff command."""
    try:
        from ..tools.diffing import BinaryDiffer

        differ = BinaryDiffer()
        result = differ.diff(
            binary_v1_path=args.binary_v1,
            binary_v2_path=args.binary_v2,
            deep_analysis=args.deep,
        )

        if args.format == "json":
            # Convert to JSON-serializable format
            output = {
                "similarity_score": result.similarity_score,
                "unchanged_count": len(result.unchanged_functions),
                "modified_count": len(result.modified_functions),
                "new_count": len(result.new_functions),
                "deleted_count": len(result.deleted_functions),
                "modified_functions": [
                    {
                        "name": m.name_v1,
                        "similarity": m.similarity_score,
                        "size_v1": m.size_v1,
                        "size_v2": m.size_v2,
                    }
                    for m in result.modified_functions
                ],
            }
            print(json.dumps(output, indent=2))
        else:
            report = differ.generate_report(result, format=args.format)
            print(report)

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_patch_analysis_command(args):
    """Handle the patch-analysis command."""
    try:
        from ..tools.diffing import PatchAnalyzer

        analyzer = PatchAnalyzer()
        vulnerabilities = analyzer.analyze_patch(
            unpatched_binary=args.unpatched_binary,
            patched_binary=args.patched_binary,
            cve=args.cve,
        )

        if args.format == "json":
            output = [v.__dict__ for v in vulnerabilities]
            print(json.dumps(output, indent=2))
        else:
            report = analyzer.generate_report(vulnerabilities, format=args.format, cve=args.cve)
            print(report)

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_detect_packer_command(args):
    """Handle the detect-packer command."""
    try:
        from ..tools.anti_analysis import PackerDetector

        detector = PackerDetector()
        info = detector.detect(args.binary_path)

        if args.format == "json":
            print(json.dumps(info.__dict__, indent=2))
        elif args.format == "markdown":
            print("# Packer Detection Report\n")
            print(f"**Packed:** {info.packed}\n")
            if info.packer_name:
                print(f"**Packer:** {info.packer_name}\n")
            print(f"**Confidence:** {info.confidence:.1%}\n")
            print(f"**Entropy:** {info.entropy:.2f}\n")
            if info.indicators:
                print("\n## Indicators\n")
                for indicator in info.indicators:
                    print(f"- {indicator}")
        else:  # text
            print(f"Packed: {info.packed}")
            if info.packer_name:
                print(f"Packer: {info.packer_name}")
            print(f"Confidence: {info.confidence:.1%}")
            print(f"Entropy: {info.entropy:.2f}")
            if info.indicators:
                print("\nIndicators:")
                for indicator in info.indicators:
                    print(f"  - {indicator}")

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_unpack_command(args):
    """Handle the unpack command."""
    try:
        from ..tools.anti_analysis import UniversalUnpacker

        unpacker = UniversalUnpacker()
        result = unpacker.unpack(
            packed_binary=args.binary_path, output_path=args.output, method=args.method
        )

        report = unpacker.generate_report(result, format="markdown")
        print(report)

        if result.success:
            print(f"\nUnpacked binary saved to: {result.unpacked_path}")
            return 0
        else:
            return 1

    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_enhance_code_command(args):
    """Handle the enhance-code command."""
    try:
        from ..agents.ai.ai_enhanced import AICodeQualityEnhancer

        # Read code file
        with open(args.code_file, "r") as f:
            code = f.read()

        enhancer = AICodeQualityEnhancer()
        result = enhancer.enhance_function(function_code=code, function_name=args.function_name)

        # Determine output path
        output_path = args.output
        if not output_path:
            code_path = Path(args.code_file)
            output_path = code_path.parent / f"{code_path.stem}_enhanced{code_path.suffix}"

        # Save enhanced code
        with open(output_path, "w") as f:
            f.write(f"// Original function: {args.function_name}\n")
            f.write(f"// Suggested name: {result.suggested_function_name}\n")
            f.write(f"// Improvements: {', '.join(result.improvements)}\n\n")
            f.write(result.enhanced_code)

        print(f"Enhanced code saved to: {output_path}")
        print("\nImprovements applied:")
        for improvement in result.improvements:
            print(f"  - {improvement}")

        return 0

    except ImportError:
        print("Error: AI code enhancer not available")
        print("Install dependencies: pip install ollama")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_recompile_command(args):
    """Handle the recompile command."""
    try:
        extractor, info = _detect_bun_executable(args.binary_path)
        if info.is_bun_executable:
            print("Detected Bun executable; routing recompile to Node SEA build.")
            result = _run_bun_sea_build(
                binary_path=args.binary_path,
                output_dir=args.output_dir,
                output_path=None,
                skip_install=False,
            )
            if result["status"] != "success":
                print(f"Error: {result.get('message', 'Bun SEA build failed')}")
                if result.get("reason"):
                    print(f"Reason: {result['reason']}")
                if result.get("report_path"):
                    print(f"Build report: {result['report_path']}")
                return 1

            normalization = result["normalization"]
            build_result = result["build_result"]
            print(f"Preferred recompilation input: {result['canonical_input']}")
            print(f"Normalized project workspace: {normalization.output_dir}")
            print(f"SEA executable: {build_result.output_path}")
            print(f"Build report: {result['report_path']}")
            return 0

        from ..recompile_command import run_recompile_command

        return run_recompile_command(
            binary_path=args.binary_path,
            output_dir=args.output_dir,
            ghidra_url=args.ghidra_url,
            ghidra_timeout=max(60, int(args.ghidra_timeout)),
            use_gemini=not args.no_gemini,
        )
    except ImportError as e:
        print("Error: Recompilation engine not available")
        print(f"Details: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_build_bun_sea_command(args):
    """Handle packaging a recovered Bun executable with Node SEA."""
    try:
        if not Path(args.binary_path).exists():
            print(f"Error: Binary not found: {args.binary_path}")
            return 1

        result = _run_bun_sea_build(
            binary_path=args.binary_path,
            output_dir=args.output_dir,
            output_path=args.output,
            skip_install=args.skip_install,
        )

        if result["status"] == "not_bun":
            print(f"Error: {result['message']}")
            return 1

        if result["status"] != "success":
            print(f"Error: {result.get('message', 'Node SEA build failed')}")
            if result.get("reason"):
                print(f"Reason: {result['reason']}")
            if result.get("report_path"):
                print(f"Build report: {result['report_path']}")
            return 1

        normalization = result["normalization"]
        build_result = result["build_result"]

        print("Built Bun executable with Node SEA.")
        print(f"Preferred recompilation input: {result['canonical_input']}")
        print(f"Normalized project workspace: {normalization.output_dir}")
        print(f"SEA executable: {build_result.output_path}")
        print(f"Build report: {result['report_path']}")
        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1


def _flatten_decompiled_output(result: dict) -> str:
    """Convert structured decompiler output into a text blob for file export."""
    decompiled_code = result.get("decompiled_code", "")
    if isinstance(decompiled_code, dict):
        ordered_chunks = [
            str(chunk).strip() for chunk in decompiled_code.values() if str(chunk).strip()
        ]
        if ordered_chunks:
            return "\n\n".join(ordered_chunks)
    if isinstance(decompiled_code, str) and decompiled_code.strip():
        return decompiled_code

    function_chunks = []
    for function in result.get("functions", []):
        if not isinstance(function, dict):
            continue
        source = str(function.get("source") or function.get("decompiled") or "").strip()
        if source:
            function_chunks.append(source)
    return "\n\n".join(function_chunks)


def handle_decompile_command(args):
    """Handle the decompile command."""
    try:
        from ..integrations.ghidra.ghidra_engine import GhidraConnectionError, GhidraEngine

        print("=" * 70)
        print("  REVENG Binary Decompilation")
        print("=" * 70)
        print()

        # Validate binary exists
        if not Path(args.binary_path).exists():
            print(f"Error: Binary not found: {args.binary_path}")
            return 1

        bun_result = _maybe_handle_bun_decompile(args)
        if bun_result is not None:
            return bun_result

        # Initialize Ghidra
        print("Initializing Ghidra engine...")
        ghidra = GhidraEngine(timeout=max(30, int(args.timeout)))

        # Perform decompilation
        print(f"Decompiling: {args.binary_path}")
        result = ghidra.decompile(args.binary_path)

        # Determine output path
        output_path = args.output
        if not output_path:
            binary_name = Path(args.binary_path).stem
            ext = {"c": ".c", "python": ".py", "pseudo": ".txt"}[args.language]
            output_path = f"{binary_name}_decompiled{ext}"

        # Save decompiled code
        decompiled_code = _flatten_decompiled_output(result)
        if not decompiled_code.strip():
            print("Error: Ghidra did not return any decompiled code")
            return 1

        # Apply AI enhancement if requested
        if args.enhance and decompiled_code:
            print("Applying AI enhancement...")
            try:
                from ..agents.ai.ai_enhanced import AICodeQualityEnhancer

                enhancer = AICodeQualityEnhancer()
                enhanced = enhancer.enhance_function(
                    function_code=decompiled_code, function_name="main"
                )
                decompiled_code = enhanced.enhanced_code
                print("✓ AI enhancement applied")
            except Exception as e:
                print(f"Warning: AI enhancement failed: {e}")

        Path(output_path).write_text(decompiled_code, encoding="utf-8")

        print(f"\n✓ Decompiled code saved to: {output_path}")
        print(f"  Functions: {len(result.get('functions', []))}")
        print(f"  Language: {args.language}")

        return 0

    except ImportError:
        print("Error: Ghidra integration not available")
        print("Please install Ghidra and start the server")
        return 1
    except GhidraConnectionError as e:
        print(f"Error: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_generate_exploit_command(args):
    """Handle the generate-exploit command."""
    try:
        print("=" * 70)
        print("  REVENG Exploit Generation — EXPERIMENTAL (non-GA)")
        print("=" * 70)
        print()
        print(
            "WARNING: Exploit generation is experimental and not part of the "
            "supported GA surface. See docs/support_matrix.json "
            "(workflow: exploit_generation, status: experimental)."
        )
        print()

        # Validate binary exists
        if not Path(args.binary_path).exists():
            print(f"Error: Binary not found: {args.binary_path}")
            return 1

        # Check for existing analysis results
        if args.analysis_results:
            print(f"Loading analysis results from: {args.analysis_results}")
            with open(args.analysis_results, "r") as f:
                analysis = json.load(f)
        else:
            print("Running vulnerability analysis...")
            # Run analysis first
            from ..analysis.analyzer import REVENGAnalyzer

            analyzer = REVENGAnalyzer()
            analysis = analyzer.analyze(args.binary_path)

        # Find vulnerabilities
        vulns = analysis.get("vulnerabilities", [])
        if not vulns:
            print("No vulnerabilities found in binary")
            print("Try running: reveng analyze --enhanced " + args.binary_path)
            return 1

        print(f"Found {len(vulns)} vulnerabilities")

        # Select vulnerability to exploit
        target_vuln = None
        if args.vulnerability:
            # Find specific vulnerability
            for v in vulns:
                if v.get("type") == args.vulnerability:
                    target_vuln = v
                    break
            if not target_vuln:
                print(f"Error: Vulnerability '{args.vulnerability}' not found")
                print("Available vulnerabilities:")
                for v in vulns:
                    print(f"  - {v.get('type')}")
                return 1
        else:
            # Use first critical/high severity vulnerability
            for v in vulns:
                if v.get("severity") in ["critical", "high"]:
                    target_vuln = v
                    break
            if not target_vuln:
                target_vuln = vulns[0]

        print(f"\nTargeting vulnerability: {target_vuln.get('type')}")
        print(f"  Severity: {target_vuln.get('severity')}")
        print(f"  CWE: {target_vuln.get('cwe')}")

        # Generate exploit
        print("\nGenerating exploit...")
        from ..exploits.exploit_chain_generator import ExploitChainGenerator

        generator = ExploitChainGenerator()
        exploit = generator.generate_exploit(
            vulnerability=target_vuln,
            binary_path=args.binary_path,
            language=args.language,
        )

        # Determine output path
        output_path = args.output
        if not output_path:
            vuln_type = target_vuln.get("type", "unknown")
            ext = {"python": ".py", "c": ".c", "shellcode": ".bin"}[args.language]
            output_path = f"exploit_{vuln_type}{ext}"

        # Save exploit
        with open(output_path, "w") as f:
            f.write(f"# Exploit for {target_vuln.get('type')}\n")
            f.write(f"# CWE: {target_vuln.get('cwe')}\n")
            f.write(f"# Severity: {target_vuln.get('severity')}\n\n")
            f.write(exploit.get("exploit_code", ""))

        print(f"\n✓ Exploit saved to: {output_path}")
        print(f"  Language: {args.language}")
        print(f"  Type: {target_vuln.get('type')}")

        if exploit.get("steps"):
            print("\nExploit steps:")
            for i, step in enumerate(exploit["steps"], 1):
                print(f"  {i}. {step}")

        print("\n⚠️  Use responsibly: Only in authorized testing environments")

        return 0

    except ImportError as e:
        print("Error: Exploit generation module not available")
        print(f"Details: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
        return 1


def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle no command provided
    if not args.command:
        parser.print_help()
        return 1

    # Route to appropriate handler
    handlers = {
        "analyze": handle_analyze_command,
        "reverse-engineer-app": handle_reverse_engineer_app_command,
        "serve": handle_serve_command,
        "ask": handle_ask_command,
        "ai": handle_ai_command,
        "triage": handle_triage_command,
        "vt-lookup": handle_vt_lookup_command,
        "vt-submit": handle_vt_submit_command,
        "generate-yara": handle_generate_yara_command,
        "scan-yara": handle_scan_yara_command,
        "diff": handle_diff_command,
        "patch-analysis": handle_patch_analysis_command,
        "detect-packer": handle_detect_packer_command,
        "unpack": handle_unpack_command,
        "enhance-code": handle_enhance_code_command,
        "recompile": handle_recompile_command,
        "build-bun-sea": handle_build_bun_sea_command,
        "decompile": handle_decompile_command,
        "generate-exploit": handle_generate_exploit_command,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args)
    else:
        print(f"Error: Unknown command '{args.command}'")
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
