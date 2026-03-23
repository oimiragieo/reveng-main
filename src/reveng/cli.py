#!/usr/bin/env python3
"""
REVENG Universal Reverse Engineering Platform - CLI Interface
============================================================

Command-line interface for the REVENG platform.

Author: REVENG Development Team
Version: 4.0.0
License: MIT
"""

import argparse
import json
import sys
from pathlib import Path

from .analyzer import EnhancedAnalysisFeatures, REVENGAnalyzer
from .version import get_version_string
from .translations import get_translator


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
    serve_parser.add_argument(
        "--reload", action="store_true", help=t["reload_help"]
    )

    # Ask command (Natural Language Interface)
    ask_parser = subparsers.add_parser(
        "ask",
        help=t["ask_help"],
        description=t["ask_desc"],
    )
    ask_parser.add_argument(
        "question", help=t["question_help"]
    )
    ask_parser.add_argument(
        "binary_path",
        nargs="?",
        help=t["binary_path_opt_help"],
    )
    ask_parser.add_argument(
        "--analysis-results", help=t["results_help"]
    )
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
    vt_lookup_parser.add_argument(
        "--api-key", help=t["api_key_help"]
    )

    # VirusTotal submit command
    vt_submit_parser = subparsers.add_parser(
        "vt-submit",
        help=t["vt_submit_help"],
        description=t["vt_submit_desc"],
    )
    vt_submit_parser.add_argument("binary_path", help=t["binary_path_help"])
    vt_submit_parser.add_argument(
        "--api-key", help=t["api_key_help"]
    )
    vt_submit_parser.add_argument(
        "--wait", action="store_true", help=t["wait_help"]
    )

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
    unpack_parser.add_argument(
        "--output", help=t["output_help"]
    )
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
    enhance_parser.add_argument(
        "--function-name", default="unknown", help=t["func_name_help"]
    )
    enhance_parser.add_argument(
        "--output", help=t["output_help"]
    )

    # Recompile command (Binary → Source → Binary pipeline)
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
        "--no-gemini",
        action="store_true",
        help=t["no_gemini_help"],
    )
    recompile_parser.add_argument(
        "--no-exploits",
        action="store_true",
        help=t["no_exploits_help"],
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

    # Generate exploit command
    generate_exploit_parser = subparsers.add_parser(
        "generate-exploit",
        help=t["exploit_help"],
        description=t["exploit_desc"],
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
    enhanced_group = parser.add_argument_group(
        t["enhanced_group"], t["enhanced_group_desc"]
    )
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
    enhanced_group.add_argument(
        "--no-vuln", action="store_true", help=t["no_vuln_help"]
    )
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
    enhanced_group.add_argument(
        "--no-demo", action="store_true", help=t["no_demo_help"]
    )

    # Configuration options
    config_group = parser.add_argument_group(
        t["config_group"], t["config_group_desc"]
    )
    config_group.add_argument("--config", help=t["config_help"])
    config_group.add_argument(
        "--no-ollama-check", action="store_true", help=t["no_ollama_help"]
    )
    config_group.add_argument(
        "--output-dir",
        help=t["out_dir_help"],
    )

    # Logging options
    logging_group = parser.add_argument_group(
        t["logging_group"], t["logging_group_desc"]
    )
    logging_group.add_argument("--verbose", "-V", action="store_true", help=t["verbose_help"])
    logging_group.add_argument(
        "--quiet", "-q", action="store_true", help=t["quiet_help"]
    )
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


def handle_analyze_command(args):
    """Handle the analyze command."""
    t = get_translator(getattr(args, "lang", "en"))

    # Create enhanced analysis features
    enhanced_features = create_enhanced_features(args)

    # Create and run REVENG analyzer
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

    # Run analysis
    analysis = analyzer.analyze_binary()

    if isinstance(analysis, dict) and analysis.get("status") == "success":
        print(f"\n{t['success']}")
        analysis_folder = analysis.get("analysis_folder")
        if analysis_folder:
            print(f"Results stored in: {analysis_folder}")
        if enhanced_features.is_any_enhanced_enabled():
            print(f"Enhanced modules executed: {analyzer._count_enabled_modules()}")
        return 0

    error_message = None
    if isinstance(analysis, dict):
        error_message = analysis.get("error") or analysis.get("message")

    print(f"\n{t['error']}")
    if error_message:
        print(f"Reason: {error_message}")
    return 1


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
        from ..ai.ai_assistant import ask_about_binary
        import asyncio

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
        from ..ai.ai_assistant import REVENGAIAssistant, AIAnalysisRequest
        import asyncio

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
        from ..tools.ai.ai_enhanced import InstantTriageEngine

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
        from ..tools.ai.ai_enhanced import AICodeQualityEnhancer

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
        from .recompile_command import run_recompile_command

        return run_recompile_command(
            binary_path=args.binary_path,
            output_dir=args.output_dir,
            ghidra_url=args.ghidra_url,
            use_gemini=not args.no_gemini,
        )
    except ImportError as e:
        print("Error: Recompilation engine not available")
        print(f"Details: {e}")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_decompile_command(args):
    """Handle the decompile command."""
    try:
        from ..integrations.ghidra.ghidra_engine import GhidraEngine

        print("=" * 70)
        print("  REVENG Binary Decompilation")
        print("=" * 70)
        print()

        # Validate binary exists
        if not Path(args.binary_path).exists():
            print(f"Error: Binary not found: {args.binary_path}")
            return 1

        # Initialize Ghidra
        print("Initializing Ghidra engine...")
        ghidra = GhidraEngine()

        # Perform decompilation
        print(f"Decompiling: {args.binary_path}")
        result = ghidra.decompile_binary(args.binary_path)

        # Determine output path
        output_path = args.output
        if not output_path:
            binary_name = Path(args.binary_path).stem
            ext = {"c": ".c", "python": ".py", "pseudo": ".txt"}[args.language]
            output_path = f"{binary_name}_decompiled{ext}"

        # Save decompiled code
        decompiled_code = result.get("decompiled_code", "")

        # Apply AI enhancement if requested
        if args.enhance and decompiled_code:
            print("Applying AI enhancement...")
            try:
                from ..tools.ai.ai_enhanced import AICodeQualityEnhancer

                enhancer = AICodeQualityEnhancer()
                enhanced = enhancer.enhance_function(
                    function_code=decompiled_code, function_name="main"
                )
                decompiled_code = enhanced.enhanced_code
                print("✓ AI enhancement applied")
            except Exception as e:
                print(f"Warning: AI enhancement failed: {e}")

        with open(output_path, "w") as f:
            f.write(decompiled_code)

        print(f"\n✓ Decompiled code saved to: {output_path}")
        print(f"  Functions: {len(result.get('functions', []))}")
        print(f"  Language: {args.language}")

        return 0

    except ImportError:
        print("Error: Ghidra integration not available")
        print("Please install Ghidra and start the server")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1


def handle_generate_exploit_command(args):
    """Handle the generate-exploit command."""
    try:
        print("=" * 70)
        print("  REVENG Exploit Generation")
        print("=" * 70)
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
            from .analyzer import REVENGAnalyzer

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
