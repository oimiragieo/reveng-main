#!/usr/bin/env python3
"""
REVENG Universal Reverse Engineering Platform - CLI Interface
============================================================

Command-line interface for the REVENG platform.

Author: REVENG Development Team
Version: 2.1.0
License: MIT
"""

import sys
import argparse
import json
from pathlib import Path
from typing import Optional

from .analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures
from .version import get_version, get_version_string

def create_parser() -> argparse.ArgumentParser:
    """Create the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog='reveng',
        description='REVENG - Universal Reverse Engineering Platform',
        epilog='For more information, visit: https://github.com/oimiragieo/reveng-main',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True
    )

    # Version information
    parser.add_argument(
        '--version', '-v',
        action='version',
        version=get_version_string(),
        help='Show version information and exit'
    )

    # Main command
    subparsers = parser.add_subparsers(
        dest='command',
        help='Available commands',
        metavar='COMMAND'
    )

    # Analyze command
    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Analyze a binary file',
        description='Run comprehensive binary analysis on the specified file'
    )
    analyze_parser.add_argument(
        'binary_path',
        nargs='?',
        help='Path to binary file (auto-detected if not provided)'
    )

    # Serve command (web interface)
    serve_parser = subparsers.add_parser(
        'serve',
        help='Start web interface server',
        description='Launch the REVENG web interface for interactive analysis'
    )
    serve_parser.add_argument(
        '--host',
        default='localhost',
        help='Host to bind the server to (default: localhost)'
    )
    serve_parser.add_argument(
        '--port',
        type=int,
        default=3000,
        help='Port to bind the server to (default: 3000)'
    )
    serve_parser.add_argument(
        '--reload',
        action='store_true',
        help='Enable auto-reload for development'
    )

    # Ask command (Natural Language Interface)
    ask_parser = subparsers.add_parser(
        'ask',
        help='Ask natural language questions about a binary',
        description='Use AI to answer questions about binary behavior and functionality'
    )
    ask_parser.add_argument(
        'question',
        help='Natural language question (e.g., "What does this binary do?")'
    )
    ask_parser.add_argument(
        'binary_path',
        nargs='?',
        help='Path to binary file (optional if analysis results provided)'
    )
    ask_parser.add_argument(
        '--analysis-results',
        help='Path to previous analysis results JSON file'
    )

    # Triage command (Instant Triage)
    triage_parser = subparsers.add_parser(
        'triage',
        help='Rapid threat assessment (<30 seconds)',
        description='Perform instant triage analysis for incident response'
    )
    triage_parser.add_argument(
        'binary_path',
        help='Path to binary file'
    )
    triage_parser.add_argument(
        '--bulk',
        nargs='+',
        help='Triage multiple files in batch'
    )
    triage_parser.add_argument(
        '--format',
        choices=['text', 'json', 'markdown'],
        default='text',
        help='Output format (default: text)'
    )

    # VirusTotal lookup command
    vt_lookup_parser = subparsers.add_parser(
        'vt-lookup',
        help='Lookup file hash on VirusTotal',
        description='Enrich analysis with VirusTotal threat intelligence'
    )
    vt_lookup_parser.add_argument(
        'binary_path',
        help='Path to binary file or SHA256 hash'
    )
    vt_lookup_parser.add_argument(
        '--api-key',
        help='VirusTotal API key (or set VT_API_KEY environment variable)'
    )

    # VirusTotal submit command
    vt_submit_parser = subparsers.add_parser(
        'vt-submit',
        help='Submit file to VirusTotal for analysis',
        description='Upload binary to VirusTotal and wait for results'
    )
    vt_submit_parser.add_argument(
        'binary_path',
        help='Path to binary file'
    )
    vt_submit_parser.add_argument(
        '--api-key',
        help='VirusTotal API key (or set VT_API_KEY environment variable)'
    )
    vt_submit_parser.add_argument(
        '--wait',
        action='store_true',
        help='Wait for analysis to complete'
    )

    # YARA rule generation command
    yara_gen_parser = subparsers.add_parser(
        'generate-yara',
        help='Generate YARA rule from binary',
        description='Create YARA detection rule based on binary characteristics'
    )
    yara_gen_parser.add_argument(
        'binary_path',
        help='Path to binary file'
    )
    yara_gen_parser.add_argument(
        '--rule-name',
        help='Custom name for YARA rule'
    )
    yara_gen_parser.add_argument(
        '--output',
        help='Path to save YARA rule file'
    )
    yara_gen_parser.add_argument(
        '--analysis-results',
        help='Path to previous analysis results for better rule generation'
    )

    # YARA scanning command
    yara_scan_parser = subparsers.add_parser(
        'scan-yara',
        help='Scan binary with YARA rules',
        description='Scan binary using YARA rules for threat detection'
    )
    yara_scan_parser.add_argument(
        'binary_path',
        help='Path to binary file'
    )
    yara_scan_parser.add_argument(
        '--rules-dir',
        help='Directory containing YARA rules'
    )
    yara_scan_parser.add_argument(
        '--rule-file',
        help='Single YARA rule file to scan with'
    )

    # Binary diffing command
    diff_parser = subparsers.add_parser(
        'diff',
        help='Compare two binary versions',
        description='Identify differences between two binary files at function level'
    )
    diff_parser.add_argument(
        'binary_v1',
        help='Path to first binary (older version)'
    )
    diff_parser.add_argument(
        'binary_v2',
        help='Path to second binary (newer version)'
    )
    diff_parser.add_argument(
        '--deep',
        action='store_true',
        help='Enable deep analysis for detailed comparison'
    )
    diff_parser.add_argument(
        '--format',
        choices=['text', 'json', 'markdown'],
        default='text',
        help='Output format (default: text)'
    )

    # Patch analysis command
    patch_parser = subparsers.add_parser(
        'patch-analysis',
        help='Analyze security patches',
        description='Identify vulnerabilities fixed in a security patch'
    )
    patch_parser.add_argument(
        'unpatched_binary',
        help='Path to unpatched binary'
    )
    patch_parser.add_argument(
        'patched_binary',
        help='Path to patched binary'
    )
    patch_parser.add_argument(
        '--cve',
        help='CVE identifier for the patch (optional)'
    )
    patch_parser.add_argument(
        '--format',
        choices=['text', 'json', 'markdown'],
        default='markdown',
        help='Output format (default: markdown)'
    )

    # Packer detection command
    detect_packer_parser = subparsers.add_parser(
        'detect-packer',
        help='Detect if binary is packed',
        description='Identify packer/obfuscator used on binary'
    )
    detect_packer_parser.add_argument(
        'binary_path',
        help='Path to binary file'
    )
    detect_packer_parser.add_argument(
        '--format',
        choices=['text', 'json', 'markdown'],
        default='text',
        help='Output format (default: text)'
    )

    # Unpacking command
    unpack_parser = subparsers.add_parser(
        'unpack',
        help='Unpack packed binary',
        description='Attempt to unpack/decompress packed binary'
    )
    unpack_parser.add_argument(
        'binary_path',
        help='Path to packed binary'
    )
    unpack_parser.add_argument(
        '--output',
        help='Path for unpacked binary (default: auto-generated)'
    )
    unpack_parser.add_argument(
        '--method',
        choices=['auto', 'specialized', 'generic'],
        default='auto',
        help='Unpacking method (default: auto)'
    )

    # Code enhancement command
    enhance_parser = subparsers.add_parser(
        'enhance-code',
        help='Improve decompiled code quality with AI',
        description='Transform raw decompiled code into readable, documented code'
    )
    enhance_parser.add_argument(
        'code_file',
        help='Path to decompiled code file'
    )
    enhance_parser.add_argument(
        '--function-name',
        default='unknown',
        help='Name of the function being enhanced'
    )
    enhance_parser.add_argument(
        '--output',
        help='Path to save enhanced code (default: <file>_enhanced.c)'
    )

    # Enhanced analysis options
    enhanced_group = parser.add_argument_group(
        'Enhanced Analysis Options',
        'Control AI-enhanced analysis modules'
    )
    enhanced_group.add_argument(
        '--no-enhanced',
        action='store_true',
        help='Disable all enhanced analysis modules'
    )
    enhanced_group.add_argument(
        '--no-corporate',
        action='store_true',
        help='Disable corporate exposure analysis'
    )
    enhanced_group.add_argument(
        '--no-vuln',
        action='store_true',
        help='Disable vulnerability discovery'
    )
    enhanced_group.add_argument(
        '--no-threat',
        action='store_true',
        help='Disable threat intelligence correlation'
    )
    enhanced_group.add_argument(
        '--no-reconstruction',
        action='store_true',
        help='Disable enhanced binary reconstruction'
    )
    enhanced_group.add_argument(
        '--no-demo',
        action='store_true',
        help='Disable demonstration generation'
    )

    # Configuration options
    config_group = parser.add_argument_group(
        'Configuration Options',
        'Control analysis configuration'
    )
    config_group.add_argument(
        '--config',
        help='Path to enhanced analysis configuration file'
    )
    config_group.add_argument(
        '--no-ollama-check',
        action='store_true',
        help='Skip Ollama availability check'
    )
    config_group.add_argument(
        '--output-dir',
        help='Directory to save analysis results (default: analysis_<binary_name>)'
    )

    # Logging options
    logging_group = parser.add_argument_group(
        'Logging Options',
        'Control logging and output verbosity'
    )
    logging_group.add_argument(
        '--verbose', '-V',
        action='store_true',
        help='Enable verbose output'
    )
    logging_group.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Suppress non-essential output'
    )
    logging_group.add_argument(
        '--log-file',
        help='Path to log file (default: reveng_analyzer.log)'
    )

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
            with open(args.config, 'r', encoding='utf-8') as f:
                config_data = json.load(f)
            features.from_config(config_data.get('enhanced_analysis', {}))
            print(f"Loaded configuration from {args.config}")
        except Exception as e:
            print(f"Warning: Error loading configuration file: {e}")

    return features

def handle_analyze_command(args):
    """Handle the analyze command."""
    # Create enhanced analysis features
    enhanced_features = create_enhanced_features(args)

    # Create and run REVENG analyzer
    analyzer = REVENGAnalyzer(
        binary_path=args.binary_path,
        check_ollama=not args.no_ollama_check,
        enhanced_features=enhanced_features
    )

    # Check if binary exists
    if not Path(analyzer.binary_path).exists():
        print(f"Error: Binary not found: {analyzer.binary_path}")
        print("\nUsage: reveng analyze [binary_path] [options]")
        print("Or place a binary file in the current directory")
        print("\nEnhanced Analysis Options:")
        print("  --no-enhanced        Disable all enhanced analysis modules")
        print("  --no-corporate       Disable corporate exposure analysis")
        print("  --no-vuln           Disable vulnerability discovery")
        print("  --no-threat         Disable threat intelligence correlation")
        print("  --no-reconstruction Disable enhanced binary reconstruction")
        print("  --no-demo           Disable demonstration generation")
        print("  --config FILE       Load configuration from JSON file")
        return 1

    # Run analysis
    success = analyzer.analyze_binary()

    if success:
        print("\n[SUCCESS] REVENG analysis completed successfully!")
        if enhanced_features.is_any_enhanced_enabled():
            print(f"Enhanced modules executed: {analyzer._count_enabled_modules()}")
        return 0
    else:
        print("\n[ERROR] REVENG analysis failed!")
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
        start_server(
            host=args.host,
            port=args.port,
            reload=args.reload
        )

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
        from ..tools.tools.ai_enhanced import NaturalLanguageInterface

        # Load analysis results if provided
        analysis_results = None
        if args.analysis_results:
            with open(args.analysis_results, 'r') as f:
                analysis_results = json.load(f)

        # Create NL interface
        nl = NaturalLanguageInterface()

        # Query
        answer = nl.query(
            question=args.question,
            binary_path=args.binary_path,
            analysis_results=analysis_results
        )

        print("\n" + "="*60)
        print(f"Question: {args.question}")
        print("="*60)
        print(answer)
        print("="*60 + "\n")

        return 0

    except ImportError as e:
        print(f"Error: Natural Language Interface not available: {e}")
        print("Install dependencies: pip install ollama")
        return 1
    except Exception as e:
        print(f"Error: {e}")
        return 1

def handle_triage_command(args):
    """Handle the triage command (Instant Triage)."""
    try:
        from ..tools.tools.ai_enhanced import InstantTriageEngine

        engine = InstantTriageEngine()

        # Bulk triage
        if args.bulk:
            results = engine.batch_triage(args.bulk)

            for result in results:
                if args.format == 'json':
                    print(json.dumps(result.__dict__, indent=2))
                else:
                    report = engine.generate_report(result, format=args.format)
                    print(report)
                    print("\n" + "="*60 + "\n")
        else:
            # Single triage
            result = engine.triage(args.binary_path)

            if args.format == 'json':
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
        from ..tools.tools.threat_intel import VirusTotalConnector
        import os

        api_key = args.api_key or os.getenv('VT_API_KEY')
        if not api_key:
            print("Error: VirusTotal API key required")
            print("Set VT_API_KEY environment variable or use --api-key")
            return 1

        vt = VirusTotalConnector(api_key=api_key)

        # Check if input is hash or file
        if len(args.binary_path) == 64 and all(c in '0123456789abcdef' for c in args.binary_path.lower()):
            # It's a hash
            result = vt.lookup_hash(args.binary_path)
        else:
            # It's a file path
            import hashlib
            with open(args.binary_path, 'rb') as f:
                sha256 = hashlib.sha256(f.read()).hexdigest()
            result = vt.lookup_hash(sha256)

        if result:
            report = vt.generate_report(result, format='markdown')
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
        from ..tools.tools.threat_intel import VirusTotalConnector
        import os

        api_key = args.api_key or os.getenv('VT_API_KEY')
        if not api_key:
            print("Error: VirusTotal API key required")
            print("Set VT_API_KEY environment variable or use --api-key")
            return 1

        vt = VirusTotalConnector(api_key=api_key)

        print(f"Submitting {args.binary_path} to VirusTotal...")
        analysis_id = vt.submit_file(args.binary_path, wait_for_analysis=args.wait)

        print(f"Submission successful!")
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
        from ..tools.tools.threat_intel import YARAGenerator

        # Load analysis results if provided
        analysis_results = None
        if args.analysis_results:
            with open(args.analysis_results, 'r') as f:
                analysis_results = json.load(f)

        generator = YARAGenerator()
        rule = generator.generate_rule(
            file_path=args.binary_path,
            analysis_results=analysis_results,
            rule_name=args.rule_name
        )

        # Save or print
        if args.output:
            with open(args.output, 'w') as f:
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
        from ..tools.tools.threat_intel import YARAScanner

        scanner = YARAScanner(
            rules_dir=args.rules_dir,
            rule_file=args.rule_file
        )

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
        from ..tools.tools.diffing import BinaryDiffer

        differ = BinaryDiffer()
        result = differ.diff(
            binary_v1_path=args.binary_v1,
            binary_v2_path=args.binary_v2,
            deep_analysis=args.deep
        )

        if args.format == 'json':
            # Convert to JSON-serializable format
            output = {
                'similarity_score': result.similarity_score,
                'unchanged_count': len(result.unchanged_functions),
                'modified_count': len(result.modified_functions),
                'new_count': len(result.new_functions),
                'deleted_count': len(result.deleted_functions),
                'modified_functions': [
                    {
                        'name': m.name_v1,
                        'similarity': m.similarity_score,
                        'size_v1': m.size_v1,
                        'size_v2': m.size_v2
                    }
                    for m in result.modified_functions
                ]
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
        from ..tools.tools.diffing import PatchAnalyzer

        analyzer = PatchAnalyzer()
        vulnerabilities = analyzer.analyze_patch(
            unpatched_binary=args.unpatched_binary,
            patched_binary=args.patched_binary,
            cve=args.cve
        )

        if args.format == 'json':
            output = [v.__dict__ for v in vulnerabilities]
            print(json.dumps(output, indent=2))
        else:
            report = analyzer.generate_report(
                vulnerabilities,
                format=args.format,
                cve=args.cve
            )
            print(report)

        return 0

    except Exception as e:
        print(f"Error: {e}")
        return 1

def handle_detect_packer_command(args):
    """Handle the detect-packer command."""
    try:
        from ..tools.tools.anti_analysis import PackerDetector

        detector = PackerDetector()
        info = detector.detect(args.binary_path)

        if args.format == 'json':
            print(json.dumps(info.__dict__, indent=2))
        elif args.format == 'markdown':
            print(f"# Packer Detection Report\n")
            print(f"**Packed:** {info.packed}\n")
            if info.packer_name:
                print(f"**Packer:** {info.packer_name}\n")
            print(f"**Confidence:** {info.confidence:.1%}\n")
            print(f"**Entropy:** {info.entropy:.2f}\n")
            if info.indicators:
                print(f"\n## Indicators\n")
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
        from ..tools.tools.anti_analysis import UniversalUnpacker

        unpacker = UniversalUnpacker()
        result = unpacker.unpack(
            packed_binary=args.binary_path,
            output_path=args.output,
            method=args.method
        )

        report = unpacker.generate_report(result, format='markdown')
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
        from ..tools.tools.ai_enhanced import AICodeQualityEnhancer

        # Read code file
        with open(args.code_file, 'r') as f:
            code = f.read()

        enhancer = AICodeQualityEnhancer()
        result = enhancer.enhance_function(
            function_code=code,
            function_name=args.function_name
        )

        # Determine output path
        output_path = args.output
        if not output_path:
            code_path = Path(args.code_file)
            output_path = code_path.parent / f"{code_path.stem}_enhanced{code_path.suffix}"

        # Save enhanced code
        with open(output_path, 'w') as f:
            f.write(f"// Original function: {args.function_name}\n")
            f.write(f"// Suggested name: {result.suggested_function_name}\n")
            f.write(f"// Improvements: {', '.join(result.improvements)}\n\n")
            f.write(result.enhanced_code)

        print(f"Enhanced code saved to: {output_path}")
        print(f"\nImprovements applied:")
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
        'analyze': handle_analyze_command,
        'serve': handle_serve_command,
        'ask': handle_ask_command,
        'triage': handle_triage_command,
        'vt-lookup': handle_vt_lookup_command,
        'vt-submit': handle_vt_submit_command,
        'generate-yara': handle_generate_yara_command,
        'scan-yara': handle_scan_yara_command,
        'diff': handle_diff_command,
        'patch-analysis': handle_patch_analysis_command,
        'detect-packer': handle_detect_packer_command,
        'unpack': handle_unpack_command,
        'enhance-code': handle_enhance_code_command,
    }

    handler = handlers.get(args.command)
    if handler:
        return handler(args)
    else:
        print(f"Error: Unknown command '{args.command}'")
        parser.print_help()
        return 1

if __name__ == '__main__':
    sys.exit(main())
