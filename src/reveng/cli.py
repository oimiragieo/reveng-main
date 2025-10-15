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

def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    # Handle no command provided
    if not args.command:
        parser.print_help()
        return 1

    # Route to appropriate handler
    if args.command == 'analyze':
        return handle_analyze_command(args)
    elif args.command == 'serve':
        return handle_serve_command(args)
    else:
        print(f"Error: Unknown command '{args.command}'")
        parser.print_help()
        return 1

if __name__ == '__main__':
    sys.exit(main())
