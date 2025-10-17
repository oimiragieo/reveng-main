#!/usr/bin/env python3
"""
REVENG Universal Reverse Engineering Platform - Unified CLI

Modern command-line interface for REVENG with advanced features including:
- Binary analysis with multiple formats
- Hex editor integration
- PE resource extraction
- Ghidra automation
- Malware analysis workflows
- Automated pipelines
"""

import sys
import argparse
import logging
from pathlib import Path
from typing import List, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

from reveng.core.logger import setup_logging, get_logger
from reveng.core.dependency_manager import DependencyManager
from reveng.core.errors import REVENGError, create_error_context

def main():
    """Main CLI entry point"""
    parser = create_parser()
    args = parser.parse_args()

    # Setup logging
    logger = setup_logging(level=args.log_level)

    try:
        # Execute command
        if hasattr(args, 'func'):
            args.func(args)
        else:
            parser.print_help()

    except REVENGError as e:
        logger.error(f"REVENG Error: {e.get_detailed_message()}")
        sys.exit(1)

    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        sys.exit(130)

    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

def create_parser() -> argparse.ArgumentParser:
    """Create argument parser with all commands"""
    parser = argparse.ArgumentParser(
        prog="reveng",
        description="REVENG Universal Reverse Engineering Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  reveng analyze binary.exe
  reveng analyze binary.exe --format dotnet --output analysis.json

  # Hex editor operations
  reveng hex binary.exe --search "4D5A" --extract 0:100
  reveng hex binary.exe --entropy --strings

  # PE analysis
  reveng pe resources binary.exe --extract-all
  reveng pe imports binary.exe --categorize
  reveng pe exports binary.exe

  # Ghidra automation
  reveng ghidra analyze binary.exe --script extract_functions.py
  reveng ghidra decompile binary.exe --function 0x401000
  reveng ghidra batch binaries.txt --script analyze_imports.py

  # Pipeline operations
  reveng pipeline create malware_analysis
  reveng pipeline run malware_analysis.yaml binary.exe
  reveng pipeline list

  # Malware analysis
  reveng malware analyze sample.exe --behavioral --memory --unpack
  reveng malware unpack packed.exe
  reveng malware behavioral sample.exe --monitor-network
  reveng malware memory 1234

  # Setup and configuration
  reveng setup verify
  reveng setup install-deps
  reveng config set tool.ghidra.path /path/to/ghidra
        """
    )

    # Global options
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level'
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--config',
        type=Path,
        help='Path to configuration file'
    )

    # Create subparsers
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Analysis commands
    create_analyze_parser(subparsers)

    # Hex editor commands
    create_hex_parser(subparsers)

    # PE analysis commands
    create_pe_parser(subparsers)

    # Ghidra commands
    create_ghidra_parser(subparsers)

    # Pipeline commands
    create_pipeline_parser(subparsers)

    # Malware analysis commands
    create_malware_parser(subparsers)

    # ML analysis commands
    create_ml_parser(subparsers)

    # Setup commands
    create_setup_parser(subparsers)

    # Config commands
    create_config_parser(subparsers)

    # Plugin commands
    create_plugin_parser(subparsers)

    # Serve command
    create_serve_parser(subparsers)

    return parser

def create_analyze_parser(subparsers):
    """Create analysis command parser"""
    parser = subparsers.add_parser(
        'analyze',
        help='Analyze binary files'
    )

    parser.add_argument(
        'binary',
        type=Path,
        help='Binary file to analyze'
    )
    parser.add_argument(
        '--format',
        choices=['auto', 'dotnet', 'java', 'python', 'native', 'all'],
        default='auto',
        help='Analysis format (default: auto-detect)'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        help='Output file path'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Output in JSON format'
    )
    parser.add_argument(
        '--detailed',
        action='store_true',
        help='Include detailed analysis'
    )
    parser.add_argument(
        '--timeout',
        type=int,
        default=300,
        help='Analysis timeout in seconds'
    )

    parser.set_defaults(func=cmd_analyze)

def create_hex_parser(subparsers):
    """Create hex editor command parser"""
    parser = subparsers.add_parser(
        'hex',
        help='Hex editor operations'
    )

    parser.add_argument(
        'binary',
        type=Path,
        help='Binary file to examine'
    )
    parser.add_argument(
        '--search',
        help='Search for hex pattern'
    )
    parser.add_argument(
        '--extract',
        help='Extract bytes (format: offset:length)'
    )
    parser.add_argument(
        '--entropy',
        action='store_true',
        help='Analyze entropy'
    )
    parser.add_argument(
        '--strings',
        action='store_true',
        help='Extract strings'
    )
    parser.add_argument(
        '--output', '-o',
        type=Path,
        help='Output file'
    )

    parser.set_defaults(func=cmd_hex)

def create_pe_parser(subparsers):
    """Create PE analysis command parser"""
    parser = subparsers.add_parser(
        'pe',
        help='PE file analysis'
    )

    sub_parsers = parser.add_subparsers(dest='pe_command', help='PE analysis commands')

    # PE resources
    resources_parser = sub_parsers.add_parser('resources', help='Extract PE resources')
    resources_parser.add_argument('binary', type=Path, help='PE file')
    resources_parser.add_argument('--extract-all', action='store_true', help='Extract all resources')
    resources_parser.add_argument('--output', '-o', type=Path, help='Output directory')
    resources_parser.set_defaults(func=cmd_pe_resources)

    # PE imports
    imports_parser = sub_parsers.add_parser('imports', help='Analyze PE imports')
    imports_parser.add_argument('binary', type=Path, help='PE file')
    imports_parser.add_argument('--categorize', action='store_true', help='Categorize APIs')
    imports_parser.add_argument('--suspicious', action='store_true', help='Find suspicious APIs')
    imports_parser.set_defaults(func=cmd_pe_imports)

    # PE exports
    exports_parser = sub_parsers.add_parser('exports', help='Analyze PE exports')
    exports_parser.add_argument('binary', type=Path, help='PE file')
    exports_parser.set_defaults(func=cmd_pe_exports)

def create_ghidra_parser(subparsers):
    """Create Ghidra command parser"""
    parser = subparsers.add_parser(
        'ghidra',
        help='Ghidra automation'
    )

    sub_parsers = parser.add_subparsers(dest='ghidra_command', help='Ghidra commands')

    # Ghidra analyze
    analyze_parser = sub_parsers.add_parser('analyze', help='Analyze with Ghidra')
    analyze_parser.add_argument('binary', type=Path, help='Binary file')
    analyze_parser.add_argument('--script', type=Path, help='Ghidra script to run')
    analyze_parser.add_argument('--output', '-o', type=Path, help='Output directory')
    analyze_parser.set_defaults(func=cmd_ghidra_analyze)

    # Ghidra decompile
    decompile_parser = sub_parsers.add_parser('decompile', help='Decompile function')
    decompile_parser.add_argument('binary', type=Path, help='Binary file')
    decompile_parser.add_argument('--function', help='Function address')
    decompile_parser.add_argument('--output', '-o', type=Path, help='Output file')
    decompile_parser.set_defaults(func=cmd_ghidra_decompile)

    # Ghidra batch
    batch_parser = sub_parsers.add_parser('batch', help='Batch analysis')
    batch_parser.add_argument('binary_list', type=Path, help='File containing list of binaries')
    batch_parser.add_argument('--script', type=Path, help='Ghidra script to run')
    batch_parser.set_defaults(func=cmd_ghidra_batch)

def create_pipeline_parser(subparsers):
    """Create pipeline command parser"""
    parser = subparsers.add_parser(
        'pipeline',
        help='Analysis pipeline management'
    )

    sub_parsers = parser.add_subparsers(dest='pipeline_command', help='Pipeline commands')

    # Create pipeline
    create_parser = sub_parsers.add_parser('create', help='Create pipeline')
    create_parser.add_argument('name', help='Pipeline name')
    create_parser.add_argument('--template', help='Template to use')
    create_parser.set_defaults(func=cmd_pipeline_create)

    # Run pipeline
    run_parser = sub_parsers.add_parser('run', help='Run pipeline')
    run_parser.add_argument('pipeline', type=Path, help='Pipeline file')
    run_parser.add_argument('binary', type=Path, help='Binary file')
    run_parser.set_defaults(func=cmd_pipeline_run)

    # List pipelines
    list_parser = sub_parsers.add_parser('list', help='List pipelines')
    list_parser.set_defaults(func=cmd_pipeline_list)

def create_malware_parser(subparsers):
    """Create malware analysis command parser"""
    parser = subparsers.add_parser(
        'malware',
        help='Malware analysis'
    )

    sub_parsers = parser.add_subparsers(dest='malware_command', help='Malware analysis commands')

    # Analyze malware
    analyze_parser = sub_parsers.add_parser('analyze', help='Analyze malware sample')
    analyze_parser.add_argument('sample', type=Path, help='Malware sample')
    analyze_parser.add_argument('--behavioral', action='store_true', help='Run behavioral analysis')
    analyze_parser.add_argument('--memory', action='store_true', help='Run memory forensics')
    analyze_parser.add_argument('--unpack', action='store_true', help='Attempt unpacking')
    analyze_parser.set_defaults(func=cmd_malware_analyze)

    # Unpack binary
    unpack_parser = sub_parsers.add_parser('unpack', help='Unpack packed binary')
    unpack_parser.add_argument('binary', type=Path, help='Packed binary')
    unpack_parser.add_argument('--output', '-o', type=Path, help='Output file')
    unpack_parser.set_defaults(func=cmd_malware_unpack)

    # Behavioral analysis
    behavioral_parser = sub_parsers.add_parser('behavioral', help='Behavioral analysis')
    behavioral_parser.add_argument('sample', type=Path, help='Sample to analyze')
    behavioral_parser.add_argument('--monitor-network', action='store_true', help='Monitor network')
    behavioral_parser.add_argument('--monitor-registry', action='store_true', help='Monitor registry')
    behavioral_parser.set_defaults(func=cmd_malware_behavioral)

    # Memory analysis
    memory_parser = sub_parsers.add_parser('memory', help='Memory forensics')
    memory_parser.add_argument('process_id', type=int, help='Process ID')
    memory_parser.add_argument('--output', '-o', type=Path, help='Output file')
    memory_parser.set_defaults(func=cmd_malware_memory)

def create_setup_parser(subparsers):
    """Create setup command parser"""
    parser = subparsers.add_parser(
        'setup',
        help='Setup and installation'
    )

    sub_parsers = parser.add_subparsers(dest='setup_command', help='Setup commands')

    # Verify setup
    verify_parser = sub_parsers.add_parser('verify', help='Verify installation')
    verify_parser.set_defaults(func=cmd_setup_verify)

    # Install dependencies
    install_parser = sub_parsers.add_parser('install-deps', help='Install dependencies')
    install_parser.add_argument('--auto', action='store_true', help='Auto-install missing tools')
    install_parser.set_defaults(func=cmd_setup_install_deps)

def create_config_parser(subparsers):
    """Create config command parser"""
    parser = subparsers.add_parser(
        'config',
        help='Configuration management'
    )

    sub_parsers = parser.add_subparsers(dest='config_command', help='Config commands')

    # Set config
    set_parser = sub_parsers.add_parser('set', help='Set configuration value')
    set_parser.add_argument('key', help='Configuration key')
    set_parser.add_argument('value', help='Configuration value')
    set_parser.set_defaults(func=cmd_config_set)

    # Get config
    get_parser = sub_parsers.add_parser('get', help='Get configuration value')
    get_parser.add_argument('key', help='Configuration key')
    get_parser.set_defaults(func=cmd_config_get)

    # List config
    list_parser = sub_parsers.add_parser('list', help='List all configuration')
    list_parser.set_defaults(func=cmd_config_list)

def create_plugin_parser(subparsers):
    """Create plugin command parser"""
    parser = subparsers.add_parser(
        'plugin',
        help='Plugin management'
    )

    sub_parsers = parser.add_subparsers(dest='plugin_command', help='Plugin commands')

    # List plugins
    list_parser = sub_parsers.add_parser('list', help='List plugins')
    list_parser.set_defaults(func=cmd_plugin_list)

    # Install plugin
    install_parser = sub_parsers.add_parser('install', help='Install plugin')
    install_parser.add_argument('name', help='Plugin name')
    install_parser.set_defaults(func=cmd_plugin_install)

def create_serve_parser(subparsers):
    """Create serve command parser"""
    parser = subparsers.add_parser(
        'serve',
        help='Start web server'
    )

    parser.add_argument(
        '--port',
        type=int,
        default=3000,
        help='Port to serve on'
    )
    parser.add_argument(
        '--host',
        default='localhost',
        help='Host to bind to'
    )

    parser.set_defaults(func=cmd_serve)

# Command implementations
def cmd_analyze(args):
    """Analyze binary command"""
    logger = get_logger()
    logger.info(f"Analyzing {args.binary}")

    # TODO: Implement analysis logic
    print(f"Analyzing {args.binary} with format {args.format}")

def cmd_hex(args):
    """Hex editor command"""
    logger = get_logger()
    logger.info(f"Hex operations on {args.binary}")

    # TODO: Implement hex editor logic
    print(f"Hex operations on {args.binary}")

def cmd_pe_resources(args):
    """PE resources command"""
    logger = get_logger()
    logger.info(f"Extracting PE resources from {args.binary}")

    # TODO: Implement PE resource extraction
    print(f"Extracting PE resources from {args.binary}")

def cmd_pe_imports(args):
    """PE imports command"""
    logger = get_logger()
    logger.info(f"Analyzing PE imports from {args.binary}")

    # TODO: Implement PE import analysis
    print(f"Analyzing PE imports from {args.binary}")

def cmd_pe_exports(args):
    """PE exports command"""
    logger = get_logger()
    logger.info(f"Analyzing PE exports from {args.binary}")

    # TODO: Implement PE export analysis
    print(f"Analyzing PE exports from {args.binary}")

def cmd_ghidra_analyze(args):
    """Ghidra analyze command"""
    logger = get_logger()
    logger.info(f"Ghidra analysis of {args.binary}")

    # TODO: Implement Ghidra analysis
    print(f"Ghidra analysis of {args.binary}")

def cmd_ghidra_decompile(args):
    """Ghidra decompile command"""
    logger = get_logger()
    logger.info(f"Ghidra decompile of {args.binary}")

    # TODO: Implement Ghidra decompilation
    print(f"Ghidra decompile of {args.binary}")

def cmd_ghidra_batch(args):
    """Ghidra batch command"""
    logger = get_logger()
    logger.info(f"Ghidra batch analysis of {args.binary_list}")

    # TODO: Implement Ghidra batch analysis
    print(f"Ghidra batch analysis of {args.binary_list}")

def cmd_pipeline_create(args):
    """Pipeline create command"""
    logger = get_logger()
    logger.info(f"Creating pipeline: {args.name}")

    # TODO: Implement pipeline creation
    print(f"Creating pipeline: {args.name}")

def cmd_pipeline_run(args):
    """Pipeline run command"""
    logger = get_logger()
    logger.info(f"Running pipeline: {args.pipeline}")

    # TODO: Implement pipeline execution
    print(f"Running pipeline: {args.pipeline}")

def cmd_pipeline_list(args):
    """Pipeline list command"""
    logger = get_logger()
    logger.info("Listing pipelines")

    # TODO: Implement pipeline listing
    print("Available pipelines:")

def cmd_malware_analyze(args):
    """Malware analyze command"""
    logger = get_logger()
    logger.info(f"Malware analysis of {args.sample}")

    # TODO: Implement malware analysis
    print(f"Malware analysis of {args.sample}")

def cmd_malware_unpack(args):
    """Malware unpack command"""
    logger = get_logger()
    logger.info(f"Unpacking {args.binary}")

    # TODO: Implement unpacking
    print(f"Unpacking {args.binary}")

def cmd_malware_behavioral(args):
    """Malware behavioral command"""
    logger = get_logger()
    logger.info(f"Behavioral analysis of {args.sample}")

    # TODO: Implement behavioral analysis
    print(f"Behavioral analysis of {args.sample}")

def cmd_malware_memory(args):
    """Malware memory command"""
    logger = get_logger()
    logger.info(f"Memory forensics of process {args.process_id}")

    # TODO: Implement memory forensics
    print(f"Memory forensics of process {args.process_id}")

def cmd_setup_verify(args):
    """Setup verify command"""
    logger = get_logger()
    logger.info("Verifying REVENG installation")

    # Check dependencies
    dep_manager = DependencyManager()
    status = dep_manager.check_all_dependencies()

    print("REVENG Installation Status:")
    for tool, installed in status.items():
        status_icon = "✓" if installed else "✗"
        print(f"  {status_icon} {tool}")

    if not all(status.values()):
        print("\nSome tools are missing. Run 'reveng setup install-deps' to install them.")

def cmd_setup_install_deps(args):
    """Setup install dependencies command"""
    logger = get_logger()
    logger.info("Installing dependencies")

    # Install missing tools
    dep_manager = DependencyManager()
    status = dep_manager.check_all_dependencies()
    missing_tools = [tool for tool, installed in status.items() if not installed]

    if missing_tools:
        print(f"Installing missing tools: {', '.join(missing_tools)}")
        results = dep_manager.install_missing_tools(missing_tools, auto_install=args.auto)

        for tool, success in results.items():
            status_icon = "✓" if success else "✗"
            print(f"  {status_icon} {tool}")
    else:
        print("All dependencies are already installed.")

def cmd_config_set(args):
    """Config set command"""
    logger = get_logger()
    logger.info(f"Setting config: {args.key} = {args.value}")

    # TODO: Implement config setting
    print(f"Setting {args.key} = {args.value}")

def cmd_config_get(args):
    """Config get command"""
    logger = get_logger()
    logger.info(f"Getting config: {args.key}")

    # TODO: Implement config getting
    print(f"Getting {args.key}")

def cmd_config_list(args):
    """Config list command"""
    logger = get_logger()
    logger.info("Listing configuration")

    # TODO: Implement config listing
    print("Configuration:")

def cmd_plugin_list(args):
    """Plugin list command"""
    logger = get_logger()
    logger.info("Listing plugins")

    # TODO: Implement plugin listing
    print("Available plugins:")

def cmd_plugin_install(args):
    """Plugin install command"""
    logger = get_logger()
    logger.info(f"Installing plugin: {args.name}")

    # TODO: Implement plugin installation
    print(f"Installing plugin: {args.name}")

def cmd_serve(args):
    """Serve command"""
    logger = get_logger()
    logger.info(f"Starting web server on {args.host}:{args.port}")

    # TODO: Implement web server
    print(f"Starting web server on {args.host}:{args.port}")

def create_ml_parser(subparsers):
    """Create ML analysis parser"""
    ml_parser = subparsers.add_parser('ml', help='ML-powered analysis')
    ml_subparsers = ml_parser.add_subparsers(dest='ml_command', help='ML commands')

    # ML analyze command
    analyze_parser = ml_subparsers.add_parser('analyze', help='ML-powered binary analysis')
    analyze_parser.add_argument('binary', help='Binary file to analyze')
    analyze_parser.add_argument('--reconstruct', action='store_true',
                               help='Enable code reconstruction')
    analyze_parser.add_argument('--anomaly', action='store_true',
                               help='Enable anomaly detection')
    analyze_parser.add_argument('--threat', action='store_true',
                               help='Enable threat intelligence')
    analyze_parser.add_argument('--model', choices=['codebert', 'codet5', 'gpt', 'claude'],
                               help='ML model to use')
    analyze_parser.add_argument('--output', '-o', help='Output directory')
    analyze_parser.set_defaults(func=cmd_ml_analyze)

    # ML reconstruct command
    reconstruct_parser = ml_subparsers.add_parser('reconstruct', help='Code reconstruction')
    reconstruct_parser.add_argument('binary', help='Binary file to reconstruct')
    reconstruct_parser.add_argument('--task', choices=['decompilation', 'function', 'variable', 'control_flow'],
                                   default='decompilation', help='Reconstruction task')
    reconstruct_parser.add_argument('--model', choices=['codebert', 'codet5', 'gpt', 'claude'],
                                   help='ML model to use')
    reconstruct_parser.add_argument('--output', '-o', help='Output directory')
    reconstruct_parser.set_defaults(func=cmd_ml_reconstruct)

    # ML anomaly command
    anomaly_parser = ml_subparsers.add_parser('anomaly', help='Anomaly detection')
    anomaly_parser.add_argument('binary', help='Binary file to analyze')
    anomaly_parser.add_argument('--types', nargs='+',
                               choices=['behavioral', 'structural', 'statistical', 'pattern', 'temporal'],
                               default=['behavioral', 'structural'], help='Anomaly types to detect')
    anomaly_parser.add_argument('--output', '-o', help='Output directory')
    anomaly_parser.set_defaults(func=cmd_ml_anomaly)

    # ML threat command
    threat_parser = ml_subparsers.add_parser('threat', help='Threat intelligence')
    threat_parser.add_argument('binary', help='Binary file to analyze')
    threat_parser.add_argument('--model', choices=['gpt', 'claude', 'codebert'],
                               help='ML model to use')
    threat_parser.add_argument('--output', '-o', help='Output directory')
    threat_parser.set_defaults(func=cmd_ml_threat)

    # ML status command
    status_parser = ml_subparsers.add_parser('status', help='ML model status')
    status_parser.set_defaults(func=cmd_ml_status)

def cmd_ml_analyze(args):
    """ML analyze command"""
    logger = get_logger()
    logger.info(f"Starting ML analysis for: {args.binary}")

    try:
        from reveng.ml import MLIntegration, MLIntegrationConfig

        # Create ML configuration
        config = MLIntegrationConfig(
            enable_code_reconstruction=args.reconstruct,
            enable_anomaly_detection=args.anomaly,
            enable_threat_intelligence=args.threat,
            output_directory=args.output or "ml_analysis"
        )

        # Initialize ML integration
        ml_integration = MLIntegration(config)

        # TODO: Load analysis data from binary
        analysis_data = {}

        # Perform ML analysis
        results = ml_integration.analyze_binary(args.binary, analysis_data)

        print(f"ML analysis completed for {args.binary}")
        print(f"Results saved to: {config.output_directory}")

    except Exception as e:
        logger.error(f"ML analysis failed: {e}")
        raise

def cmd_ml_reconstruct(args):
    """ML reconstruct command"""
    logger = get_logger()
    logger.info(f"Starting code reconstruction for: {args.binary}")

    try:
        from reveng.ml import MLCodeReconstruction, CodeFragment, ReconstructionTask

        # Initialize code reconstruction
        reconstruction = MLCodeReconstruction()

        # TODO: Extract code fragments from binary
        fragments = []

        # Perform reconstruction
        for fragment in fragments:
            result = reconstruction.reconstruct_code(fragment, ReconstructionTask.DECOMPILATION)
            print(f"Reconstructed code at {hex(fragment.address)}")

        print(f"Code reconstruction completed for {args.binary}")

    except Exception as e:
        logger.error(f"Code reconstruction failed: {e}")
        raise

def cmd_ml_anomaly(args):
    """ML anomaly command"""
    logger = get_logger()
    logger.info(f"Starting anomaly detection for: {args.binary}")

    try:
        from reveng.ml import MLAnomalyDetection, AnomalyType

        # Initialize anomaly detection
        anomaly_detection = MLAnomalyDetection()

        # TODO: Load analysis data from binary
        analysis_data = {}

        # Convert anomaly types
        anomaly_types = [AnomalyType(t) for t in args.types]

        # Detect anomalies
        anomalies = anomaly_detection.detect_anomalies(analysis_data, anomaly_types)

        print(f"Detected {len(anomalies)} anomalies")
        for anomaly in anomalies:
            print(f"  {anomaly.anomaly_type.value}: {anomaly.description}")

    except Exception as e:
        logger.error(f"Anomaly detection failed: {e}")
        raise

def cmd_ml_threat(args):
    """ML threat command"""
    logger = get_logger()
    logger.info(f"Starting threat intelligence for: {args.binary}")

    try:
        from reveng.ml import MLCodeReconstruction

        # Initialize code reconstruction
        reconstruction = MLCodeReconstruction()

        # TODO: Load analysis data from binary
        analysis_data = {}

        # Generate threat intelligence
        threat_intelligence = reconstruction.generate_threat_intelligence(analysis_data)

        print(f"Generated {len(threat_intelligence)} threat intelligence items")
        for threat in threat_intelligence:
            print(f"  {threat.threat_type}: {threat.description}")

    except Exception as e:
        logger.error(f"Threat intelligence failed: {e}")
        raise

def cmd_ml_status(args):
    """ML status command"""
    logger = get_logger()
    logger.info("Checking ML model status")

    try:
        from reveng.ml import MLIntegration, MLIntegrationConfig

        # Initialize ML integration
        config = MLIntegrationConfig()
        ml_integration = MLIntegration(config)

        # Get model status
        status = ml_integration.get_model_status()

        print("ML Model Status:")
        print(f"  Code Reconstruction: {'Available' if status['code_reconstruction']['available'] else 'Not Available'}")
        print(f"  Anomaly Detection: {'Available' if status['anomaly_detection']['available'] else 'Not Available'}")

        # Show available models
        if status['code_reconstruction']['available']:
            print("\nCode Reconstruction Models:")
            for model_name, model_info in status['code_reconstruction']['models'].items():
                status_text = "Loaded" if model_info['loaded'] else "Not Loaded"
                print(f"  {model_name}: {status_text}")

        if status['anomaly_detection']['available']:
            print("\nAnomaly Detection Models:")
            for model_name, model_info in status['anomaly_detection']['models'].items():
                print(f"  {model_name}: {model_info['name']}")

    except Exception as e:
        logger.error(f"Failed to get ML status: {e}")
        raise

if __name__ == "__main__":
    main()
