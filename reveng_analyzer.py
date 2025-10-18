#!/usr/bin/env python3
"""
DEPRECATED: This script is deprecated in favor of the modern 'reveng' CLI

This file will be removed in v3.0.0. Please migrate to the new CLI interface.

Migration Guide:
================

OLD COMMAND                    →  NEW COMMAND
python reveng_analyzer.py     →  reveng analyze
python reveng_analyzer.py -h  →  reveng --help

For enhanced analysis features:
python reveng_analyzer.py --no-enhanced  →  reveng analyze --no-enhanced

Installation:
============
pip install reveng

Usage:
======
reveng analyze <binary_path> [options]
reveng serve                    # Web interface
reveng triage <binary_path>     # Quick threat assessment
reveng ask <question> <binary>  # Natural language queries

For more information, visit: https://github.com/oimiragieo/reveng-main
"""

import subprocess
import sys
import warnings
from pathlib import Path


def main():
    """Deprecated entry point - redirect to modern CLI"""

    # Show deprecation warning
    warnings.warn(
        "reveng_analyzer.py is DEPRECATED and will be removed in v3.0.0. "
        "Use 'reveng analyze' instead. See migration guide in the file header.",
        DeprecationWarning,
        stacklevel=2,
    )

    print("=" * 70)
    print(" DEPRECATION NOTICE")
    print("=" * 70)
    print("reveng_analyzer.py is DEPRECATED and will be removed in v3.0.0")
    print()
    print("MIGRATION:")
    print("  OLD: python reveng_analyzer.py <binary>")
    print("  NEW: reveng analyze <binary>")
    print()
    print("Install the modern CLI:")
    print("  pip install reveng")
    print()
    print("For help:")
    print("  reveng --help")
    print("=" * 70)
    print()

    # Try to redirect to modern CLI if available
    try:
        # Check if reveng CLI is available
        result = subprocess.run(["reveng", "--version"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("Modern CLI detected. Redirecting to: reveng analyze")
            print()

            # Get arguments (skip script name)
            args = sys.argv[1:]

            # Map old arguments to new format
            if args:
                # Basic argument mapping
                new_args = ["reveng", "analyze"] + args

                print(f"Running: {' '.join(new_args)}")
                print()

                # Execute the modern CLI
                subprocess.run(new_args)
            else:
                print("No binary specified. Use: reveng analyze <binary_path>")
                print("For help: reveng --help")
        else:
            print("Modern CLI not found. Please install with: pip install reveng")

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        print("Modern CLI not available. Please install with: pip install reveng")
        print()
        print("For now, you can use the legacy functionality by importing:")
        print("  from reveng_analyzer import REVENGAnalyzer")
        print("  analyzer = REVENGAnalyzer(binary_path)")
        print("  analyzer.analyze_binary()")

        # Fallback to legacy functionality
        try:
            from reveng_analyzer_legacy import REVENGAnalyzer

            if len(sys.argv) > 1:
                binary_path = sys.argv[1]
                if Path(binary_path).exists():
                    print(f"\nRunning legacy analysis on: {binary_path}")
                    analyzer = REVENGAnalyzer(binary_path)
                    analyzer.analyze_binary()
                else:
                    print(f"Error: Binary not found: {binary_path}")
            else:
                print("Error: No binary specified")
                print("Usage: python reveng_analyzer.py <binary_path>")

        except ImportError:
            print("Legacy functionality not available.")
            print("Please install the modern CLI: pip install reveng")


if __name__ == "__main__":
    main()
