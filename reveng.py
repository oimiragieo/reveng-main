#!/usr/bin/env python3
"""
REVENG Universal Reverse Engineering Platform - Entry Point

This is the main entry point for the REVENG platform. It provides a thin wrapper
that delegates to the production CLI implementation in src/reveng/cli/.

For CLI implementation details, see: src/reveng/cli/__init__.py

Modern command-line interface for REVENG with advanced features including:
- Binary analysis with multiple formats (PE, ELF, Mach-O, JAR, .NET)
- AI-powered decompilation and reconstruction
- JavaScript deobfuscation and malware detection
- Vulnerability discovery and exploit generation
- VirusTotal integration and threat intelligence
- YARA rule generation and scanning
- Binary diffing and patch analysis
- Ghidra automation and MCP server integration
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))


def main(argv=None):
    """Main entry point that delegates to the production CLI.

    Args:
        argv: Optional command-line arguments. If None, uses sys.argv

    Returns:
        int: Exit code (0 for success, non-zero for errors)
    """
    if argv is not None:
        sys.argv = [sys.argv[0], *list(argv)]

    try:
        from reveng.cli import main as cli_main
    except ImportError as exc:
        print("╔══════════════════════════════════════════════════════════════════════╗")
        print("║                     REVENG Installation Required                     ║")
        print("╚══════════════════════════════════════════════════════════════════════╝")
        print()
        print(f"Error: Failed to load REVENG CLI: {exc}")
        print()
        print("REVENG is not installed. Please run the installer:")
        print()
        print("  Option 1 (Recommended): Run the installer")
        print("    ./install-reveng.sh")
        print()
        print("  Option 2: Manual installation")
        print("    pip install -e .")
        print()
        print("  Option 3: Install dependencies only")
        print("    pip install -r requirements.txt")
        print()
        print("For detailed installation instructions, see:")
        print("  - QUICK_START.md (2-minute setup)")
        print("  - docs/getting-started/installation.md (complete guide)")
        print()
        return 1

    try:
        return cli_main()
    except SystemExit as exc:
        # Allow cli_main to control exit codes
        return int(exc.code or 0)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        return 130
    except Exception as exc:
        # Try to use REVENG logger if available, otherwise fall back to print
        try:
            from reveng.core.logger import get_logger
            get_logger().error(f"Unexpected REVENG error: {exc}")
        except Exception:
            print(f"\nUnexpected REVENG error: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
