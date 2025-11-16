#!/usr/bin/env python3
"""
REVENG Basic Example 01: Simple Binary Analysis
===============================================

This example demonstrates the most basic usage of REVENG:
analyzing a binary file and understanding the results.

**Prerequisites:**
- REVENG installed (pip install -e .)
- No API keys needed
- No Ghidra needed

**Time:** ~2 minutes

Usage:
    python examples/basic/01_simple_analysis.py [binary_path]
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from reveng.analyzer import REVENGAnalyzer, EnhancedAnalysisFeatures


def main():
    print("=" * 70)
    print("  REVENG Basic Example: Simple Binary Analysis")
    print("=" * 70)
    print()

    # Get binary path from args or use default
    if len(sys.argv) > 1:
        binary_path = sys.argv[1]
    else:
        # Use a system binary as default
        binary_path = "/bin/ls" if Path("/bin/ls").exists() else __file__

    print(f"📁 Analyzing: {binary_path}")
    print()

    # Check if file exists
    if not Path(binary_path).exists():
        print(f"❌ Error: File not found: {binary_path}")
        print()
        print("Usage: python 01_simple_analysis.py [binary_path]")
        return 1

    # Create analyzer with minimal configuration
    # No AI, no Ghidra - just basic analysis
    print("⚙️  Setting up analyzer...")
    features = EnhancedAnalysisFeatures()
    features.enable_ghidra_analysis = False  # Skip Ghidra for speed
    features.enable_ai_enhancement = False  # Skip AI for speed
    features.timeout_seconds = 30

    try:
        analyzer = REVENGAnalyzer(binary_path, features=features)
        print("✅ Analyzer ready")
        print()

        # Run analysis
        print("🔍 Running analysis (this may take 10-30 seconds)...")
        print()
        results = analyzer.analyze_binary()

        # Display results
        print("=" * 70)
        print("  Analysis Results")
        print("=" * 70)
        print()

        # Basic file info
        print("📊 File Information:")
        print(f"  Path: {results.get('binary_path', 'N/A')}")
        print(
            f"  Size: {results.get('file_size', 0):,} bytes "
            f"({results.get('file_size', 0) / 1024:.1f} KB)"
        )
        print(f"  Format: {results.get('file_format', 'Unknown')}")
        print(f"  Architecture: {results.get('architecture', 'Unknown')}")
        print()

        # Security features
        security = results.get("security_features", {})
        if security:
            print("🔒 Security Features:")
            for feature, enabled in security.items():
                status = "✅ Enabled" if enabled else "❌ Disabled"
                print(f"  {feature}: {status}")
            print()

        # Strings found
        strings = results.get("interesting_strings", [])
        if strings:
            print(f"🔤 Interesting Strings ({len(strings)} found):")
            for i, string in enumerate(strings[:10], 1):
                print(f"  {i}. {string[:60]}...")
            if len(strings) > 10:
                print(f"  ... and {len(strings) - 10} more")
            print()

        # Imports
        imports = results.get("imports", [])
        if imports:
            print(f"📚 Imports ({len(imports)} found):")
            for i, imp in enumerate(imports[:10], 1):
                print(f"  {i}. {imp}")
            if len(imports) > 10:
                print(f"  ... and {len(imports) - 10} more")
            print()

        # Summary
        print("=" * 70)
        print("  Summary")
        print("=" * 70)
        print()
        print(f"✅ Analysis completed successfully")
        print(
            f"📄 Full results saved to: analysis_{Path(binary_path).name}/"
        )
        print()

        # Next steps
        print("📚 Next Steps:")
        print()
        print("  1. Try with AI enhancement:")
        print(f"     reveng analyze --enhanced {binary_path}")
        print()
        print("  2. Try more examples:")
        print("     python examples/basic/02_java_analysis.py")
        print()
        print("  3. Read the docs:")
        print("     cat QUICK_START.md")
        print()

        return 0

    except Exception as e:
        print(f"❌ Analysis failed: {e}")
        print()
        print("Troubleshooting:")
        print("  1. Check file permissions")
        print("  2. Verify file is a valid binary")
        print("  3. Run with --verbose for more details")
        print()
        return 1


if __name__ == "__main__":
    sys.exit(main())
