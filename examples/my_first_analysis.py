#!/usr/bin/env python3
"""
My First REVENG Analysis
========================

This is the simplest possible example of using REVENG.
No external dependencies, no API keys needed.

You can run this immediately after installation!

Usage:
    python examples/my_first_analysis.py
"""

import sys
from pathlib import Path

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

def main():
    print("=" * 70)
    print("  REVENG - My First Analysis")
    print("=" * 70)
    print()

    # Example 1: Detect file type
    print("📁 Example 1: File Type Detection")
    print("-" * 70)

    # You can replace this with any binary file you want to analyze
    test_file = __file__  # This Python script itself

    print(f"File: {test_file}")
    print(f"Size: {Path(test_file).stat().st_size} bytes")

    # Simple file type detection
    with open(test_file, "rb") as f:
        magic_bytes = f.read(4)

    if magic_bytes[:2] == b'MZ':
        file_type = "Windows PE Executable"
    elif magic_bytes == b'\x7fELF':
        file_type = "Linux ELF Binary"
    elif magic_bytes[:2] == b'#!':
        file_type = "Script (Shell/Python)"
    else:
        file_type = f"Unknown (magic: {magic_bytes.hex()})"

    print(f"Detected type: {file_type}")
    print()

    # Example 2: JavaScript Obfuscation Detection (simple)
    print("📁 Example 2: JavaScript Obfuscation Detection")
    print("-" * 70)

    # Sample obfuscated JavaScript
    obfuscated_js = """
    var _0x1234=['hello','world'];function _0x5678(a){return _0x1234[a];}console.log(_0x5678(0));
    """

    # Simple detection
    indicators = []
    if "_0x" in obfuscated_js:
        indicators.append("✓ Hex variable names (_0x...)")
    if "eval(" in obfuscated_js:
        indicators.append("✓ eval() calls")
    if len(obfuscated_js.split()) / len(obfuscated_js.split(';')) < 2:
        indicators.append("✓ Minified (few whitespace)")

    print(f"JavaScript sample: {obfuscated_js[:60]}...")
    print(f"\nObfuscation indicators found:")
    for indicator in indicators:
        print(f"  {indicator}")
    print()

    # Example 3: Using REVENG JavaScript Module
    print("📁 Example 3: REVENG JavaScript Deobfuscation")
    print("-" * 70)

    try:
        from reveng.javascript.detectors import ObfuscationDetector

        detector = ObfuscationDetector()
        result = detector.detect(obfuscated_js)

        print(f"Obfuscation types detected: {[t.value for t in result.obfuscation_types]}")
        print(f"Confidence: {result.confidence:.1%}")

        print("\n✅ REVENG JavaScript module is working!")

    except ImportError as e:
        print("⚠️  REVENG JavaScript module not available")
        print(f"   (This is optional - install with: ./install-js-deob.sh)")
    print()

    # Example 4: Using REVENG Core
    print("📁 Example 4: REVENG Core Analyzer")
    print("-" * 70)

    try:
        from reveng.analyzer import REVENGAnalyzer

        print("✅ REVENG core analyzer is available!")
        print("   Try: reveng analyze /path/to/binary")

    except ImportError:
        print("⚠️  REVENG core not installed")
        print("   Run: pip install -e .")
    print()

    # Next steps
    print("=" * 70)
    print("  🎉 Great! You've completed your first REVENG analysis!")
    print("=" * 70)
    print()
    print("📚 Next Steps:")
    print()
    print("  1. Try the JavaScript deobfuscation demo:")
    print("     python examples/javascript_deobfuscation_demo.py")
    print()
    print("  2. Analyze a real binary:")
    print("     reveng analyze /path/to/binary.exe")
    print()
    print("  3. Deobfuscate JavaScript:")
    print("     ./reveng-js deobfuscate examples/test-samples/obfuscated-simple.js")
    print()
    print("  4. Explore more features:")
    print("     reveng --help")
    print("     ./reveng-js --help")
    print()
    print("📖 Documentation:")
    print("   • Quick Start: QUICK_START.md")
    print("   • JavaScript: src/reveng/javascript/README.md")
    print("   • Full Docs: docs/")
    print()


if __name__ == "__main__":
    main()
