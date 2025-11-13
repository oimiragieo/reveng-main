#!/usr/bin/env python3
"""
REVENG v6.0 - JavaScript Deobfuscation Demo

Demonstrates the multi-stage JavaScript deobfuscation pipeline:
- Source map recovery
- Webpack/Browserify unbundling
- obfuscator.io deobfuscation
- Control flow unflattening
- ML-based variable renaming
- LLM semantic enhancement (optional)

Based on 2024-2025 research:
- webcrack, UnuglifyJS, Humanify integration
- 70-95% success rate
"""

import asyncio
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from reveng.javascript import (
    JavaScriptDeobfuscator,
    SourceMapRecoverer,
    ObfuscationDetector
)


async def demo_basic_deobfuscation():
    """Demo 1: Basic deobfuscation (no LLM)"""
    print("=" * 70)
    print("DEMO 1: Basic JavaScript Deobfuscation (Free, No LLM)")
    print("=" * 70)

    # Example obfuscated code (minified)
    obfuscated = """
    function a(b,c){var d=b+c;return d}function e(f){return f*2}var g=10;var h=a(g,5);console.log(e(h));
    """.strip()

    print(f"\n📄 Original obfuscated code ({len(obfuscated)} chars):")
    print(obfuscated[:200] + "..." if len(obfuscated) > 200 else obfuscated)

    # Create deobfuscator (ML enabled, no LLM)
    deob = JavaScriptDeobfuscator(
        use_ml=True,   # Use UnuglifyJS for variable renaming
        use_llm=False  # No LLM (free)
    )

    # Deobfuscate
    print("\n🔄 Running deobfuscation pipeline...")
    result = await deob.deobfuscate(obfuscated)

    # Results
    print(f"\n✅ Success: {result.success}")
    print(f"📊 Confidence: {result.confidence:.1%}")
    print(f"⏱️  Time: {result.execution_time:.2f}s")
    print(f"🔍 Obfuscation types detected: {[t.value for t in result.obfuscation_types]}")
    print(f"🛠️  Stages applied: {len(result.stages_applied)}")

    print(f"\n📝 Deobfuscated code:")
    print(result.deobfuscated_code)

    if result.warnings:
        print(f"\n⚠️  Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")


async def demo_llm_enhancement():
    """Demo 2: LLM-enhanced deobfuscation (costs money!)"""
    print("\n" + "=" * 70)
    print("DEMO 2: LLM-Enhanced Deobfuscation (GPT-4)")
    print("=" * 70)

    obfuscated = """
    function _0x1234(_0x5678,_0x9abc){var _0xdef0=_0x5678+_0x9abc;return _0xdef0;}
    """.strip()

    print(f"\n📄 Obfuscated code:")
    print(obfuscated)

    # Create deobfuscator with LLM
    deob = JavaScriptDeobfuscator(
        use_ml=True,
        use_llm=True,           # Enable LLM enhancement
        llm_provider="gpt4"
    )

    print("\n🔄 Running deobfuscation with GPT-4 enhancement...")
    print("💰 Note: This costs $0.01-0.10 per function via OpenAI API")

    result = await deob.deobfuscate(obfuscated)

    print(f"\n✅ Success: {result.success}")
    print(f"📊 Confidence: {result.confidence:.1%}")

    print(f"\n📝 Deobfuscated code:")
    print(result.deobfuscated_code)

    if result.llm_analysis:
        print(f"\n🤖 LLM Analysis:")
        print(f"  Explanation: {result.llm_analysis.get('explanation', 'N/A')}")
        print(f"  Malicious: {result.llm_analysis.get('malicious', 'Unknown')}")
        if result.llm_analysis.get('behaviors'):
            print(f"  Behaviors: {', '.join(result.llm_analysis['behaviors'])}")


async def demo_source_map_recovery():
    """Demo 3: Source map recovery (perfect recovery)"""
    print("\n" + "=" * 70)
    print("DEMO 3: Source Map Recovery from Web App")
    print("=" * 70)

    recoverer = SourceMapRecoverer()

    # Example: Check a URL for source maps
    # (Using a placeholder URL - replace with real site)
    url = "https://example.com/app.js"

    print(f"\n🔍 Searching for source maps at: {url}")
    print("⚠️  Note: This is a placeholder URL for demo purposes")

    # In real usage:
    # maps = recoverer.find_sourcemaps(url)
    #
    # if maps:
    #     print(f"\n✅ Found {len(maps)} source map(s)!")
    #     for map_url in maps:
    #         print(f"  - {map_url}")
    #
    #     # Recover sources
    #     result = recoverer.recover(maps[0])
    #
    #     if result.success:
    #         print(f"\n🎉 Recovered {len(result.sources)} source files:")
    #         for filename in result.sources.keys():
    #             print(f"  - {filename}")
    #
    #         # Save to directory
    #         recoverer.save_directory(result.sources, "recovered_sources/")
    #         print(f"\n💾 Saved to recovered_sources/")
    # else:
    #     print("\n❌ No source maps found")

    print("\n📝 How to use in production:")
    print("  1. Scan web app: maps = recoverer.scan_webapp('https://target.com')")
    print("  2. Recover sources: result = recoverer.recover(maps[0])")
    print("  3. Save to disk: recoverer.save_directory(result.sources, 'output/')")


async def demo_obfuscation_detection():
    """Demo 4: Obfuscation type detection"""
    print("\n" + "=" * 70)
    print("DEMO 4: Obfuscation Type Detection")
    print("=" * 70)

    test_cases = [
        ("Minified", "function a(b,c){return b+c}var d=a(1,2);"),
        ("Packed", "eval(function(p,a,c,k,e,d){...})"),
        ("Webpack", "var __webpack_require__ = function(moduleId) {...}"),
        ("obfuscator.io", "var _0x1234=['test','\\x48\\x65\\x6c\\x6c\\x6f'];"),
        ("CFG Flattened", "while(true){switch(_0x1234){case 0:...}}"),
    ]

    detector = ObfuscationDetector()

    for name, code in test_cases:
        print(f"\n🔍 Detecting: {name}")
        print(f"   Code: {code[:50]}...")

        result = detector.detect(code)

        print(f"   Types: {[t.value for t in result.obfuscation_types]}")
        print(f"   Confidence: {result.confidence:.1%}")


async def demo_file_deobfuscation():
    """Demo 5: Deobfuscate from file"""
    print("\n" + "=" * 70)
    print("DEMO 5: Deobfuscate File")
    print("=" * 70)

    # Example: deobfuscate a file
    input_file = "examples/data/obfuscated.js"  # Would be a real file
    output_file = "examples/data/deobfuscated.js"

    print(f"\n📂 Input: {input_file}")
    print(f"📂 Output: {output_file}")

    print("\n📝 Code to use:")
    print("""
    # Load obfuscated code
    with open(input_file, 'r') as f:
        obfuscated = f.read()

    # Deobfuscate
    deob = JavaScriptDeobfuscator(use_ml=True, use_llm=False)
    result = await deob.deobfuscate(obfuscated, filename=input_file)

    # Save result
    if result.success:
        with open(output_file, 'w') as f:
            f.write(result.deobfuscated_code)
        print(f"✅ Saved to {output_file}")
    """)


async def main():
    """Run all demos"""
    print("""
╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║   REVENG v6.0 - JavaScript Deobfuscation Demo                      ║
║                                                                    ║
║   Multi-stage pipeline for JavaScript reverse engineering         ║
║   Based on 2024-2025 state-of-the-art research                    ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝
    """)

    print("\n📋 Available demos:")
    print("  1. Basic deobfuscation (free, no LLM)")
    print("  2. LLM-enhanced deobfuscation (GPT-4, costs $$$)")
    print("  3. Source map recovery")
    print("  4. Obfuscation type detection")
    print("  5. File deobfuscation example")

    # Run demos
    await demo_basic_deobfuscation()
    # await demo_llm_enhancement()  # Commented out - requires API key
    await demo_source_map_recovery()
    await demo_obfuscation_detection()
    await demo_file_deobfuscation()

    print("\n" + "=" * 70)
    print("✅ All demos complete!")
    print("=" * 70)

    print("\n📚 Next steps:")
    print("  1. Install tools: npm install -g webcrack prettier unuglify-js")
    print("  2. For LLM: export OPENAI_API_KEY=sk-...")
    print("  3. Try on real obfuscated code!")

    print("\n📖 Documentation: RESEARCH_JAVASCRIPT_DEOBFUSCATION.md")


if __name__ == "__main__":
    asyncio.run(main())
