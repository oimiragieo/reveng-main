#!/usr/bin/env python3
"""
Gemini Continuous Feedback Loop - Demo

This demonstrates REVENG's self-improving capability:
AI analyzing and improving our reverse engineering tool.

Author: REVENG Team
Version: 3.0.0
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from reveng.ai.gemini_feedback_loop import GeminiFeedbackLoop


async def main():
    """Run Gemini feedback loop demonstration"""

    print("=" * 80)
    print("GEMINI CONTINUOUS FEEDBACK LOOP")
    print("AI Analyzing and Improving REVENG")
    print("=" * 80)

    # Configuration
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    OUTPUT_DIR = PROJECT_ROOT / "gemini_feedback"
    INTERVAL_MINUTES = 1  # Fast demo (normally 5-10 minutes)
    MAX_ITERATIONS = 3  # Run 3 iterations for demo

    print(f"\n📁 Project Root: {PROJECT_ROOT}")
    print(f"📁 Output Directory: {OUTPUT_DIR}")
    print(f"⏰ Interval: {INTERVAL_MINUTES} minute(s)")
    print(f"🔄 Max Iterations: {MAX_ITERATIONS}")

    # Initialize feedback loop
    print("\n[Initializing Gemini Feedback Loop...]")

    loop = GeminiFeedbackLoop(
        project_root=PROJECT_ROOT,
        output_dir=OUTPUT_DIR,
        interval_minutes=INTERVAL_MINUTES,
        auto_apply=False,  # Don't auto-apply for safety
    )

    if not loop.gemini.is_available():
        print("\n❌ ERROR: Gemini API not configured!")
        print("\nTo use Gemini feedback loop:")
        print("1. Get API key from: https://makersuite.google.com/app/apikey")
        print("2. Set environment variable:")
        print("   export GEMINI_API_KEY='your-api-key-here'")
        print("\n3. Install google-generativeai:")
        print("   pip install google-generativeai")
        return 1

    print("✅ Gemini feedback loop initialized")

    # Run loop
    print(f"\n{'='*80}")
    print("Starting feedback loop...")
    print(f"{'='*80}\n")

    try:
        await loop.start(max_iterations=MAX_ITERATIONS)
    except KeyboardInterrupt:
        print("\n\n⏸️  Feedback loop interrupted by user")

    # Show results
    print(f"\n{'='*80}")
    print("FEEDBACK LOOP SUMMARY")
    print(f"{'='*80}")

    # List generated reports
    reports = sorted(OUTPUT_DIR.glob("feedback_iteration_*.md"))

    print(f"\n📊 Generated Reports: {len(reports)}")
    for report in reports:
        size = report.stat().st_size
        print(f"  - {report.name} ({size:,} bytes)")

    if reports:
        # Show latest report summary
        latest = reports[-1]
        print(f"\n📄 Latest Report: {latest.name}")
        print(f"\nPreview:")
        print("-" * 80)
        content = latest.read_text()
        lines = content.split("\n")[:50]  # First 50 lines
        print("\n".join(lines))
        print("-" * 80)
        print(f"\nFull report available at: {latest}")

    print(f"\n✅ Feedback loop completed successfully!")
    print(f"\n💡 Next Steps:")
    print(f"   1. Review the feedback reports in: {OUTPUT_DIR}/")
    print(f"   2. Implement suggested improvements")
    print(f"   3. Run tests to validate changes")
    print(f"   4. Re-run feedback loop to verify improvements")

    return 0


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
