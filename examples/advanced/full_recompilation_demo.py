#!/usr/bin/env python3
"""
REVENG Full Recompilation Pipeline - Complete Demo

This script demonstrates the revolutionary capability:
Binary → Decompilation → AI Enhancement → Recompilation → Exploit Generation

Author: REVENG Team
Version: 3.0.0
"""

import asyncio
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from reveng.integrations.ghidra.ghidra_engine import (
    GhidraEngine,
    GhidraConnectionError,
)
from reveng.ai.gemini_engine import GeminiEngine
from reveng.ai.recompilation_engine import BinaryRecompilationEngine


async def main():
    """Run complete recompilation demonstration"""

    print("=" * 80)
    print("REVENG REVOLUTIONARY RECOMPILATION PIPELINE")
    print("Binary → Source → Compiled → Exploits")
    print("=" * 80)

    # Configuration
    BINARY_PATH = "test_samples/sample.exe"  # Replace with your binary
    GHIDRA_URL = "http://127.0.0.1:13370"
    OUTPUT_DIR = "demo_output"

    # Step 0: Prerequisites check
    print("\n[Step 0/7] Checking prerequisites...")

    # Check if binary exists (for demo, we'll create a simple one)
    if not Path(BINARY_PATH).exists():
        print(f"⚠️  Binary not found: {BINARY_PATH}")
        print("Creating demo binary for testing...")
        create_demo_binary(BINARY_PATH)

    # Check Ghidra server
    print(f"  Checking Ghidra server at {GHIDRA_URL}...")
    try:
        ghidra = GhidraEngine(server_url=GHIDRA_URL, fail_fast=True)
        print("  ✅ Ghidra server is running")
    except GhidraConnectionError as e:
        print(f"  ❌ Ghidra server not running!")
        print(f"\n  Please start Ghidra server in another terminal:")
        print(f"  cd external/ghidra-server")
        print(f"  python ghidra_http_server.py")
        return 1

    # Check Gemini API
    print("  Checking Gemini API configuration...")
    gemini = GeminiEngine()
    if gemini.is_available():
        print("  ✅ Gemini AI is available")
    else:
        print("  ⚠️  Gemini AI not configured (set GEMINI_API_KEY)")
        print("  Continuing without AI enhancement...")

    # Step 1: Initialize recompilation engine
    print("\n[Step 1/7] Initializing recompilation engine...")
    recomp = BinaryRecompilationEngine(
        ghidra_engine=ghidra,
        gemini_engine=gemini if gemini.is_available() else None,
        work_dir=Path(OUTPUT_DIR),
    )
    print("  ✅ Engine initialized")

    # Step 2: Run full pipeline
    print("\n[Step 2/7] Running full reconstruction pipeline...")
    print("  This may take 30-60 seconds for large binaries...")

    try:
        results = await recomp.full_reconstruction_pipeline(
            binary_path=BINARY_PATH, output_dir=Path(OUTPUT_DIR)
        )
    except Exception as e:
        print(f"  ❌ Pipeline failed: {e}")
        import traceback

        traceback.print_exc()
        return 1

    # Step 3: Display source files
    print("\n[Step 3/7] Generated Source Files:")
    for lang, path in results.get("source_files", {}).items():
        if Path(path).exists():
            size = Path(path).stat().st_size
            lines = len(Path(path).read_text().split("\n"))
            print(f"  ✅ {lang.upper()}: {path}")
            print(f"     Size: {size:,} bytes, Lines: {lines}")

            # Show first 20 lines
            if lang == "c":
                code = Path(path).read_text()
                preview = "\n".join(code.split("\n")[:20])
                print(f"\n     Preview:")
                for line in preview.split("\n"):
                    print(f"     {line}")
                print(f"     ... (truncated)")
        else:
            print(f"  ❌ {lang.upper()}: File not created")

    # Step 4: Display compiled binaries
    print("\n[Step 4/7] Compiled Binaries:")
    for compiler, path in results.get("compiled_binaries", {}).items():
        if Path(path).exists():
            size = Path(path).stat().st_size
            print(f"  ✅ {compiler}: {path}")
            print(f"     Size: {size:,} bytes")
        else:
            print(f"  ⚠️  {compiler}: Compilation failed")

    # Step 5: Display validation results
    print("\n[Step 5/7] Behavioral Validation:")
    validation = results.get("validation_results", {})
    similarity = validation.get("similarity_score", 0.0)
    print(f"  Similarity Score: {similarity*100:.1f}%")

    for test in validation.get("tests", []):
        passed = test.get("tests_passed", 0)
        failed = test.get("tests_failed", 0)
        print(f"\n  {test['target']}:")
        print(f"    Passed: {passed}")
        print(f"    Failed: {failed}")
        for note in test.get("notes", []):
            print(f"    - {note}")

    # Step 6: Display vulnerabilities
    print("\n[Step 6/7] Security Vulnerabilities Discovered:")
    vulns = results.get("vulnerabilities", [])

    if vulns:
        # Group by severity
        by_severity = {}
        for v in vulns:
            severity = v.get("severity", "unknown")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(v)

        # Print summary
        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                count = len(by_severity[severity])
                icon = (
                    "🔴"
                    if severity == "critical"
                    else "🟡" if severity == "high" else "🟢"
                )
                print(f"  {icon} {severity.upper()}: {count} vulnerabilities")

        # Show top 5
        print(f"\n  Top Vulnerabilities:")
        for i, v in enumerate(vulns[:5], 1):
            print(f"\n  {i}. {v.get('type').upper()}")
            print(f"     Severity: {v.get('severity')}")
            print(f"     CWE: {v.get('cwe')}")
            print(f"     Location: {v.get('location')}")
            print(f"     Description: {v.get('description')}")
    else:
        print("  ✅ No vulnerabilities detected")

    # Step 7: Display generated exploits
    print("\n[Step 7/7] Proof-of-Concept Exploits Generated:")
    exploits = results.get("exploits", [])

    if exploits:
        for i, exploit in enumerate(exploits, 1):
            print(f"\n  Exploit #{i}: {exploit.get('description')}")
            print(f"  Language: {exploit.get('language')}")

            if exploit.get("steps"):
                print(f"  Steps:")
                for step in exploit["steps"]:
                    print(f"    {step}")

            # Save exploit to file
            exploit_file = Path(OUTPUT_DIR) / f"exploit_{i}.py"
            exploit_file.write_text(exploit.get("exploit_code", ""), encoding="utf-8")
            print(f"  ✅ Saved to: {exploit_file}")

            # Show preview
            code_lines = exploit.get("exploit_code", "").split("\n")[:15]
            print(f"\n  Preview:")
            for line in code_lines:
                print(f"    {line}")
            print(f"    ... (see full exploit in {exploit_file})")
    else:
        print("  No exploits generated")

    # Final summary
    print("\n" + "=" * 80)
    print("RECONSTRUCTION COMPLETE")
    print("=" * 80)
    print(f"\n📁 All results saved to: {OUTPUT_DIR}/")
    print(f"📄 Full report: {OUTPUT_DIR}/RECONSTRUCTION_REPORT.md")
    print(f"💾 JSON results: {OUTPUT_DIR}/reconstruction_results.json")

    print("\n✅ SUCCESS! Binary reconstruction pipeline completed.")
    print("\n🎯 Key Achievements:")
    print(f"   - Decompiled {len(results.get('ghidra_data', {}).get('functions', []))} functions")
    print(f"   - Generated {len(results.get('source_files', {}))} source files")
    print(f"   - Compiled {len(results.get('compiled_binaries', {}))} binaries")
    print(f"   - Found {len(vulns)} security vulnerabilities")
    print(f"   - Created {len(exploits)} working exploits")

    print("\n🔐 Security Impact:")
    print(
        "   This demonstrates how REVENG proves vulnerabilities through working code,"
    )
    print("   not just theoretical analysis. This is the future of security research.")

    return 0


def create_demo_binary(output_path: str):
    """Create a simple demo binary with intentional vulnerabilities for testing"""

    # Create a simple vulnerable C program
    vulnerable_code = """
/* Demo vulnerable program for REVENG testing */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // CWE-120: Buffer overflow
    printf("Input: %s\\n", buffer);
}

void use_after_free_demo() {
    char *ptr = (char*)malloc(64);
    free(ptr);
    printf("%s\\n", ptr);  // CWE-416: Use after free
}

int main(int argc, char *argv[]) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }

    printf("Demo binary for REVENG analysis\\n");
    return 0;
}
"""

    # Save source
    demo_c = Path("demo_vulnerable.c")
    demo_c.write_text(vulnerable_code)

    print(f"  Created vulnerable C source: {demo_c}")
    print(f"  Compiling with GCC...")

    # Compile
    import subprocess

    try:
        result = subprocess.run(
            ["gcc", "-o", output_path, str(demo_c), "-w"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            print(f"  ✅ Demo binary created: {output_path}")
        else:
            print(f"  ❌ Compilation failed: {result.stderr}")
            print(
                f"  You may need to provide your own binary for testing or install GCC"
            )

    except FileNotFoundError:
        print(f"  ⚠️  GCC not found. Using pre-existing binary if available.")


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
