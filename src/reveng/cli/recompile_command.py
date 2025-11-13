"""
Recompile Command - Binary to Source to Binary Pipeline

Revolutionary command that proves security vulnerabilities by reconstructing
working source code and exploits from binaries.

Author: REVENG Team
Version: 3.0.0
"""

import asyncio
import logging
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


async def recompile_command(
    binary_path: str,
    output_dir: Optional[str] = None,
    ghidra_url: str = "http://127.0.0.1:13370",
    use_gemini: bool = True,
    generate_exploits: bool = True,
    compile_output: bool = True,
) -> int:
    """
    Run the complete binary recompilation pipeline.

    This command demonstrates REVENG's revolutionary capability:
    Binary → Source → Compiled Binary → Exploits

    Args:
        binary_path: Path to binary to analyze
        output_dir: Output directory (default: analysis_<binary_name>)
        ghidra_url: Ghidra Analysis Server URL
        use_gemini: Use Gemini AI for enhancement
        generate_exploits: Generate proof-of-concept exploits
        compile_output: Attempt to compile reconstructed code

    Returns:
        int: Exit code (0 = success, 1 = failure)
    """
    from reveng.integrations.ghidra.ghidra_engine import GhidraEngine
    from reveng.ai.gemini_engine import GeminiEngine
    from reveng.ai.recompilation_engine import BinaryRecompilationEngine

    logger.info("=" * 80)
    logger.info("REVENG BINARY RECOMPILATION PIPELINE")
    logger.info("Proving Security Vulnerabilities Through Code Reconstruction")
    logger.info("=" * 80)

    # Validate binary exists
    if not Path(binary_path).exists():
        logger.error(f"❌ Binary not found: {binary_path}")
        return 1

    # Setup output directory
    if not output_dir:
        output_dir = f"analysis_{Path(binary_path).stem}"
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Initialize engines
    logger.info("\n🔧 Initializing analysis engines...")

    try:
        # Ghidra engine
        logger.info(f"  Connecting to Ghidra at {ghidra_url}...")
        ghidra = GhidraEngine(server_url=ghidra_url, fail_fast=True)
        logger.info("  ✅ Ghidra engine ready")

        # Gemini engine (optional)
        gemini = None
        if use_gemini:
            logger.info("  Initializing Gemini AI engine...")
            gemini = GeminiEngine()
            if gemini.is_available():
                logger.info("  ✅ Gemini AI ready")
            else:
                logger.warning("  ⚠️ Gemini not available (set GEMINI_API_KEY)")

        # Recompilation engine
        logger.info("  Initializing recompilation engine...")
        recomp = BinaryRecompilationEngine(
            ghidra_engine=ghidra, gemini_engine=gemini, work_dir=output_path
        )
        logger.info("  ✅ Recompilation engine ready")

    except Exception as e:
        logger.error(f"❌ Engine initialization failed: {e}")
        return 1

    # Run pipeline
    try:
        results = await recomp.full_reconstruction_pipeline(
            binary_path, output_dir=output_path
        )

        # Print summary
        print_reconstruction_summary(results)

        # Save report
        report_path = output_path / "RECONSTRUCTION_REPORT.md"
        generate_reconstruction_report(results, report_path)
        logger.info(f"\n📄 Full report saved to: {report_path}")

        return 0 if results["status"] == "success" else 1

    except Exception as e:
        logger.error(f"❌ Pipeline failed: {e}", exc_info=True)
        return 1


def print_reconstruction_summary(results: dict):
    """Print a beautiful summary of reconstruction results."""
    print("\n" + "=" * 80)
    print("RECONSTRUCTION SUMMARY")
    print("=" * 80)

    # Source files
    print("\n📝 Generated Source Files:")
    for lang, path in results.get("source_files", {}).items():
        size = Path(path).stat().st_size if Path(path).exists() else 0
        print(f"  ✅ {lang.upper()}: {path} ({size:,} bytes)")

    # Compiled binaries
    print("\n🔨 Compiled Binaries:")
    for target, path in results.get("compiled_binaries", {}).items():
        if Path(path).exists():
            size = Path(path).stat().st_size
            print(f"  ✅ {target}: {path} ({size:,} bytes)")
        else:
            print(f"  ❌ {target}: Compilation failed")

    # Validation
    print("\n✓ Behavioral Validation:")
    validation = results.get("validation_results", {})
    score = validation.get("similarity_score", 0.0)
    print(f"  Similarity Score: {score*100:.1f}%")
    for test in validation.get("tests", []):
        passed = test.get("tests_passed", 0)
        failed = test.get("tests_failed", 0)
        print(f"  {test['target']}: {passed} passed, {failed} failed")

    # Vulnerabilities
    print("\n🔐 Security Vulnerabilities:")
    vulns = results.get("vulnerabilities", [])
    if vulns:
        severity_counts = {}
        for v in vulns:
            severity = v.get("severity", "unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        for severity, count in sorted(severity_counts.items()):
            icon = (
                "🔴" if severity == "critical" else "🟡" if severity == "high" else "🟢"
            )
            print(f"  {icon} {severity.upper()}: {count}")

        print(f"\n  Total: {len(vulns)} vulnerabilities discovered")

        # List top vulnerabilities
        print("\n  Top Vulnerabilities:")
        for v in vulns[:5]:
            print(f"    - {v.get('type')}: {v.get('description')} ({v.get('cwe')})")
    else:
        print("  ✅ No vulnerabilities detected")

    # Exploits
    print("\n💣 Proof-of-Concept Exploits:")
    exploits = results.get("exploits", [])
    if exploits:
        for i, exploit in enumerate(exploits, 1):
            print(f"  {i}. {exploit.get('description', 'Unnamed exploit')}")
            print(f"     Language: {exploit.get('language')}")
        print(f"\n  Total: {len(exploits)} working exploits generated")
    else:
        print("  No exploits generated")

    print("\n" + "=" * 80)
    print(f"Status: {results.get('status', 'unknown').upper()}")
    print("=" * 80 + "\n")


def generate_reconstruction_report(results: dict, output_path: Path):
    """Generate a comprehensive markdown report."""
    report = []

    report.append("# Binary Reconstruction Report")
    report.append("")
    report.append("Generated by REVENG AI-Powered Recompilation Engine")
    report.append("")

    report.append("## Executive Summary")
    report.append("")
    report.append(f"- **Binary**: `{results.get('binary_path')}`")
    report.append(f"- **Status**: {results.get('status').upper()}")
    report.append(f"- **Output Directory**: `{results.get('output_dir')}`")
    report.append("")

    # Ghidra analysis
    ghidra_data = results.get("ghidra_data", {})
    report.append("## Ghidra Analysis")
    report.append("")
    report.append(f"- Functions: {len(ghidra_data.get('functions', []))}")
    report.append(
        f"- Decompiled Functions: {len(ghidra_data.get('decompiled_code', {}))}"
    )
    report.append(f"- Strings: {len(ghidra_data.get('strings', []))}")
    report.append(f"- Imports: {len(ghidra_data.get('imports', []))}")
    report.append("")

    # Source files
    report.append("## Generated Source Code")
    report.append("")
    for lang, path in results.get("source_files", {}).items():
        report.append(f"### {lang.upper()}")
        report.append("")
        report.append(f"**File**: `{path}`")
        if Path(path).exists():
            size = Path(path).stat().st_size
            report.append(f"**Size**: {size:,} bytes")
            report.append("")

            # Include code snippet
            code = Path(path).read_text()
            lines = code.split("\n")[:50]  # First 50 lines
            report.append("```" + lang)
            report.append("\n".join(lines))
            if len(code.split("\n")) > 50:
                report.append("... (truncated)")
            report.append("```")
        report.append("")

    # Vulnerabilities
    report.append("## Security Vulnerabilities")
    report.append("")
    vulns = results.get("vulnerabilities", [])
    if vulns:
        # Group by severity
        by_severity = {}
        for v in vulns:
            severity = v.get("severity", "unknown")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(v)

        for severity in ["critical", "high", "medium", "low"]:
            if severity in by_severity:
                report.append(f"### {severity.upper()} Severity")
                report.append("")
                for v in by_severity[severity]:
                    report.append(f"#### {v.get('type')}")
                    report.append("")
                    report.append(f"- **CWE**: {v.get('cwe')}")
                    report.append(f"- **Location**: {v.get('location')}")
                    report.append(f"- **Description**: {v.get('description')}")
                    if v.get("code"):
                        report.append("")
                        report.append("```c")
                        report.append(v.get("code"))
                        report.append("```")
                    report.append("")
    else:
        report.append("No vulnerabilities detected.")
        report.append("")

    # Exploits
    report.append("## Proof-of-Concept Exploits")
    report.append("")
    exploits = results.get("exploits", [])
    if exploits:
        for i, exploit in enumerate(exploits, 1):
            report.append(f"### Exploit #{i}: {exploit.get('description', 'Unnamed')}")
            report.append("")
            report.append(f"**Language**: {exploit.get('language')}")
            report.append("")

            if exploit.get("steps"):
                report.append("**Steps:**")
                for step in exploit["steps"]:
                    report.append(f"1. {step}")
                report.append("")

            if exploit.get("exploit_code"):
                report.append("**Code:**")
                report.append("```" + exploit.get("language", "python"))
                report.append(exploit["exploit_code"])
                report.append("```")
                report.append("")

            if exploit.get("mitigation"):
                report.append(f"**Mitigation**: {exploit['mitigation']}")
                report.append("")
    else:
        report.append("No exploits generated.")
        report.append("")

    # Disclaimer
    report.append("---")
    report.append("")
    report.append("## Disclaimer")
    report.append("")
    report.append(
        "This report is generated for **educational and defensive security purposes only**."
    )
    report.append(
        "Exploits should only be used in authorized penetration testing environments."
    )
    report.append("")
    report.append("**Generated by**: REVENG AI-Powered Analysis Platform")
    report.append("**Website**: https://github.com/oimiragieo/reveng-main")

    # Write report
    output_path.write_text("\n".join(report), encoding="utf-8")


# Synchronous wrapper for CLI
def run_recompile_command(
    binary_path: str,
    output_dir: Optional[str] = None,
    ghidra_url: str = "http://127.0.0.1:13370",
    use_gemini: bool = True,
) -> int:
    """Synchronous wrapper for asyncio command."""
    return asyncio.run(
        recompile_command(
            binary_path=binary_path,
            output_dir=output_dir,
            ghidra_url=ghidra_url,
            use_gemini=use_gemini,
        )
    )
