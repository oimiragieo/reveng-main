#!/usr/bin/env python3
"""Generic CLI for app-level reverse engineering across languages."""

from __future__ import annotations

import argparse
import asyncio
from typing import List, Optional

from reveng.app_reverse_engineering import create_default_framework


def create_parser() -> argparse.ArgumentParser:
    """Create the generic app reverse-engineering CLI parser."""
    parser = argparse.ArgumentParser(
        prog="reveng-app",
        description="REVENG app reverse-engineering toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  reveng-app reverse-engineer cli.js -o analysis_js --language javascript --skip-pattern sentry
  reveng-app reverse-engineer test_samples/HelloWorld.java -o analysis_java --language jvm
  reveng-app reverse-engineer app.jar -o analysis_jar
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    reverse_parser = subparsers.add_parser(
        "reverse-engineer",
        help="Generate a SPECS library and artifacts for a supported application",
    )
    reverse_parser.add_argument("input", help="Input application entrypoint or bundle")
    reverse_parser.add_argument("-o", "--output-dir", required=True, dest="output_dir")
    reverse_parser.add_argument(
        "--language",
        default="auto",
        choices=["auto", "javascript", "jvm", "python", "dotnet"],
        help="Language adapter to use; defaults to auto inference",
    )
    reverse_parser.add_argument("--input-root", help="Root directory to inventory before analysis")
    reverse_parser.add_argument(
        "--skip-pattern",
        action="append",
        default=[],
        help="Case-insensitive pattern to exclude from generated excerpts; repeat as needed",
    )
    reverse_parser.add_argument(
        "--max-snippets",
        type=int,
        default=12,
        help="Maximum excerpts to keep per topic",
    )
    reverse_parser.add_argument(
        "--snippet-context",
        type=int,
        default=2,
        help="Neighboring pseudo-lines to keep around a match",
    )
    reverse_parser.add_argument(
        "--run-deobfuscator",
        action="store_true",
        help="Attempt deeper deobfuscation when the selected adapter supports it",
    )

    return parser


async def main(args: Optional[List[str]] = None) -> int:
    """Async entrypoint for the generic app reverse-engineering CLI."""
    parser = create_parser()
    parsed = parser.parse_args(args)

    if parsed.command != "reverse-engineer":
        parser.print_help()
        return 1

    framework = create_default_framework()
    result = await framework.reverse_engineer(
        parsed.input,
        parsed.output_dir,
        language=parsed.language,
        input_root=parsed.input_root,
        skip_patterns=parsed.skip_pattern,
        max_snippets=parsed.max_snippets,
        snippet_context=parsed.snippet_context,
        run_deobfuscator=parsed.run_deobfuscator,
    )

    print(f"Language: {result.language}")
    print(f"Adapter: {result.adapter_name}")
    print(f"Specs root: {result.specs_dir}")
    print(f"Analysis summary: {result.analysis_file}")
    print(f"Recovered source files: {result.source_count}")
    if result.primary_artifacts:
        print("Primary artifacts:")
        for name, artifact in result.primary_artifacts.items():
            print(f"  - {name}: {artifact}")
    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")

    return 0


def console_main() -> int:
    """Synchronous console entrypoint."""
    return asyncio.run(main()) or 0


if __name__ == "__main__":
    raise SystemExit(console_main())
