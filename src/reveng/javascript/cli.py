#!/usr/bin/env python3
"""
REVENG JavaScript CLI.

This command surface covers the existing deobfuscation workflows and adds a
bundle-oriented reverse-engineering flow for large minified applications.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import List, Optional

# Add src root for direct execution.
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from reveng.javascript import JavaScriptBundleReverseEngineer, JavaScriptDeobfuscator  # noqa: E402
from reveng.javascript.cache_system import DeobfuscationCache  # noqa: E402
from reveng.javascript.malware_detector import MalwareDetector  # noqa: E402


class CLI:
    """Command-line interface for JavaScript workflows."""

    def __init__(self) -> None:
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="reveng-js",
            description="REVENG JavaScript reverse-engineering toolkit",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  reveng-js deobfuscate input.js -o output.js
  reveng-js reverse-engineer-bundle cli.js -o analysis_claude_code --skip-pattern sentry
  reveng-js batch input_dir/ -o output_dir/ --workers 4
  reveng-js analyze suspicious.js --json report.json
  reveng-js scan https://example.com --recover
  reveng-js cache --stats
            """,
        )

        subparsers = parser.add_subparsers(dest="command", help="Command to run")

        deob_parser = subparsers.add_parser("deobfuscate", help="Deobfuscate JavaScript file")
        deob_parser.add_argument("input", help="Input JavaScript file")
        deob_parser.add_argument("-o", "--output", help="Output file")
        deob_parser.add_argument("--ml", action="store_true", help="Use ML variable renaming")
        deob_parser.add_argument(
            "--llm", choices=["gpt4", "claude", "local"], help="Use LLM enhancement"
        )
        deob_parser.add_argument("--no-cache", action="store_true", help="Disable caching")
        deob_parser.add_argument(
            "--format", choices=["js", "json"], default="js", help="Output format"
        )

        bundle_parser = subparsers.add_parser(
            "reverse-engineer-bundle",
            help="Generate a spec library and domain split for a bundled JavaScript app",
        )
        bundle_parser.add_argument("input", help="Input JavaScript bundle")
        bundle_parser.add_argument(
            "-o",
            "--output-dir",
            required=True,
            dest="output_dir",
            help="Output directory for generated SPECS and artifacts",
        )
        bundle_parser.add_argument(
            "--input-root",
            help="Root directory to inventory before analysis (defaults to bundle parent)",
        )
        bundle_parser.add_argument(
            "--skip-pattern",
            action="append",
            default=[],
            help="Case-insensitive pattern to exclude from generated excerpts; repeat as needed",
        )
        bundle_parser.add_argument(
            "--max-snippets",
            type=int,
            default=12,
            help="Maximum excerpts to keep per topic",
        )
        bundle_parser.add_argument(
            "--snippet-context",
            type=int,
            default=2,
            help="Neighboring pseudo-lines to keep around a match",
        )
        bundle_parser.add_argument(
            "--run-deobfuscator",
            action="store_true",
            help="Attempt a deeper deobfuscation pass with the JS pipeline",
        )

        batch_parser = subparsers.add_parser("batch", help="Batch process directory")
        batch_parser.add_argument("input_dir", help="Input directory")
        batch_parser.add_argument("-o", "--output_dir", required=True, help="Output directory")
        batch_parser.add_argument(
            "--workers", type=int, default=4, help="Number of parallel workers"
        )
        batch_parser.add_argument("--ml", action="store_true", help="Use ML variable renaming")
        batch_parser.add_argument("--llm", choices=["gpt4", "claude"], help="Use LLM enhancement")

        analyze_parser = subparsers.add_parser("analyze", help="Analyze for malware")
        analyze_parser.add_argument("input", help="Input JavaScript file")
        analyze_parser.add_argument("--report", help="Generate HTML report")
        analyze_parser.add_argument("--json", help="Export JSON report")

        scan_parser = subparsers.add_parser("scan", help="Scan website for source maps")
        scan_parser.add_argument("url", help="Website URL")
        scan_parser.add_argument("--recover", action="store_true", help="Recover sources from maps")
        scan_parser.add_argument("-o", "--output_dir", help="Output directory for recovered sources")

        cache_parser = subparsers.add_parser("cache", help="Manage cache")
        cache_parser.add_argument("--stats", action="store_true", help="Show cache statistics")
        cache_parser.add_argument("--clear", action="store_true", help="Clear cache")
        cache_parser.add_argument(
            "--cleanup",
            type=int,
            metavar="DAYS",
            help="Remove entries older than N days",
        )

        return parser

    async def run(self, args: Optional[List[str]] = None) -> int:
        parsed = self.parser.parse_args(args)

        if not parsed.command:
            self.parser.print_help()
            return 1

        if parsed.command == "deobfuscate":
            return await self._cmd_deobfuscate(parsed)
        if parsed.command == "reverse-engineer-bundle":
            return await self._cmd_reverse_engineer_bundle(parsed)
        if parsed.command == "batch":
            return await self._cmd_batch(parsed)
        if parsed.command == "analyze":
            return await self._cmd_analyze(parsed)
        if parsed.command == "scan":
            return await self._cmd_scan(parsed)
        if parsed.command == "cache":
            return self._cmd_cache(parsed)

        return 1

    async def _cmd_deobfuscate(self, args: argparse.Namespace) -> int:
        print(f"Deobfuscating: {args.input}")
        code = Path(args.input).read_text(encoding="utf-8", errors="replace")

        cache = None if args.no_cache else DeobfuscationCache()
        if cache:
            cached = cache.get(code)
            if cached:
                print(f"Found in cache (saved {cached.processing_time:.2f}s)")
                result_code = cached.deobfuscated_code
                confidence = cached.confidence
            else:
                result_code, confidence = await self._deobfuscate_with_cache(code, args, cache)
        else:
            deob = JavaScriptDeobfuscator(
                use_ml=args.ml,
                use_llm=bool(args.llm),
                llm_provider=args.llm if args.llm else "gpt4",
            )
            result = await deob.deobfuscate(code)
            result_code = result.deobfuscated_code
            confidence = result.confidence

        print(f"Deobfuscation complete (confidence: {confidence:.1%})")

        if args.output:
            output_path = Path(args.output)
            if args.format == "json":
                output_path.write_text(
                    json.dumps(
                        {
                            "original_file": args.input,
                            "deobfuscated_code": result_code,
                            "confidence": confidence,
                        },
                        indent=2,
                    ),
                    encoding="utf-8",
                )
            else:
                output_path.write_text(result_code, encoding="utf-8")
            print(f"Saved to: {output_path}")
        else:
            print("\n" + "=" * 70)
            print(result_code)
            print("=" * 70)

        return 0

    async def _cmd_reverse_engineer_bundle(self, args: argparse.Namespace) -> int:
        print(f"Reverse engineering bundle: {args.input}")

        engine = JavaScriptBundleReverseEngineer(
            skip_patterns=args.skip_pattern,
            max_snippets_per_topic=args.max_snippets,
            snippet_context=args.snippet_context,
            run_deobfuscator=args.run_deobfuscator,
        )
        result = await engine.reverse_engineer_bundle(
            args.input,
            args.output_dir,
            input_root=args.input_root,
        )

        print(f"  Specs root: {result.specs_dir}")
        print(f"  Normalized bundle: {result.normalized_bundle}")
        print(f"  Analysis summary: {result.analysis_file}")
        print(f"  Topic specs: {len(result.topic_files)}")
        print(f"  Domain splits: {len(result.domain_files)}")
        print(f"  Obfuscation types: {', '.join(result.obfuscation_types) or 'none detected'}")

        if result.bundler_signals:
            print("  Bundler signals:")
            for name, count in result.bundler_signals.items():
                print(f"    - {name}: {count}")

        if result.cli_flags:
            print(f"  CLI flags: {', '.join(result.cli_flags[:10])}")
        if result.slash_commands:
            print(f"  Slash commands: {', '.join(result.slash_commands[:10])}")
        if result.deep_deobfuscation_output:
            print(f"  Deep deobfuscation output: {result.deep_deobfuscation_output}")
        if result.warnings:
            print("  Warnings:")
            for warning in result.warnings:
                print(f"    - {warning}")

        return 0

    async def _deobfuscate_with_cache(
        self,
        code: str,
        args: argparse.Namespace,
        cache: DeobfuscationCache,
    ) -> tuple[str, float]:
        import time

        deob = JavaScriptDeobfuscator(
            use_ml=args.ml,
            use_llm=bool(args.llm),
            llm_provider=args.llm if args.llm else "gpt4",
        )

        start = time.time()
        result = await deob.deobfuscate(code)
        processing_time = time.time() - start
        cache.put(
            code,
            result.deobfuscated_code,
            result.confidence,
            [item.value for item in result.obfuscation_types],
            processing_time,
        )
        return result.deobfuscated_code, result.confidence

    async def _cmd_batch(self, args: argparse.Namespace) -> int:
        print(f"Batch processing: {args.input_dir}")
        input_dir = Path(args.input_dir)
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"Found {len(list(input_dir.glob('**/*.js')))} JavaScript files")

        from reveng.javascript.batch_processor import BatchProcessor

        processor = BatchProcessor(
            use_ml=args.ml,
            use_llm=bool(args.llm),
            llm_provider=args.llm if args.llm else "gpt4",
            max_workers=args.workers,
        )
        results = await processor.process_directory(str(input_dir), str(output_dir))
        successful = sum(1 for result in results if result.success)
        print(f"Completed: {successful}/{len(results)} files processed successfully")
        return 0

    async def _cmd_analyze(self, args: argparse.Namespace) -> int:
        print(f"Analyzing: {args.input}")
        code = Path(args.input).read_text(encoding="utf-8", errors="replace")

        deob = JavaScriptDeobfuscator(use_ml=True, use_llm=False)
        deob_result = await deob.deobfuscate(code)
        detector = MalwareDetector()
        malware_result = detector.analyze(deob_result.deobfuscated_code)

        print("\n" + "=" * 70)
        print(malware_result.summary)
        print("=" * 70)

        if malware_result.indicators:
            print(f"\nThreat Indicators ({len(malware_result.indicators)}):")
            for index, indicator in enumerate(malware_result.indicators[:10], start=1):
                print(f"  {index}. [{indicator.level.value.upper()}] {indicator.description}")

        if malware_result.recommendations:
            print("\nRecommendations:")
            for recommendation in malware_result.recommendations:
                print(f"  - {recommendation}")

        if args.report:
            from reveng.javascript.report_generator import ReportGenerator

            generator = ReportGenerator()
            generator.generate_html(malware_result, args.report)
            print(f"\nHTML report saved to: {args.report}")

        if args.json:
            Path(args.json).write_text(
                json.dumps(
                    {
                        "is_malicious": malware_result.is_malicious,
                        "threat_score": malware_result.threat_score,
                        "indicators": [
                            {
                                "category": indicator.category.value,
                                "level": indicator.level.value,
                                "description": indicator.description,
                            }
                            for indicator in malware_result.indicators
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
            print(f"JSON report saved to: {args.json}")

        return 0

    async def _cmd_scan(self, args: argparse.Namespace) -> int:
        print(f"Scanning: {args.url}")
        from reveng.javascript.source_map_recoverer import SourceMapRecoverer

        recoverer = SourceMapRecoverer()
        maps = recoverer.find_sourcemaps(args.url)
        if not maps:
            print("No source maps found")
            return 1

        print(f"Found {len(maps)} source map(s):")
        for map_url in maps:
            print(f"  - {map_url}")

        if args.recover:
            print("\nRecovering sources...")
            for map_url in maps:
                result = recoverer.recover(map_url)
                if result.success:
                    print(f"Recovered {len(result.sources)} source files")
                    if args.output_dir:
                        recoverer.save_directory(result.sources, args.output_dir)
                        print(f"Saved to: {args.output_dir}")
                else:
                    print(f"Recovery failed: {result.error}")

        return 0

    def _cmd_cache(self, args: argparse.Namespace) -> int:
        cache = DeobfuscationCache()

        if args.stats:
            stats = cache.get_stats()
            print("\nCache Statistics:")
            print(f"  Memory entries: {stats['memory_entries']}")
            print(f"  Disk entries: {stats['disk_entries']}")
            print(f"  Disk size: {stats['disk_size_mb']:.2f} MB")
            print(f"  Cache hits: {stats['hits']}")
            print(f"  Cache misses: {stats['misses']}")
            print(f"  Hit rate: {stats['hit_rate']:.1%}")
            print(f"  Evictions: {stats['evictions']}")

        if args.clear:
            cache.clear()
            print("Cache cleared")

        if args.cleanup:
            removed = cache.cleanup_old_entries(args.cleanup)
            print(f"Cleaned up {removed} old entries")

        return 0


async def main(args: Optional[List[str]] = None) -> int:
    """Async entry point used by tests and wrappers."""
    cli = CLI()
    return await cli.run(args)


def console_main() -> int:
    """Synchronous console entry point."""
    return asyncio.run(main()) or 0


if __name__ == "__main__":
    raise SystemExit(console_main())
