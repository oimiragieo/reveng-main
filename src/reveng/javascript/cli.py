#!/usr/bin/env python3
"""
REVENG v6.0 - JavaScript Deobfuscation CLI

World-class command-line interface for JavaScript deobfuscation.

Features:
- Single file or batch processing
- Multiple output formats (JS, JSON, HTML, PDF)
- Malware analysis and reporting
- Caching for performance
- Progress tracking
- CI/CD integration

Usage:
    reveng-js deobfuscate input.js -o output.js
    reveng-js batch input_dir/ -o output_dir/
    reveng-js analyze malware.js --report report.html
    reveng-js scan https://example.com/app.js
"""

import argparse
import asyncio
import sys
import json
from pathlib import Path
from typing import List

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from reveng.javascript import JavaScriptDeobfuscator
from reveng.javascript.malware_detector import MalwareDetector
from reveng.javascript.cache_system import DeobfuscationCache


class CLI:
    """Command-line interface"""

    def __init__(self):
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog="reveng-js",
            description="REVENG v6.0 - World-Class JavaScript Deobfuscation",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Deobfuscate single file
  reveng-js deobfuscate input.js -o output.js

  # Use ML + LLM (best quality)
  reveng-js deobfuscate input.js --ml --llm gpt4 -o output.js

  # Batch process directory
  reveng-js batch input_dir/ -o output_dir/ --workers 4

  # Malware analysis with report
  reveng-js analyze malware.js --report report.html

  # Scan website for source maps
  reveng-js scan https://example.com --recover

  # Show cache stats
  reveng-js cache --stats

For more information: https://github.com/oimiragieo/reveng-main
            """,
        )

        subparsers = parser.add_subparsers(dest="command", help="Command to run")

        # Deobfuscate command
        deob_parser = subparsers.add_parser(
            "deobfuscate", help="Deobfuscate JavaScript file"
        )
        deob_parser.add_argument("input", help="Input JavaScript file")
        deob_parser.add_argument("-o", "--output", help="Output file")
        deob_parser.add_argument(
            "--ml", action="store_true", help="Use ML variable renaming"
        )
        deob_parser.add_argument(
            "--llm", choices=["gpt4", "claude", "local"], help="Use LLM enhancement"
        )
        deob_parser.add_argument(
            "--no-cache", action="store_true", help="Disable caching"
        )
        deob_parser.add_argument(
            "--format", choices=["js", "json"], default="js", help="Output format"
        )

        # Batch command
        batch_parser = subparsers.add_parser("batch", help="Batch process directory")
        batch_parser.add_argument("input_dir", help="Input directory")
        batch_parser.add_argument(
            "-o", "--output_dir", required=True, help="Output directory"
        )
        batch_parser.add_argument(
            "--workers", type=int, default=4, help="Number of parallel workers"
        )
        batch_parser.add_argument(
            "--ml", action="store_true", help="Use ML variable renaming"
        )
        batch_parser.add_argument(
            "--llm", choices=["gpt4", "claude"], help="Use LLM enhancement"
        )

        # Analyze command
        analyze_parser = subparsers.add_parser("analyze", help="Analyze for malware")
        analyze_parser.add_argument("input", help="Input JavaScript file")
        analyze_parser.add_argument("--report", help="Generate HTML report")
        analyze_parser.add_argument("--json", help="Export JSON report")

        # Scan command
        scan_parser = subparsers.add_parser("scan", help="Scan website for source maps")
        scan_parser.add_argument("url", help="Website URL")
        scan_parser.add_argument(
            "--recover", action="store_true", help="Recover sources from maps"
        )
        scan_parser.add_argument(
            "-o", "--output_dir", help="Output directory for recovered sources"
        )

        # Cache command
        cache_parser = subparsers.add_parser("cache", help="Manage cache")
        cache_parser.add_argument(
            "--stats", action="store_true", help="Show cache statistics"
        )
        cache_parser.add_argument("--clear", action="store_true", help="Clear cache")
        cache_parser.add_argument(
            "--cleanup",
            type=int,
            metavar="DAYS",
            help="Remove entries older than N days",
        )

        return parser

    async def run(self, args: List[str] = None):
        """Run CLI"""
        parsed = self.parser.parse_args(args)

        if not parsed.command:
            self.parser.print_help()
            return

        # Dispatch to command handler
        if parsed.command == "deobfuscate":
            await self._cmd_deobfuscate(parsed)
        elif parsed.command == "batch":
            await self._cmd_batch(parsed)
        elif parsed.command == "analyze":
            await self._cmd_analyze(parsed)
        elif parsed.command == "scan":
            await self._cmd_scan(parsed)
        elif parsed.command == "cache":
            self._cmd_cache(parsed)

    async def _cmd_deobfuscate(self, args):
        """Deobfuscate command"""
        print(f"🔄 Deobfuscating: {args.input}")

        # Read input
        with open(args.input, "r") as f:
            code = f.read()

        # Check cache
        cache = None if args.no_cache else DeobfuscationCache()

        if cache:
            cached = cache.get(code)
            if cached:
                print(f"✅ Found in cache (saved {cached.processing_time:.2f}s)")
                result_code = cached.deobfuscated_code
                confidence = cached.confidence
            else:
                result_code, confidence = await self._deobfuscate_with_cache(
                    code, args, cache
                )
        else:
            # Deobfuscate
            deob = JavaScriptDeobfuscator(
                use_ml=args.ml,
                use_llm=bool(args.llm),
                llm_provider=args.llm if args.llm else "gpt4",
            )

            result = await deob.deobfuscate(code)
            result_code = result.deobfuscated_code
            confidence = result.confidence

        print(f"✅ Deobfuscation complete (confidence: {confidence:.1%})")

        # Output
        if args.output:
            if args.format == "json":
                output_data = {
                    "original_file": args.input,
                    "deobfuscated_code": result_code,
                    "confidence": confidence,
                }
                with open(args.output, "w") as f:
                    json.dump(output_data, f, indent=2)
            else:
                with open(args.output, "w") as f:
                    f.write(result_code)

            print(f"💾 Saved to: {args.output}")
        else:
            print("\n" + "=" * 70)
            print(result_code)
            print("=" * 70)

    async def _deobfuscate_with_cache(self, code, args, cache):
        """Deobfuscate and cache result"""
        import time

        deob = JavaScriptDeobfuscator(
            use_ml=args.ml,
            use_llm=bool(args.llm),
            llm_provider=args.llm if args.llm else "gpt4",
        )

        start = time.time()
        result = await deob.deobfuscate(code)
        processing_time = time.time() - start

        # Cache result
        cache.put(
            code,
            result.deobfuscated_code,
            result.confidence,
            [t.value for t in result.obfuscation_types],
            processing_time,
        )

        return result.deobfuscated_code, result.confidence

    async def _cmd_batch(self, args):
        """Batch processing command"""
        print(f"🔄 Batch processing: {args.input_dir}")

        input_dir = Path(args.input_dir)
        output_dir = Path(args.output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Find all .js files
        js_files = list(input_dir.glob("**/*.js"))

        print(f"📂 Found {len(js_files)} JavaScript files")

        # Process in parallel
        from reveng.javascript.batch_processor import BatchProcessor

        processor = BatchProcessor(
            use_ml=args.ml,
            use_llm=bool(args.llm),
            llm_provider=args.llm if args.llm else "gpt4",
            max_workers=args.workers,
        )

        results = await processor.process_directory(str(input_dir), str(output_dir))

        # Summary
        successful = sum(1 for r in results if r.success)
        print(
            f"\n✅ Completed: {successful}/{len(results)} files processed successfully"
        )

    async def _cmd_analyze(self, args):
        """Analyze for malware"""
        print(f"🔍 Analyzing: {args.input}")

        # Read code
        with open(args.input, "r") as f:
            code = f.read()

        # Deobfuscate first
        deob = JavaScriptDeobfuscator(use_ml=True, use_llm=False)
        deob_result = await deob.deobfuscate(code)

        # Malware detection
        detector = MalwareDetector()
        malware_result = detector.analyze(deob_result.deobfuscated_code)

        # Print summary
        print(f"\n{'='*70}")
        print(malware_result.summary)
        print(f"{'='*70}")

        if malware_result.indicators:
            print(f"\n🚨 Threat Indicators ({len(malware_result.indicators)}):")
            for i, indicator in enumerate(malware_result.indicators[:10], 1):
                print(
                    f"  {i}. [{indicator.level.value.upper()}] {indicator.description}"
                )

        if malware_result.recommendations:
            print(f"\n💡 Recommendations:")
            for rec in malware_result.recommendations:
                print(f"  • {rec}")

        # Generate report
        if args.report:
            from reveng.javascript.report_generator import ReportGenerator

            generator = ReportGenerator()
            generator.generate_html(malware_result, args.report)
            print(f"\n📄 HTML report saved to: {args.report}")

        if args.json:
            with open(args.json, "w") as f:
                json.dump(
                    {
                        "is_malicious": malware_result.is_malicious,
                        "threat_score": malware_result.threat_score,
                        "indicators": [
                            {
                                "category": ind.category.value,
                                "level": ind.level.value,
                                "description": ind.description,
                            }
                            for ind in malware_result.indicators
                        ],
                    },
                    f,
                    indent=2,
                )
            print(f"📄 JSON report saved to: {args.json}")

    async def _cmd_scan(self, args):
        """Scan website for source maps"""
        print(f"🔍 Scanning: {args.url}")

        from reveng.javascript.source_map_recoverer import SourceMapRecoverer

        recoverer = SourceMapRecoverer()

        # Find source maps
        maps = recoverer.find_sourcemaps(args.url)

        if not maps:
            print("❌ No source maps found")
            return

        print(f"✅ Found {len(maps)} source map(s):")
        for map_url in maps:
            print(f"  • {map_url}")

        if args.recover:
            print(f"\n🔄 Recovering sources...")

            for map_url in maps:
                result = recoverer.recover(map_url)

                if result.success:
                    print(f"✅ Recovered {len(result.sources)} source files")

                    if args.output_dir:
                        recoverer.save_directory(result.sources, args.output_dir)
                        print(f"💾 Saved to: {args.output_dir}")
                else:
                    print(f"❌ Recovery failed: {result.error}")

    def _cmd_cache(self, args):
        """Cache management"""
        cache = DeobfuscationCache()

        if args.stats:
            stats = cache.get_stats()
            print(f"\n📊 Cache Statistics:")
            print(f"  Memory entries: {stats['memory_entries']}")
            print(f"  Disk entries: {stats['disk_entries']}")
            print(f"  Disk size: {stats['disk_size_mb']:.2f} MB")
            print(f"  Cache hits: {stats['hits']}")
            print(f"  Cache misses: {stats['misses']}")
            print(f"  Hit rate: {stats['hit_rate']:.1%}")
            print(f"  Evictions: {stats['evictions']}")

        if args.clear:
            cache.clear()
            print("✅ Cache cleared")

        if args.cleanup:
            removed = cache.cleanup_old_entries(args.cleanup)
            print(f"✅ Cleaned up {removed} old entries")


async def main():
    """Main entry point"""
    cli = CLI()
    await cli.run()


if __name__ == "__main__":
    asyncio.run(main())
