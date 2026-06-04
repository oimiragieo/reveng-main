#!/usr/bin/env python3
"""
Ralph-style loop: re-run JavaScript app reverse-engineering with rotating tool variants
until oracle project_file_recall reaches a target or scores plateau.

This does not magically reach high recall without code changes; it automates
"try baseline -> webcrack -> ..." and records the best attempt for humans/agents to iterate on.

Variant schedule:
  - Built-in defaults (unless --no-default-variants or --variants-json-only)
  - Optional JSON array (--variants-json), merged after defaults unless --variants-json-only
  - Optional heavy profiles: --append-wakaru, --append-js-deobfuscator (slow; needs tools installed)

Example (Windows paths; expand env vars yourself):

    python scripts/ralph_js_oracle_loop.py \\
        --input "%USERPROFILE%\\\\AppData\\\\Roaming\\\\npm\\\\node_modules\\\\@anthropic-ai\\\\claude-code\\\\cli.js" \\
        --oracle C:\\\\dev\\\\projects\\\\claude-code-main \\
        --output-dir reports/js_oracle_ralph_cli \\
        --target-recall 0.80 \\
        --max-attempts 100 \\
        --no-plateau \\
        --variants-json projects/js-oracle-ralph/variants.example.json \\
        --append-wakaru
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from reveng.app_reverse_engineering.ralph_js_loop import (  # noqa: E402
    compose_ralph_variants,
    load_js_ralph_variants_from_json,
    run_ralph_js_oracle_loop,
)


def _resolve_variants(args: argparse.Namespace) -> tuple[list[dict], dict[str, object]]:
    meta: dict[str, object] = {
        "variants_json_only": bool(args.variants_json_only),
        "no_default_variants": bool(args.no_default_variants),
        "variants_json": args.variants_json,
        "append_wakaru": bool(args.append_wakaru),
        "append_js_deobfuscator": bool(args.append_js_deobfuscator),
    }
    extra_json = None
    if args.variants_json:
        p = Path(os.path.expandvars(args.variants_json)).expanduser().resolve()
        if not p.is_file():
            raise FileNotFoundError(f"variants JSON not found: {p}")
        extra_json = load_js_ralph_variants_from_json(p)
        meta["variants_json_resolved"] = str(p)

    if args.variants_json_only:
        if not extra_json:
            raise ValueError("--variants-json-only requires --variants-json")
        return list(extra_json), meta

    use_defaults = not args.no_default_variants
    if (
        not use_defaults
        and not extra_json
        and not args.append_wakaru
        and not args.append_js_deobfuscator
    ):
        raise ValueError(
            "Empty variant schedule: use defaults, or --variants-json, or --append-wakaru / "
            "--append-js-deobfuscator"
        )

    variants = compose_ralph_variants(
        use_defaults=use_defaults,
        extra_from_json=extra_json,
        append_wakaru=args.append_wakaru,
        append_js_deobfuscator=args.append_js_deobfuscator,
    )
    return variants, meta


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--input",
        required=True,
        help="Path to bundled JavaScript entry (e.g. cli.js)",
    )
    parser.add_argument(
        "--oracle",
        required=True,
        help="Oracle source tree directory",
    )
    parser.add_argument(
        "--output-dir",
        default=str(REPO_ROOT / "reports" / "js_oracle_ralph"),
        help="Root directory for attempt_* subfolders + report JSON",
    )
    parser.add_argument(
        "--target-recall",
        type=float,
        default=0.8,
        help="Stop when project_file_recall >= this value (default: 0.8)",
    )
    parser.add_argument(
        "--max-attempts",
        type=int,
        default=100,
        help=(
            "Hard cap on loop iterations (cycles through the variant list). "
            "Pair with --no-plateau to always run this many attempts unless --target-recall is hit first."
        ),
    )
    parser.add_argument(
        "--plateau-attempts",
        type=int,
        default=12,
        help=(
            "With plateau stopping (default): stop after this many consecutive non-improving "
            "attempts (internally raised to at least the variant count). Ignored with --no-plateau."
        ),
    )
    parser.add_argument(
        "--no-plateau",
        action="store_true",
        help=(
            "Do not stop when scores plateau; only --target-recall or --max-attempts ends the loop "
            "(e.g. --max-attempts 100 --no-plateau runs up to 100 full attempts)"
        ),
    )
    parser.add_argument(
        "--until-target",
        action="store_true",
        help=(
            "Long-horizon preset: raise --max-attempts to at least 5000 and plateau budget to at "
            "least max(150, 35 * variant_count). Combine with --no-plateau to prioritize the attempt "
            "budget over plateau stopping."
        ),
    )
    parser.add_argument(
        "--report",
        help="Write full JSON report to this path (default: <output-dir>/ralph_report.json)",
    )
    parser.add_argument(
        "--variants-json",
        metavar="PATH",
        help="JSON array of variant objects (see projects/js-oracle-ralph/variants.example.json)",
    )
    parser.add_argument(
        "--variants-json-only",
        action="store_true",
        help="Use only variants from --variants-json (ignore built-in defaults)",
    )
    parser.add_argument(
        "--no-default-variants",
        action="store_true",
        help="Skip built-in default variant list (still use JSON and/or heavy append flags)",
    )
    parser.add_argument(
        "--append-wakaru",
        action="store_true",
        help="Append a webcrack+wakaru attempt profile (slow; requires wakaru)",
    )
    parser.add_argument(
        "--append-js-deobfuscator",
        action="store_true",
        help="Append a webcrack+js-deobfuscator attempt profile (slow)",
    )
    parser.add_argument(
        "--no-js-behavior-probe",
        action="store_true",
        help="Skip node <entry> --help on reconstructed_project (faster; weaker Ralph tie-breaks)",
    )
    args = parser.parse_args()

    inp = Path(os.path.expandvars(args.input)).expanduser().resolve()
    oracle = Path(os.path.expandvars(args.oracle)).expanduser().resolve()
    if not inp.is_file():
        print(f"Input not found: {inp}", file=sys.stderr)
        return 1
    if not oracle.is_dir():
        print(f"Oracle directory not found: {oracle}", file=sys.stderr)
        return 1

    out_root = Path(os.path.expandvars(args.output_dir)).expanduser().resolve()
    report_path = (
        Path(os.path.expandvars(args.report)).expanduser().resolve()
        if args.report
        else (out_root / "ralph_report.json")
    )

    try:
        variants, schedule_meta = _resolve_variants(args)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

    max_attempts = args.max_attempts
    plateau_attempts = args.plateau_attempts
    stop_on_plateau = not args.no_plateau
    if args.until_target:
        n_var = len(variants)
        max_attempts = max(max_attempts, 5000)
        plateau_attempts = max(plateau_attempts, 150, 35 * n_var)

    report = asyncio.run(
        run_ralph_js_oracle_loop(
            input_path=str(inp),
            oracle_dir=str(oracle),
            output_root=str(out_root),
            target_project_file_recall=args.target_recall,
            max_attempts=max_attempts,
            plateau_attempts=plateau_attempts,
            variants=variants,
            stop_on_plateau=stop_on_plateau,
            run_js_behavior_probe=not args.no_js_behavior_probe,
        )
    )
    report["variant_schedule"] = {
        **schedule_meta,
        "variant_count": len(variants),
        "variant_labels": [v.get("label", f"idx_{i}") for i, v in enumerate(variants)],
        "run_js_behavior_probe": not args.no_js_behavior_probe,
        "until_target": bool(args.until_target),
        "stop_on_plateau": stop_on_plateau,
        "max_attempts_resolved": max_attempts,
        "plateau_attempts_resolved": plateau_attempts,
    }

    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print(json.dumps({k: report[k] for k in report if k != "attempts"}, indent=2))
    print(f"\nFull report: {report_path}", file=sys.stderr)

    if report["best_project_file_recall"] >= args.target_recall:
        return 0
    print(
        f"Target recall {args.target_recall} not reached; best={report['best_project_file_recall']}",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
