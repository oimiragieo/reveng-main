#!/usr/bin/env python3
"""CLI for the JS recovery toolkit (Wave 7)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="REVENG JS recovery toolkit")
    parser.add_argument("--bundle", type=Path, help="JS/TS bundle path")
    parser.add_argument("--map", type=Path, dest="sourcemap", help="Sibling or stale .map")
    parser.add_argument("--oracle", type=Path, help="Oracle source tree for behavior overlap")
    parser.add_argument("--bun-binary", type=Path, help="Optional Bun SEA executable")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--run-external",
        action="store_true",
        help="Also try npx webcrack / @wakaru/cli (network; non-hermetic)",
    )
    args = parser.parse_args(argv)

    # Ensure src layout importable when run from repo
    repo_src = Path(__file__).resolve().parents[1] / "src"
    if repo_src.is_dir() and str(repo_src) not in sys.path:
        sys.path.insert(0, str(repo_src))

    from reveng.app_reverse_engineering.js_recovery_toolkit import run_recovery_toolkit

    report = run_recovery_toolkit(
        output_dir=args.output_dir,
        bundle=args.bundle,
        sourcemap=args.sourcemap,
        oracle_dir=args.oracle,
        bun_binary=args.bun_binary,
        run_external=bool(args.run_external),
    )
    print(json.dumps(report.to_serializable(), indent=2)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
