#!/usr/bin/env python3
"""Project-aware pytest launcher for REVENG."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
TESTS = ROOT / "tests"

if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def run_suite(name: str, *pytest_args: str) -> int:
    print(f"\n=== {name} ===")
    cmd = [sys.executable, "-m", "pytest", *pytest_args]
    result = subprocess.run(cmd, cwd=ROOT)
    if result.returncode == 0:
        print(f"✓ {name} passed")
    else:
        print(f"✗ {name} failed")
    return result.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run REVENG test suites")
    parser.add_argument(
        "suites",
        nargs="*",
        default=["unit", "integration"],
        help="Named suites to run (unit, integration, security, e2e)",
    )
    parser.add_argument(
        "--extra",
        nargs=argparse.REMAINDER,
        help="Additional arguments forwarded to pytest",
    )
    args = parser.parse_args(argv)

    suite_args = {
        "unit": [str(TESTS / "unit")],
        "integration": [str(TESTS / "integration")],
        "security": [str(TESTS / "security"), str(ROOT / "test_security_simple.py")],
        "e2e": [str(TESTS / "e2e")],
    }

    failures = 0
    for suite in args.suites:
        paths = suite_args.get(suite)
        if not paths:
            print(f"! Unknown test suite: {suite}")
            failures += 1
            continue
        pytest_args = [*paths]
        if args.extra:
            pytest_args.extend(args.extra)
        failures += int(run_suite(suite.capitalize(), *pytest_args) != 0)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
