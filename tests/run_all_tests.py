#!/usr/bin/env python3
"""
Comprehensive test runner for REVENG platform
"""

import sys
import subprocess
import argparse
from pathlib import Path
from typing import List, Optional


def run_command(cmd: List[str], description: str) -> bool:
    """Run a command and return success status"""
    print(f"\n{'='*60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'='*60}")

    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"✅ {description} - SUCCESS")
        if result.stdout:
            print("STDOUT:")
            print(result.stdout)
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} - FAILED")
        print(f"Return code: {e.returncode}")
        if e.stdout:
            print("STDOUT:")
            print(e.stdout)
        if e.stderr:
            print("STDERR:")
            print(e.stderr)
        return False
    except Exception as e:
        print(f"❌ {description} - ERROR: {e}")
        return False


def run_unit_tests(test_path: Optional[str] = None) -> bool:
    """Run unit tests"""
    if test_path:
        cmd = ["python", "-m", "pytest", f"tests/unit/{test_path}", "-v"]
        description = f"Unit tests for {test_path}"
    else:
        cmd = ["python", "-m", "pytest", "tests/unit/", "-v"]
        description = "All unit tests"

    return run_command(cmd, description)


def run_integration_tests(test_path: Optional[str] = None) -> bool:
    """Run integration tests"""
    if test_path:
        cmd = ["python", "-m", "pytest", f"tests/integration/{test_path}", "-v"]
        description = f"Integration tests for {test_path}"
    else:
        cmd = ["python", "-m", "pytest", "tests/integration/", "-v"]
        description = "All integration tests"

    return run_command(cmd, description)


def run_e2e_tests(test_path: Optional[str] = None) -> bool:
    """Run end-to-end tests"""
    if test_path:
        cmd = ["python", "-m", "pytest", f"tests/e2e/{test_path}", "-v"]
        description = f"E2E tests for {test_path}"
    else:
        cmd = ["python", "-m", "pytest", "tests/e2e/", "-v"]
        description = "All E2E tests"

    return run_command(cmd, description)


def run_all_tests() -> bool:
    """Run all tests"""
    cmd = ["python", "-m", "pytest", "tests/", "-v", "--tb=short"]
    description = "All tests (unit, integration, e2e)"
    return run_command(cmd, description)


def run_linting() -> bool:
    """Run linting checks"""
    cmd = ["python", "-m", "flake8", "src/", "tests/", "--max-line-length=120", "--ignore=E203,W503"]
    description = "Code linting"
    return run_command(cmd, description)


def run_type_checking() -> bool:
    """Run type checking"""
    cmd = ["python", "-m", "mypy", "src/", "--ignore-missing-imports"]
    description = "Type checking"
    return run_command(cmd, description)


def run_security_checks() -> bool:
    """Run security checks"""
    cmd = ["python", "-m", "bandit", "-r", "src/", "-f", "json"]
    description = "Security checks"
    return run_command(cmd, description)


def run_coverage() -> bool:
    """Run tests with coverage"""
    cmd = ["python", "-m", "pytest", "tests/", "--cov=src", "--cov-report=html", "--cov-report=term"]
    description = "Test coverage"
    return run_command(cmd, description)


def run_performance_tests() -> bool:
    """Run performance tests"""
    cmd = ["python", "-m", "pytest", "tests/performance/", "-v", "--benchmark-only"]
    description = "Performance tests"
    return run_command(cmd, description)


def run_specific_test(test_name: str) -> bool:
    """Run a specific test"""
    cmd = ["python", "-m", "pytest", f"tests/{test_name}", "-v"]
    description = f"Specific test: {test_name}"
    return run_command(cmd, description)


def main():
    """Main test runner"""
    parser = argparse.ArgumentParser(description="REVENG Test Runner")
    parser.add_argument("--unit", help="Run unit tests (optionally specify test file)")
    parser.add_argument("--integration", help="Run integration tests (optionally specify test file)")
    parser.add_argument("--e2e", help="Run E2E tests (optionally specify test file)")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--lint", action="store_true", help="Run linting")
    parser.add_argument("--type-check", action="store_true", help="Run type checking")
    parser.add_argument("--security", action="store_true", help="Run security checks")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage")
    parser.add_argument("--performance", action="store_true", help="Run performance tests")
    parser.add_argument("--test", help="Run specific test")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Change to project root directory
    project_root = Path(__file__).parent.parent
    import os
    os.chdir(project_root)

    print("🚀 REVENG Test Runner")
    print(f"Project root: {project_root}")
    print(f"Python version: {sys.version}")

    success = True

    # Run specific tests based on arguments
    if args.unit is not None:
        success &= run_unit_tests(args.unit)
    elif args.integration is not None:
        success &= run_integration_tests(args.integration)
    elif args.e2e is not None:
        success &= run_e2e_tests(args.e2e)
    elif args.test is not None:
        success &= run_specific_test(args.test)
    elif args.all:
        success &= run_all_tests()
    else:
        # Default: run all tests
        success &= run_all_tests()

    # Run additional checks if requested
    if args.lint:
        success &= run_linting()

    if args.type_check:
        success &= run_type_checking()

    if args.security:
        success &= run_security_checks()

    if args.coverage:
        success &= run_coverage()

    if args.performance:
        success &= run_performance_tests()

    # Print final results
    print(f"\n{'='*60}")
    if success:
        print("🎉 All tests passed successfully!")
        sys.exit(0)
    else:
        print("❌ Some tests failed!")
        sys.exit(1)


if __name__ == "__main__":
    main()
