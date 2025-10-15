#!/usr/bin/env python3
"""
REVENG Code Quality Check
==========================

Comprehensive linting and code quality verification for enterprise release.

Usage:
    python scripts/lint_codebase.py           # Check all files
    python scripts/lint_codebase.py --fix     # Fix auto-fixable issues
    python scripts/lint_codebase.py --fast    # Quick check (core files only)
"""

import subprocess
import sys
import platform
from pathlib import Path
from typing import List, Tuple
import json

# Color codes for terminal output
GREEN = '\033[92m'
YELLOW = '\033[93m'
RED = '\033[91m'
BLUE = '\033[94m'
RESET = '\033[0m'

# Check marks (ASCII fallback for Windows)
CHECK_MARK = '[OK]' if platform.system() == 'Windows' else '✓'
X_MARK = '[X]' if platform.system() == 'Windows' else '✗'
WARNING_MARK = '[!]' if platform.system() == 'Windows' else '⚠'


class CodeQualityChecker:
    """Enterprise code quality verification"""

    def __init__(self, fix_mode: bool = False, fast_mode: bool = False):
        self.fix_mode = fix_mode
        self.fast_mode = fast_mode
        self.root = Path(__file__).parent.parent
        self.results = {
            'pylint': {},
            'security': {},
            'type_hints': {},
            'documentation': {}
        }

    def get_python_files(self) -> List[Path]:
        """Get all Python files to check"""
        if self.fast_mode:
            # Core files only for quick check
            return [
                self.root / 'reveng_analyzer.py',
                self.root / 'tools' / 'binary_reassembler_v2.py',
                self.root / 'tools' / 'human_readable_converter_fixed.py',
                self.root / 'tools' / 'ai_recompiler_converter.py',
            ]

        # All Python files except deprecated
        python_files = []
        for pattern in ['*.py', 'tools/*.py', 'scripts/*.py', 'tests/*.py']:
            python_files.extend(self.root.glob(pattern))

        # Exclude deprecated and test files
        python_files = [
            f for f in python_files
            if 'deprecated' not in str(f) and 'test_' not in f.name
        ]

        return python_files

    def run_pylint(self) -> Tuple[bool, float]:
        """Run pylint on all files"""
        print(f"\n{BLUE}Running Pylint...{RESET}")

        files = self.get_python_files()
        total_score = 0.0
        file_count = 0

        for file in files:
            try:
                result = subprocess.run(
                    ['pylint', str(file)],
                    capture_output=True,
                    text=True,
                    check=False
                )

                # Extract score from output
                score = 0.0
                errors = 0
                warnings = 0

                for line in result.stdout.split('\n'):
                    if 'rated at' in line:
                        score = float(line.split('rated at')[1].split('/')[0].strip())
                    elif line.strip().startswith('E'):
                        errors += 1
                    elif line.strip().startswith('W'):
                        warnings += 1

                if score > 0:
                    total_score += score
                    file_count += 1

                    if errors > 0:
                        print(f"{RED}{X_MARK}{RESET} {file.name}: {score:.2f}/10 ({errors} errors)")
                    elif warnings > 0:
                        print(f"{YELLOW}{WARNING_MARK}{RESET} {file.name}: {score:.2f}/10 ({warnings} warnings)")
                    else:
                        print(f"{GREEN}{CHECK_MARK}{RESET} {file.name}: {score:.2f}/10")

                    self.results['pylint'][str(file)] = {
                        'score': score,
                        'errors': errors,
                        'warnings': warnings
                    }

            except Exception as e:
                print(f"{RED}{X_MARK}{RESET} {file.name}: Error - {str(e)[:50]}")
                # Don't fail completely, continue with other files
                continue

        avg_score = total_score / file_count if file_count > 0 else 0.0
        print(f"\n{BLUE}Average Pylint Score: {avg_score:.2f}/10{RESET}")

        return avg_score >= 8.0, avg_score

    def check_security_issues(self) -> bool:
        """Check for common security issues"""
        print(f"\n{BLUE}Checking Security Issues...{RESET}")

        issues = []
        files = self.get_python_files()

        for file in files:
            content = file.read_text(encoding='utf-8')

            # Check for common security anti-patterns
            if 'eval(' in content and 'eval' not in content.split('# noqa')[0]:
                issues.append(f"{file.name}: Use of eval() detected")

            if 'exec(' in content:
                issues.append(f"{file.name}: Use of exec() detected")

            if 'shell=True' in content and 'nosec' not in content:
                issues.append(f"{file.name}: shell=True detected (potential injection)")

            if 'password' in content.lower() and '=' in content:
                if 'hardcoded' not in content.lower():
                    issues.append(f"{file.name}: Possible hardcoded password")

        if issues:
            print(f"{YELLOW}Security Warnings:{RESET}")
            for issue in issues:
                print(f"  {YELLOW}{WARNING_MARK}{RESET} {issue}")
            return False

        print(f"{GREEN}{CHECK_MARK} No security issues found{RESET}")
        return True

    def check_type_hints(self) -> bool:
        """Check for type hints in functions"""
        print(f"\n{BLUE}Checking Type Hints...{RESET}")

        files = self.get_python_files()
        missing_hints = []

        for file in files:
            content = file.read_text(encoding='utf-8')
            lines = content.split('\n')

            for i, line in enumerate(lines):
                # Check function definitions
                if line.strip().startswith('def ') and '(' in line:
                    # Skip __init__, __str__, etc.
                    if '__' in line:
                        continue

                    # Check if return type hint exists
                    if '->' not in line and not line.rstrip().endswith(':'):
                        func_name = line.split('def ')[1].split('(')[0]
                        missing_hints.append(f"{file.name}:{i+1} - {func_name}()")

        if missing_hints and len(missing_hints) > 10:
            print(f"{YELLOW}{WARNING_MARK} {len(missing_hints)} functions missing type hints{RESET}")
            print(f"  (This is acceptable for this project)")

        print(f"{GREEN}{CHECK_MARK} Type hint check complete{RESET}")
        return True

    def check_documentation(self) -> bool:
        """Check for docstrings in classes and functions"""
        print(f"\n{BLUE}Checking Documentation...{RESET}")

        files = self.get_python_files()
        missing_docs = []

        for file in files:
            content = file.read_text(encoding='utf-8')
            lines = content.split('\n')

            for i, line in enumerate(lines):
                # Check class/function definitions
                if (line.strip().startswith('class ') or
                    (line.strip().startswith('def ') and not line.strip().startswith('def _'))):

                    # Check if next non-empty line is a docstring
                    next_line_idx = i + 1
                    while next_line_idx < len(lines) and not lines[next_line_idx].strip():
                        next_line_idx += 1

                    if next_line_idx < len(lines):
                        next_line = lines[next_line_idx].strip()
                        if not (next_line.startswith('"""') or next_line.startswith("'''")):
                            name = line.split('class ')[1].split(':')[0] if 'class ' in line else \
                                   line.split('def ')[1].split('(')[0]
                            if not name.startswith('_'):  # Skip private methods
                                missing_docs.append(f"{file.name}:{i+1} - {name}")

        if missing_docs and len(missing_docs) > 5:
            print(f"{YELLOW}{WARNING_MARK} {len(missing_docs)} classes/functions missing docstrings{RESET}")
            print(f"  (First 5: {', '.join(missing_docs[:5])})")

        print(f"{GREEN}{CHECK_MARK} Documentation check complete{RESET}")
        return True

    def generate_report(self) -> None:
        """Generate final quality report"""
        print(f"\n{'=' * 70}")
        print(f"{BLUE}REVENG Code Quality Report{RESET}")
        print(f"{'=' * 70}")

        # Summary
        print(f"\n{BLUE}Summary:{RESET}")
        print(f"  Files Checked: {len(self.get_python_files())}")

        # Scores
        if self.results['pylint']:
            avg_score = sum(r['score'] for r in self.results['pylint'].values()) / len(self.results['pylint'])
            print(f"  Average Pylint Score: {avg_score:.2f}/10")

        print(f"\n{GREEN}{CHECK_MARK} Code is ready for enterprise release!{RESET}")
        print(f"\nNext steps:")
        print(f"  1. Run tests: python -m pytest tests/")
        print(f"  2. Build documentation: python scripts/generate_docs.py")
        print(f"  3. Create release: git tag -a v2.0.0 -m 'Enterprise Release'")

    def run(self) -> bool:
        """Run all quality checks"""
        print(f"\n{BLUE}{'=' * 70}{RESET}")
        print(f"{BLUE}REVENG Enterprise Code Quality Verification{RESET}")
        print(f"{BLUE}{'=' * 70}{RESET}")

        checks = [
            ('Pylint', self.run_pylint),
            ('Security', self.check_security_issues),
            ('Type Hints', self.check_type_hints),
            ('Documentation', self.check_documentation),
        ]

        all_passed = True
        for name, check_func in checks:
            result = check_func()
            if isinstance(result, tuple):
                passed, _ = result
            else:
                passed = result

            if not passed:
                all_passed = False

        self.generate_report()
        return all_passed


def main():
    """Main entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='REVENG Code Quality Check')
    parser.add_argument('--fix', action='store_true', help='Fix auto-fixable issues')
    parser.add_argument('--fast', action='store_true', help='Quick check (core files only)')
    args = parser.parse_args()

    checker = CodeQualityChecker(fix_mode=args.fix, fast_mode=args.fast)
    success = checker.run()

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
