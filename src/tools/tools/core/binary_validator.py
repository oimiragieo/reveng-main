#!/usr/bin/env python3
"""
REVENG Binary Validator
========================

Validates rebuilt binaries against originals.

Checks:
- Checksum comparison (SHA256)
- Size comparison
- Section comparison (code, data, resources)
- Behavioral comparison (smoke tests)
- Confidence scoring
"""

import hashlib
import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional
import platform

logger = logging.getLogger(__name__)

# Try to import LIEF for binary parsing
try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False
    logger.warning("LIEF not available - section comparison disabled")


class BinaryValidator:
    """Validate rebuilt binaries"""

    def __init__(self, validation_config=None):
        """Initialize validator"""
        self.config = validation_config

    def validate_rebuild(
        self,
        original_path: Path,
        rebuilt_path: Path,
        smoke_tests: Optional[List[Dict]] = None
    ) -> Dict:
        """
        Validate rebuilt binary against original

        Returns validation report with:
        - Checksums
        - Size comparison
        - Section comparison (if LIEF available)
        - Smoke test results
        - Overall verdict
        """
        report = {
            'original': self._get_binary_info(original_path),
            'rebuilt': self._get_binary_info(rebuilt_path),
            'comparison': {},
            'smoke_tests': {},
            'verdict': {}
        }

        # Size comparison
        report['comparison']['size_match'] = (
            report['original']['size'] == report['rebuilt']['size']
        )
        report['comparison']['size_diff'] = abs(
            report['original']['size'] - report['rebuilt']['size']
        )

        # Checksum comparison
        report['comparison']['checksum_match'] = (
            report['original']['sha256'] == report['rebuilt']['sha256']
        )

        # Section comparison (if LIEF available)
        if HAS_LIEF and rebuilt_path.exists():
            report['comparison']['sections'] = self._compare_sections(
                original_path,
                rebuilt_path
            )

        # Run smoke tests
        if smoke_tests or (self.config and self.config.smoke_tests):
            tests_to_run = smoke_tests or self.config.smoke_tests
            report['smoke_tests'] = self._run_smoke_tests(
                rebuilt_path,
                tests_to_run
            )

        # Generate verdict
        report['verdict'] = self._generate_verdict(report)

        return report

    def _get_binary_info(self, binary_path: Path) -> Dict:
        """Get binary information"""
        if not binary_path.exists():
            return {
                'path': str(binary_path),
                'exists': False,
                'size': 0,
                'sha256': None
            }

        # Calculate checksum
        sha256_hash = hashlib.sha256()
        with open(binary_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256_hash.update(chunk)

        info = {
            'path': str(binary_path),
            'exists': True,
            'size': binary_path.stat().st_size,
            'sha256': sha256_hash.hexdigest()
        }

        # Get sections if LIEF available
        if HAS_LIEF:
            try:
                binary = lief.parse(str(binary_path))
                if binary:
                    info['sections'] = {}
                    for section in binary.sections:
                        info['sections'][section.name] = {
                            'size': section.size,
                            'virtual_address': section.virtual_address
                        }
            except Exception as e:
                logger.warning(f"Could not parse binary with LIEF: {e}")

        return info

    def _compare_sections(self, original_path: Path, rebuilt_path: Path) -> Dict:
        """Compare binary sections"""
        try:
            original = lief.parse(str(original_path))
            rebuilt = lief.parse(str(rebuilt_path))

            if not original or not rebuilt:
                return {'error': 'Could not parse binaries'}

            section_matches = {}

            # Get all section names
            orig_sections = {s.name: s for s in original.sections}
            rebuilt_sections = {s.name: s for s in rebuilt.sections}

            all_sections = set(orig_sections.keys()) | set(rebuilt_sections.keys())

            for section_name in all_sections:
                orig_section = orig_sections.get(section_name)
                rebuilt_section = rebuilt_sections.get(section_name)

                if not orig_section:
                    section_matches[section_name] = 'missing_in_original'
                elif not rebuilt_section:
                    section_matches[section_name] = 'missing_in_rebuilt'
                else:
                    # Compare sizes
                    size_match = orig_section.size == rebuilt_section.size
                    section_matches[section_name] = 'match' if size_match else 'size_mismatch'

            return section_matches

        except Exception as e:
            logger.error(f"Error comparing sections: {e}")
            return {'error': str(e)}

    def _run_smoke_tests(self, binary_path: Path, smoke_tests: List) -> Dict:
        """Run smoke tests on binary"""
        if not binary_path.exists():
            return {
                'tests_run': 0,
                'tests_passed': 0,
                'tests_failed': 0,
                'results': []
            }

        results = {
            'tests_run': len(smoke_tests),
            'tests_passed': 0,
            'tests_failed': 0,
            'results': []
        }

        for test in smoke_tests:
            test_result = self._run_single_smoke_test(binary_path, test)
            results['results'].append(test_result)

            if test_result['passed']:
                results['tests_passed'] += 1
            else:
                results['tests_failed'] += 1

        return results

    def _run_single_smoke_test(self, binary_path: Path, test) -> Dict:
        """Run a single smoke test"""
        # Handle both dict and SmokeTest object
        if hasattr(test, 'args'):
            args = test.args
            expected_exit_code = test.expected_exit_code
            timeout = test.timeout
            description = test.description
        else:
            args = test.get('args', [])
            expected_exit_code = test.get('expected_exit_code')
            timeout = test.get('timeout', 5)
            description = test.get('description', 'Smoke test')

        result = {
            'description': description,
            'args': args,
            'passed': False,
            'exit_code': None,
            'stdout': None,
            'stderr': None,
            'error': None
        }

        try:
            # Run binary with args
            proc = subprocess.run(
                [str(binary_path)] + args,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            result['exit_code'] = proc.returncode
            result['stdout'] = proc.stdout[:500]  # Limit output
            result['stderr'] = proc.stderr[:500]

            # Check if passed
            if expected_exit_code is None:
                # Any exit code is OK
                result['passed'] = True
            else:
                result['passed'] = (proc.returncode == expected_exit_code)

        except subprocess.TimeoutExpired:
            result['error'] = f'Timeout after {timeout}s'
        except Exception as e:
            result['error'] = str(e)

        return result

    def _generate_verdict(self, report: Dict) -> Dict:
        """Generate overall verdict"""
        verdict = {
            'valid': True,
            'confidence': 1.0,
            'warnings': [],
            'errors': []
        }

        # Check if rebuilt binary exists
        if not report['rebuilt']['exists']:
            verdict['valid'] = False
            verdict['confidence'] = 0.0
            verdict['errors'].append('Rebuilt binary does not exist')
            return verdict

        # Size mismatch warning
        size_diff = report['comparison']['size_diff']
        if size_diff > 0:
            pct_diff = (size_diff / report['original']['size']) * 100
            if pct_diff > 10:
                verdict['warnings'].append(
                    f"Size differs by {size_diff} bytes ({pct_diff:.1f}%)"
                )
                verdict['confidence'] -= 0.2
            elif pct_diff > 1:
                verdict['warnings'].append(
                    f"Size differs by {size_diff} bytes ({pct_diff:.2f}%)"
                )
                verdict['confidence'] -= 0.05

        # Checksum mismatch warning
        if not report['comparison']['checksum_match']:
            verdict['warnings'].append('Checksum does not match original')
            verdict['confidence'] -= 0.1

        # Smoke test failures
        smoke_tests = report.get('smoke_tests', {})
        if smoke_tests:
            tests_run = smoke_tests.get('tests_run', 0)
            tests_failed = smoke_tests.get('tests_failed', 0)

            if tests_run > 0:
                pass_rate = (tests_run - tests_failed) / tests_run

                if pass_rate < 0.5:
                    verdict['errors'].append(
                        f"More than 50% of smoke tests failed ({tests_failed}/{tests_run})"
                    )
                    verdict['confidence'] -= 0.3
                elif tests_failed > 0:
                    verdict['warnings'].append(
                        f"{tests_failed}/{tests_run} smoke tests failed"
                    )
                    verdict['confidence'] -= 0.1 * (tests_failed / tests_run)

        # Section mismatches
        sections = report['comparison'].get('sections', {})
        if sections:
            mismatches = [name for name, status in sections.items()
                         if status != 'match']
            if mismatches:
                verdict['warnings'].append(
                    f"Section mismatches: {', '.join(mismatches[:3])}"
                )
                verdict['confidence'] -= 0.05 * min(len(mismatches), 5)

        # Clamp confidence to [0, 1]
        verdict['confidence'] = max(0.0, min(1.0, verdict['confidence']))

        # Determine if valid
        if verdict['errors']:
            verdict['valid'] = False
        elif verdict['confidence'] < 0.5:
            verdict['valid'] = False
            verdict['errors'].append('Confidence too low (<0.5)')

        return verdict

    def save_report(self, report: Dict, output_path: Path):
        """Save validation report to JSON"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Validation report saved to {output_path}")


# Example usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    validator = BinaryValidator()

    if len(sys.argv) >= 3:
        original = Path(sys.argv[1])
        rebuilt = Path(sys.argv[2])
    else:
        print("Usage: python binary_validator.py original.exe rebuilt.exe")
        sys.exit(1)

    # Run validation
    print(f"Validating: {rebuilt} against {original}")
    print()

    report = validator.validate_rebuild(original, rebuilt)

    # Print results
    print("=" * 60)
    print("VALIDATION REPORT")
    print("=" * 60)
    print(f"Original: {report['original']['path']}")
    print(f"  Size: {report['original']['size']:,} bytes")
    print(f"  SHA256: {report['original']['sha256']}")
    print()
    print(f"Rebuilt: {report['rebuilt']['path']}")
    print(f"  Size: {report['rebuilt']['size']:,} bytes")
    print(f"  SHA256: {report['rebuilt']['sha256']}")
    print()
    print("Comparison:")
    print(f"  Size match: {report['comparison']['size_match']}")
    if not report['comparison']['size_match']:
        print(f"  Size diff: {report['comparison']['size_diff']:,} bytes")
    print(f"  Checksum match: {report['comparison']['checksum_match']}")
    print()
    print("Verdict:")
    print(f"  Valid: {report['verdict']['valid']}")
    print(f"  Confidence: {report['verdict']['confidence']:.2f}")
    if report['verdict']['warnings']:
        print("  Warnings:")
        for warning in report['verdict']['warnings']:
            print(f"    - {warning}")
    if report['verdict']['errors']:
        print("  Errors:")
        for error in report['verdict']['errors']:
            print(f"    - {error}")
    print("=" * 60)

    # Save report
    report_path = rebuilt.with_suffix('.validation.json')
    validator.save_report(report, report_path)
    print(f"\nFull report saved to: {report_path}")
