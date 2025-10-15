#!/usr/bin/env python3
"""
REVENG Binary Diff Tool
========================

Compare original vs rebuilt binaries at multiple levels:
- File-level comparison (size, checksum)
- Section-level comparison (headers, code, data)
- Instruction-level comparison (disassembly diff)
- Visual diff output

Helps identify divergence points in binary reconstruction.
"""

import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json
import difflib

try:
    import lief
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False
    logging.warning("LIEF not installed - section analysis disabled")

try:
    import capstone
    HAS_CAPSTONE = True
except ImportError:
    HAS_CAPSTONE = False
    logging.warning("Capstone not installed - instruction diff disabled")

logger = logging.getLogger(__name__)


class BinaryDiff:
    """Compare binaries at multiple levels"""

    def __init__(self):
        """Initialize binary diff tool"""
        self.has_lief = HAS_LIEF
        self.has_capstone = HAS_CAPSTONE

    def compare(
        self,
        original_path: Path,
        rebuilt_path: Path,
        include_instructions: bool = False
    ) -> Dict:
        """
        Compare two binaries

        Args:
            original_path: Path to original binary
            rebuilt_path: Path to rebuilt binary
            include_instructions: Whether to include instruction-level diff

        Returns:
            Diff report dict
        """
        report = {
            'original': str(original_path),
            'rebuilt': str(rebuilt_path),
            'file_diff': {},
            'section_diff': {},
            'instruction_diff': {},
            'summary': {}
        }

        # File-level comparison
        report['file_diff'] = self._compare_files(original_path, rebuilt_path)

        # Section-level comparison (if LIEF available)
        if self.has_lief:
            report['section_diff'] = self._compare_sections(original_path, rebuilt_path)

        # Instruction-level comparison (if requested and Capstone available)
        if include_instructions and self.has_capstone:
            report['instruction_diff'] = self._compare_instructions(
                original_path, rebuilt_path
            )

        # Generate summary
        report['summary'] = self._generate_summary(report)

        return report

    def _compare_files(self, original_path: Path, rebuilt_path: Path) -> Dict:
        """Compare file-level properties"""
        diff = {}

        # File sizes
        original_size = original_path.stat().st_size
        rebuilt_size = rebuilt_path.stat().st_size

        diff['size'] = {
            'original': original_size,
            'rebuilt': rebuilt_size,
            'difference': rebuilt_size - original_size,
            'match': original_size == rebuilt_size
        }

        # Checksums
        original_hash = self._calculate_hash(original_path)
        rebuilt_hash = self._calculate_hash(rebuilt_path)

        diff['checksum'] = {
            'original': original_hash,
            'rebuilt': rebuilt_hash,
            'match': original_hash == rebuilt_hash
        }

        return diff

    def _calculate_hash(self, file_path: Path, algorithm: str = 'sha256') -> str:
        """Calculate file hash"""
        hasher = hashlib.new(algorithm)

        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)

        return hasher.hexdigest()

    def _compare_sections(self, original_path: Path, rebuilt_path: Path) -> Dict:
        """Compare binary sections using LIEF"""
        diff = {'sections': []}

        try:
            original_bin = lief.parse(str(original_path))
            rebuilt_bin = lief.parse(str(rebuilt_path))

            if not original_bin or not rebuilt_bin:
                return {'error': 'Failed to parse binaries with LIEF'}

            # Get sections
            original_sections = {s.name: s for s in original_bin.sections}
            rebuilt_sections = {s.name: s for s in rebuilt_bin.sections}

            # Compare common sections
            all_section_names = set(original_sections.keys()) | set(rebuilt_sections.keys())

            for section_name in sorted(all_section_names):
                section_diff = {
                    'name': section_name,
                    'in_original': section_name in original_sections,
                    'in_rebuilt': section_name in rebuilt_sections
                }

                if section_name in original_sections and section_name in rebuilt_sections:
                    orig_section = original_sections[section_name]
                    rebuilt_section = rebuilt_sections[section_name]

                    # Compare sizes
                    section_diff['size'] = {
                        'original': orig_section.size,
                        'rebuilt': rebuilt_section.size,
                        'match': orig_section.size == rebuilt_section.size
                    }

                    # Compare virtual addresses
                    section_diff['virtual_address'] = {
                        'original': orig_section.virtual_address,
                        'rebuilt': rebuilt_section.virtual_address,
                        'match': orig_section.virtual_address == rebuilt_section.virtual_address
                    }

                    # Compare content (first 1KB only to save memory)
                    orig_content = bytes(orig_section.content[:1024])
                    rebuilt_content = bytes(rebuilt_section.content[:1024])

                    section_diff['content_match'] = orig_content == rebuilt_content

                    if not section_diff['content_match']:
                        # Count differing bytes
                        diff_bytes = sum(
                            1 for a, b in zip(orig_content, rebuilt_content) if a != b
                        )
                        section_diff['diff_bytes'] = diff_bytes
                        section_diff['diff_percentage'] = (diff_bytes / len(orig_content)) * 100

                diff['sections'].append(section_diff)

        except Exception as e:
            diff['error'] = str(e)
            logger.error(f"Section comparison failed: {e}")

        return diff

    def _compare_instructions(
        self,
        original_path: Path,
        rebuilt_path: Path,
        max_instructions: int = 1000
    ) -> Dict:
        """Compare disassembled instructions"""
        diff = {'functions': []}

        if not self.has_capstone:
            return {'error': 'Capstone not available'}

        try:
            # This is a simplified example - real implementation would need
            # function boundaries from Ghidra or similar

            # For now, just disassemble first N bytes
            with open(original_path, 'rb') as f:
                original_code = f.read(4096)

            with open(rebuilt_path, 'rb') as f:
                rebuilt_code = f.read(4096)

            # Detect architecture (simplified - assume x86-64)
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)

            # Disassemble
            original_instructions = list(md.disasm(original_code, 0x1000))
            rebuilt_instructions = list(md.disasm(rebuilt_code, 0x1000))

            # Limit to max_instructions
            original_instructions = original_instructions[:max_instructions]
            rebuilt_instructions = rebuilt_instructions[:max_instructions]

            # Compare instruction counts
            diff['instruction_count'] = {
                'original': len(original_instructions),
                'rebuilt': len(rebuilt_instructions),
                'match': len(original_instructions) == len(rebuilt_instructions)
            }

            # Find first divergence
            for i, (orig, rebuilt) in enumerate(zip(original_instructions, rebuilt_instructions)):
                if orig.mnemonic != rebuilt.mnemonic or orig.op_str != rebuilt.op_str:
                    diff['first_divergence'] = {
                        'offset': i,
                        'address': hex(orig.address),
                        'original': f"{orig.mnemonic} {orig.op_str}",
                        'rebuilt': f"{rebuilt.mnemonic} {rebuilt.op_str}"
                    }
                    break

            # Generate text diff
            original_text = [
                f"{hex(i.address)}: {i.mnemonic} {i.op_str}"
                for i in original_instructions[:50]
            ]
            rebuilt_text = [
                f"{hex(i.address)}: {i.mnemonic} {i.op_str}"
                for i in rebuilt_instructions[:50]
            ]

            unified_diff = list(difflib.unified_diff(
                original_text,
                rebuilt_text,
                fromfile='original',
                tofile='rebuilt',
                lineterm=''
            ))

            diff['unified_diff'] = unified_diff[:100]  # Limit to 100 lines

        except Exception as e:
            diff['error'] = str(e)
            logger.error(f"Instruction comparison failed: {e}")

        return diff

    def _generate_summary(self, report: Dict) -> Dict:
        """Generate summary of differences"""
        summary = {
            'files_identical': report['file_diff']['checksum']['match'],
            'size_difference': report['file_diff']['size']['difference'],
            'sections_compared': 0,
            'sections_matching': 0,
            'sections_differing': 0,
            'critical_differences': []
        }

        # Section summary
        if 'sections' in report['section_diff']:
            sections = report['section_diff']['sections']
            summary['sections_compared'] = len(sections)

            for section in sections:
                if section.get('in_original') and section.get('in_rebuilt'):
                    if section.get('content_match'):
                        summary['sections_matching'] += 1
                    else:
                        summary['sections_differing'] += 1

                        # Flag critical sections
                        if section['name'] in ['.text', 'code', '__text']:
                            summary['critical_differences'].append(
                                f"Code section '{section['name']}' differs"
                            )

        # Instruction summary
        if 'instruction_count' in report.get('instruction_diff', {}):
            inst_diff = report['instruction_diff']
            if not inst_diff['instruction_count']['match']:
                summary['critical_differences'].append(
                    f"Instruction count mismatch: "
                    f"{inst_diff['instruction_count']['original']} vs "
                    f"{inst_diff['instruction_count']['rebuilt']}"
                )

            if 'first_divergence' in inst_diff:
                div = inst_diff['first_divergence']
                summary['critical_differences'].append(
                    f"Instructions diverge at offset {div['offset']}: "
                    f"'{div['original']}' vs '{div['rebuilt']}'"
                )

        return summary

    def save_report(self, report: Dict, output_path: Path):
        """Save diff report to JSON"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Diff report saved to {output_path}")

    def print_summary(self, report: Dict):
        """Print human-readable summary"""
        print("=" * 70)
        print("BINARY DIFF SUMMARY")
        print("=" * 70)

        file_diff = report['file_diff']
        print(f"Original: {report['original']}")
        print(f"Rebuilt:  {report['rebuilt']}")
        print()

        print("File Comparison:")
        print(f"  Size:     {file_diff['size']['original']:,} bytes -> "
              f"{file_diff['size']['rebuilt']:,} bytes "
              f"(diff: {file_diff['size']['difference']:+,})")
        print(f"  Match:    {'✓ YES' if file_diff['checksum']['match'] else '✗ NO'}")
        print()

        if 'sections' in report['section_diff']:
            summary = report['summary']
            print("Section Comparison:")
            print(f"  Sections compared: {summary['sections_compared']}")
            print(f"  Matching:          {summary['sections_matching']}")
            print(f"  Differing:         {summary['sections_differing']}")
            print()

            # Show differing sections
            for section in report['section_diff']['sections']:
                if not section.get('content_match', True):
                    name = section['name']
                    diff_pct = section.get('diff_percentage', 0)
                    print(f"  ✗ {name}: {diff_pct:.1f}% different")

            print()

        if 'instruction_count' in report.get('instruction_diff', {}):
            inst_diff = report['instruction_diff']
            print("Instruction Comparison:")
            print(f"  Original instructions: {inst_diff['instruction_count']['original']}")
            print(f"  Rebuilt instructions:  {inst_diff['instruction_count']['rebuilt']}")

            if 'first_divergence' in inst_diff:
                div = inst_diff['first_divergence']
                print(f"  First divergence at offset {div['offset']} ({div['address']}):")
                print(f"    Original: {div['original']}")
                print(f"    Rebuilt:  {div['rebuilt']}")

            print()

        if report['summary']['critical_differences']:
            print("Critical Differences:")
            for diff in report['summary']['critical_differences']:
                print(f"  ✗ {diff}")
            print()

        print("=" * 70)


# Example usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    differ = BinaryDiff()

    print("=" * 70)
    print("REVENG BINARY DIFF TOOL")
    print("=" * 70)
    print()

    if len(sys.argv) >= 3:
        original = Path(sys.argv[1])
        rebuilt = Path(sys.argv[2])

        if not original.exists():
            print(f"Error: Original binary not found: {original}")
            sys.exit(1)

        if not rebuilt.exists():
            print(f"Error: Rebuilt binary not found: {rebuilt}")
            sys.exit(1)

        print(f"Comparing binaries...")
        print(f"  Original: {original}")
        print(f"  Rebuilt:  {rebuilt}")
        print()

        # Run comparison
        include_instructions = '--instructions' in sys.argv
        report = differ.compare(original, rebuilt, include_instructions)

        # Print summary
        differ.print_summary(report)

        # Save full report
        output_path = Path("binary_diff_report.json")
        differ.save_report(report, output_path)

        print(f"Full report saved to: {output_path}")

    else:
        print("Usage:")
        print("  python binary_diff.py <original> <rebuilt> [--instructions]")
        print()
        print("Options:")
        print("  --instructions    Include instruction-level comparison (slower)")
        print()
        print("Example:")
        print("  python binary_diff.py droid.exe droid_rebuilt.exe")
        print()
        print("Output:")
        print("  - Console summary of differences")
        print("  - binary_diff_report.json (detailed JSON report)")

    print("=" * 70)
