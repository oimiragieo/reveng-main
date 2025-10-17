"""
Binary Diffing Engine for REVENG

Compares two binaries to find differences at function and instruction level.
Use cases:
- Patch analysis (find what changed in security updates)
- Malware variant detection (compare similar malware samples)
- Code evolution tracking (track changes across versions)
"""

import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass
from difflib import SequenceMatcher

logger = logging.getLogger(__name__)


@dataclass
class FunctionMatch:
    """Represents a match between functions in two binaries"""
    func_v1_name: str
    func_v2_name: str
    similarity: float  # 0.0 to 1.0
    match_type: str  # 'exact', 'similar', 'unmatched'
    changes: Optional[List[str]] = None


@dataclass
class DiffResult:
    """Result of binary diff operation"""
    binary_v1: str
    binary_v2: str
    similarity_score: float  # Overall similarity (0.0 to 1.0)

    # Function categorization
    unchanged_functions: List[str]
    modified_functions: List[FunctionMatch]
    new_functions: List[str]
    deleted_functions: List[str]

    # Statistics
    total_functions_v1: int
    total_functions_v2: int
    match_count: int

    # Detailed changes (optional)
    instruction_changes: Optional[Dict[str, Any]] = None
    string_changes: Optional[Dict[str, Any]] = None


class BinaryDiffer:
    """
    Binary diffing engine for comparing two binaries.

    Performs function-level and instruction-level comparison to
    identify what changed between two versions of a binary.
    """

    def __init__(self, similarity_threshold: float = 0.85):
        """
        Initialize binary differ.

        Args:
            similarity_threshold: Minimum similarity to consider functions matched (0.0-1.0)
        """
        self.similarity_threshold = similarity_threshold
        logger.info(f"Binary differ initialized (threshold: {similarity_threshold})")

    def diff(
        self,
        binary_v1_path: str,
        binary_v2_path: str,
        deep_analysis: bool = False
    ) -> DiffResult:
        """
        Compare two binaries and identify differences.

        Args:
            binary_v1_path: Path to first (older) binary
            binary_v2_path: Path to second (newer) binary
            deep_analysis: Whether to perform instruction-level analysis

        Returns:
            DiffResult with comparison details
        """
        logger.info(f"Diffing: {binary_v1_path} vs {binary_v2_path}")

        # Analyze both binaries
        analysis_v1 = self._analyze_binary(binary_v1_path)
        analysis_v2 = self._analyze_binary(binary_v2_path)

        # Match functions by name first
        matched_by_name = self._match_by_name(
            analysis_v1['functions'],
            analysis_v2['functions']
        )

        # Match remaining functions by code similarity
        unmatched_v1 = set(analysis_v1['functions'].keys()) - set(matched_by_name.keys())
        unmatched_v2 = set(analysis_v2['functions'].keys()) - set(matched_by_name.values())

        matched_by_similarity = self._match_by_similarity(
            {k: analysis_v1['functions'][k] for k in unmatched_v1},
            {k: analysis_v2['functions'][k] for k in unmatched_v2}
        )

        # Categorize results
        unchanged = []
        modified = []

        # Check name matches for modifications
        for func_v1, func_v2 in matched_by_name.items():
            similarity = self._calculate_function_similarity(
                analysis_v1['functions'][func_v1],
                analysis_v2['functions'][func_v2]
            )

            if similarity >= 0.99:
                unchanged.append(func_v1)
            else:
                changes = self._identify_changes(
                    analysis_v1['functions'][func_v1],
                    analysis_v2['functions'][func_v2]
                ) if deep_analysis else None

                modified.append(FunctionMatch(
                    func_v1_name=func_v1,
                    func_v2_name=func_v2,
                    similarity=similarity,
                    match_type='name_match',
                    changes=changes
                ))

        # Add similarity matches as modified
        for func_v1, func_v2, similarity in matched_by_similarity:
            changes = self._identify_changes(
                analysis_v1['functions'][func_v1],
                analysis_v2['functions'][func_v2]
            ) if deep_analysis else None

            modified.append(FunctionMatch(
                func_v1_name=func_v1,
                func_v2_name=func_v2,
                similarity=similarity,
                match_type='similarity_match',
                changes=changes
            ))

        # Identify new and deleted functions
        matched_v1 = {m.func_v1_name for m in modified} | set(unchanged)
        matched_v2 = {m.func_v2_name for m in modified} | set(unchanged)

        deleted = list(set(analysis_v1['functions'].keys()) - matched_v1)
        new = list(set(analysis_v2['functions'].keys()) - matched_v2)

        # Calculate overall similarity
        total_functions = max(len(analysis_v1['functions']), len(analysis_v2['functions']))
        if total_functions > 0:
            similarity_score = (len(unchanged) + len(matched_by_similarity)) / total_functions
        else:
            similarity_score = 0.0

        result = DiffResult(
            binary_v1=binary_v1_path,
            binary_v2=binary_v2_path,
            similarity_score=similarity_score,
            unchanged_functions=unchanged,
            modified_functions=modified,
            new_functions=new,
            deleted_functions=deleted,
            total_functions_v1=len(analysis_v1['functions']),
            total_functions_v2=len(analysis_v2['functions']),
            match_count=len(unchanged) + len(modified)
        )

        logger.info(
            f"Diff complete: {similarity_score:.1%} similar, "
            f"{len(modified)} modified, {len(new)} new, {len(deleted)} deleted"
        )

        return result

    def _analyze_binary(self, binary_path: str) -> Dict[str, Any]:
        """
        Analyze binary to extract functions.

        For now, uses simple analysis. In full implementation, this would
        integrate with REVENG's existing analysis pipeline.
        """
        # Placeholder: In real implementation, use REVENGAnalyzer
        # For now, create simple structure

        logger.info(f"Analyzing {binary_path}...")

        # This is a simplified version. Real implementation would:
        # 1. Use REVENGAnalyzer to get full analysis
        # 2. Extract function code, instructions, basic blocks
        # 3. Calculate function hashes and features

        analysis = {
            'binary_path': binary_path,
            'functions': {},
            'strings': [],
            'imports': []
        }

        # Simulate function extraction
        # In real implementation, use actual disassembly
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()

            # Calculate file hash for identification
            file_hash = hashlib.sha256(data).hexdigest()
            analysis['sha256'] = file_hash

            # Extract basic info
            # This is where we'd integrate with existing REVENG analysis
            # For demonstration, create simple function structure
            analysis['functions'] = self._extract_functions_simple(data)

        except Exception as e:
            logger.error(f"Binary analysis failed: {e}")

        return analysis

    def _extract_functions_simple(self, data: bytes) -> Dict[str, Dict[str, Any]]:
        """
        Simple function extraction (placeholder).

        In real implementation, this would use REVENG's disassembly.
        """
        functions = {}

        # Placeholder: create fake functions based on file structure
        # Real implementation would use Ghidra/REVENG disassembly

        # For PE files, we could extract based on section data
        if data[:2] == b'MZ':  # PE file
            # Simple heuristic: look for function prologues
            # Real implementation would use proper disassembly
            prologue_pattern = b'\x55\x8B\xEC'  # push ebp; mov ebp, esp

            offset = 0
            func_count = 0
            while offset < len(data) - 3:
                if data[offset:offset+3] == prologue_pattern:
                    func_addr = hex(offset)
                    func_name = f"sub_{func_addr[2:].upper()}"

                    # Extract a chunk of code (simplified)
                    code_chunk = data[offset:offset+100]

                    functions[func_name] = {
                        'address': func_addr,
                        'code': code_chunk,
                        'size': 100,  # Simplified
                        'hash': hashlib.md5(code_chunk).hexdigest()
                    }

                    func_count += 1
                    offset += 100  # Skip ahead
                else:
                    offset += 1

            logger.info(f"Extracted {func_count} functions (simplified)")

        return functions

    def _match_by_name(
        self,
        functions_v1: Dict[str, Any],
        functions_v2: Dict[str, Any]
    ) -> Dict[str, str]:
        """Match functions by name (exact string match)"""
        matches = {}

        for func_name in functions_v1.keys():
            if func_name in functions_v2:
                matches[func_name] = func_name

        logger.info(f"Matched {len(matches)} functions by name")
        return matches

    def _match_by_similarity(
        self,
        functions_v1: Dict[str, Any],
        functions_v2: Dict[str, Any]
    ) -> List[Tuple[str, str, float]]:
        """
        Match functions by code similarity.

        Returns list of (func_v1_name, func_v2_name, similarity)
        """
        matches = []

        # For each unmatched function in v1, find best match in v2
        for func_v1_name, func_v1_data in functions_v1.items():
            best_match = None
            best_similarity = 0.0

            for func_v2_name, func_v2_data in functions_v2.items():
                similarity = self._calculate_function_similarity(
                    func_v1_data,
                    func_v2_data
                )

                if similarity > best_similarity and similarity >= self.similarity_threshold:
                    best_similarity = similarity
                    best_match = func_v2_name

            if best_match:
                matches.append((func_v1_name, best_match, best_similarity))

        logger.info(f"Matched {len(matches)} functions by similarity")
        return matches

    def _calculate_function_similarity(
        self,
        func1_data: Dict[str, Any],
        func2_data: Dict[str, Any]
    ) -> float:
        """Calculate similarity between two functions (0.0 to 1.0)"""
        # Use multiple similarity metrics

        # 1. Hash-based (fastest, exact match)
        if func1_data.get('hash') and func2_data.get('hash'):
            if func1_data['hash'] == func2_data['hash']:
                return 1.0

        # 2. Code size similarity
        size1 = func1_data.get('size', 0)
        size2 = func2_data.get('size', 0)

        if size1 == 0 or size2 == 0:
            return 0.0

        size_ratio = min(size1, size2) / max(size1, size2)

        # If sizes are very different, low similarity
        if size_ratio < 0.5:
            return size_ratio * 0.5

        # 3. Byte-level similarity
        code1 = func1_data.get('code', b'')
        code2 = func2_data.get('code', b'')

        if isinstance(code1, bytes) and isinstance(code2, bytes):
            matcher = SequenceMatcher(None, code1, code2)
            code_similarity = matcher.ratio()
        else:
            code_similarity = 0.0

        # Weighted combination
        similarity = (size_ratio * 0.2) + (code_similarity * 0.8)

        return similarity

    def _identify_changes(
        self,
        func1_data: Dict[str, Any],
        func2_data: Dict[str, Any]
    ) -> List[str]:
        """Identify specific changes between two functions"""
        changes = []

        # Size change
        size1 = func1_data.get('size', 0)
        size2 = func2_data.get('size', 0)

        if size1 != size2:
            diff = size2 - size1
            changes.append(f"Size changed by {diff:+d} bytes ({size1} -> {size2})")

        # Code changes (simplified)
        code1 = func1_data.get('code', b'')
        code2 = func2_data.get('code', b'')

        if isinstance(code1, bytes) and isinstance(code2, bytes):
            if code1 != code2:
                changes.append("Code modified")

                # Basic diff statistics
                matcher = SequenceMatcher(None, code1, code2)
                opcodes = matcher.get_opcodes()

                modifications = sum(1 for tag, _, _, _, _ in opcodes if tag in ['replace', 'insert', 'delete'])
                changes.append(f"{modifications} code block(s) changed")

        return changes

    def generate_report(self, diff_result: DiffResult, format: str = 'text') -> str:
        """Generate diff report"""
        if format == 'markdown':
            report = f"# Binary Diff Report\n\n"
            report += f"**Binary v1:** `{Path(diff_result.binary_v1).name}`\n"
            report += f"**Binary v2:** `{Path(diff_result.binary_v2).name}`\n\n"

            report += f"## Summary\n\n"
            report += f"- **Overall Similarity:** {diff_result.similarity_score:.1%}\n"
            report += f"- **Total Functions (v1):** {diff_result.total_functions_v1}\n"
            report += f"- **Total Functions (v2):** {diff_result.total_functions_v2}\n\n"

            report += f"## Changes\n\n"
            report += f"| Category | Count |\n"
            report += f"|----------|-------|\n"
            report += f"| Unchanged | {len(diff_result.unchanged_functions)} |\n"
            report += f"| Modified | {len(diff_result.modified_functions)} |\n"
            report += f"| New | {len(diff_result.new_functions)} |\n"
            report += f"| Deleted | {len(diff_result.deleted_functions)} |\n\n"

            if diff_result.modified_functions:
                report += f"## Modified Functions\n\n"
                for match in diff_result.modified_functions[:20]:
                    report += f"### {match.func_v1_name} → {match.func_v2_name}\n\n"
                    report += f"- **Similarity:** {match.similarity:.1%}\n"
                    if match.changes:
                        report += f"- **Changes:**\n"
                        for change in match.changes:
                            report += f"  - {change}\n"
                    report += "\n"

            if diff_result.new_functions:
                report += f"## New Functions ({len(diff_result.new_functions)})\n\n"
                for func in diff_result.new_functions[:10]:
                    report += f"- {func}\n"
                if len(diff_result.new_functions) > 10:
                    report += f"- ...and {len(diff_result.new_functions) - 10} more\n"
                report += "\n"

        else:  # text format
            report = f"Binary Diff Report\n"
            report += f"{'=' * 60}\n\n"
            report += f"Binary v1: {Path(diff_result.binary_v1).name}\n"
            report += f"Binary v2: {Path(diff_result.binary_v2).name}\n\n"

            report += f"Overall Similarity: {diff_result.similarity_score:.1%}\n\n"

            report += f"Summary:\n"
            report += f"  Unchanged: {len(diff_result.unchanged_functions)}\n"
            report += f"  Modified:  {len(diff_result.modified_functions)}\n"
            report += f"  New:       {len(diff_result.new_functions)}\n"
            report += f"  Deleted:   {len(diff_result.deleted_functions)}\n\n"

            if diff_result.modified_functions:
                report += f"Modified Functions:\n"
                for match in diff_result.modified_functions[:10]:
                    report += f"  {match.func_v1_name} -> {match.func_v2_name} ({match.similarity:.1%} similar)\n"
                    if match.changes:
                        for change in match.changes:
                            report += f"    - {change}\n"

        return report


# Convenience function
def quick_diff(binary_v1: str, binary_v2: str) -> DiffResult:
    """Quick binary diff"""
    differ = BinaryDiffer()
    return differ.diff(binary_v1, binary_v2)
