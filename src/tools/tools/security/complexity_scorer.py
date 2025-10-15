#!/usr/bin/env python3
"""
REVENG Function Complexity Scorer
==================================

Analyzes function complexity using multiple metrics:
- Cyclomatic complexity (McCabe)
- Lines of code (LOC)
- Nesting depth
- Parameter count
- Branch count
- Loop count

Assigns complexity scores (low/medium/high) to help prioritize review.
"""

import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)


@dataclass
class ComplexityMetrics:
    """Complexity metrics for a function"""
    function_name: str
    file_path: str

    # Metrics
    cyclomatic_complexity: int = 0
    lines_of_code: int = 0
    nesting_depth: int = 0
    parameter_count: int = 0
    branch_count: int = 0
    loop_count: int = 0

    # Derived
    complexity_score: float = 0.0
    complexity_level: str = "low"  # low, medium, high, very_high

    # Analysis
    issues: List[str] = None
    recommendations: List[str] = None

    def __post_init__(self):
        if self.issues is None:
            self.issues = []
        if self.recommendations is None:
            self.recommendations = []


class ComplexityScorer:
    """Analyze and score function complexity"""

    def __init__(self):
        """Initialize complexity scorer"""
        self.thresholds = {
            'cyclomatic': {'low': 5, 'medium': 10, 'high': 20},
            'loc': {'low': 50, 'medium': 100, 'high': 200},
            'nesting': {'low': 2, 'medium': 4, 'high': 6},
            'parameters': {'low': 3, 'medium': 5, 'high': 8},
            'branches': {'low': 5, 'medium': 10, 'high': 15},
            'loops': {'low': 2, 'medium': 4, 'high': 6}
        }

    def analyze_file(self, file_path: Path) -> List[ComplexityMetrics]:
        """
        Analyze all functions in a C file

        Returns:
            List of ComplexityMetrics for each function
        """
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return []

        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Extract functions
        functions = self._extract_functions(content)

        # Analyze each function
        results = []
        for func_name, func_body in functions:
            metrics = self._analyze_function(func_name, str(file_path), func_body)
            results.append(metrics)

        return results

    def analyze_directory(
        self,
        directory: Path,
        pattern: str = "**/*.c"
    ) -> List[ComplexityMetrics]:
        """
        Analyze all C files in a directory

        Args:
            directory: Directory to scan
            pattern: Glob pattern for files (default: **/*.c)

        Returns:
            List of ComplexityMetrics for all functions
        """
        all_metrics = []

        c_files = list(directory.glob(pattern))
        logger.info(f"Analyzing {len(c_files)} C files in {directory}")

        for c_file in c_files:
            file_metrics = self.analyze_file(c_file)
            all_metrics.extend(file_metrics)

        return all_metrics

    def _extract_functions(self, content: str) -> List[Tuple[str, str]]:
        """
        Extract function names and bodies from C code

        Returns:
            List of (function_name, function_body) tuples
        """
        functions = []

        # Pattern to match function definitions
        # Matches: return_type function_name(params) { body }
        func_pattern = re.compile(
            r'([\w\s\*]+)\s+(\w+)\s*\(([^)]*)\)\s*\{',
            re.MULTILINE
        )

        matches = list(func_pattern.finditer(content))

        for i, match in enumerate(matches):
            func_name = match.group(2)
            start_pos = match.end()

            # Find matching closing brace
            brace_count = 1
            end_pos = start_pos

            while end_pos < len(content) and brace_count > 0:
                if content[end_pos] == '{':
                    brace_count += 1
                elif content[end_pos] == '}':
                    brace_count -= 1
                end_pos += 1

            func_body = content[start_pos:end_pos-1]
            functions.append((func_name, func_body))

        return functions

    def _analyze_function(
        self,
        func_name: str,
        file_path: str,
        func_body: str
    ) -> ComplexityMetrics:
        """Analyze a single function"""
        metrics = ComplexityMetrics(
            function_name=func_name,
            file_path=file_path
        )

        # Calculate metrics
        metrics.cyclomatic_complexity = self._calculate_cyclomatic(func_body)
        metrics.lines_of_code = self._calculate_loc(func_body)
        metrics.nesting_depth = self._calculate_nesting(func_body)
        metrics.branch_count = self._count_branches(func_body)
        metrics.loop_count = self._count_loops(func_body)

        # Calculate overall score
        metrics.complexity_score = self._calculate_score(metrics)
        metrics.complexity_level = self._determine_level(metrics)

        # Generate issues and recommendations
        self._analyze_issues(metrics)

        return metrics

    def _calculate_cyclomatic(self, func_body: str) -> int:
        """
        Calculate cyclomatic complexity (McCabe)

        Formula: CC = E - N + 2P
        Simplified: CC = decision_points + 1

        Decision points: if, else if, for, while, do, case, &&, ||, ?
        """
        complexity = 1  # Base complexity

        # Count decision points
        decision_keywords = [
            r'\bif\b', r'\belse\s+if\b', r'\bfor\b', r'\bwhile\b',
            r'\bdo\b', r'\bcase\b', r'\bswitch\b'
        ]

        for pattern in decision_keywords:
            matches = re.findall(pattern, func_body)
            complexity += len(matches)

        # Count logical operators
        complexity += func_body.count('&&')
        complexity += func_body.count('||')
        complexity += func_body.count('?')

        return complexity

    def _calculate_loc(self, func_body: str) -> int:
        """Calculate lines of code (excluding blank lines and comments)"""
        lines = func_body.split('\n')

        loc = 0
        in_multiline_comment = False

        for line in lines:
            stripped = line.strip()

            # Skip blank lines
            if not stripped:
                continue

            # Handle multiline comments
            if '/*' in stripped:
                in_multiline_comment = True
            if '*/' in stripped:
                in_multiline_comment = False
                continue
            if in_multiline_comment:
                continue

            # Skip single-line comments
            if stripped.startswith('//'):
                continue

            loc += 1

        return loc

    def _calculate_nesting(self, func_body: str) -> int:
        """Calculate maximum nesting depth"""
        max_depth = 0
        current_depth = 0

        for char in func_body:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth -= 1

        return max_depth

    def _count_branches(self, func_body: str) -> int:
        """Count branch statements (if, else, switch, case)"""
        count = 0

        branch_keywords = [
            r'\bif\b', r'\belse\b', r'\bswitch\b', r'\bcase\b'
        ]

        for pattern in branch_keywords:
            matches = re.findall(pattern, func_body)
            count += len(matches)

        return count

    def _count_loops(self, func_body: str) -> int:
        """Count loop statements (for, while, do-while)"""
        count = 0

        loop_keywords = [r'\bfor\b', r'\bwhile\b', r'\bdo\b']

        for pattern in loop_keywords:
            matches = re.findall(pattern, func_body)
            count += len(matches)

        return count

    def _calculate_score(self, metrics: ComplexityMetrics) -> float:
        """
        Calculate overall complexity score (0.0 - 1.0)

        Weighted average of normalized metrics
        """
        weights = {
            'cyclomatic': 0.30,
            'loc': 0.25,
            'nesting': 0.20,
            'branches': 0.15,
            'loops': 0.10
        }

        # Normalize each metric to 0.0-1.0
        normalized = {}

        for metric_name, metric_value in [
            ('cyclomatic', metrics.cyclomatic_complexity),
            ('loc', metrics.lines_of_code),
            ('nesting', metrics.nesting_depth),
            ('branches', metrics.branch_count),
            ('loops', metrics.loop_count)
        ]:
            thresholds = self.thresholds[metric_name]

            if metric_value <= thresholds['low']:
                normalized[metric_name] = 0.0
            elif metric_value <= thresholds['medium']:
                normalized[metric_name] = 0.33
            elif metric_value <= thresholds['high']:
                normalized[metric_name] = 0.67
            else:
                normalized[metric_name] = 1.0

        # Calculate weighted score
        score = sum(
            normalized[name] * weights[name]
            for name in weights.keys()
        )

        return score

    def _determine_level(self, metrics: ComplexityMetrics) -> str:
        """Determine complexity level from score"""
        if metrics.complexity_score < 0.25:
            return 'low'
        elif metrics.complexity_score < 0.50:
            return 'medium'
        elif metrics.complexity_score < 0.75:
            return 'high'
        else:
            return 'very_high'

    def _analyze_issues(self, metrics: ComplexityMetrics):
        """Identify issues and generate recommendations"""
        # Cyclomatic complexity
        if metrics.cyclomatic_complexity > self.thresholds['cyclomatic']['high']:
            metrics.issues.append(
                f"Very high cyclomatic complexity ({metrics.cyclomatic_complexity})"
            )
            metrics.recommendations.append(
                "Consider refactoring into smaller functions"
            )
        elif metrics.cyclomatic_complexity > self.thresholds['cyclomatic']['medium']:
            metrics.issues.append(
                f"High cyclomatic complexity ({metrics.cyclomatic_complexity})"
            )
            metrics.recommendations.append(
                "Review branching logic for simplification opportunities"
            )

        # Lines of code
        if metrics.lines_of_code > self.thresholds['loc']['high']:
            metrics.issues.append(
                f"Very long function ({metrics.lines_of_code} LOC)"
            )
            metrics.recommendations.append(
                "Split into multiple smaller functions"
            )
        elif metrics.lines_of_code > self.thresholds['loc']['medium']:
            metrics.issues.append(
                f"Long function ({metrics.lines_of_code} LOC)"
            )
            metrics.recommendations.append(
                "Consider extracting helper functions"
            )

        # Nesting depth
        if metrics.nesting_depth > self.thresholds['nesting']['high']:
            metrics.issues.append(
                f"Very deep nesting ({metrics.nesting_depth} levels)"
            )
            metrics.recommendations.append(
                "Use early returns or extract nested logic"
            )
        elif metrics.nesting_depth > self.thresholds['nesting']['medium']:
            metrics.issues.append(
                f"Deep nesting ({metrics.nesting_depth} levels)"
            )
            metrics.recommendations.append(
                "Consider flattening nested conditionals"
            )

        # Branch count
        if metrics.branch_count > self.thresholds['branches']['high']:
            metrics.issues.append(
                f"Too many branches ({metrics.branch_count})"
            )
            metrics.recommendations.append(
                "Use lookup tables or strategy pattern"
            )

    def generate_report(
        self,
        metrics_list: List[ComplexityMetrics],
        output_path: Optional[Path] = None
    ) -> Dict:
        """
        Generate complexity analysis report

        Returns:
            Report dict with summary and detailed results
        """
        # Sort by complexity score (highest first)
        sorted_metrics = sorted(
            metrics_list,
            key=lambda m: m.complexity_score,
            reverse=True
        )

        # Calculate summary statistics
        total_functions = len(metrics_list)

        level_counts = {
            'low': 0,
            'medium': 0,
            'high': 0,
            'very_high': 0
        }

        for metrics in metrics_list:
            level_counts[metrics.complexity_level] += 1

        avg_complexity = (
            sum(m.complexity_score for m in metrics_list) / total_functions
            if total_functions > 0 else 0.0
        )

        # Build report
        report = {
            'summary': {
                'total_functions': total_functions,
                'average_complexity': round(avg_complexity, 3),
                'complexity_distribution': level_counts,
                'high_complexity_count': level_counts['high'] + level_counts['very_high'],
                'review_recommended': level_counts['high'] + level_counts['very_high']
            },
            'top_10_complex': [
                {
                    'function': m.function_name,
                    'file': m.file_path,
                    'score': round(m.complexity_score, 3),
                    'level': m.complexity_level,
                    'metrics': {
                        'cyclomatic': m.cyclomatic_complexity,
                        'loc': m.lines_of_code,
                        'nesting': m.nesting_depth,
                        'branches': m.branch_count,
                        'loops': m.loop_count
                    },
                    'issues': m.issues,
                    'recommendations': m.recommendations
                }
                for m in sorted_metrics[:10]
            ],
            'all_functions': [
                {
                    'function': m.function_name,
                    'file': m.file_path,
                    'score': round(m.complexity_score, 3),
                    'level': m.complexity_level
                }
                for m in sorted_metrics
            ]
        }

        # Save report if path provided
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Complexity report saved to {output_path}")

        return report

    def print_summary(self, report: Dict):
        """Print human-readable summary"""
        print("=" * 70)
        print("COMPLEXITY ANALYSIS SUMMARY")
        print("=" * 70)

        summary = report['summary']
        print(f"Total functions analyzed: {summary['total_functions']}")
        print(f"Average complexity: {summary['average_complexity']:.3f}")
        print()

        print("Complexity Distribution:")
        dist = summary['complexity_distribution']
        print(f"  Low:       {dist['low']:4d} ({dist['low']/summary['total_functions']*100:.1f}%)")
        print(f"  Medium:    {dist['medium']:4d} ({dist['medium']/summary['total_functions']*100:.1f}%)")
        print(f"  High:      {dist['high']:4d} ({dist['high']/summary['total_functions']*100:.1f}%)")
        print(f"  Very High: {dist['very_high']:4d} ({dist['very_high']/summary['total_functions']*100:.1f}%)")
        print()

        print(f"Functions requiring review: {summary['review_recommended']}")
        print()

        print("Top 10 Most Complex Functions:")
        print("-" * 70)

        for i, func in enumerate(report['top_10_complex'], 1):
            print(f"{i}. {func['function']} ({func['level'].upper()})")
            print(f"   File: {func['file']}")
            print(f"   Score: {func['score']:.3f}")
            print(f"   Metrics: CC={func['metrics']['cyclomatic']}, "
                  f"LOC={func['metrics']['loc']}, "
                  f"Depth={func['metrics']['nesting']}")

            if func['issues']:
                print(f"   Issues: {', '.join(func['issues'])}")

            print()

        print("=" * 70)


# Example usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    scorer = ComplexityScorer()

    print("=" * 70)
    print("REVENG FUNCTION COMPLEXITY SCORER")
    print("=" * 70)
    print()

    if len(sys.argv) >= 2:
        target = Path(sys.argv[1])

        if target.is_file():
            # Analyze single file
            print(f"Analyzing file: {target}\n")
            metrics_list = scorer.analyze_file(target)
        elif target.is_dir():
            # Analyze directory
            print(f"Analyzing directory: {target}\n")
            metrics_list = scorer.analyze_directory(target)
        else:
            print(f"Error: {target} not found")
            sys.exit(1)

        # Generate report
        report = scorer.generate_report(
            metrics_list,
            output_path=Path("complexity_report.json")
        )

        # Print summary
        scorer.print_summary(report)

        print(f"\nFull report saved to: complexity_report.json")

    else:
        print("Usage:")
        print("  python complexity_scorer.py file.c        # Analyze single file")
        print("  python complexity_scorer.py src_dir/      # Analyze directory")
        print()
        print("Output:")
        print("  - complexity_report.json (detailed JSON report)")
        print("  - Console summary with top 10 complex functions")

    print("=" * 70)
