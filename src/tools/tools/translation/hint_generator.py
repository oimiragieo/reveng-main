"""
Translation hint generator for AI-assisted C-to-Python conversion.

Generates inline hints and examples to guide AI agents in translating
decompiled C code to Python.
"""

from typing import List, Dict, Optional
from dataclasses import dataclass, asdict
import json

from .api_mappings import get_api_mapping
from .pattern_matcher import detect_api_calls, detect_api_patterns, get_translation_complexity


@dataclass
class TranslationHint:
    """Represents a translation hint for converting C code to Python."""

    line_number: int
    api_name: str
    python_equivalent: str
    example: str
    imports_needed: List[str]
    notes: str
    context: Optional[str] = None
    variables: Optional[List[str]] = None

    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return asdict(self)

    def to_inline_comment(self) -> str:
        """Generate an inline comment hint for insertion into code."""
        comment = f"# HINT: {self.api_name} → {self.python_equivalent}"
        if self.notes:
            comment += f" | {self.notes}"
        return comment

    def to_detailed_comment(self) -> str:
        """Generate a detailed multi-line comment hint."""
        lines = [
            f"# Translation Hint for {self.api_name}:",
            f"# Python equivalent: {self.python_equivalent}",
        ]

        if self.imports_needed:
            imports_str = ", ".join(self.imports_needed)
            lines.append(f"# Required imports: {imports_str}")

        if self.notes:
            lines.append(f"# Notes: {self.notes}")

        if self.example:
            lines.append("# Example:")
            for example_line in self.example.split("\n"):
                lines.append(f"#   {example_line}")

        return "\n".join(lines)


def generate_translation_hints(
    code: str, detail_level: str = "inline", include_patterns: bool = True
) -> Dict[str, any]:
    """
    Generate comprehensive translation hints for C code.

    Args:
        code: C source code to analyze
        detail_level: Level of detail for hints ('inline', 'detailed', 'full')
        include_patterns: Whether to include pattern analysis

    Returns:
        Dictionary containing:
        - hints: List of TranslationHint objects
        - patterns: Detected API usage patterns (if include_patterns=True)
        - complexity: Estimated translation complexity
        - summary: High-level summary
    """
    # Detect all API calls
    matches = detect_api_calls(code)

    # Generate hints for each match
    hints = []
    imports_needed = set()

    for match in matches:
        mapping = get_api_mapping(match.api_name)

        if mapping:
            hint = TranslationHint(
                line_number=match.line_number,
                api_name=match.api_name,
                python_equivalent=mapping.python_equivalent,
                example=mapping.example,
                imports_needed=mapping.imports,
                notes=mapping.notes,
                context=match.function_context,
                variables=match.variables_used,
            )
            hints.append(hint)

            # Collect all needed imports
            imports_needed.update(mapping.imports)

    # Analyze patterns if requested
    patterns = None
    if include_patterns:
        patterns = detect_api_patterns(code)

    # Calculate complexity
    complexity = get_translation_complexity(matches)

    # Generate summary
    summary = generate_summary(hints, patterns, complexity)

    result = {
        "hints": [hint.to_dict() for hint in hints],
        "patterns": patterns,
        "complexity": complexity,
        "imports_needed": sorted(list(imports_needed)),
        "summary": summary,
        "statistics": {
            "total_api_calls": len(matches),
            "unique_apis": len(set(m.api_name for m in matches)),
            "coverage": calculate_coverage(matches),
        },
    }

    return result


def generate_summary(
    hints: List[TranslationHint], patterns: Optional[dict], complexity: str
) -> Dict[str, any]:
    """
    Generate high-level summary of translation task.

    Args:
        hints: List of translation hints
        patterns: Detected API patterns
        complexity: Complexity level

    Returns:
        Summary dictionary
    """
    if not hints:
        return {
            "message": "No Windows API calls detected. Code may be pure C logic.",
            "recommendation": "Focus on translating C syntax to Python (pointers, structs, etc.)",
        }

    # Group hints by category
    by_category = {}
    for hint in hints:
        mapping = get_api_mapping(hint.api_name)
        if mapping:
            category = mapping.category
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(hint)

    # Generate category summary
    category_summary = {category: len(hints_list) for category, hints_list in by_category.items()}

    # Generate recommendations
    recommendations = []

    if "file_io" in by_category:
        recommendations.append(
            "Replace file I/O with Python's built-in open() and context managers"
        )

    if "network" in by_category:
        recommendations.append("Replace WinHTTP/WinINet with requests library for HTTP operations")

    if "registry" in by_category:
        recommendations.append("Use winreg module for registry access (Windows-only functionality)")

    if "crypto" in by_category:
        recommendations.append("Replace CryptoAPI with hashlib or cryptography library")

    if "process" in by_category:
        recommendations.append("Use subprocess and threading modules for process/thread management")

    if "memory" in by_category:
        recommendations.append(
            "Remove manual memory management - Python handles this automatically"
        )

    # Pattern-based recommendations
    if patterns:
        if patterns.get("file_operations"):
            recommendations.append(
                "File operations detected: Use 'with' statements for automatic resource cleanup"
            )
        if patterns.get("http_requests"):
            recommendations.append(
                "HTTP pattern detected: Consider using requests.Session() for multiple requests"
            )

    return {
        "total_hints": len(hints),
        "complexity": complexity,
        "categories": category_summary,
        "recommendations": recommendations,
        "estimated_effort": estimate_effort(complexity, len(hints)),
    }


def calculate_coverage(matches: List) -> float:
    """
    Calculate what percentage of detected APIs have known mappings.

    Args:
        matches: List of APICallMatch objects

    Returns:
        Coverage percentage (0.0 to 1.0)
    """
    if not matches:
        return 1.0

    known_count = sum(1 for m in matches if get_api_mapping(m.api_name) is not None)
    return known_count / len(matches)


def estimate_effort(complexity: str, hint_count: int) -> str:
    """
    Estimate translation effort based on complexity and hints.

    Args:
        complexity: Complexity level ('simple', 'moderate', 'complex')
        hint_count: Number of translation hints

    Returns:
        Human-readable effort estimate
    """
    if complexity == "simple" and hint_count <= 5:
        return "Low - straightforward translation with good library support"
    elif complexity == "moderate" or (complexity == "simple" and hint_count <= 15):
        return "Moderate - requires understanding of Windows API to Python mappings"
    else:
        return "High - complex Windows APIs and patterns require careful translation"


def generate_inline_hints(code: str) -> str:
    """
    Generate C code with inline translation hints as comments.

    Args:
        code: Original C code

    Returns:
        C code with inline hint comments inserted
    """
    result = generate_translation_hints(code, detail_level="inline")
    hints = [TranslationHint(**h) for h in result["hints"]]

    # Insert hints as comments before each API call
    lines = code.split("\n")
    output_lines = []

    # Create a map of line numbers to hints
    hints_by_line = {}
    for hint in hints:
        if hint.line_number not in hints_by_line:
            hints_by_line[hint.line_number] = []
        hints_by_line[hint.line_number].append(hint)

    for line_num, line in enumerate(lines, start=1):
        # Insert hints for this line
        if line_num in hints_by_line:
            for hint in hints_by_line[line_num]:
                output_lines.append(hint.to_inline_comment())

        # Add the original line
        output_lines.append(line)

    return "\n".join(output_lines)


def generate_translation_guide(code: str, output_format: str = "markdown") -> str:
    """
    Generate a comprehensive translation guide document.

    Args:
        code: C source code to analyze
        output_format: Output format ('markdown', 'text', 'json')

    Returns:
        Formatted translation guide
    """
    result = generate_translation_hints(code, include_patterns=True)

    if output_format == "json":
        return json.dumps(result, indent=2)

    # Generate markdown guide
    if output_format == "markdown":
        md_lines = [
            "# C to Python Translation Guide",
            "",
            "## Summary",
            f"- **Complexity**: {result['complexity']}",
            f"- **Total API calls**: {result['statistics']['total_api_calls']}",
            f"- **Unique APIs**: {result['statistics']['unique_apis']}",
            f"- **Coverage**: {result['statistics']['coverage'] * 100:.1f}%",
            f"- **Estimated effort**: {result['summary']['estimated_effort']}",
            "",
            "## Required Imports",
            "```python",
        ]

        for imp in result["imports_needed"]:
            md_lines.append(f"import {imp}")

        md_lines.extend(["```", "", "## API Translation Hints", ""])

        # Group hints by category
        hints_by_category = {}
        for hint_dict in result["hints"]:
            hint = TranslationHint(**hint_dict)
            mapping = get_api_mapping(hint.api_name)
            category = mapping.category if mapping else "other"

            if category not in hints_by_category:
                hints_by_category[category] = []
            hints_by_category[category].append(hint)

        # Output hints by category
        category_names = {
            "file_io": "File I/O",
            "network": "Network/HTTP",
            "registry": "Registry",
            "process": "Process/Thread",
            "memory": "Memory Management",
            "crypto": "Cryptography",
        }

        for category in sorted(hints_by_category.keys()):
            category_name = category_names.get(category, category.title())
            md_lines.extend([f"### {category_name}", ""])

            for hint in hints_by_category[category]:
                md_lines.extend(
                    [
                        f"**{hint.api_name}** (line {hint.line_number})",
                        f"- Python: `{hint.python_equivalent}`",
                        f"- Notes: {hint.notes}",
                        "- Example:",
                        "```python",
                        hint.example,
                        "```",
                        "",
                    ]
                )

        # Add recommendations
        if result["summary"]["recommendations"]:
            md_lines.extend(["## Recommendations", ""])
            for rec in result["summary"]["recommendations"]:
                md_lines.append(f"- {rec}")
            md_lines.append("")

        # Add detected patterns
        if result["patterns"]:
            md_lines.extend(["## Detected Patterns", ""])

            for pattern_type, instances in result["patterns"].items():
                if instances:
                    pattern_name = pattern_type.replace("_", " ").title()
                    md_lines.append(f"### {pattern_name}")
                    md_lines.append("")

                    for instance in instances:
                        func = instance.get("function", "Unknown")
                        pattern = instance.get("pattern", "")
                        apis = instance.get("apis", [])

                        md_lines.extend(
                            [
                                f"- **Function**: `{func}`",
                                f"  - **Pattern**: {pattern}",
                                f"  - **APIs**: {', '.join(apis)}",
                                "",
                            ]
                        )

        return "\n".join(md_lines)

    # Text format
    else:
        text_lines = [
            "=" * 70,
            "C TO PYTHON TRANSLATION GUIDE",
            "=" * 70,
            "",
            f"Complexity: {result['complexity']}",
            f"Total API calls: {result['statistics']['total_api_calls']}",
            f"Estimated effort: {result['summary']['estimated_effort']}",
            "",
            "REQUIRED IMPORTS:",
            "-" * 70,
        ]

        for imp in result["imports_needed"]:
            text_lines.append(f"  import {imp}")

        text_lines.extend(["", "API TRANSLATION HINTS:", "-" * 70])

        for hint_dict in result["hints"]:
            hint = TranslationHint(**hint_dict)
            text_lines.extend(
                [
                    f"Line {hint.line_number}: {hint.api_name}",
                    f"  → {hint.python_equivalent}",
                    f"  {hint.notes}",
                    "",
                ]
            )

        return "\n".join(text_lines)
