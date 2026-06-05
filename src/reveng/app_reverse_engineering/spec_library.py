"""Helpers for writing app reverse-engineering spec libraries."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Sequence


@dataclass(frozen=True)
class TopicDefinition:
    """Definition of one spec-library topic."""

    key: str
    title: str
    description: str
    keywords: Sequence[str] = field(default_factory=tuple)


def normalize_skip_patterns(patterns: Sequence[str]) -> List[str]:
    """Normalize comma-separated or repeated skip patterns."""
    values: List[str] = []
    for pattern in patterns:
        for item in pattern.split(","):
            cleaned = item.strip().lower()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    return values


def should_skip_text(text: str, skip_patterns: Sequence[str]) -> bool:
    """Return whether a snippet should be omitted based on skip patterns."""
    lowered = text.lower()
    return any(pattern in lowered for pattern in skip_patterns)


def build_directory_tree(
    root_path: Path,
    *,
    max_depth: int = 2,
    max_entries_per_directory: int = 20,
) -> List[str]:
    """Render a bounded directory tree for documentation."""
    lines: List[str] = []

    for current_dir, dir_names, file_names in os.walk(root_path):
        relative_dir = Path(current_dir).resolve().relative_to(root_path)
        depth = 0 if str(relative_dir) == "." else len(relative_dir.parts)
        if depth > max_depth:
            dir_names[:] = []
            continue

        dir_names[:] = sorted(dir_names)
        file_names = sorted(file_names)
        label = "." if str(relative_dir) == "." else relative_dir.as_posix()
        indent = "  " * depth
        lines.append(f"{indent}- `{label}/`")

        for directory_name in dir_names[:max_entries_per_directory]:
            lines.append(f"{indent}  - `{directory_name}/`")
        if len(dir_names) > max_entries_per_directory:
            lines.append(
                f"{indent}  - `... {len(dir_names) - max_entries_per_directory} more dirs`"
            )

        for file_name in file_names[:max_entries_per_directory]:
            lines.append(f"{indent}  - `{file_name}`")
        if len(file_names) > max_entries_per_directory:
            lines.append(
                f"{indent}  - `... {len(file_names) - max_entries_per_directory} more files`"
            )

    return lines


def segment_text(text: str, *, max_segment_length: int = 220) -> List[str]:
    """Split dense text into bounded pseudo-lines."""
    raw_segments = text.splitlines()
    if len(raw_segments) < 50:
        raw_segments = re.split(r"(?<=[;{}])", text)

    segments: List[str] = []
    for segment in raw_segments:
        cleaned = segment.strip()
        if not cleaned:
            continue
        if len(cleaned) <= max_segment_length:
            segments.append(cleaned)
            continue

        for index in range(0, len(cleaned), max_segment_length):
            chunk = cleaned[index : index + max_segment_length].strip()
            if chunk:
                segments.append(chunk)

    return segments


def collect_keyword_matches(
    source_segments: Sequence[Dict[str, object]],
    *,
    keywords: Sequence[str],
    skip_patterns: Sequence[str],
    max_snippets: int,
    snippet_context: int,
) -> List[Dict[str, object]]:
    """Collect top-scoring evidence snippets across multiple sources."""
    lowered_keywords = [keyword.lower() for keyword in keywords]
    candidates: List[Dict[str, object]] = []
    seen = set()

    for source in source_segments:
        source_name = str(source["source"])
        segments = list(source["segments"])
        for index, segment in enumerate(segments):
            lowered_segment = segment.lower()
            matched_keywords = [
                keyword for keyword in lowered_keywords if keyword in lowered_segment
            ]
            if not matched_keywords:
                continue

            start = max(0, index - snippet_context)
            end = min(len(segments), index + snippet_context + 1)
            snippet = "\n".join(segments[start:end])
            if should_skip_text(snippet, skip_patterns):
                continue

            normalized = f"{source_name}:{re.sub(r'\s+', ' ', snippet)}"
            if normalized in seen:
                continue

            score = sum(len(keyword) for keyword in matched_keywords) + 10 * len(
                set(matched_keywords)
            )
            candidates.append(
                {
                    "score": score,
                    "source": source_name,
                    "segment_range": [start, end - 1],
                    "matched_keywords": matched_keywords,
                    "snippet": snippet,
                }
            )
            seen.add(normalized)

    candidates.sort(
        key=lambda item: (int(item["score"]), len(item["matched_keywords"])),
        reverse=True,
    )
    return candidates[:max_snippets]


def render_directory_structure_doc(
    *,
    bundle_label: str,
    input_path: Path,
    root_path: Path,
    output_path: Path,
    planned_layout: Sequence[str],
    input_tree: Sequence[str],
) -> str:
    """Render the directory structure document."""
    lines = [
        "# Directory Structure",
        "",
        "## Scope",
        f"- Workflow label: `{bundle_label}`",
        f"- Input entrypoint: `{input_path}`",
        f"- Input root scanned before analysis: `{root_path}`",
        f"- Analysis output root: `{output_path}`",
        "",
        "## Planned Output Layout",
    ]
    lines.extend(f"- {item}" for item in planned_layout)
    lines.extend(["", "## Input Tree"])
    lines.extend(input_tree)
    lines.append("")
    return "\n".join(lines)


def render_specs_index(
    *,
    entry_name: str,
    structure_path: Path,
    topic_files: Dict[str, Path],
    topic_definitions: Sequence[TopicDefinition],
    topic_match_counts: Dict[str, int],
) -> str:
    """Render the main SPECS index."""
    lines = [
        "# Specification Library",
        "",
        f"Reverse-engineering output for `{entry_name}`.",
        "",
        "## Files",
        f"- [Directory Structure]({structure_path.name})",
    ]

    for topic in topic_definitions:
        lines.append(
            f"- [{topic.title}]({topic_files[topic.key].name}) - "
            f"{topic_match_counts.get(topic.key, 0)} evidence snippet(s)"
        )

    lines.extend(
        [
            "",
            "## Notes",
            "- Topic files are evidence-backed summaries, not claims of perfect source recovery.",
            "- Domain files contain grouped excerpts for focused review and follow-on implementation work.",
            "- Skip patterns are applied to generated excerpts where configured.",
            "",
        ]
    )
    return "\n".join(lines)


def render_topic_spec(
    *,
    title: str,
    description: str,
    language: str,
    matches: Sequence[Dict[str, object]],
    assessment_lines: Sequence[str],
) -> str:
    """Render one topic specification document."""
    lines = [
        f"# {title}",
        "",
        description,
        "",
        "## Assessment",
    ]
    lines.extend(f"- {line}" for line in assessment_lines)
    lines.extend(["", "## Evidence"])

    if not matches:
        lines.extend(["- No excerpts matched the current heuristics for this topic.", ""])
        return "\n".join(lines)

    for index, match in enumerate(matches, start=1):
        lines.extend(
            [
                f"### Excerpt {index}",
                f"- Source: `{match['source']}`",
                f"- Segment range: `{match['segment_range'][0]}-{match['segment_range'][1]}`",
                f"- Matched keywords: `{', '.join(match['matched_keywords'])}`",
                "",
                f"```{language}",
                str(match["snippet"]).strip(),
                "```",
                "",
            ]
        )

    return "\n".join(lines)


def render_domain_file(
    *,
    title: str,
    language: str,
    topic_key: str,
    matches: Sequence[Dict[str, object]],
) -> str:
    """Render the domain evidence split file."""
    lines = [
        f"# {title} Domain Split",
        "",
        f"Focused evidence for `{topic_key}` extracted during analysis.",
        "",
    ]

    if not matches:
        lines.extend(["No domain evidence matched the current topic heuristics.", ""])
        return "\n".join(lines)

    for index, match in enumerate(matches, start=1):
        lines.extend(
            [
                f"## Segment {index}",
                f"- Source: `{match['source']}`",
                f"- Segment range: `{match['segment_range'][0]}-{match['segment_range'][1]}`",
                "",
                f"```{language}",
                str(match["snippet"]).strip(),
                "```",
                "",
            ]
        )

    return "\n".join(lines)


def top_values(values: Iterable[str], limit: int = 10) -> List[str]:
    """Return a stable limited list of unique values."""
    return sorted(set(values))[:limit]
