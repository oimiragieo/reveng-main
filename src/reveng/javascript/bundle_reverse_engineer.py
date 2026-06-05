"""
Bundle-oriented JavaScript reverse engineering workflow.

This module is designed for large bundled or minified JavaScript applications
where the immediate goal is not perfect source recovery, but a disciplined,
repeatable reverse-engineering process:

1. Inventory the installed application directory.
2. Normalize the bundle into a more readable artifact.
3. Detect bundling and obfuscation signals.
4. Generate a technical specification library by topic.
5. Split evidence into domain-oriented files under a SPECS library.

The output is intentionally evidence-backed and avoids pretending that a
minified bundle has been perfectly reconstructed when it has not.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from reveng.core.ir import REEdge, RENode, REProjectIR

from .deobfuscator import JavaScriptDeobfuscator
from .detectors import ObfuscationDetector

TOPIC_DEFINITIONS: Dict[str, Dict[str, object]] = {
    "runtime_architecture": {
        "title": "Runtime Architecture",
        "description": (
            "Execution model, module system, entrypoint shape, and runtime helpers "
            "present in the bundle."
        ),
        "keywords": [
            "__webpack_require__",
            "webpackChunk",
            "__commonJS",
            "__toCommonJS",
            "module.exports",
            "exports.",
            "createRequire",
            "process.argv",
            "stdin",
            "stdout",
            "worker",
            "child_process",
            "isInteractive",
            "clientType",
            "spawn(",
        ],
    },
    "cli_surface": {
        "title": "CLI Surface",
        "description": "Commands, flags, slash commands, terminal flows, and user entrypoints.",
        "keywords": [
            "command(",
            ".command(",
            "option(",
            ".option(",
            "process.argv",
            "/init",
            "/review",
            "allowed-tools",
            "flagSettings",
            "clientType",
            "terminal",
            "tty",
            "readline",
        ],
    },
    "agent_runtime_and_prompts": {
        "title": "Agent Runtime And Prompts",
        "description": (
            "Agent loop, prompt surfaces, instruction libraries, model-facing content, "
            "and review or edit orchestration."
        ),
        "keywords": [
            "prompt",
            "systemPrompt",
            "assistant",
            "completion",
            "agent",
            "apply_patch",
            "tool_use",
            "tool_result",
            "CLAUDE.md",
            "instructions",
            "promptCache",
            "mainLoopModel",
        ],
    },
    "tools_and_permissions": {
        "title": "Tools And Permissions",
        "description": "Tool routing, shell execution, file actions, and permission controls.",
        "keywords": [
            "bash",
            "shell",
            "exec(",
            "spawn(",
            "permission",
            "sandbox",
            "allow",
            "deny",
            "allowed-tools",
            "dangerously-skip-permissions",
            "writeFile",
            "readFile",
            "search",
            "apply_patch",
        ],
    },
    "integrations_and_networking": {
        "title": "Integrations And Networking",
        "description": "External APIs, MCP or protocol surfaces, transport layers, and remote I/O.",
        "keywords": [
            "http://",
            "https://",
            "fetch(",
            "websocket",
            "ws",
            "grpc",
            "mcp",
            "localhost",
            "socket",
            "proxy",
        ],
    },
    "storage_state_and_artifacts": {
        "title": "Storage State And Artifacts",
        "description": "Local files, config, caches, session state, artifacts, and durable data.",
        "keywords": [
            "sqlite",
            "cache",
            "config",
            "session",
            "artifact",
            "history",
            "writeFile",
            "readFile",
            ".json",
            ".db",
            ".claude",
            "homedir",
            "originalCwd",
            "projectRoot",
            "flagSettings",
        ],
    },
    "observability_and_telemetry": {
        "title": "Observability And Telemetry",
        "description": "Logging, tracing, metrics, diagnostics, crash handling, and debug flows.",
        "keywords": [
            "telemetry",
            "trace",
            "span",
            "logger",
            "metric",
            "debug",
            "diagnostic",
            "crash",
            "exception",
            "observability",
            "eventLogger",
        ],
    },
    "dependencies_and_binaries": {
        "title": "Dependencies And Binaries",
        "description": (
            "External packages, Node builtins, bundled assets, binaries, and native modules."
        ),
        "keywords": [
            "node:",
            ".node",
            ".dll",
            ".so",
            ".dylib",
            "ripgrep",
            "rg",
            "rg.exe",
            "sharp",
            "sqlite",
            "vendor",
            "binary",
        ],
    },
}

STRING_LITERAL_PATTERN = re.compile(r'"((?:\\.|[^"\\]){3,220})"|\'((?:\\.|[^\'\\]){3,220})\'')
CLI_FLAG_PATTERN = re.compile(r"--[a-z0-9][a-z0-9-]*")
SLASH_COMMAND_PATTERN = re.compile(r"/[a-z][a-z0-9-]{1,30}")
URL_PATTERN = re.compile(r"https?://[^\s\"'`]+")
PACKAGE_PATTERN = re.compile(r"^(?:node:[a-z0-9_/-]+|@?[a-z0-9][a-z0-9._/-]+)$")
DEPENDENCY_STOPWORDS = {
    "string",
    "none",
    "object",
    "function",
    "error",
    "number",
    "column",
    "text",
    "user",
    "type",
    "path",
    "default",
    "assistant",
    "warn",
    "utf-8",
    "success",
    "system",
    "boolean",
    "unknown",
    "client",
    "allow",
    "warning",
    "info",
    "tool_result",
    "utf8",
    "name",
    "tool_use",
    "failed",
    "ask",
    "abort",
    "auto",
    "close",
    "deny",
    "running",
    "content",
    "row",
    "data",
    "prompt",
    "base64",
}


@dataclass
class BundleReverseEngineeringResult:
    """Structured output from the bundle reverse-engineering workflow."""

    input_path: Path
    input_root: Path
    output_dir: Path
    specs_dir: Path
    domains_dir: Path
    artifacts_dir: Path
    analysis_file: Path
    normalized_bundle: Path
    topic_files: Dict[str, Path]
    domain_files: Dict[str, Path]
    topic_match_counts: Dict[str, int]
    bundler_signals: Dict[str, int]
    obfuscation_types: List[str]
    dependency_candidates: List[str]
    cli_flags: List[str]
    slash_commands: List[str]
    warnings: List[str]
    deep_deobfuscation_output: Optional[Path] = None
    ir_file: Optional[Path] = None


class JavaScriptBundleReverseEngineer:
    """
    Reverse engineer a bundled JavaScript application into specs and domain files.

    The class is intentionally conservative. It produces normalized evidence and
    topic-level specifications instead of claiming perfect reconstruction.
    """

    def __init__(
        self,
        *,
        skip_patterns: Optional[Sequence[str]] = None,
        max_snippets_per_topic: int = 12,
        snippet_context: int = 2,
        run_deobfuscator: bool = False,
    ) -> None:
        self.skip_patterns = self._normalize_skip_patterns(skip_patterns or [])
        self.max_snippets_per_topic = max(1, max_snippets_per_topic)
        self.snippet_context = max(0, snippet_context)
        self.run_deobfuscator = run_deobfuscator

    async def reverse_engineer_bundle(
        self,
        input_path: str,
        output_dir: str,
        *,
        input_root: Optional[str] = None,
    ) -> BundleReverseEngineeringResult:
        """Run the full bundle reverse-engineering workflow."""
        bundle_path = Path(input_path).expanduser().resolve()
        if not bundle_path.is_file():
            raise FileNotFoundError(f"JavaScript bundle not found: {bundle_path}")

        root_path = (
            Path(input_root).expanduser().resolve() if input_root else bundle_path.parent.resolve()
        )
        output_path = Path(output_dir).expanduser().resolve()
        specs_dir = output_path / "SPECS"
        domains_dir = specs_dir / "domains"
        artifacts_dir = output_path / "artifacts"

        domains_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        code = bundle_path.read_text(encoding="utf-8", errors="replace")
        segments = self._segment_code(code)
        normalized_text = "\n".join(segments) + "\n"
        normalized_path = artifacts_dir / "normalized.js"
        normalized_path.write_text(normalized_text, encoding="utf-8")

        detector = ObfuscationDetector()
        detection = detector.detect(code)
        bundler_signals = self._detect_bundler_signals(code)
        string_literals = self._extract_string_literals(code)
        dependency_candidates = self._extract_dependency_candidates(string_literals)
        cli_flags = self._extract_cli_flags(string_literals)
        slash_commands = self._extract_slash_commands(string_literals)
        urls = self._extract_urls(string_literals)
        warnings: List[str] = []

        input_tree = self._build_directory_tree(root_path)
        analysis_payload = {
            "input_path": str(bundle_path),
            "input_root": str(root_path),
            "output_dir": str(output_path),
            "file_size_bytes": bundle_path.stat().st_size,
            "segment_count": len(segments),
            "obfuscation_types": [item.value for item in detection.obfuscation_types],
            "bundler_signals": bundler_signals,
            "dependency_candidates": dependency_candidates,
            "cli_flags": cli_flags,
            "slash_commands": slash_commands,
            "urls": urls[:40],
            "skip_patterns": self.skip_patterns,
        }

        structure_path = specs_dir / "00-directory-structure.md"
        structure_path.write_text(
            self._render_directory_structure_doc(
                bundle_path=bundle_path,
                root_path=root_path,
                output_path=output_path,
                input_tree=input_tree,
            ),
            encoding="utf-8",
        )

        topic_files: Dict[str, Path] = {}
        domain_files: Dict[str, Path] = {}
        topic_match_counts: Dict[str, int] = {}

        for index, (topic_key, topic_config) in enumerate(TOPIC_DEFINITIONS.items(), start=1):
            keywords = topic_config["keywords"]
            topic_matches = self._collect_topic_matches(segments, keywords)
            topic_match_counts[topic_key] = len(topic_matches)

            spec_path = specs_dir / f"{index:02d}-{topic_key.replace('_', '-')}.md"
            domain_path = domains_dir / f"{topic_key.replace('_', '-')}.md"

            spec_path.write_text(
                self._render_topic_spec(
                    topic_key=topic_key,
                    title=str(topic_config["title"]),
                    description=str(topic_config["description"]),
                    matches=topic_matches,
                    dependency_candidates=dependency_candidates,
                    cli_flags=cli_flags,
                    slash_commands=slash_commands,
                    urls=urls,
                ),
                encoding="utf-8",
            )
            domain_path.write_text(
                self._render_domain_file(
                    topic_key=topic_key,
                    title=str(topic_config["title"]),
                    matches=topic_matches,
                ),
                encoding="utf-8",
            )

            topic_files[topic_key] = spec_path
            domain_files[topic_key] = domain_path

        readme_path = specs_dir / "README.md"
        readme_path.write_text(
            self._render_specs_index(
                bundle_path=bundle_path,
                structure_path=structure_path,
                topic_files=topic_files,
                topic_match_counts=topic_match_counts,
            ),
            encoding="utf-8",
        )

        deep_deobfuscation_output: Optional[Path] = None
        if self.run_deobfuscator:
            deep_deobfuscation_output, deob_warnings = await self._run_optional_deobfuscator(
                code=code,
                artifacts_dir=artifacts_dir,
            )
            warnings.extend(deob_warnings)

        analysis_file = output_path / "analysis.json"
        analysis_payload["topic_match_counts"] = topic_match_counts
        analysis_payload["warnings"] = warnings
        if deep_deobfuscation_output:
            analysis_payload["deep_deobfuscation_output"] = str(deep_deobfuscation_output)
        analysis_file.write_text(json.dumps(analysis_payload, indent=2), encoding="utf-8")

        ir_file = self._emit_project_ir(
            bundle_path=bundle_path,
            root_path=root_path,
            artifacts_dir=artifacts_dir,
            code=code,
            topic_match_counts=topic_match_counts,
        )

        return BundleReverseEngineeringResult(
            input_path=bundle_path,
            input_root=root_path,
            output_dir=output_path,
            specs_dir=specs_dir,
            domains_dir=domains_dir,
            artifacts_dir=artifacts_dir,
            analysis_file=analysis_file,
            normalized_bundle=normalized_path,
            topic_files=topic_files,
            domain_files=domain_files,
            topic_match_counts=topic_match_counts,
            bundler_signals=bundler_signals,
            obfuscation_types=[item.value for item in detection.obfuscation_types],
            dependency_candidates=dependency_candidates,
            cli_flags=cli_flags,
            slash_commands=slash_commands,
            warnings=warnings,
            deep_deobfuscation_output=deep_deobfuscation_output,
            ir_file=ir_file,
        )

    # Canonical recovered-domain signals, mapped to stable IR node ids.
    _IR_DOMAIN_KEYWORDS: Dict[str, Tuple[str, ...]] = {
        "auth": (r"\bauth\b", r"\blogin\b", r"\boauth\b"),
        "mcp": (r"\bmcp\b",),
        "config": (r"\bconfig\b", r"\bsettings\b"),
        "tools": (r"\btools?\b", r"\bpermission"),
        "session": (r"\bsession\b",),
        "prompts": (r"\bprompt",),
        "telemetry": (r"\btelemetry\b", r"\banalytics\b"),
    }

    def _emit_project_ir(
        self,
        *,
        bundle_path: Path,
        root_path: Path,
        artifacts_dir: Path,
        code: str,
        topic_match_counts: Dict[str, int],
    ) -> Path:
        """Emit a shared REProjectIR artifact for the recovered bundle.

        The IR always carries a ``cli`` entrypoint node plus one ``domain`` node
        per canonical recovered domain (auth, mcp, ...) detected in the bundle,
        each wired to ``cli`` via a ``references`` edge. Serialized to
        ``artifacts_dir/project.re_project_ir.json``.
        """
        nodes = [
            RENode(
                node_id="cli",
                kind="entrypoint",
                label="CLI entrypoint",
                attributes={"input": bundle_path.name},
            )
        ]
        edges = []
        for domain, patterns in self._IR_DOMAIN_KEYWORDS.items():
            hits = sum(len(re.findall(p, code, re.IGNORECASE)) for p in patterns)
            if hits:
                nodes.append(
                    RENode(
                        node_id=domain,
                        kind="domain",
                        label=domain.replace("_", " ").title(),
                        attributes={"evidence": hits},
                    )
                )
                edges.append(REEdge(source="cli", target=domain, kind="references"))

        ir = REProjectIR(
            schema_version="1.0",
            project_name=root_path.name or bundle_path.stem,
            input_path=str(bundle_path),
            language="javascript",
            nodes=nodes,
            edges=edges,
            metadata={"topic_match_counts": dict(topic_match_counts)},
        )
        ir_file = artifacts_dir / "project.re_project_ir.json"
        ir.to_json(ir_file)
        return ir_file

    async def _run_optional_deobfuscator(
        self,
        *,
        code: str,
        artifacts_dir: Path,
    ) -> Tuple[Optional[Path], List[str]]:
        """Run the existing deobfuscator when explicitly requested."""
        warnings: List[str] = []
        try:
            deobfuscator = JavaScriptDeobfuscator(use_ml=False, use_llm=False)
            result = await asyncio.wait_for(
                deobfuscator.deobfuscate(code, filename="bundle.js"),
                timeout=120,
            )
        except asyncio.TimeoutError:
            warnings.append("Deep deobfuscation timed out after 120 seconds.")
            return None, warnings
        except Exception as exc:
            warnings.append(f"Deep deobfuscation failed: {exc}")
            return None, warnings

        output_path = artifacts_dir / "deobfuscated.js"
        output_path.write_text(result.deobfuscated_code, encoding="utf-8")
        if result.warnings:
            warnings.extend(result.warnings)
        return output_path, warnings

    @staticmethod
    def _normalize_skip_patterns(patterns: Sequence[str]) -> List[str]:
        values: List[str] = []
        for pattern in patterns:
            for item in pattern.split(","):
                cleaned = item.strip().lower()
                if cleaned and cleaned not in values:
                    values.append(cleaned)
        return values

    def _should_skip_text(self, text: str) -> bool:
        lowered = text.lower()
        return any(pattern in lowered for pattern in self.skip_patterns)

    def _build_directory_tree(
        self,
        root_path: Path,
        *,
        max_depth: int = 2,
        max_entries_per_directory: int = 20,
    ) -> List[str]:
        """Render a bounded directory tree for the target install root."""
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

    def _segment_code(self, code: str) -> List[str]:
        """
        Split large minified code into readable pseudo-lines.

        This is intentionally heuristic. It produces bounded segments suitable
        for excerpting even when the original bundle is one dense line.
        """
        raw_segments = code.splitlines()
        if len(raw_segments) < 50:
            raw_segments = re.split(r"(?<=[;{}])", code)

        segments: List[str] = []
        for segment in raw_segments:
            cleaned = segment.strip()
            if not cleaned:
                continue
            if len(cleaned) <= 220:
                segments.append(cleaned)
                continue

            for index in range(0, len(cleaned), 220):
                chunk = cleaned[index : index + 220].strip()
                if chunk:
                    segments.append(chunk)

        return segments

    def _collect_topic_matches(
        self, segments: Sequence[str], keywords: object
    ) -> List[Dict[str, object]]:
        """Collect bounded evidence snippets for one topic."""
        if not isinstance(keywords, list):
            return []

        lowered_keywords = [str(keyword).lower() for keyword in keywords]
        candidates: List[Dict[str, object]] = []
        seen_snippets = set()

        for index, segment in enumerate(segments):
            lowered_segment = segment.lower()
            matched_keywords = [
                keyword for keyword in lowered_keywords if keyword in lowered_segment
            ]
            if not matched_keywords:
                continue

            start = max(0, index - self.snippet_context)
            end = min(len(segments), index + self.snippet_context + 1)
            snippet = "\n".join(segments[start:end])
            if self._should_skip_text(snippet):
                continue
            normalized = re.sub(r"\s+", " ", snippet)
            if normalized in seen_snippets:
                continue

            score = (
                sum(len(keyword) for keyword in matched_keywords) + len(set(matched_keywords)) * 10
            )
            candidates.append(
                {
                    "score": score,
                    "segment_range": [start, end - 1],
                    "matched_keywords": matched_keywords,
                    "snippet": snippet,
                }
            )
            seen_snippets.add(normalized)

        candidates.sort(
            key=lambda item: (int(item["score"]), len(item["matched_keywords"])),
            reverse=True,
        )
        matches = candidates[: self.max_snippets_per_topic]
        return matches

    def _detect_bundler_signals(self, code: str) -> Dict[str, int]:
        """Count high-signal bundler/runtime markers."""
        signals = {
            "webpack_runtime": len(re.findall(r"__webpack_require__|webpackChunk", code)),
            "browserify_runtime": len(re.findall(r"function r\(e,n,t\)|require=\(", code)),
            "esbuild_runtime": len(re.findall(r"__commonJS|__toCommonJS|__export", code)),
            "source_map_markers": len(re.findall(r"sourceMappingURL=", code)),
            "dynamic_imports": len(re.findall(r"import\(", code)),
            "child_process_usage": len(re.findall(r"child_process|spawn\(|exec\(", code)),
            "node_builtin_imports": len(re.findall(r"node:[a-z0-9_/-]+", code)),
        }
        return {key: value for key, value in signals.items() if value}

    def _extract_string_literals(self, code: str) -> List[str]:
        """Extract decoded string literals from the bundle."""
        values: List[str] = []
        for match in STRING_LITERAL_PATTERN.finditer(code):
            value = match.group(1) or match.group(2) or ""
            value = value.strip()
            if value and not self._should_skip_text(value):
                values.append(value)
        return values

    def _extract_dependency_candidates(self, string_literals: Sequence[str]) -> List[str]:
        """Extract likely package names, binary names, and resource identifiers."""
        candidates: Counter[str] = Counter()

        for value in string_literals:
            if value.lower() in DEPENDENCY_STOPWORDS:
                continue
            if PACKAGE_PATTERN.match(value) or any(
                marker in value for marker in (".node", ".dll", ".so", ".dylib", ".json", ".db")
            ):
                if "/" not in value and "." not in value and ":" not in value and "@" not in value:
                    continue
                candidates[value] += 1
                continue

            if value.startswith(("http://", "https://", "./", "../", "/")):
                candidates[value] += 1

        return [item for item, _count in candidates.most_common(40)]

    def _extract_cli_flags(self, string_literals: Sequence[str]) -> List[str]:
        """Extract likely CLI flags from string literals."""
        flags: List[str] = []
        for value in string_literals:
            if value.startswith("--") and re.fullmatch(r"--[a-z0-9][a-z0-9-]{1,50}", value):
                flags.append(value)
            else:
                flags.extend(CLI_FLAG_PATTERN.findall(value))
        return self._extract_sorted_unique(flags)

    def _extract_slash_commands(self, string_literals: Sequence[str]) -> List[str]:
        """Extract slash commands while filtering obvious regex fragments."""
        commands: List[str] = []
        for value in string_literals:
            if any(marker in value for marker in "[]{}*+?|\\"):
                continue
            if value.startswith("/") and re.fullmatch(r"/[a-z][a-z0-9-]{1,30}", value):
                commands.append(value)
                continue
            commands.extend(SLASH_COMMAND_PATTERN.findall(value))
        return self._extract_sorted_unique(commands)

    def _extract_urls(self, string_literals: Sequence[str]) -> List[str]:
        """Extract URLs from string literals."""
        urls: List[str] = []
        for value in string_literals:
            if value.startswith(("http://", "https://")):
                urls.append(value)
            else:
                urls.extend(URL_PATTERN.findall(value))
        return self._extract_sorted_unique(urls)

    @staticmethod
    def _extract_sorted_unique(values: Iterable[str], *, limit: int = 40) -> List[str]:
        """Sort and deduplicate extracted tokens."""
        unique = sorted(set(values))
        return unique[:limit]

    def _render_directory_structure_doc(
        self,
        *,
        bundle_path: Path,
        root_path: Path,
        output_path: Path,
        input_tree: Sequence[str],
    ) -> str:
        lines = [
            "# Directory Structure",
            "",
            "## Scope",
            f"- Bundle entrypoint: `{bundle_path}`",
            f"- Input root scanned before deobfuscation: `{root_path}`",
            f"- Analysis output root: `{output_path}`",
            "",
            "## Planned Output Layout",
            "- `artifacts/normalized.js`: pseudo-prettified bundle for review",
            "- `artifacts/deobfuscated.js`: deeper pass when the optional deobfuscator succeeds",
            "- `SPECS/*.md`: topic-by-topic specification library",
            "- `SPECS/domains/*.md`: domain-oriented evidence splits",
            "- `analysis.json`: machine-readable summary",
            "",
            "## Input Tree",
        ]
        lines.extend(input_tree)
        lines.append("")
        return "\n".join(lines)

    def _render_specs_index(
        self,
        *,
        bundle_path: Path,
        structure_path: Path,
        topic_files: Dict[str, Path],
        topic_match_counts: Dict[str, int],
    ) -> str:
        lines = [
            "# Specification Library",
            "",
            f"Reverse-engineering output for `{bundle_path.name}`.",
            "",
            "## Files",
            f"- [Directory Structure]({structure_path.name})",
        ]

        for topic_key, file_path in topic_files.items():
            title = str(TOPIC_DEFINITIONS[topic_key]["title"])
            lines.append(
                f"- [{title}]({file_path.name}) - {topic_match_counts.get(topic_key, 0)} evidence snippet(s)"
            )

        lines.extend(
            [
                "",
                "## Notes",
                "- Topic files are evidence-backed summaries, not claims of perfect source recovery.",
                "- Domain files contain grouped excerpts for focused review and follow-on implementation work.",
                "- Skip patterns are applied to excerpt selection and dependency extraction.",
                "",
            ]
        )
        return "\n".join(lines)

    def _render_topic_spec(
        self,
        *,
        topic_key: str,
        title: str,
        description: str,
        matches: Sequence[Dict[str, object]],
        dependency_candidates: Sequence[str],
        cli_flags: Sequence[str],
        slash_commands: Sequence[str],
        urls: Sequence[str],
    ) -> str:
        lines = [
            f"# {title}",
            "",
            description,
            "",
            "## Assessment",
            (f"- Evidence coverage: {len(matches)} excerpt(s) collected for " f"`{topic_key}`."),
            "- Confidence model: keyword- and snippet-driven static analysis of a bundled artifact.",
        ]

        if dependency_candidates:
            lines.append(
                f"- Related dependencies: {', '.join(self._limit_values(dependency_candidates, 8))}"
            )
        if cli_flags and topic_key in {"cli_surface", "tools_and_permissions"}:
            lines.append(f"- Related CLI flags: {', '.join(self._limit_values(cli_flags, 10))}")
        if slash_commands and topic_key in {"cli_surface", "agent_runtime_and_prompts"}:
            lines.append(
                f"- Related slash commands: {', '.join(self._limit_values(slash_commands, 10))}"
            )
        if urls and topic_key == "integrations_and_networking":
            lines.append(f"- Related URLs: {', '.join(self._limit_values(urls, 6))}")

        lines.extend(["", "## Evidence"])

        if not matches:
            lines.append("- No excerpts matched the current heuristics for this topic.")
            lines.append("")
            return "\n".join(lines)

        for index, match in enumerate(matches, start=1):
            segment_range = match["segment_range"]
            snippet = str(match["snippet"]).strip()
            keywords = ", ".join(match["matched_keywords"])
            lines.extend(
                [
                    f"### Excerpt {index}",
                    f"- Segment range: `{segment_range[0]}-{segment_range[1]}`",
                    f"- Matched keywords: `{keywords}`",
                    "",
                    "```javascript",
                    snippet,
                    "```",
                    "",
                ]
            )

        return "\n".join(lines)

    def _render_domain_file(
        self,
        *,
        topic_key: str,
        title: str,
        matches: Sequence[Dict[str, object]],
    ) -> str:
        lines = [
            f"# {title} Domain Split",
            "",
            f"Focused evidence for `{topic_key}` extracted from the bundle.",
            "",
        ]

        if not matches:
            lines.append("No domain evidence matched the current topic heuristics.")
            lines.append("")
            return "\n".join(lines)

        for index, match in enumerate(matches, start=1):
            segment_range = match["segment_range"]
            snippet = str(match["snippet"]).strip()
            lines.extend(
                [
                    f"## Segment {index}",
                    f"- Source range: `{segment_range[0]}-{segment_range[1]}`",
                    "",
                    "```javascript",
                    snippet,
                    "```",
                    "",
                ]
            )

        return "\n".join(lines)

    @staticmethod
    def _limit_values(values: Sequence[str], limit: int) -> List[str]:
        return list(values[:limit])
