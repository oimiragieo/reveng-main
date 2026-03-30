""" .NET adapter for the shared app reverse-engineering framework."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from xml.etree import ElementTree

from reveng.analyzers.dotnet_analyzer import DotNetAnalyzer
from reveng.tools.languages.csharp_il_analyzer import CSharpILAnalyzer, DotNetDetector

from ..models import AppReverseEngineeringResult
from ..spec_library import (
    TopicDefinition,
    build_directory_tree,
    collect_keyword_matches,
    normalize_skip_patterns,
    render_directory_structure_doc,
    render_domain_file,
    render_specs_index,
    render_topic_spec,
    segment_text,
    top_values,
)

DOTNET_TOPIC_DEFINITIONS = [
    TopicDefinition(
        key="project_structure",
        title="Project Structure",
        description="Assembly shape, recovered source layout, IL artifacts, and top-level project organization.",
        keywords=(".assembly", ".namespace", ".class", "namespace ", "class "),
    ),
    TopicDefinition(
        key="assemblies_and_types",
        title="Assemblies And Types",
        description="Assembly metadata, namespaces, type surfaces, and representative class declarations.",
        keywords=(".assembly", ".class", "namespace ", "class ", "interface "),
    ),
    TopicDefinition(
        key="dependencies_and_resources",
        title="Dependencies And Resources",
        description="Managed dependencies, embedded resources, and API usage signals.",
        keywords=("System.", "Microsoft.", ".mresource", "resource", "using "),
    ),
    TopicDefinition(
        key="entrypoints_and_gui",
        title="Entrypoints And Gui",
        description="Entry points, GUI framework detection, and application mode signals.",
        keywords=(".entrypoint", "Main(", "Console", "Windows Forms", "WPF"),
    ),
    TopicDefinition(
        key="runtime_and_obfuscation",
        title="Runtime And Obfuscation",
        description="Runtime version, framework, IL/decompiler availability, and obfuscation status.",
        keywords=("runtime", "framework", "obfus", "ConfuserEx", ".NET Reactor", "Eazfuscator"),
    ),
]


class DotNetAppAdapter:
    """Adapter for .NET assemblies using the repo's IL and metadata analyzers."""

    language = "dotnet"
    adapter_name = "dotnet_app_workflow"
    supported_extensions = (".dll", ".exe")

    def __init__(self) -> None:
        self._detector = DotNetDetector()

    def supports_path(self, path: Path) -> bool:
        suffix = path.suffix.lower()
        if suffix == ".dll":
            return True
        if suffix == ".exe":
            is_dotnet, _ = self._detector.is_dotnet_assembly(str(path))
            return is_dotnet
        return False

    async def reverse_engineer(
        self,
        input_path: str,
        output_dir: str,
        *,
        input_root: Optional[str] = None,
        skip_patterns: Optional[Sequence[str]] = None,
        max_snippets: int = 12,
        snippet_context: int = 2,
        run_deobfuscator: bool = False,
    ) -> AppReverseEngineeringResult:
        del run_deobfuscator

        entry_path = Path(input_path).expanduser().resolve()
        if not entry_path.exists():
            raise FileNotFoundError(f".NET input not found: {entry_path}")

        root_path = (
            Path(input_root).expanduser().resolve() if input_root else entry_path.parent.resolve()
        )
        output_path = Path(output_dir).expanduser().resolve()
        specs_dir = output_path / "SPECS"
        domains_dir = specs_dir / "domains"
        artifacts_dir = output_path / "artifacts"
        specs_dir.mkdir(parents=True, exist_ok=True)
        domains_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        skip_values = normalize_skip_patterns(skip_patterns or [])
        input_tree = build_directory_tree(root_path)
        primary_artifacts: Dict[str, Path] = {}
        warnings: List[str] = []
        summary: Dict[str, object] = {
            "dependencies": [],
            "resources": {},
            "entrypoints": [],
            "namespaces": [],
            "types": [],
            "gui_framework": "Unknown",
            "framework_version": "Unknown",
            "runtime_version": "Unknown",
            "obfuscation_level": "Unknown",
            "analysis_confidence": 0.0,
            "il_metadata": {},
            "tooling": {},
            "decompiled_project": {},
        }

        il_analyzer = CSharpILAnalyzer(output_dir=str(artifacts_dir / "dotnet_analysis"))
        il_result = il_analyzer.analyze(str(entry_path))
        if il_result.error:
            warnings.append(il_result.error)
        summary["il_metadata"] = dict(il_result.metadata)
        summary["tooling"] = dict(il_result.metadata.get("tooling", {}))

        dotnet_analyzer = DotNetAnalyzer()
        try:
            dotnet_result = dotnet_analyzer.analyze_assembly(str(entry_path))
        except Exception as exc:
            dotnet_result = None
            warnings.append(f"dotnet analyzer failed: {exc}")

        if dotnet_result is not None:
            summary.update(
                {
                    "dependencies": dotnet_result.dependencies,
                    "resources": dotnet_result.resources,
                    "entrypoints": top_values(
                        list(dotnet_result.entry_points)
                        + [str(il_result.metadata.get("entry_point", ""))]
                    ),
                    "gui_framework": dotnet_result.gui_framework,
                    "framework_version": dotnet_result.framework_version,
                    "runtime_version": dotnet_result.runtime_version,
                    "obfuscation_level": dotnet_result.obfuscation_level,
                    "analysis_confidence": dotnet_result.analysis_confidence,
                }
            )
            if not summary.get("dependencies") and dotnet_result.api_calls:
                summary["dependencies"] = dotnet_result.api_calls
        else:
            summary["entrypoints"] = top_values([str(il_result.metadata.get("entry_point", ""))])

        source_files, generated_artifacts, decompiled_project_summary = self._collect_sources_from_analysis(
            entry_path, artifacts_dir, il_result
        )
        primary_artifacts.update(generated_artifacts)
        summary["decompiled_project"] = decompiled_project_summary

        il_namespaces = list(il_result.metadata.get("namespaces", []))
        il_types = [str(item) for item in il_result.metadata.get("types", [])]
        summary["namespaces"] = top_values(il_namespaces, 80)
        summary["types"] = top_values(il_types, 80)

        source_segments = self._load_segments(source_files, root_path)

        structure_path = specs_dir / "00-directory-structure.md"
        structure_path.write_text(
            render_directory_structure_doc(
                bundle_label="dotnet_app",
                input_path=entry_path,
                root_path=root_path,
                output_path=output_path,
                planned_layout=[
                    "`artifacts/dotnet_analysis/`: analyzer output, IL, and report files",
                    "`artifacts/recovered_sources/`: recovered summary and fallback source notes",
                    "`SPECS/*.md`: topic-by-topic specification library",
                    "`SPECS/domains/*.md`: domain-oriented evidence splits",
                    "`analysis.json`: machine-readable summary",
                ],
                input_tree=input_tree,
            ),
            encoding="utf-8",
        )

        topic_files: Dict[str, Path] = {}
        domain_files: Dict[str, Path] = {}
        topic_match_counts: Dict[str, int] = {}
        for index, topic in enumerate(DOTNET_TOPIC_DEFINITIONS, start=1):
            matches = collect_keyword_matches(
                source_segments,
                keywords=topic.keywords,
                skip_patterns=skip_values,
                max_snippets=max_snippets,
                snippet_context=snippet_context,
            )
            topic_match_counts[topic.key] = len(matches)

            spec_path = specs_dir / f"{index:02d}-{topic.key.replace('_', '-')}.md"
            domain_path = domains_dir / f"{topic.key.replace('_', '-')}.md"
            spec_path.write_text(
                render_topic_spec(
                    title=topic.title,
                    description=topic.description,
                    language="csharp",
                    matches=matches,
                    assessment_lines=self._assessment_lines(topic.key, summary, len(source_files)),
                ),
                encoding="utf-8",
            )
            domain_path.write_text(
                render_domain_file(
                    title=topic.title,
                    language="csharp",
                    topic_key=topic.key,
                    matches=matches,
                ),
                encoding="utf-8",
            )
            topic_files[topic.key] = spec_path
            domain_files[topic.key] = domain_path

        readme_path = specs_dir / "README.md"
        readme_path.write_text(
            render_specs_index(
                entry_name=entry_path.name,
                structure_path=structure_path,
                topic_files=topic_files,
                topic_definitions=DOTNET_TOPIC_DEFINITIONS,
                topic_match_counts=topic_match_counts,
            ),
            encoding="utf-8",
        )

        analysis_payload = {
            "language": self.language,
            "adapter_name": self.adapter_name,
            "input_path": str(entry_path),
            "input_root": str(root_path),
            "output_dir": str(output_path),
            "source_count": len(source_files),
            "framework_version": summary.get("framework_version", "Unknown"),
            "runtime_version": summary.get("runtime_version", "Unknown"),
            "gui_framework": summary.get("gui_framework", "Unknown"),
            "entrypoints": top_values(summary.get("entrypoints", []), 40),
            "dependencies": top_values(summary.get("dependencies", []), 80),
            "namespaces": top_values(summary.get("namespaces", []), 80),
            "types": top_values(summary.get("types", []), 80),
            "resources": summary.get("resources", {}),
            "obfuscation_level": summary.get("obfuscation_level", "Unknown"),
            "analysis_confidence": summary.get("analysis_confidence", 0.0),
            "il_metadata": summary.get("il_metadata", {}),
            "tooling": summary.get("tooling", {}),
            "decompiled_project": summary.get("decompiled_project", {}),
            "topic_match_counts": topic_match_counts,
            "warnings": warnings,
        }
        analysis_file = output_path / "analysis.json"
        analysis_file.write_text(json.dumps(analysis_payload, indent=2), encoding="utf-8")

        return AppReverseEngineeringResult(
            language=self.language,
            adapter_name=self.adapter_name,
            input_path=entry_path,
            input_root=root_path,
            output_dir=output_path,
            specs_dir=specs_dir,
            domains_dir=domains_dir,
            artifacts_dir=artifacts_dir,
            analysis_file=analysis_file,
            topic_files=topic_files,
            domain_files=domain_files,
            warnings=warnings,
            metadata=analysis_payload,
            primary_artifacts=primary_artifacts,
            source_count=len(source_files),
            source_language="csharp",
        )

    def _collect_sources_from_analysis(
        self,
        entry_path: Path,
        artifacts_dir: Path,
        il_result,
    ) -> Tuple[List[Path], Dict[str, Path], Dict[str, object]]:
        recovered_root = artifacts_dir / "recovered_sources"
        recovered_root.mkdir(parents=True, exist_ok=True)
        source_files: List[Path] = []
        primary_artifacts: Dict[str, Path] = {}
        decompiled_project_summary: Dict[str, object] = {
            "available": False,
            "project_file_count": 0,
            "project_files": [],
            "source_file_count": 0,
            "config_file_count": 0,
            "package_references": [],
            "project_references": [],
            "target_frameworks": [],
        }

        if il_result.il_output_file:
            il_path = Path(il_result.il_output_file)
            if il_path.exists():
                primary_artifacts["il_listing"] = il_path
                source_files.append(il_path)

        if il_result.decompiled_output_dir:
            decompiled_dir = Path(il_result.decompiled_output_dir)
            if decompiled_dir.exists():
                primary_artifacts["decompiled_project"] = decompiled_dir
                source_files.extend(sorted(decompiled_dir.rglob("*.cs")))
                decompiled_project_summary = self._summarize_decompiled_project(
                    decompiled_dir,
                    artifacts_dir,
                    primary_artifacts,
                )

        if not source_files:
            fallback_path = recovered_root / f"{entry_path.stem}_assembly_summary.cs"
            fallback_path.write_text(
                self._render_fallback_summary(entry_path, il_result.metadata, il_result.error),
                encoding="utf-8",
            )
            source_files.append(fallback_path)

        return source_files, primary_artifacts, decompiled_project_summary

    def _summarize_decompiled_project(
        self,
        decompiled_dir: Path,
        artifacts_dir: Path,
        primary_artifacts: Dict[str, Path],
    ) -> Dict[str, object]:
        project_files = sorted(
            [
                path
                for pattern in ("*.csproj", "*.fsproj", "*.vbproj")
                for path in decompiled_dir.rglob(pattern)
            ]
        )
        source_files = sorted(decompiled_dir.rglob("*.cs"))
        config_files = sorted(
            [
                path
                for pattern in ("*.json", "*.config", "*.resx", "*.xml")
                for path in decompiled_dir.rglob(pattern)
            ]
        )

        package_references: List[str] = []
        project_references: List[str] = []
        target_frameworks: List[str] = []
        for project_file in project_files:
            parsed = self._parse_project_file(project_file)
            package_references.extend(parsed["package_references"])
            project_references.extend(parsed["project_references"])
            target_frameworks.extend(parsed["target_frameworks"])

        manifest = {
            "available": True,
            "project_file_count": len(project_files),
            "project_files": [
                path.relative_to(decompiled_dir).as_posix() for path in project_files
            ],
            "source_file_count": len(source_files),
            "config_file_count": len(config_files),
            "package_references": top_values(package_references, 80),
            "project_references": top_values(project_references, 80),
            "target_frameworks": top_values(target_frameworks, 20),
        }

        manifest_path = artifacts_dir / "decompiled_project_manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        primary_artifacts["decompiled_project_manifest"] = manifest_path
        return manifest

    def _parse_project_file(self, project_file: Path) -> Dict[str, List[str]]:
        try:
            root = ElementTree.fromstring(project_file.read_text(encoding="utf-8", errors="ignore"))
        except ElementTree.ParseError:
            return {
                "package_references": [],
                "project_references": [],
                "target_frameworks": [],
            }

        package_references: List[str] = []
        project_references: List[str] = []
        target_frameworks: List[str] = []

        for element in root.iter():
            tag = element.tag.split("}", 1)[-1]
            if tag == "PackageReference":
                include = (element.attrib.get("Include") or "").strip()
                if include:
                    package_references.append(include)
            elif tag == "ProjectReference":
                include = (element.attrib.get("Include") or "").strip().replace("\\", "/")
                if include:
                    project_references.append(include)
            elif tag in {"TargetFramework", "TargetFrameworks"}:
                value = (element.text or "").strip()
                if value:
                    target_frameworks.extend([item.strip() for item in value.split(";") if item.strip()])

        return {
            "package_references": package_references,
            "project_references": project_references,
            "target_frameworks": target_frameworks,
        }

    def _render_fallback_summary(
        self, entry_path: Path, metadata: Dict[str, object], error: Optional[str]
    ) -> str:
        lines = [
            f"// Recovered summary for .NET assembly: {entry_path.name}",
            "// This file documents metadata when IL or C# decompilation is unavailable.",
            "",
            f"// Architecture: {metadata.get('architecture', 'unknown')}",
            f"// CLR header: {metadata.get('has_clr_header', False)}",
            f"// Entry point: {metadata.get('entry_point', 'unknown')}",
        ]
        if error:
            lines.append(f"// Analyzer note: {error}")
        lines.extend(
            [
                "",
                "namespace Recovered.DotNet",
                "{",
                "    public static class AssemblySummary",
                "    {",
                "        public static string Describe() => \".NET assembly metadata recovered\";",
                "    }",
                "}",
                "",
            ]
        )
        return "\n".join(lines)

    def _load_segments(self, source_files: List[Path], root_path: Path) -> List[Dict[str, object]]:
        segments: List[Dict[str, object]] = []
        for source_file in source_files:
            try:
                relative_path = source_file.resolve().relative_to(root_path)
                source_label = relative_path.as_posix()
            except ValueError:
                source_label = source_file.name
            text = source_file.read_text(encoding="utf-8", errors="ignore")
            segments.append({"source": source_label, "segments": segment_text(text)})
        return segments

    def _assessment_lines(
        self, topic_key: str, summary: Dict[str, object], source_count: int
    ) -> List[str]:
        entrypoints = list(summary.get("entrypoints", []))
        dependencies = list(summary.get("dependencies", []))
        namespaces = list(summary.get("namespaces", []))
        types = list(summary.get("types", []))
        if topic_key == "project_structure":
            return [
                f"Recovered {source_count} source or IL artifact(s) for this assembly.",
                f"Namespaces identified: {', '.join(top_values(namespaces, 8)) or 'none found'}.",
                f"Types identified: {len(types)}.",
            ]
        if topic_key == "assemblies_and_types":
            return [
                f"Framework version: {summary.get('framework_version', 'Unknown')}.",
                f"Representative types: {', '.join(top_values(types, 8)) or 'none found'}.",
                f"GUI framework: {summary.get('gui_framework', 'Unknown')}.",
            ]
        if topic_key == "dependencies_and_resources":
            return [
                f"Dependencies detected: {len(dependencies)}.",
                f"Top dependencies: {', '.join(top_values(dependencies, 10)) or 'none found'}.",
                "Dependency and resource coverage is bounded by available analyzer output.",
            ]
        if topic_key == "entrypoints_and_gui":
            return [
                f"Entrypoints: {', '.join(top_values(entrypoints, 8)) or 'none found'}.",
                f"GUI framework: {summary.get('gui_framework', 'Unknown')}.",
                "Entrypoint coverage prefers explicit IL metadata when present.",
            ]
        return [
            f"Runtime version: {summary.get('runtime_version', 'Unknown')}.",
            f"Obfuscation level: {summary.get('obfuscation_level', 'Unknown')}.",
            (
                "Tooling: "
                f"ildasm={'available' if summary.get('tooling', {}).get('ildasm', {}).get('available') else 'missing'}, "
                f"ILSpy={'used' if summary.get('tooling', {}).get('ilspy', {}).get('used') else ('available' if summary.get('tooling', {}).get('ilspy', {}).get('available') else 'missing')}."
            ),
            (
                "Decompiled project: "
                f"{summary.get('decompiled_project', {}).get('project_file_count', 0)} project file(s), "
                f"packages={', '.join(top_values(summary.get('decompiled_project', {}).get('package_references', []), 6)) or 'none found'}."
            ),
        ]
