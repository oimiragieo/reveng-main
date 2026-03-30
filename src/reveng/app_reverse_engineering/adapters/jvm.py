"""JVM adapter for the shared app reverse-engineering framework."""

from __future__ import annotations

import json
import re
import shutil
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from reveng.tools.languages.java_bytecode_analyzer import JavaBytecodeAnalyzer
from reveng.tools.languages.java_project_reconstructor import JavaProjectReconstructor

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

JVM_TOPIC_DEFINITIONS = [
    TopicDefinition(
        key="project_structure",
        title="Project Structure",
        description="Package layout, source organization, archive contents, and top-level JVM app shape.",
        keywords=("package ", "import ", "src/main/java", "META-INF", "MANIFEST.MF"),
    ),
    TopicDefinition(
        key="classes_and_methods",
        title="Classes And Methods",
        description="Class declarations, interfaces, method surfaces, and likely entrypoints.",
        keywords=("class ", "interface ", "enum ", "public static void main", "void "),
    ),
    TopicDefinition(
        key="dependencies_and_imports",
        title="Dependencies And Imports",
        description="Third-party imports, Java package dependencies, and likely build-time requirements.",
        keywords=("import ", "org.", "com.", "java.", "javax.", "kotlin.", "scala."),
    ),
    TopicDefinition(
        key="state_and_io",
        title="State And IO",
        description="Fields, stateful objects, console output, file IO, and common persistence patterns.",
        keywords=("private ", "System.out", "System.err", "File", "Path", "InputStream", "OutputStream"),
    ),
    TopicDefinition(
        key="build_and_runtime",
        title="Build And Runtime",
        description="Manifest data, main classes, decompilation routes, and reconstructed project metadata.",
        keywords=("Main-Class", "Implementation-Version", "public static void main", "maven", "gradle"),
    ),
]

PACKAGE_PATTERN = re.compile(r"(?m)^\s*package\s+([\w.]+)\s*;")
IMPORT_PATTERN = re.compile(r"(?m)^\s*import\s+([\w.*]+)\s*;")
CLASS_PATTERN = re.compile(
    r"(?m)^\s*(?:public\s+)?(?:abstract\s+)?(?:final\s+)?(?:class|interface|enum)\s+(\w+)"
)
METHOD_PATTERN = re.compile(
    r"(?m)^\s*(?:public|protected|private)?\s*(?:static\s+)?[\w<>\[\], ?]+\s+(\w+)\s*\("
)


class JVMAppAdapter:
    """Adapter for Java/JVM source and bytecode applications."""

    language = "jvm"
    adapter_name = "jvm_app_workflow"
    supported_extensions = (".java", ".class", ".jar", ".war", ".ear")

    def supports_path(self, path: Path) -> bool:
        return path.suffix.lower() in self.supported_extensions

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
        del run_deobfuscator  # Reserved for future JVM deobfuscation stages.

        entry_path = Path(input_path).expanduser().resolve()
        if not entry_path.exists():
            raise FileNotFoundError(f"JVM input not found: {entry_path}")

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
        warnings: List[str] = []
        primary_artifacts: Dict[str, Path] = {}

        source_files: List[Path] = []
        source_origin = "source"
        summary: Dict[str, object] = {
            "entry_mode": "source" if entry_path.suffix.lower() == ".java" else "bytecode",
            "packages": [],
            "classes": [],
            "methods": [],
            "imports": [],
            "entrypoints": [],
            "archive_entries": [],
            "manifest": {},
            "bytecode_analysis": {},
        }

        if entry_path.suffix.lower() == ".java":
            normalized_source_dir = artifacts_dir / "normalized_sources"
            source_files = self._collect_java_sources(entry_path, root_path)
            self._copy_sources(source_files, normalized_source_dir, root_path)
            primary_artifacts["normalized_sources"] = normalized_source_dir
            source_origin = "source"
        else:
            source_files, bytecode_metadata, generated_artifacts, generated_warnings = (
                self._reverse_engineer_bytecode(entry_path, artifacts_dir)
            )
            summary.update(bytecode_metadata)
            primary_artifacts.update(generated_artifacts)
            warnings.extend(generated_warnings)
            source_origin = "recovered_source" if source_files else "bytecode_only"

        source_segments, parsed_summary = self._load_source_segments(source_files, root_path)
        self._merge_summary(summary, parsed_summary)

        structure_path = specs_dir / "00-directory-structure.md"
        structure_path.write_text(
            render_directory_structure_doc(
                bundle_label="jvm_app",
                input_path=entry_path,
                root_path=root_path,
                output_path=output_path,
                planned_layout=[
                    "`artifacts/normalized_sources/`: copied JVM source files when source is available",
                    "`artifacts/java_bytecode_analysis/`: analyzer output for .class/.jar/.war/.ear inputs",
                    "`artifacts/recovered_sources/`: synthetic or decompiled Java sources recovered from bytecode",
                    "`artifacts/reconstructed_project/`: reconstructed Maven/Gradle project when possible",
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

        for index, topic in enumerate(JVM_TOPIC_DEFINITIONS, start=1):
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
                    language="java",
                    matches=matches,
                    assessment_lines=self._assessment_lines(topic.key, summary, source_origin, len(source_files)),
                ),
                encoding="utf-8",
            )
            domain_path.write_text(
                render_domain_file(
                    title=topic.title,
                    language="java",
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
                topic_definitions=JVM_TOPIC_DEFINITIONS,
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
            "source_origin": source_origin,
            "source_count": len(source_files),
            "packages": summary.get("packages", []),
            "classes": summary.get("classes", []),
            "methods": top_values(summary.get("methods", []), 40),
            "imports": top_values(summary.get("imports", []), 40),
            "entrypoints": summary.get("entrypoints", []),
            "archive_entries": top_values(summary.get("archive_entries", []), 80),
            "manifest": summary.get("manifest", {}),
            "bytecode_analysis": summary.get("bytecode_analysis", {}),
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
            source_language="java",
        )

    def _reverse_engineer_bytecode(
        self,
        entry_path: Path,
        artifacts_dir: Path,
    ) -> Tuple[List[Path], Dict[str, object], Dict[str, Path], List[str]]:
        """Analyze JVM bytecode input and recover Java sources where possible."""
        warnings: List[str] = []
        primary_artifacts: Dict[str, Path] = {}
        bytecode_dir = artifacts_dir / "java_bytecode_analysis"
        primary_artifacts["bytecode_analysis"] = bytecode_dir

        analyzer = JavaBytecodeAnalyzer(output_dir=str(bytecode_dir))
        analysis_result = analyzer.analyze(str(entry_path))

        metadata: Dict[str, object] = {
            "bytecode_analysis": {
                "analysis_complete": analysis_result.get("analysis_complete", False),
                "archive_type": analysis_result.get("archive_type", entry_path.suffix.lstrip(".")),
                "total_classes": analysis_result.get("total_classes", 1),
                "analyzed_classes": analysis_result.get("analyzed_classes", 1),
                "obfuscation_detected": analysis_result.get("obfuscation_detected")
                if "obfuscation_detected" in analysis_result
                else analysis_result.get("obfuscated", False),
            }
        }

        if entry_path.suffix.lower() in {".jar", ".war", ".ear"}:
            manifest, archive_entries = self._extract_archive_metadata(entry_path)
            metadata["manifest"] = manifest
            metadata["archive_entries"] = archive_entries

        source_files = self._recover_java_sources(entry_path, bytecode_dir, analysis_result, artifacts_dir)
        if not source_files:
            warnings.append("No Java sources were recovered from the bytecode input.")

        reconstructed_project = None
        if entry_path.suffix.lower() == ".jar" and source_files:
            reconstructed_dir = artifacts_dir / "reconstructed_project"
            try:
                reconstructor = JavaProjectReconstructor(output_dir=str(reconstructed_dir))
                project = reconstructor.reconstruct_from_jar(str(entry_path), str(bytecode_dir))
                reconstructed_project = reconstructed_dir
                metadata["reconstructed_project"] = {
                    "project_name": project.project_name,
                    "build_system": project.build_system,
                    "main_class": project.main_class,
                    "dependency_count": len(project.dependencies),
                }
            except Exception as exc:
                warnings.append(f"Project reconstruction failed: {exc}")

        if reconstructed_project:
            primary_artifacts["reconstructed_project"] = reconstructed_project

        return source_files, metadata, primary_artifacts, warnings

    def _recover_java_sources(
        self,
        entry_path: Path,
        bytecode_dir: Path,
        analysis_result: Dict[str, object],
        artifacts_dir: Path,
    ) -> List[Path]:
        """Recover Java source files from analyzer output or fallback decompilation."""
        decompiled_sources = sorted((bytecode_dir / "decompiled").rglob("*.java"))
        if decompiled_sources:
            return decompiled_sources

        recovered_dir = artifacts_dir / "recovered_sources"
        recovered_dir.mkdir(parents=True, exist_ok=True)
        recovered_files: List[Path] = []

        reports = analysis_result.get("results")
        class_reports = reports if isinstance(reports, list) else [analysis_result]

        for report in class_reports:
            if not isinstance(report, dict):
                continue
            class_info = report.get("class_info", {})
            decompilation_results = report.get("decompilation_results", [])
            source_code = None
            for decompilation in decompilation_results:
                if decompilation.get("success") and decompilation.get("source_code"):
                    source_code = decompilation["source_code"]
                    break
            if not source_code:
                continue

            class_name = class_info.get("class_name") or entry_path.stem
            package_name = class_info.get("package") or ""
            package_dir = recovered_dir / Path(package_name.replace(".", "/"))
            package_dir.mkdir(parents=True, exist_ok=True)
            source_path = package_dir / f"{class_name}.java"
            source_path.write_text(source_code, encoding="utf-8")
            recovered_files.append(source_path)

        return recovered_files

    def _extract_archive_metadata(self, archive_path: Path) -> Tuple[Dict[str, str], List[str]]:
        """Extract manifest and bounded file list from a JVM archive."""
        manifest: Dict[str, str] = {}
        archive_entries: List[str] = []

        try:
            with zipfile.ZipFile(archive_path, "r") as archive:
                archive_entries = archive.namelist()[:200]
                if "META-INF/MANIFEST.MF" in archive.namelist():
                    content = archive.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                    for line in content.splitlines():
                        if ":" in line:
                            key, value = line.split(":", 1)
                            manifest[key.strip()] = value.strip()
        except Exception:
            return manifest, archive_entries

        return manifest, archive_entries

    def _collect_java_sources(self, entry_path: Path, root_path: Path) -> List[Path]:
        """Collect source files for a source-based JVM app."""
        if entry_path.is_file():
            if root_path != entry_path.parent:
                files = sorted(root_path.rglob("*.java"))
                return files or [entry_path]
            return [entry_path]
        return sorted(entry_path.rglob("*.java"))

    def _copy_sources(self, source_files: Sequence[Path], dest_root: Path, root_path: Path) -> None:
        """Copy source files into the analysis artifact area."""
        dest_root.mkdir(parents=True, exist_ok=True)
        for source_file in source_files:
            try:
                relative_path = source_file.resolve().relative_to(root_path)
            except ValueError:
                relative_path = Path(source_file.name)
            destination = dest_root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_file, destination)

    def _load_source_segments(
        self,
        source_files: Sequence[Path],
        root_path: Path,
    ) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
        """Load Java source files and produce segment collections and metadata."""
        source_segments: List[Dict[str, object]] = []
        packages: List[str] = []
        classes: List[str] = []
        methods: List[str] = []
        imports: List[str] = []
        entrypoints: List[str] = []

        for source_file in source_files:
            text = source_file.read_text(encoding="utf-8", errors="replace")
            normalized_text = self._strip_java_comments(text)
            try:
                source_label = str(source_file.resolve().relative_to(root_path)).replace("\\", "/")
            except ValueError:
                source_label = source_file.name
            source_segments.append({"source": source_label, "segments": segment_text(text)})

            package_match = PACKAGE_PATTERN.search(normalized_text)
            if package_match:
                packages.append(package_match.group(1))
            classes.extend(CLASS_PATTERN.findall(normalized_text))
            imports.extend(IMPORT_PATTERN.findall(normalized_text))
            methods.extend(
                method_name
                for method_name in METHOD_PATTERN.findall(normalized_text)
                if method_name not in {"if", "for", "while", "switch", "catch", "return"}
            )
            if "public static void main" in normalized_text:
                entrypoints.append(source_label)

        summary = {
            "packages": top_values(packages, 40),
            "classes": top_values(classes, 80),
            "methods": top_values(methods, 120),
            "imports": top_values(imports, 120),
            "entrypoints": top_values(entrypoints, 40),
        }
        return source_segments, summary

    @staticmethod
    def _strip_java_comments(text: str) -> str:
        """Remove block and line comments before regex-based metadata extraction."""
        without_block_comments = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
        return re.sub(r"//.*", "", without_block_comments)

    def _merge_summary(self, summary: Dict[str, object], parsed_summary: Dict[str, object]) -> None:
        """Merge parsed source summary data into the analysis summary."""
        for key, value in parsed_summary.items():
            existing = summary.get(key, [])
            if isinstance(existing, list) and isinstance(value, list):
                summary[key] = top_values(existing + value, 120)
            else:
                summary[key] = value

    def _assessment_lines(
        self,
        topic_key: str,
        summary: Dict[str, object],
        source_origin: str,
        source_count: int,
    ) -> List[str]:
        """Build topic-specific assessment lines."""
        packages = summary.get("packages", [])
        classes = summary.get("classes", [])
        imports = summary.get("imports", [])
        entrypoints = summary.get("entrypoints", [])
        bytecode = summary.get("bytecode_analysis", {})

        lines = [
            f"Source origin: {source_origin}.",
            f"Recovered source files: {source_count}.",
            f"Packages identified: {len(packages)}.",
            f"Classes identified: {len(classes)}.",
        ]

        if topic_key == "project_structure":
            lines.append(f"Top packages: {', '.join(top_values(packages, 8)) or 'none found'}.")
        elif topic_key == "classes_and_methods":
            lines.append(
                f"Entry points: {', '.join(top_values(entrypoints, 6)) or 'no main method found'}."
            )
            lines.append(
                f"Representative classes: {', '.join(top_values(classes, 8)) or 'none found'}."
            )
        elif topic_key == "dependencies_and_imports":
            lines.append(
                f"Representative imports: {', '.join(top_values(imports, 10)) or 'none found'}."
            )
        elif topic_key == "state_and_io":
            lines.append(
                f"State and IO are inferred from source snippets, fields, and console/file patterns."
            )
        elif topic_key == "build_and_runtime":
            if isinstance(bytecode, dict) and bytecode:
                lines.append(
                    f"Bytecode analysis: {bytecode.get('analyzed_classes', 0)} class(es) analyzed; "
                    f"obfuscation_detected={bytecode.get('obfuscation_detected')}."
                )
            manifest = summary.get("manifest", {})
            if isinstance(manifest, dict) and manifest:
                manifest_preview = ", ".join(
                    f"{key}={manifest[key]}" for key in list(manifest)[:4]
                )
                lines.append(f"Manifest preview: {manifest_preview}.")

        return lines
