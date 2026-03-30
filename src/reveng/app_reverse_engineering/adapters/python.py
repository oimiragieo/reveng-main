"""Python adapter for the shared app reverse-engineering framework."""

from __future__ import annotations

import ast
import dis
import io
import json
import marshal
import re
import shutil
import subprocess
import zipfile
from pathlib import Path
from types import CodeType
from typing import Dict, List, Optional, Sequence, Tuple

from reveng.tools.languages.python_bytecode_analyzer import PythonBytecodeDetector

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

PYTHON_TOPIC_DEFINITIONS = [
    TopicDefinition(
        key="project_structure",
        title="Project Structure",
        description="Package layout, module organization, extracted archive members, and application shape.",
        keywords=("__main__.py", "class ", "def ", "import ", "from "),
    ),
    TopicDefinition(
        key="cli_and_entrypoints",
        title="CLI And Entrypoints",
        description="Main functions, CLI libraries, argument parsing, and executable entry surfaces.",
        keywords=("argparse", "click", "typer", "__name__ == '__main__'", "__name__ == \"__main__\"", "def main"),
    ),
    TopicDefinition(
        key="dependencies_and_imports",
        title="Dependencies And Imports",
        description="Imported modules, standard-library usage, and third-party dependency signals.",
        keywords=("import ", "from ", "site-packages", "dist-packages", "click", "requests"),
    ),
    TopicDefinition(
        key="state_and_io",
        title="State And IO",
        description="Filesystem, JSON, subprocess, console output, and other external effects.",
        keywords=("open(", "Path(", "print(", "json.", "subprocess", "os.environ", "write_text"),
    ),
    TopicDefinition(
        key="runtime_and_packaging",
        title="Runtime And Packaging",
        description="Bytecode versioning, archive packaging, interpreter assumptions, and recovered source caveats.",
        keywords=("python", "marshal", "dis", "zipapp", "PyInstaller", ".pyc", ".pyz"),
    ),
]


class _PythonMetadataVisitor(ast.NodeVisitor):
    """Collect summary metadata from Python ASTs."""

    def __init__(self) -> None:
        self.imports: List[str] = []
        self.functions: List[str] = []
        self.classes: List[str] = []
        self.entrypoints: List[str] = []
        self.cli_signals: List[str] = []
        self.io_signals: List[str] = []

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append(alias.name)
            if alias.name in {"argparse", "click", "typer"}:
                self.cli_signals.append(alias.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        if module:
            self.imports.append(module)
            if module in {"argparse", "click", "typer"}:
                self.cli_signals.append(module)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.classes.append(node.name)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.functions.append(node.name)
        if node.name == "main":
            self.entrypoints.append("main")
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.functions.append(node.name)
        if node.name == "main":
            self.entrypoints.append("main")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._render_name(node.func)
        if callee in {"open", "print"}:
            self.io_signals.append(callee)
        if callee.startswith("Path.") or callee == "Path":
            self.io_signals.append("pathlib")
        if callee.startswith("json."):
            self.io_signals.append("json")
        if callee.startswith("subprocess."):
            self.io_signals.append("subprocess")
        self.generic_visit(node)

    def visit_If(self, node: ast.If) -> None:
        if self._is_main_guard(node.test):
            self.entrypoints.append("__main__")
        self.generic_visit(node)

    @staticmethod
    def _is_main_guard(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == "__name__"
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.Eq)
            and len(node.comparators) == 1
            and isinstance(node.comparators[0], ast.Constant)
            and node.comparators[0].value == "__main__"
        )

    @staticmethod
    def _render_name(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            root = _PythonMetadataVisitor._render_name(node.value)
            return f"{root}.{node.attr}" if root else node.attr
        return ""


class PythonAppAdapter:
    """Adapter for Python source, bytecode, and zipapp-style inputs."""

    language = "python"
    adapter_name = "python_app_workflow"
    supported_extensions = (".py", ".pyc", ".pyo", ".pyz")
    pyinstaller_markers = (
        b"PyInstaller",
        b"_MEIPASS",
        b"pyi_rth_",
        b"pyimod",
        b"base_library.zip",
        b"PYZ.pyz",
        b"MEI\x0c\x0b\x0a\x0b\x0e",
    )

    def supports_path(self, path: Path) -> bool:
        if path.suffix.lower() in self.supported_extensions:
            return True
        return self._looks_like_pyinstaller(path)

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
        del run_deobfuscator  # Reserved for future Python deobfuscation work.

        entry_path = Path(input_path).expanduser().resolve()
        if not entry_path.exists():
            raise FileNotFoundError(f"Python input not found: {entry_path}")

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
        summary: Dict[str, object] = {
            "entry_mode": entry_path.suffix.lower().lstrip("."),
            "imports": [],
            "functions": [],
            "classes": [],
            "entrypoints": [],
            "cli_signals": [],
            "io_signals": [],
            "archive_entries": [],
            "packaging": "source",
            "bytecode": {},
        }

        if entry_path.suffix.lower() == ".py":
            source_origin = "source"
            source_root = artifacts_dir / "normalized_sources"
            source_files = self._copy_python_sources([entry_path], source_root, root_path)
            primary_artifacts["normalized_sources"] = source_root
        elif entry_path.suffix.lower() in {".pyc", ".pyo"}:
            source_origin = "bytecode"
            source_files, bytecode_summary, bytecode_artifacts, bytecode_warnings = (
                self._reverse_engineer_bytecode(entry_path, artifacts_dir)
            )
            summary.update(bytecode_summary)
            primary_artifacts.update(bytecode_artifacts)
            warnings.extend(bytecode_warnings)
        elif entry_path.suffix.lower() == ".pyz":
            source_origin = "archive"
            source_files, archive_summary, archive_artifacts = self._extract_zipapp(
                entry_path, artifacts_dir
            )
            summary.update(archive_summary)
            primary_artifacts.update(archive_artifacts)
        else:
            source_origin = "frozen_binary"
            source_files, frozen_summary, frozen_artifacts, frozen_warnings = (
                self._reverse_engineer_frozen_python(entry_path, artifacts_dir)
            )
            summary.update(frozen_summary)
            primary_artifacts.update(frozen_artifacts)
            warnings.extend(frozen_warnings)

        source_segments, parsed_summary = self._load_source_segments(source_files, root_path)
        self._merge_summary(summary, parsed_summary)

        structure_path = specs_dir / "00-directory-structure.md"
        structure_path.write_text(
            render_directory_structure_doc(
                bundle_label="python_app",
                input_path=entry_path,
                root_path=root_path,
                output_path=output_path,
                planned_layout=[
                    "`artifacts/normalized_sources/`: copied Python sources when source input is available",
                    "`artifacts/recovered_sources/`: synthetic or decompiled Python recovered from bytecode",
                    "`artifacts/bytecode_disassembly.txt`: stdlib disassembly for .pyc/.pyo analysis",
                    "`artifacts/extracted_sources/`: extracted zipapp sources for .pyz inputs",
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

        for index, topic in enumerate(PYTHON_TOPIC_DEFINITIONS, start=1):
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
                    language="python",
                    matches=matches,
                    assessment_lines=self._assessment_lines(
                        topic.key, summary, source_origin, len(source_files)
                    ),
                ),
                encoding="utf-8",
            )
            domain_path.write_text(
                render_domain_file(
                    title=topic.title,
                    language="python",
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
                topic_definitions=PYTHON_TOPIC_DEFINITIONS,
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
            "imports": top_values(summary.get("imports", []), 80),
            "functions": top_values(summary.get("functions", []), 80),
            "classes": top_values(summary.get("classes", []), 80),
            "entrypoints": top_values(summary.get("entrypoints", []), 40),
            "cli_signals": top_values(summary.get("cli_signals", []), 20),
            "io_signals": top_values(summary.get("io_signals", []), 20),
            "archive_entries": top_values(summary.get("archive_entries", []), 120),
            "packaging": summary.get("packaging", "source"),
            "bytecode": summary.get("bytecode", {}),
            "frozen_python": summary.get("frozen_python", {}),
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
            source_language="python",
        )

    def _copy_python_sources(
        self, source_files: List[Path], destination_root: Path, root_path: Path
    ) -> List[Path]:
        destination_root.mkdir(parents=True, exist_ok=True)
        copied: List[Path] = []
        for source_file in source_files:
            try:
                relative_path = source_file.resolve().relative_to(root_path)
            except ValueError:
                relative_path = Path(source_file.name)
            destination_path = destination_root / relative_path
            destination_path.parent.mkdir(parents=True, exist_ok=True)
            destination_path.write_text(source_file.read_text(encoding="utf-8"), encoding="utf-8")
            copied.append(destination_path)
        return copied

    def _extract_zipapp(
        self, archive_path: Path, artifacts_dir: Path
    ) -> Tuple[List[Path], Dict[str, object], Dict[str, Path]]:
        extracted_root = artifacts_dir / "extracted_sources"
        extracted_root.mkdir(parents=True, exist_ok=True)
        archive_entries: List[str] = []
        source_files: List[Path] = []

        with zipfile.ZipFile(archive_path, "r") as archive:
            for member in archive.namelist():
                archive_entries.append(member)
                if member.endswith("/") or not member.endswith(".py"):
                    continue
                destination = extracted_root / Path(member)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(member))
                source_files.append(destination)

        summary = {
            "archive_entries": archive_entries,
            "packaging": "zipapp",
            "entrypoints": ["__main__.py"] if "__main__.py" in archive_entries else [],
        }
        artifacts = {"extracted_sources": extracted_root}
        return source_files, summary, artifacts

    def _reverse_engineer_frozen_python(
        self, frozen_path: Path, artifacts_dir: Path
    ) -> Tuple[List[Path], Dict[str, object], Dict[str, Path], List[str]]:
        warnings: List[str] = []
        source_files: List[Path] = []
        recovered_root = artifacts_dir / "recovered_sources"
        extracted_root = artifacts_dir / "extracted_sources"
        recovered_root.mkdir(parents=True, exist_ok=True)
        extracted_root.mkdir(parents=True, exist_ok=True)
        strings_path = artifacts_dir / "frozen_python_strings.txt"

        payload = frozen_path.read_bytes()
        markers = self._detect_pyinstaller_markers(payload)
        candidate_entries = self._extract_candidate_archive_entries(payload)
        strings_path.write_text("\n".join(candidate_entries), encoding="utf-8")

        viewer_listing = self._run_pyi_archive_viewer(frozen_path, artifacts_dir)
        if viewer_listing["warnings"]:
            warnings.extend(viewer_listing["warnings"])
        if viewer_listing["entries"]:
            candidate_entries = top_values(candidate_entries + viewer_listing["entries"], 200)
        extracted_entries = self._extract_python_entries_from_archive_viewer(
            frozen_path,
            extracted_root,
            viewer_listing["entries"],
        )
        source_files.extend(extracted_entries["source_files"])
        if extracted_entries["warnings"]:
            warnings.extend(extracted_entries["warnings"])

        notes_path = recovered_root / f"{frozen_path.stem}_frozen_runtime.py"
        notes_path.write_text(
            self._render_frozen_runtime_notes(frozen_path, markers, candidate_entries),
            encoding="utf-8",
        )
        source_files.append(notes_path)

        summary = {
            "packaging": "pyinstaller",
            "entrypoints": [notes_path.name],
            "imports": candidate_entries,
            "frozen_python": {
                "markers": markers,
                "candidate_entries": candidate_entries,
                "archive_viewer_available": viewer_listing["available"],
                "archive_viewer_entries": viewer_listing["entries"],
                "extracted_entries": extracted_entries["entry_names"],
            },
        }
        artifacts = {
            "frozen_python_strings": strings_path,
            "recovered_sources": recovered_root,
        }
        if extracted_entries["entry_names"]:
            artifacts["extracted_sources"] = extracted_root
        if viewer_listing["listing_path"] is not None:
            artifacts["pyi_archive_listing"] = viewer_listing["listing_path"]
        return source_files, summary, artifacts, warnings

    def _reverse_engineer_bytecode(
        self, bytecode_path: Path, artifacts_dir: Path
    ) -> Tuple[List[Path], Dict[str, object], Dict[str, Path], List[str]]:
        warnings: List[str] = []
        source_files: List[Path] = []
        recovered_root = artifacts_dir / "recovered_sources"
        recovered_root.mkdir(parents=True, exist_ok=True)
        disassembly_path = artifacts_dir / "bytecode_disassembly.txt"

        is_python, bytecode_info = PythonBytecodeDetector.detect(str(bytecode_path))
        bytecode_summary: Dict[str, object] = {
            "packaging": "bytecode",
            "bytecode": {
                "detected": is_python,
                "python_version": bytecode_info.python_version if bytecode_info else "unknown",
                "magic_number": bytecode_info.magic_number if bytecode_info else None,
                "is_obfuscated": bytecode_info.is_obfuscated if bytecode_info else False,
                "obfuscator": bytecode_info.obfuscator if bytecode_info else None,
            },
            "imports": bytecode_info.imports if bytecode_info else [],
            "functions": bytecode_info.functions if bytecode_info else [],
            "classes": bytecode_info.classes if bytecode_info else [],
            "entrypoints": [],
        }

        primary_artifacts: Dict[str, Path] = {}
        code_object = self._load_code_object(bytecode_path)
        if code_object is None:
            warnings.append("Could not decode the .pyc payload with stdlib marshal fallback.")
            return source_files, bytecode_summary, primary_artifacts, warnings

        disassembly_text = self._disassemble_code_object(code_object)
        disassembly_path.write_text(disassembly_text, encoding="utf-8")
        primary_artifacts["bytecode_disassembly"] = disassembly_path

        recovered_source = self._render_pseudo_source(bytecode_path, code_object, bytecode_summary)
        recovered_path = recovered_root / f"{bytecode_path.stem}.py"
        recovered_path.write_text(recovered_source, encoding="utf-8")
        source_files.append(recovered_path)
        primary_artifacts["recovered_sources"] = recovered_root

        summary_imports, summary_functions, summary_classes = self._analyze_code_object(code_object)
        bytecode_summary["imports"] = top_values(
            list(bytecode_summary.get("imports", [])) + summary_imports,
            80,
        )
        bytecode_summary["functions"] = top_values(
            list(bytecode_summary.get("functions", [])) + summary_functions,
            80,
        )
        bytecode_summary["classes"] = top_values(
            list(bytecode_summary.get("classes", [])) + summary_classes,
            80,
        )
        if "main" in summary_functions:
            bytecode_summary["entrypoints"] = ["main"]

        return source_files, bytecode_summary, primary_artifacts, warnings

    def _looks_like_pyinstaller(self, path: Path) -> bool:
        if not path.is_file():
            return False
        suffix = path.suffix.lower()
        if suffix not in {".exe", ".bin", ""}:
            return False
        try:
            sample = path.read_bytes()
        except OSError:
            return False
        return bool(self._detect_pyinstaller_markers(sample))

    def _detect_pyinstaller_markers(self, payload: bytes) -> List[str]:
        matches: List[str] = []
        for marker in self.pyinstaller_markers:
            if marker in payload:
                decoded = marker.decode("utf-8", errors="ignore")
                if decoded and decoded not in matches:
                    matches.append(decoded)
        return matches

    def _extract_candidate_archive_entries(self, payload: bytes) -> List[str]:
        ascii_strings = {
            match.decode("utf-8", errors="ignore")
            for match in re.findall(rb"[\x20-\x7e]{6,}", payload)
        }
        candidates: List[str] = []
        for value in sorted(ascii_strings):
            lowered = value.lower()
            if any(
                token in lowered
                for token in (
                    ".pyc",
                    ".pyz",
                    ".pyd",
                    ".dll",
                    ".so",
                    "base_library.zip",
                    "pyi_rth_",
                    "pyimod",
                    "__main__",
                )
            ):
                candidates.append(value)
        return top_values(candidates, 200)

    def _run_pyi_archive_viewer(
        self, frozen_path: Path, artifacts_dir: Path
    ) -> Dict[str, object]:
        listing_path = artifacts_dir / "pyi_archive_listing.txt"
        if shutil.which("pyi-archive_viewer") is None:
            return {
                "available": False,
                "entries": [],
                "warnings": ["pyi-archive_viewer not available; skipped PyInstaller archive introspection."],
                "listing_path": None,
            }

        try:
            result = subprocess.run(
                ["pyi-archive_viewer", str(frozen_path)],
                input="Q\n",
                capture_output=True,
                text=True,
                timeout=30,
            )
        except Exception as exc:
            return {
                "available": True,
                "entries": [],
                "warnings": [f"pyi-archive_viewer failed: {exc}"],
                "listing_path": None,
            }

        output = (result.stdout or "") + ("\n" + result.stderr if result.stderr else "")
        listing_path.write_text(output, encoding="utf-8")
        entries = self._parse_archive_viewer_entries(output)
        warnings: List[str] = []
        if result.returncode not in {0, 1}:
            warnings.append(f"pyi-archive_viewer returned code {result.returncode}.")
        return {
            "available": True,
            "entries": entries,
            "warnings": warnings,
            "listing_path": listing_path,
        }

    def _parse_archive_viewer_entries(self, output: str) -> List[str]:
        entries: List[str] = []
        for line in output.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            if any(token in stripped.lower() for token in (".py", ".pyc", ".pyz", ".pyd", ".dll")):
                entries.append(stripped)
        return top_values(entries, 200)

    def _extract_python_entries_from_archive_viewer(
        self,
        frozen_path: Path,
        extracted_root: Path,
        archive_entries: Sequence[str],
    ) -> Dict[str, object]:
        if shutil.which("pyi-archive_viewer") is None:
            return {"entry_names": [], "source_files": [], "warnings": []}

        entry_names = self._normalize_archive_entry_names(archive_entries)
        extracted_names: List[str] = []
        source_files: List[Path] = []
        warnings: List[str] = []

        for entry_name in entry_names[:12]:
            destination = extracted_root / Path(*Path(entry_name).parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            try:
                result = subprocess.run(
                    ["pyi-archive_viewer", str(frozen_path)],
                    input=f"X {entry_name}\n{destination}\nQ\n",
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
            except Exception as exc:
                warnings.append(f"pyi-archive_viewer extraction failed for {entry_name}: {exc}")
                continue

            if result.returncode not in {0, 1}:
                warnings.append(
                    f"pyi-archive_viewer extraction returned code {result.returncode} for {entry_name}."
                )
                continue

            if not destination.exists():
                continue

            extracted_names.append(entry_name)
            if destination.suffix.lower() == ".py":
                source_files.append(destination)
            elif destination.suffix.lower() in {".pyc", ".pyo"}:
                source_files.extend(
                    self._recover_extracted_bytecode_sources(destination, extracted_root, warnings)
                )

        return {
            "entry_names": extracted_names,
            "source_files": source_files,
            "warnings": warnings,
        }

    def _normalize_archive_entry_names(self, archive_entries: Sequence[str]) -> List[str]:
        normalized: List[str] = []
        for entry in archive_entries:
            value = entry.strip().strip("'\"")
            if not value:
                continue
            if "," in value:
                value = value.rsplit(",", 1)[-1].strip().strip("'\"")
            lowered = value.lower()
            if lowered.endswith((".py", ".pyc", ".pyo")) and value not in normalized:
                normalized.append(value)
        return normalized

    def _recover_extracted_bytecode_sources(
        self, bytecode_path: Path, extracted_root: Path, warnings: List[str]
    ) -> List[Path]:
        code_object = self._load_code_object(bytecode_path)
        if code_object is None:
            warnings.append(
                f"Could not decode extracted bytecode entry {bytecode_path.name} with stdlib marshal fallback."
            )
            return []
        recovered_source = self._render_pseudo_source(
            bytecode_path,
            code_object,
            {
                "bytecode": {"python_version": "unknown"},
            },
        )
        recovered_path = extracted_root / f"{bytecode_path.stem}_recovered.py"
        recovered_path.write_text(recovered_source, encoding="utf-8")
        return [recovered_path]

    def _render_frozen_runtime_notes(
        self, frozen_path: Path, markers: Sequence[str], candidate_entries: Sequence[str]
    ) -> str:
        lines = [
            f"# Recovered packaging notes for frozen Python executable: {frozen_path.name}",
            "# This file documents runtime markers and candidate embedded members.",
            "",
            f"PYINSTALLER_MARKERS = {list(markers)!r}",
            f"CANDIDATE_ARCHIVE_ENTRIES = {list(candidate_entries)!r}",
            "",
            "def describe_frozen_runtime():",
            "    return {",
            "        'packaging': 'pyinstaller',",
            "        'markers': PYINSTALLER_MARKERS,",
            "        'candidate_entries': CANDIDATE_ARCHIVE_ENTRIES,",
            "    }",
            "",
        ]
        return "\n".join(lines)

    def _load_code_object(self, bytecode_path: Path) -> Optional[CodeType]:
        payload = bytecode_path.read_bytes()
        for offset in (16, 12, 8):
            if len(payload) <= offset:
                continue
            try:
                code_object = marshal.loads(payload[offset:])
            except Exception:
                continue
            if isinstance(code_object, CodeType):
                return code_object
        return None

    def _disassemble_code_object(self, code_object: CodeType) -> str:
        buffer = io.StringIO()
        dis.dis(code_object, file=buffer, adaptive=False, show_offsets=True)
        return buffer.getvalue()

    def _render_pseudo_source(
        self, bytecode_path: Path, code_object: CodeType, bytecode_summary: Dict[str, object]
    ) -> str:
        imports, functions, classes = self._analyze_code_object(code_object)
        python_version = bytecode_summary["bytecode"].get("python_version", "unknown")
        lines = [
            f"# Recovered from bytecode: {bytecode_path.name}",
            f"# Python bytecode version: {python_version}",
            "# This is a structural reconstruction generated from stdlib bytecode inspection.",
            "",
        ]

        for module_name in top_values(imports, 20):
            if module_name.isidentifier():
                lines.append(f"import {module_name}")

        if imports:
            lines.append("")

        for class_name in top_values(classes, 20):
            if class_name.isidentifier():
                lines.extend(
                    [
                        f"class {class_name}:",
                        '    """Recovered class placeholder."""',
                        "    pass",
                        "",
                    ]
                )

        for function_name in top_values(functions, 30):
            if function_name.isidentifier():
                lines.extend(
                    [
                        f"def {function_name}(*args, **kwargs):",
                        '    """Recovered function placeholder."""',
                        "    raise NotImplementedError('Recovered from bytecode only')",
                        "",
                    ]
                )

        if len(lines) == 4:
            lines.extend(
                [
                    "def recovered_entrypoint(*args, **kwargs):",
                    '    """Fallback placeholder when symbolic recovery is limited."""',
                    "    raise NotImplementedError('Recovered from bytecode only')",
                    "",
                ]
            )

        return "\n".join(lines).strip() + "\n"

    def _analyze_code_object(self, code_object: CodeType) -> Tuple[List[str], List[str], List[str]]:
        imports: List[str] = []
        functions: List[str] = []
        classes: List[str] = []

        names = getattr(code_object, "co_names", ())
        for name in names:
            if not isinstance(name, str):
                continue
            if name and name[0].isupper():
                classes.append(name)
            else:
                functions.append(name)
        consts = getattr(code_object, "co_consts", ())
        for const in consts:
            if isinstance(const, str) and const.isidentifier():
                imports.append(const)
            elif isinstance(const, CodeType):
                functions.append(const.co_name)
                nested_imports, nested_functions, nested_classes = self._analyze_code_object(const)
                imports.extend(nested_imports)
                functions.extend(nested_functions)
                classes.extend(nested_classes)

        return top_values(imports, 80), top_values(functions, 80), top_values(classes, 80)

    def _load_source_segments(
        self, source_files: List[Path], root_path: Path
    ) -> Tuple[List[Dict[str, object]], Dict[str, object]]:
        source_segments: List[Dict[str, object]] = []
        imports: List[str] = []
        functions: List[str] = []
        classes: List[str] = []
        entrypoints: List[str] = []
        cli_signals: List[str] = []
        io_signals: List[str] = []

        for source_file in source_files:
            try:
                relative_path = source_file.resolve().relative_to(root_path)
                source_label = relative_path.as_posix()
            except ValueError:
                source_label = source_file.name

            text = source_file.read_text(encoding="utf-8", errors="ignore")
            source_segments.append({"source": source_label, "segments": segment_text(text)})

            try:
                parsed = ast.parse(text)
            except SyntaxError:
                continue

            visitor = _PythonMetadataVisitor()
            visitor.visit(parsed)
            imports.extend(visitor.imports)
            functions.extend(visitor.functions)
            classes.extend(visitor.classes)
            cli_signals.extend(visitor.cli_signals)
            io_signals.extend(visitor.io_signals)
            entrypoints.extend(visitor.entrypoints)
            if source_file.name == "__main__.py":
                entrypoints.append("__main__.py")

        summary = {
            "imports": top_values(imports, 80),
            "functions": top_values(functions, 80),
            "classes": top_values(classes, 80),
            "entrypoints": top_values(entrypoints, 40),
            "cli_signals": top_values(cli_signals, 20),
            "io_signals": top_values(io_signals, 20),
        }
        return source_segments, summary

    def _merge_summary(self, summary: Dict[str, object], parsed_summary: Dict[str, object]) -> None:
        for key in ("imports", "functions", "classes", "entrypoints", "cli_signals", "io_signals"):
            combined = list(summary.get(key, [])) + list(parsed_summary.get(key, []))
            summary[key] = top_values(combined, 80)

    def _assessment_lines(
        self, topic_key: str, summary: Dict[str, object], source_origin: str, source_count: int
    ) -> List[str]:
        imports = list(summary.get("imports", []))
        functions = list(summary.get("functions", []))
        classes = list(summary.get("classes", []))
        entrypoints = list(summary.get("entrypoints", []))
        cli_signals = list(summary.get("cli_signals", []))
        io_signals = list(summary.get("io_signals", []))
        packaging = summary.get("packaging", "source")
        bytecode = summary.get("bytecode", {})
        frozen_python = summary.get("frozen_python", {})

        if topic_key == "project_structure":
            return [
                f"Recovered {source_count} Python source file(s) from {source_origin} input.",
                f"Packaging mode: {packaging}.",
                f"Top-level classes: {', '.join(top_values(classes, 8)) or 'none found'}.",
            ]
        if topic_key == "cli_and_entrypoints":
            return [
                f"Entrypoints detected: {', '.join(top_values(entrypoints, 8)) or 'none found'}.",
                f"CLI signals: {', '.join(top_values(cli_signals, 8)) or 'none found'}.",
                f"Representative functions: {', '.join(top_values(functions, 8)) or 'none found'}.",
            ]
        if topic_key == "dependencies_and_imports":
            return [
                f"Imports detected: {len(imports)} unique module reference(s).",
                f"Top imports: {', '.join(top_values(imports, 10)) or 'none found'}.",
                "Treat imports as evidence of module reachability, not guaranteed runtime execution.",
            ]
        if topic_key == "state_and_io":
            return [
                f"IO signals: {', '.join(top_values(io_signals, 8)) or 'none found'}.",
                "State and IO coverage is heuristic and based on recovered source snippets.",
            ]
        return [
            f"Packaging mode: {packaging}.",
            (
                f"Python bytecode version: {bytecode.get('python_version', 'n/a')}."
                if packaging == "bytecode"
                else (
                    (
                        f"PyInstaller markers: {', '.join(top_values(frozen_python.get('markers', []), 8)) or 'none found'}. "
                        f"Archive viewer: {'available' if frozen_python.get('archive_viewer_available') else 'not available'}; "
                        f"viewer entries={len(frozen_python.get('archive_viewer_entries', []))}."
                    )
                    if packaging == "pyinstaller"
                    else "Runtime details are inferred from recovered source and packaging layout."
                )
            ),
            "Bytecode and packaging details are interpreter-specific and may vary across Python releases.",
        ]
