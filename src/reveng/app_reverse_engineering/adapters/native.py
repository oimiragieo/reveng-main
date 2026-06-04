"""Native adapter for the shared app reverse-engineering framework."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from reveng.analysis.native.ghidra_workflow import (
    build_native_project_ir,
    build_native_source_segments,
    materialize_decompiled_functions,
    run_native_ghidra_analysis,
    write_analysis_payload,
)

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
    top_values,
)

NATIVE_TOPIC_DEFINITIONS = [
    TopicDefinition(
        key="binary_overview",
        title="Binary Overview",
        description="Container shape, backend used, function coverage, and recovered native structure.",
        keywords=("entry", "function", "decompiled", "address", "backend"),
    ),
    TopicDefinition(
        key="imports_and_dependencies",
        title="Imports And Dependencies",
        description="Imported APIs, linked libraries, and dependency-like native surfaces.",
        keywords=("import", "LoadLibrary", "GetProcAddress", "socket", "http", "kernel32"),
    ),
    TopicDefinition(
        key="strings_and_endpoints",
        title="Strings And Endpoints",
        description="High-signal strings, URLs, flags, and configuration-like native evidence.",
        keywords=("http", "https", "--", ".json", "config", "token"),
    ),
    TopicDefinition(
        key="exports_and_entrypoints",
        title="Exports And Entrypoints",
        description="Exports, entrypoint-adjacent functions, and top-level execution surfaces.",
        keywords=("export", "main", "WinMain", "DllMain", "entry"),
    ),
    TopicDefinition(
        key="references_and_symbols",
        title="References And Symbols",
        description="Cross-references, namespaces, and recovered data symbols from the native analysis database.",
        keywords=("xref", "namespace", "symbol", "data", "call", "reference"),
    ),
]


class NativeAppAdapter:
    """Adapter for native executable and shared-library inputs."""

    language = "native"
    adapter_name = "native_ghidra_workflow"
    supported_extensions = (".exe", ".dll", ".so", ".dylib", ".elf", ".bin")

    def __init__(self, *, ghidra_timeout_seconds: int = 45) -> None:
        self.ghidra_timeout_seconds = max(10, ghidra_timeout_seconds)

    def supports_path(self, path: Path) -> bool:
        if path.suffix.lower() in self.supported_extensions:
            return True
        return path.is_file() and path.suffix == ""

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
        ghidra_timeout: int = 45,
    ) -> AppReverseEngineeringResult:
        del run_deobfuscator  # Reserved for future native post-processing.
        effective_timeout = max(10, ghidra_timeout or self.ghidra_timeout_seconds)

        entry_path = Path(input_path).expanduser().resolve()
        if not entry_path.exists():
            raise FileNotFoundError(f"Native input not found: {entry_path}")

        explicit_input_root = Path(input_root).expanduser().resolve() if input_root else None
        root_path = explicit_input_root if explicit_input_root else entry_path.parent.resolve()
        output_path = Path(output_dir).expanduser().resolve()
        specs_dir = output_path / "SPECS"
        domains_dir = specs_dir / "domains"
        artifacts_dir = output_path / "artifacts"
        specs_dir.mkdir(parents=True, exist_ok=True)
        domains_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        skip_values = normalize_skip_patterns(skip_patterns or [])
        input_tree = self._build_input_tree(entry_path, root_path, explicit_input_root)
        warnings: List[str] = []
        primary_artifacts: Dict[str, Path] = {}

        analysis_result = run_native_ghidra_analysis(
            str(entry_path), timeout=effective_timeout
        )
        analysis_data = analysis_result.get("analysis_data", {})
        if analysis_result.get("warning"):
            warnings.append(str(analysis_result["warning"]))
        if analysis_result.get("status") == "failed":
            warnings.append(
                "Native analysis completed without a working Ghidra backend; "
                "continuing with partial native enrichment only."
            )
        for error in analysis_result.get("errors", []):
            warnings.append(str(error))

        ghidra_report_path = artifacts_dir / "ghidra_analysis.json"
        write_analysis_payload(analysis_data, ghidra_report_path)
        primary_artifacts["ghidra_analysis"] = ghidra_report_path

        decompiled_dir = artifacts_dir / "decompiled_functions"
        decompiled_files = materialize_decompiled_functions(analysis_data, decompiled_dir)
        if decompiled_files:
            primary_artifacts["decompiled_functions"] = decompiled_dir

        capa_result = self._run_optional_capa(entry_path, artifacts_dir, warnings)
        if capa_result["artifact_path"] is not None:
            primary_artifacts["capa"] = capa_result["artifact_path"]

        floss_result = self._run_optional_floss(entry_path, artifacts_dir, warnings)
        if floss_result["artifact_path"] is not None:
            primary_artifacts["floss"] = floss_result["artifact_path"]

        project_ir = build_native_project_ir(
            binary_path=entry_path,
            analysis_data=analysis_data,
            backend=str(analysis_result.get("backend", "unknown")),
            warnings=warnings,
        )
        project_ir.metadata["enrichment"] = {
            "capa_rule_count": capa_result["rule_count"],
            "floss_decoded_string_count": floss_result["decoded_string_count"],
            "floss_stack_string_count": floss_result["stack_string_count"],
        }
        ir_path = artifacts_dir / "project_ir.json"
        write_analysis_payload(project_ir.to_dict(), ir_path)
        primary_artifacts["project_ir"] = ir_path

        source_segments = build_native_source_segments(analysis_data)
        if floss_result["decoded_strings"]:
            source_segments.append(
                {
                    "source": "floss:decoded_strings",
                    "segments": list(floss_result["decoded_strings"][:120]),
                }
            )
        if capa_result["capabilities"]:
            source_segments.append(
                {
                    "source": "capa:capabilities",
                    "segments": list(capa_result["capabilities"][:120]),
                }
            )

        structure_path = specs_dir / "00-directory-structure.md"
        structure_path.write_text(
            render_directory_structure_doc(
                bundle_label="native_app",
                input_path=entry_path,
                root_path=root_path,
                output_path=output_path,
                planned_layout=[
                    "`artifacts/ghidra_analysis.json`: normalized Ghidra-style analysis payload",
                    "`artifacts/decompiled_functions/`: decompiled functions recovered from analysis",
                    "`artifacts/project_ir.json`: shared reverse-engineering IR graph",
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

        for index, topic in enumerate(NATIVE_TOPIC_DEFINITIONS, start=1):
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
                    language="c",
                    matches=matches,
                    assessment_lines=self._assessment_lines(
                        topic.key,
                        analysis_data,
                        analysis_result,
                        len(decompiled_files),
                    ),
                ),
                encoding="utf-8",
            )
            domain_path.write_text(
                render_domain_file(
                    title=topic.title,
                    language="c",
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
                topic_definitions=NATIVE_TOPIC_DEFINITIONS,
                topic_match_counts=topic_match_counts,
            ),
            encoding="utf-8",
        )

        imports = self._normalize_named_items(analysis_data.get("imports", []))
        exports = self._normalize_named_items(analysis_data.get("exports", []))
        namespaces = self._normalize_named_items(analysis_data.get("namespaces", []))
        data_items = self._normalize_data_items(analysis_data.get("data_items", analysis_data.get("data", [])))
        xref_targets, xref_records = self._normalize_xref_map(analysis_data.get("xrefs", {}))
        functions = self._normalize_function_names(analysis_data.get("functions", []))
        strings = self._normalize_string_items(analysis_data.get("strings", []))
        function_details = self._build_function_detail_summary(analysis_data.get("functions", []), xref_targets)

        analysis_payload = {
            "language": self.language,
            "adapter_name": self.adapter_name,
            "input_path": str(entry_path),
            "input_root": str(root_path),
            "output_dir": str(output_path),
            "backend": analysis_result.get("backend", "unknown"),
            "analysis_status": analysis_result.get("status", "unknown"),
            "analysis_summary": analysis_result.get("summary", {}),
            "source_origin": "decompiled_native" if decompiled_files else "analysis_only",
            "source_count": len(decompiled_files),
            "functions": top_values(functions, 120),
            "imports": top_values(imports, 120),
            "exports": top_values(exports, 80),
            "namespaces": top_values(namespaces, 80),
            "data_items": top_values(data_items, 80),
            "xrefs": self._summarize_xref_targets(xref_targets),
            "function_details": function_details[:40],
            "strings": top_values(strings, 120),
            "topic_match_counts": topic_match_counts,
            "warnings": warnings,
            "project_ir_path": str(ir_path),
            "tooling": {
                "ghidra_backend": analysis_result.get("backend", "unknown"),
                "capa": {
                    "available": capa_result["available"],
                    "ran": capa_result["ran"],
                    "rule_count": capa_result["rule_count"],
                },
                "floss": {
                    "available": floss_result["available"],
                    "ran": floss_result["ran"],
                    "decoded_string_count": floss_result["decoded_string_count"],
                    "stack_string_count": floss_result["stack_string_count"],
                },
            },
            "native_surface": {
                "xref_target_count": len(xref_targets),
                "xref_reference_count": len(xref_records),
                "namespace_count": len(namespaces),
                "data_item_count": len(data_items),
                "function_detail_count": len(function_details),
            },
            "capa": {
                "capabilities": capa_result["capabilities"],
                "rule_count": capa_result["rule_count"],
            },
            "floss": {
                "decoded_strings": floss_result["decoded_strings"],
                "decoded_string_count": floss_result["decoded_string_count"],
                "stack_string_count": floss_result["stack_string_count"],
            },
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
            source_count=len(decompiled_files),
            source_language="c" if decompiled_files else None,
        )

    def _assessment_lines(
        self,
        topic_key: str,
        analysis_data: Dict[str, object],
        analysis_result: Dict[str, object],
        source_count: int,
    ) -> List[str]:
        imports = self._normalize_named_items(analysis_data.get("imports", []))
        exports = self._normalize_named_items(analysis_data.get("exports", []))
        functions = self._normalize_function_names(analysis_data.get("functions", []))
        strings = self._normalize_string_items(analysis_data.get("strings", []))
        summary = analysis_result.get("summary", {})

        lines = [
            f"Backend: {analysis_result.get('backend', 'unknown')}.",
            f"Analysis status: {analysis_result.get('status', 'unknown')}.",
            f"Recovered decompiled functions: {source_count}.",
            f"Functions observed: {summary.get('functions', len(functions))}.",
        ]
        if topic_key == "binary_overview":
            lines.append(
                f"Representative functions: {', '.join(top_values(functions, 8)) or 'none found'}."
            )
        elif topic_key == "references_and_symbols":
            lines.append(
                f"Namespaces: {', '.join(top_values(analysis_data.get('namespaces', []), 8)) or 'none found'}."
            )
            lines.append(
                f"Data items: {', '.join(top_values(self._normalize_data_items(analysis_data.get('data_items', analysis_data.get('data', []))), 8)) or 'none found'}."
            )
        elif topic_key == "imports_and_dependencies":
            lines.append(
                f"Representative imports: {', '.join(top_values(imports, 10)) or 'none found'}."
            )
        elif topic_key == "strings_and_endpoints":
            lines.append(
                f"Representative strings: {', '.join(top_values(strings, 8)) or 'none found'}."
            )
        elif topic_key == "exports_and_entrypoints":
            lines.append(f"Exports: {', '.join(top_values(exports, 8)) or 'none found'}.")
        return lines

    @staticmethod
    def _normalize_named_items(values: object) -> List[str]:
        normalized: List[str] = []
        for item in values or []:
            if isinstance(item, str):
                value = item.strip()
            elif isinstance(item, dict):
                value = str(
                    item.get("name")
                    or item.get("symbol")
                    or item.get("import_name")
                    or item.get("library")
                    or ""
                ).strip()
            else:
                value = str(item).strip()
            if value and value not in normalized:
                normalized.append(value)
        return normalized

    @staticmethod
    def _normalize_function_names(values: object) -> List[str]:
        names: List[str] = []
        for item in values or []:
            if not isinstance(item, dict):
                value = str(item).strip()
            else:
                value = str(
                    item.get("name") or item.get("entry_point") or item.get("address") or ""
                ).strip()
            if value and value not in names:
                names.append(value)
        return names

    @staticmethod
    def _normalize_string_items(values: object) -> List[str]:
        strings: List[str] = []
        for item in values or []:
            if isinstance(item, str):
                value = item.strip()
            elif isinstance(item, dict):
                value = str(item.get("value") or item.get("string") or item.get("text") or "").strip()
            else:
                value = str(item).strip()
            if value and value not in strings:
                strings.append(value)
        return strings

    @staticmethod
    def _normalize_data_items(values: object) -> List[str]:
        data_items: List[str] = []
        for item in values or []:
            if isinstance(item, str):
                value = item.strip()
            elif isinstance(item, dict):
                value = str(
                    item.get("name")
                    or item.get("label")
                    or item.get("value")
                    or item.get("string")
                    or item.get("text")
                    or item.get("address")
                    or ""
                ).strip()
            else:
                value = str(item).strip()
            if value and value not in data_items:
                data_items.append(value)
        return data_items

    @staticmethod
    def _normalize_xref_map(values: object) -> tuple[List[tuple[str, List[Dict[str, object]]]], List[Dict[str, object]]]:
        targets: List[tuple[str, List[Dict[str, object]]]] = []
        records: List[Dict[str, object]] = []

        if isinstance(values, dict):
            iterator = values.items()
        elif isinstance(values, list):
            iterator = []
            for item in values:
                if not isinstance(item, dict):
                    continue
                target = str(
                    item.get("target")
                    or item.get("address")
                    or item.get("to")
                    or item.get("entry_point")
                    or item.get("name")
                    or ""
                ).strip()
                if not target:
                    continue
                refs = item.get("references") or item.get("xrefs") or item.get("items") or []
                if not isinstance(refs, list):
                    refs = [refs]
                iterator.append((target, refs))
        else:
            iterator = []

        for target, refs in iterator:
            target_name = str(target).strip()
            if not target_name:
                continue
            normalized_refs: List[Dict[str, object]] = []
            if not isinstance(refs, list):
                refs = [refs]
            for ref in refs:
                record = NativeAppAdapter._normalize_xref_record(ref, target_name)
                if record is None:
                    continue
                normalized_refs.append(record)
                records.append(record)
            targets.append((target_name, normalized_refs))

        return targets, records

    @staticmethod
    def _normalize_xref_record(value: object, target: str) -> Optional[Dict[str, object]]:
        if isinstance(value, str):
            source = value.strip()
            if not source:
                return None
            return {"source": source, "target": target}

        if not isinstance(value, dict):
            source = str(value).strip()
            if not source:
                return None
            return {"source": source, "target": target}

        source = str(
            value.get("source")
            or value.get("from")
            or value.get("caller")
            or value.get("ref_from")
            or value.get("function")
            or value.get("address")
            or ""
        ).strip()
        record_target = str(
            value.get("target")
            or value.get("to")
            or value.get("ref_to")
            or value.get("entry_point")
            or target
        ).strip()
        if not source and not record_target:
            return None

        record: Dict[str, object] = {"target": record_target or target}
        if source:
            record["source"] = source
        for key in ("kind", "type", "label", "address", "instruction", "comment"):
            if value.get(key) is not None:
                record[key] = value[key]
        return record

    @staticmethod
    def _summarize_xref_targets(
        xref_targets: Sequence[tuple[str, List[Dict[str, object]]]]
    ) -> List[Dict[str, object]]:
        summary: List[Dict[str, object]] = []
        for target, refs in xref_targets[:80]:
            summary.append(
                {
                    "target": target,
                    "reference_count": len(refs),
                    "sample_sources": top_values(
                        [str(ref.get("source") or "") for ref in refs if ref.get("source")],
                        5,
                    ),
                }
            )
        return summary

    @staticmethod
    def _build_function_detail_summary(
        functions: object,
        xref_targets: Sequence[tuple[str, List[Dict[str, object]]]],
    ) -> List[Dict[str, object]]:
        xref_count_by_target = {target: len(refs) for target, refs in xref_targets}
        details: List[Dict[str, object]] = []

        for function in functions or []:
            if not isinstance(function, dict):
                continue
            entry_point = str(function.get("entry_point") or function.get("address") or "").strip()
            name = str(function.get("name") or entry_point or "function").strip()
            if not entry_point and not name:
                continue
            detail: Dict[str, object] = {
                "name": name,
                "entry_point": entry_point,
                "decompiled": bool(function.get("decompiled") or function.get("source")),
                "xrefs_to": int(xref_count_by_target.get(entry_point, 0)),
            }
            namespace = function.get("namespace")
            if namespace:
                detail["namespace"] = namespace
            details.append(detail)

        return details

    @staticmethod
    def _build_input_tree(
        entry_path: Path,
        root_path: Path,
        explicit_input_root: Optional[Path],
    ) -> List[str]:
        if explicit_input_root is None and entry_path.is_file():
            return [
                f"- `{root_path.as_posix()}/`",
                f"  - `{entry_path.name}`",
            ]
        return build_directory_tree(root_path)

    def _run_optional_capa(
        self,
        entry_path: Path,
        artifacts_dir: Path,
        warnings: List[str],
    ) -> Dict[str, object]:
        executable = shutil.which("capa") or shutil.which("capa.exe")
        result: Dict[str, object] = {
            "available": executable is not None,
            "ran": False,
            "rule_count": 0,
            "capabilities": [],
            "artifact_path": None,
        }
        if executable is None:
            return result

        artifact_path = artifacts_dir / "capa.json"
        try:
            completed = subprocess.run(
                [executable, "--json", str(entry_path)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            warnings.append("capa timed out after 120 seconds.")
            return result
        except Exception as exc:
            warnings.append(f"capa failed: {exc}")
            return result

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            warnings.append(f"capa failed with exit code {completed.returncode}: {stderr}")
            return result

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            warnings.append(f"capa returned invalid JSON: {exc}")
            return result

        artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        capabilities = self._extract_capa_capabilities(payload)
        result.update(
            {
                "ran": True,
                "rule_count": len(capabilities),
                "capabilities": capabilities,
                "artifact_path": artifact_path,
            }
        )
        return result

    def _run_optional_floss(
        self,
        entry_path: Path,
        artifacts_dir: Path,
        warnings: List[str],
    ) -> Dict[str, object]:
        executable = shutil.which("floss") or shutil.which("floss.exe")
        result: Dict[str, object] = {
            "available": executable is not None,
            "ran": False,
            "decoded_string_count": 0,
            "stack_string_count": 0,
            "decoded_strings": [],
            "artifact_path": None,
        }
        if executable is None:
            return result

        artifact_path = artifacts_dir / "floss.json"
        try:
            completed = subprocess.run(
                [executable, "--json", str(entry_path)],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            warnings.append("FLOSS timed out after 120 seconds.")
            return result
        except Exception as exc:
            warnings.append(f"FLOSS failed: {exc}")
            return result

        if completed.returncode != 0:
            stderr = (completed.stderr or "").strip()
            warnings.append(f"FLOSS failed with exit code {completed.returncode}: {stderr}")
            return result

        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            warnings.append(f"FLOSS returned invalid JSON: {exc}")
            return result

        artifact_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        decoded_strings, stack_string_count = self._extract_floss_strings(payload)
        result.update(
            {
                "ran": True,
                "decoded_string_count": len(decoded_strings),
                "stack_string_count": stack_string_count,
                "decoded_strings": decoded_strings,
                "artifact_path": artifact_path,
            }
        )
        return result

    @staticmethod
    def _extract_capa_capabilities(payload: Dict[str, object]) -> List[str]:
        rules = payload.get("rules", {})
        if not isinstance(rules, dict):
            return []
        return top_values(rules.keys(), 120)

    @staticmethod
    def _extract_floss_strings(payload: Dict[str, object]) -> tuple[List[str], int]:
        decoded_strings: List[str] = []
        stack_string_count = 0

        for key in ("decoded_strings", "stack_strings", "tight_strings", "static_strings"):
            values = payload.get(key, [])
            if not isinstance(values, list):
                continue
            if key in {"stack_strings", "tight_strings"}:
                stack_string_count += len(values)
            for item in values:
                if isinstance(item, str):
                    value = item.strip()
                elif isinstance(item, dict):
                    value = str(item.get("string") or item.get("decoded_string") or item.get("value") or "").strip()
                else:
                    value = str(item).strip()
                if value and value not in decoded_strings:
                    decoded_strings.append(value)

        return top_values(decoded_strings, 120), stack_string_count
