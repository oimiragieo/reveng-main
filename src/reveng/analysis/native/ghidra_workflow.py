"""Shared native/Ghidra workflow helpers."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

from reveng.ir import IR_SCHEMA_VERSION, REEdge, RENode, REProjectIR

URL_PATTERN = re.compile(r"https?://[^\s\"'`]+")
CLI_FLAG_PATTERN = re.compile(r"--[a-z0-9][a-z0-9-]*")


def candidate_ghidra_urls(preferred_url: Optional[str] = None) -> List[str]:
    """Return candidate Ghidra server URLs in priority order."""
    candidates = [
        preferred_url,
        "http://127.0.0.1:13370",
    ]
    ordered: List[str] = []
    for candidate in candidates:
        if candidate and candidate not in ordered:
            ordered.append(candidate)
    return ordered


def run_native_ghidra_analysis(
    binary_path: str,
    *,
    timeout: int = 180,
    ghidra_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Run native analysis via Ghidra with a local-disassembler fallback."""
    ghidra_errors: List[str] = []

    try:
        from ...integrations.ghidra.ghidra_engine import GhidraEngine
    except ImportError:
        GhidraEngine = None  # type: ignore[assignment]

    if GhidraEngine is not None:
        for candidate_url in candidate_ghidra_urls(ghidra_url):
            try:
                ghidra_engine = GhidraEngine(
                    server_url=candidate_url,
                    timeout=timeout,
                    fail_fast=True,
                )
                analysis_data = _analyze_with_lock_retry(
                    ghidra_engine=ghidra_engine,
                    binary_path=binary_path,
                )
                return {
                    "status": "success",
                    "backend": "ghidra_server",
                    "ghidra_url": candidate_url,
                    "analysis_data": analysis_data,
                    "summary": summarize_native_analysis(analysis_data),
                    "errors": ghidra_errors,
                }
            except Exception as exc:
                ghidra_errors.append(f"{candidate_url}: {exc}")

    try:
        from ...integrations.local_disassembler import get_local_disassembler

        local_disassembler = get_local_disassembler()
        if local_disassembler is not None:
            local_result = local_disassembler.analyze_binary(binary_path)
            if local_result.success:
                analysis_data = local_disassembler.to_ghidra_format(local_result)
                return {
                    "status": "partial_success",
                    "backend": "local_capstone",
                    "analysis_data": analysis_data,
                    "summary": summarize_native_analysis(analysis_data),
                    "warning": analysis_data.get("warning"),
                    "errors": ghidra_errors,
                }
    except Exception as exc:
        ghidra_errors.append(f"local_disassembler: {exc}")

    return {
        "status": "failed",
        "backend": "unavailable",
        "analysis_data": {},
        "summary": {"functions": 0, "imports": 0, "strings": 0, "decompiled_functions": 0},
        "errors": ghidra_errors,
    }


def _analyze_with_lock_retry(*, ghidra_engine: Any, binary_path: str) -> Dict[str, Any]:
    """Retry once when the Ghidra server reports a transient temp-project lock."""
    attempts = 2
    for attempt in range(1, attempts + 1):
        try:
            return ghidra_engine.analyze_binary(binary_path)
        except Exception as exc:
            if attempt >= attempts or not _is_ghidra_lock_error(exc):
                raise
            time.sleep(2)
    raise RuntimeError("Unreachable Ghidra retry state")


def _is_ghidra_lock_error(exc: Exception) -> bool:
    """Identify Ghidra temp-project lock failures that are worth retrying once."""
    message = str(exc).lower()
    return (
        "lock~" in message or "winerror 32" in message or "being used by another process" in message
    )


def summarize_native_analysis(analysis_data: Dict[str, Any]) -> Dict[str, int]:
    """Return bounded counts for native analysis."""
    xref_targets, xref_records = _normalize_xref_map(analysis_data.get("xrefs", {}))
    namespaces = _normalize_named_items(analysis_data.get("namespaces", []))
    data_items = _normalize_data_items(
        analysis_data.get("data_items", analysis_data.get("data", []))
    )
    return {
        "functions": len(analysis_data.get("functions", []) or []),
        "imports": len(analysis_data.get("imports", []) or []),
        "exports": len(analysis_data.get("exports", []) or []),
        "strings": len(analysis_data.get("strings", []) or []),
        "decompiled_functions": len(_get_decompiled_functions(analysis_data)),
        "xref_targets": len(xref_targets),
        "xrefs": len(xref_records),
        "namespaces": len(namespaces),
        "data_items": len(data_items),
    }


def write_analysis_payload(payload: Dict[str, Any], output_path: Path) -> None:
    """Write JSON payload with stable formatting."""
    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def materialize_decompiled_functions(
    analysis_data: Dict[str, Any],
    output_dir: Path,
) -> List[Path]:
    """Write decompiled functions to disk and return created files."""
    decompiled_functions = _get_decompiled_functions(analysis_data)
    output_dir.mkdir(parents=True, exist_ok=True)

    written: List[Path] = []
    for index, (address, code) in enumerate(decompiled_functions.items(), start=1):
        safe_address = re.sub(r"[^0-9A-Za-z_.-]+", "_", str(address)).strip("_") or str(index)
        file_path = output_dir / f"func_{safe_address}.c"
        file_path.write_text(code.strip() + "\n", encoding="utf-8")
        written.append(file_path)
    return written


def build_native_project_ir(
    *,
    binary_path: Path,
    analysis_data: Dict[str, Any],
    backend: str,
    warnings: Sequence[str],
    benchmark_scorecard: Optional[Dict[str, Any]] = None,
) -> REProjectIR:
    """Build a shared IR document from native analysis output."""
    nodes: List[RENode] = [
        RENode(
            node_id="project",
            kind="project",
            label=binary_path.name,
            attributes={"language": "native", "backend": backend},
        )
    ]
    edges: List[REEdge] = []

    functions = list(analysis_data.get("functions", []) or [])
    imports = _normalize_named_items(analysis_data.get("imports", []))
    exports = _normalize_named_items(analysis_data.get("exports", []))
    namespaces = _normalize_named_items(analysis_data.get("namespaces", []))
    data_items = _normalize_data_items(
        analysis_data.get("data_items", analysis_data.get("data", []))
    )
    xref_targets, xref_records = _normalize_xref_map(analysis_data.get("xrefs", {}))
    strings = _normalize_string_items(analysis_data.get("strings", []))
    endpoints = _extract_urls(strings)
    cli_flags = _extract_cli_flags(strings)
    domains = _infer_domains(functions, imports, strings, endpoints, cli_flags)

    for domain_key in domains:
        nodes.append(RENode(node_id=domain_key, kind="domain", label=domain_key.title()))
        edges.append(REEdge(source="project", target=domain_key, kind="contains"))

    for dependency in imports[:30]:
        dependency_id = f"dep:{dependency}"
        nodes.append(RENode(node_id=dependency_id, kind="dependency", label=dependency))
        edges.append(REEdge(source="project", target=dependency_id, kind="depends_on"))

    for export_name in exports[:20]:
        export_id = f"export:{export_name}"
        nodes.append(
            RENode(
                node_id=export_id,
                kind="slash_command",
                label=export_name,
                attributes={"origin": "native_export"},
            )
        )
        edges.append(REEdge(source="project", target=export_id, kind="exposes"))

    for namespace in namespaces[:20]:
        namespace_id = f"namespace:{namespace}"
        nodes.append(RENode(node_id=namespace_id, kind="namespace", label=namespace))
        edges.append(REEdge(source="project", target=namespace_id, kind="contains"))

    for data_item in data_items[:20]:
        data_id = f"data:{data_item}"
        nodes.append(RENode(node_id=data_id, kind="data_symbol", label=data_item))
        edges.append(REEdge(source="project", target=data_id, kind="contains"))

    for target_address, references in xref_targets[:20]:
        xref_id = f"xref:{target_address}"
        nodes.append(
            RENode(
                node_id=xref_id,
                kind="xref_target",
                label=target_address,
                attributes={"reference_count": len(references)},
            )
        )
        edges.append(REEdge(source="project", target=xref_id, kind="references"))

    for flag in cli_flags[:20]:
        flag_id = f"flag:{flag}"
        nodes.append(RENode(node_id=flag_id, kind="cli_flag", label=flag))
        edges.append(REEdge(source="project", target=flag_id, kind="exposes"))

    for index, url in enumerate(endpoints[:20], start=1):
        endpoint_id = f"url:{index}"
        nodes.append(RENode(node_id=endpoint_id, kind="endpoint", label=url))
        edges.append(REEdge(source="project", target=endpoint_id, kind="connects_to"))

    return REProjectIR(
        schema_version=IR_SCHEMA_VERSION,
        project_name=binary_path.stem,
        input_path=str(binary_path),
        language="native",
        nodes=nodes,
        edges=edges,
        metadata={
            "backend": backend,
            "summary": summarize_native_analysis(analysis_data),
            "native_surface": _build_native_surface_summary(
                analysis_data,
                xref_targets=xref_targets,
                xref_records=xref_records,
                namespaces=namespaces,
                data_items=data_items,
            ),
            "warnings": list(warnings),
            "benchmark_scorecard": benchmark_scorecard or {},
        },
    )


def build_native_source_segments(analysis_data: Dict[str, Any]) -> List[Dict[str, object]]:
    """Convert native analysis into snippet-friendly source segments."""
    segments: List[Dict[str, object]] = []

    for function in list(analysis_data.get("functions", []) or [])[:80]:
        if not isinstance(function, dict):
            continue
        name = str(function.get("name") or function.get("entry_point") or "function")
        source = function.get("decompiled") or function.get("source")
        if source:
            segments.append({"source": f"function:{name}", "segments": _segment_text(str(source))})

    import_lines = [
        f"import {name}" for name in _normalize_named_items(analysis_data.get("imports", []))
    ]
    if import_lines:
        segments.append({"source": "imports", "segments": _segment_text("\n".join(import_lines))})

    export_lines = [
        f"export {name}" for name in _normalize_named_items(analysis_data.get("exports", []))
    ]
    if export_lines:
        segments.append({"source": "exports", "segments": _segment_text("\n".join(export_lines))})

    namespace_lines = [
        f"namespace {name}" for name in _normalize_named_items(analysis_data.get("namespaces", []))
    ]
    if namespace_lines:
        segments.append(
            {"source": "namespaces", "segments": _segment_text("\n".join(namespace_lines))}
        )

    data_lines = [
        f"data {name}"
        for name in _normalize_data_items(
            analysis_data.get("data_items", analysis_data.get("data", []))
        )
    ]
    if data_lines:
        segments.append({"source": "data_items", "segments": _segment_text("\n".join(data_lines))})

    xref_lines = _render_xref_lines(analysis_data.get("xrefs", {}))
    if xref_lines:
        segments.append({"source": "xrefs", "segments": _segment_text("\n".join(xref_lines))})

    string_lines = _normalize_string_items(analysis_data.get("strings", []))[:200]
    if string_lines:
        segments.append({"source": "strings", "segments": _segment_text("\n".join(string_lines))})

    return segments


def _get_decompiled_functions(analysis_data: Dict[str, Any]) -> Dict[str, str]:
    decompiled_code = analysis_data.get("decompiled_code", {})
    if isinstance(decompiled_code, dict) and decompiled_code:
        return {str(key): str(value) for key, value in decompiled_code.items() if value}

    recovered: Dict[str, str] = {}
    for function in analysis_data.get("functions", []) or []:
        if not isinstance(function, dict):
            continue
        source = function.get("decompiled") or function.get("source")
        address = function.get("entry_point") or function.get("address") or function.get("name")
        if source and address:
            recovered[str(address)] = str(source)
    return recovered


def _normalize_named_items(values: Any) -> List[str]:
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


def _normalize_string_items(values: Any) -> List[str]:
    normalized: List[str] = []
    for item in values or []:
        if isinstance(item, str):
            value = item
        elif isinstance(item, dict):
            value = str(item.get("value") or item.get("string") or item.get("text") or "")
        else:
            value = str(item)
        value = value.strip()
        if value and value not in normalized:
            normalized.append(value)
    return normalized


def _normalize_data_items(values: Any) -> List[str]:
    normalized: List[str] = []
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
        if value and value not in normalized:
            normalized.append(value)
    return normalized


def _normalize_xref_map(
    values: Any,
) -> tuple[List[tuple[str, List[Dict[str, Any]]]], List[Dict[str, Any]]]:
    targets: List[tuple[str, List[Dict[str, Any]]]] = []
    records: List[Dict[str, Any]] = []

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
        normalized_refs: List[Dict[str, Any]] = []
        if not isinstance(refs, list):
            refs = [refs]
        for ref in refs:
            record = _normalize_xref_record(ref, target_name)
            if record is None:
                continue
            normalized_refs.append(record)
            records.append(record)
        targets.append((target_name, normalized_refs))

    return targets, records


def _normalize_xref_record(value: Any, target: str) -> Optional[Dict[str, Any]]:
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

    record: Dict[str, Any] = {"target": record_target or target}
    if source:
        record["source"] = source
    for key in ("kind", "type", "label", "address", "instruction", "comment"):
        if value.get(key) is not None:
            record[key] = value[key]
    return record


def _render_xref_lines(values: Any) -> List[str]:
    lines: List[str] = []
    targets, _ = _normalize_xref_map(values)
    for target, refs in targets[:40]:
        if not refs:
            lines.append(f"xref {target}")
            continue
        for ref in refs[:12]:
            source = str(ref.get("source") or "unknown")
            kind = str(ref.get("kind") or ref.get("type") or "").strip()
            suffix = f" [{kind}]" if kind else ""
            lines.append(f"xref {source} -> {target}{suffix}")
    return lines


def _build_native_surface_summary(
    analysis_data: Dict[str, Any],
    *,
    xref_targets: Sequence[tuple[str, List[Dict[str, Any]]]],
    xref_records: Sequence[Dict[str, Any]],
    namespaces: Sequence[str],
    data_items: Sequence[str],
) -> Dict[str, Any]:
    functions = list(analysis_data.get("functions", []) or [])
    function_details = _build_function_detail_summary(functions, xref_targets)
    return {
        "functions": len(functions),
        "function_details": function_details,
        "xref_target_count": len(xref_targets),
        "xref_reference_count": len(xref_records),
        "namespaces": list(namespaces[:40]),
        "data_items": list(data_items[:40]),
    }


def _build_function_detail_summary(
    functions: Sequence[Any],
    xref_targets: Sequence[tuple[str, List[Dict[str, Any]]]],
) -> List[Dict[str, Any]]:
    xref_count_by_target = {target: len(refs) for target, refs in xref_targets}
    details: List[Dict[str, Any]] = []

    for function in functions[:120]:
        if not isinstance(function, dict):
            continue
        entry_point = str(function.get("entry_point") or function.get("address") or "").strip()
        name = str(function.get("name") or entry_point or "function").strip()
        if not entry_point and not name:
            continue
        detail: Dict[str, Any] = {
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


def _extract_urls(strings: Sequence[str]) -> List[str]:
    urls: List[str] = []
    for value in strings:
        if value.startswith(("http://", "https://")):
            urls.append(value)
        else:
            urls.extend(URL_PATTERN.findall(value))
    return _unique(urls, limit=40)


def _extract_cli_flags(strings: Sequence[str]) -> List[str]:
    flags: List[str] = []
    for value in strings:
        if value.startswith("--"):
            flags.append(value)
        else:
            flags.extend(CLI_FLAG_PATTERN.findall(value))
    return _unique(flags, limit=40)


def _infer_domains(
    functions: Sequence[Any],
    imports: Sequence[str],
    strings: Sequence[str],
    endpoints: Sequence[str],
    cli_flags: Sequence[str],
) -> List[str]:
    domains = ["core"]
    lowered_imports = " ".join(imports).lower()
    lowered_functions = " ".join(
        str(function.get("name") if isinstance(function, dict) else function).lower()
        for function in functions[:120]
    )
    lowered_strings = " ".join(strings[:200]).lower()

    if cli_flags or "argv" in lowered_strings or "command" in lowered_functions:
        domains.append("cli")
    if endpoints or "http" in lowered_imports or "socket" in lowered_imports:
        domains.append("network")
    if any(
        token in lowered_imports or token in lowered_strings
        for token in ("auth", "token", "oauth", "login")
    ):
        domains.append("auth")
    if any(
        token in lowered_imports or token in lowered_strings
        for token in ("sqlite", "config", ".json", "registry", "file")
    ):
        domains.append("storage")
    return _unique(domains, limit=8)


def _segment_text(text: str, *, max_segment_length: int = 220) -> List[str]:
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


def _unique(values: Iterable[str], *, limit: int) -> List[str]:
    seen: List[str] = []
    for value in values:
        if value and value not in seen:
            seen.append(value)
        if len(seen) >= limit:
            break
    return seen
