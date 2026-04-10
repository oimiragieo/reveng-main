"""
Binary Recompilation Engine - Prove Vulnerabilities Through Working Code

This module implements the revolutionary feature: converting binaries back to
compilable source code that can be recompiled and executed.

This proves security vulnerabilities by demonstrating them in working code.

Author: REVENG Team
Version: 3.0.0
"""

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
import time
from bisect import bisect_right
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from reveng.ai.angr_cfg_preprocessor import AngrCFGPreprocessor

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level compiled regexes for hot normalization paths (fix #1 and #3).
# Compiled once to avoid per-call overhead in large (4 MB+) source files.
# ---------------------------------------------------------------------------

# Fix #1 — undeclared split-local pattern: _varname = GHIDRA_U128(...)  etc.
_SPLIT_LOCAL_ASSIGN_RE = re.compile(
    r"^(?P<indent>\s+)_(?P<varname>[a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*"
    r"(?P<rhs>(?:GHIDRA_U128|GHIDRA_U64|auVar|uVar|lVar)\b.*?);$",
    re.MULTILINE,
)

# Fix #3 — fragment-local declaration pattern: static uint64_t uStack_88_4_4_ = 0;
# Covers both u*Stack_ and local_ fragment families.
_FRAGMENT_DECL_RE = re.compile(
    r"^(?P<indent>[ \t]*)static\s+uint64_t\s+"
    r"(?P<base>(?:u[A-Za-z]*Stack_[0-9a-f]+|local_[0-9a-f]+))"
    r"_\d+_\d+_\s*=\s*0\s*;",
    re.MULTILINE,
)


class CompilationError(Exception):
    """Raised when code compilation fails."""

    pass


class BinaryRecompilationEngine:
    """
    Advanced engine for binary → source → binary reconstruction.

    This is the core revolutionary feature: proving vulnerabilities by
    reconstructing working executables from binaries.
    """

    def __init__(
        self,
        ghidra_engine=None,
        gemini_engine=None,
        work_dir: Optional[Path] = None,
        cfg_preprocessor: Optional[AngrCFGPreprocessor] = None,
        max_compilation_retries: int = 2,
        native_analysis_timeout: int = 180,
    ):
        """
        Initialize recompilation engine.

        Args:
            ghidra_engine: GhidraEngine instance for decompilation
            gemini_engine: GeminiEngine instance for AI enhancement
            work_dir: Working directory for compilation artifacts
        """
        self.ghidra = ghidra_engine
        self.gemini = gemini_engine
        self.cfg_preprocessor = cfg_preprocessor or AngrCFGPreprocessor()
        self.max_compilation_retries = max(0, max_compilation_retries)
        self.native_analysis_timeout = max(60, int(native_analysis_timeout))
        self.compiler_cache = self._detect_compiler_cache()
        self.work_dir = work_dir or Path(tempfile.mkdtemp(prefix="reveng_recomp_"))
        self.work_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Recompilation engine initialized (work dir: {self.work_dir})")
        if self.compiler_cache:
            logger.info("Compiler cache enabled: %s", self.compiler_cache)

    @staticmethod
    def _looks_like_native_binary(binary_path: str) -> bool:
        """Return whether the path likely points to a native binary artifact."""
        suffix = Path(binary_path).suffix.lower()
        return suffix in {".exe", ".dll", ".so", ".dylib", ".elf", ".bin"} or not suffix

    def _get_source_lookup_cache(self, cache_name: str, source: str) -> Dict[Any, Any]:
        """Return a small per-source cache for repeated whole-source lookup helpers."""
        source_key = (id(source), len(source), source[:64], source[-64:])
        cache_store = getattr(self, cache_name, None)
        if cache_store is None:
            cache_store = {}
            setattr(self, cache_name, cache_store)
        if source_key not in cache_store:
            if len(cache_store) >= 8:
                cache_store.clear()
            cache_store[source_key] = {}
        return cache_store[source_key]

    def _get_source_lines_and_starts(self, source: str) -> tuple[List[str], List[int]]:
        """Return cached source lines and their starting offsets."""
        cache = self._get_source_lookup_cache("_source_lines_cache", source)
        if "lines" not in cache:
            lines_with_endings = source.splitlines(keepends=True)
            if not lines_with_endings and source:
                lines_with_endings = [source]
            starts: List[int] = []
            lines: List[str] = []
            offset = 0
            for line in lines_with_endings:
                starts.append(offset)
                lines.append(line.rstrip("\r\n"))
                offset += len(line)
            cache["lines"] = lines
            cache["starts"] = starts
        return cache["lines"], cache["starts"]

    def _get_source_line_index(self, source: str, before_pos: int) -> int:
        """Return the line index containing the given source position."""
        _lines, starts = self._get_source_lines_and_starts(source)
        if not starts:
            return -1
        bounded_pos = min(max(before_pos, 0), len(source))
        return max(0, bisect_right(starts, bounded_pos) - 1)

    def _get_cached_line_declarations(
        self, source: str, line_index: int, line: str
    ) -> Dict[str, str]:
        """Return cached variable declarations for a source line."""
        cache = self._get_source_lookup_cache("_line_declarations_cache", source)
        if line_index not in cache:
            cache[line_index] = self._extract_declared_variable_types_from_line(line)
        return cache[line_index]

    def _is_cached_function_boundary_line(self, source: str, lines: List[str], index: int) -> bool:
        """Return whether a source line bounds function-local declaration lookup."""
        cache = self._get_source_lookup_cache("_function_boundary_line_cache", source)
        if index not in cache:
            cache[index] = self._is_function_boundary_line(lines, index)
        return cache[index]

    def _looks_like_function_signature(self, text: str) -> bool:
        """Return whether text resembles a generated-C function signature head."""
        stripped = text.strip()
        return bool(
            stripped
            and "=" not in stripped
            and not re.match(r"^(?:if|for|while|switch|else|do|try|return|case)\b", stripped)
            and re.match(
                r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\([^;]*\)$",
                stripped,
            )
        )

    def _looks_like_function_signature_start(self, text: str) -> bool:
        """Return whether text looks like the first line of a multiline function signature."""
        stripped = text.strip()
        return bool(
            stripped
            and "(" in stripped
            and not stripped.endswith(";")
            and "=" not in stripped
            and not re.match(r"^(?:if|for|while|switch|else|do|try|return|case)\b", stripped)
            and re.match(
                r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\([^;]*$",
                stripped,
            )
        )

    def _get_function_boundary_indices(self, source: str) -> List[int]:
        """Return cached line indices for generated function bodies."""
        cache = self._get_source_lookup_cache("_function_boundary_indices_cache", source)
        if "indices" not in cache:
            lines, _starts = self._get_source_lines_and_starts(source)
            boundary_indices: List[int] = []
            signature_parts: List[str] = []
            collecting_signature = False
            for index, line in enumerate(lines):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                    continue
                if not collecting_signature:
                    if stripped.endswith("{"):
                        head = stripped[:-1].strip()
                        if self._looks_like_function_signature(head):
                            boundary_indices.append(index)
                        continue
                    if self._looks_like_function_signature_start(stripped):
                        signature_parts = [stripped]
                        collecting_signature = True
                    continue
                if stripped.endswith(";"):
                    signature_parts = []
                    collecting_signature = False
                    continue
                if stripped == "{":
                    combined = " ".join(signature_parts)
                    if self._looks_like_function_signature(combined):
                        boundary_indices.append(index)
                    signature_parts = []
                    collecting_signature = False
                    continue
                if stripped.endswith("{"):
                    head = stripped[:-1].strip()
                    combined = " ".join(signature_parts + ([head] if head else []))
                    if self._looks_like_function_signature(combined):
                        boundary_indices.append(index)
                    signature_parts = []
                    collecting_signature = False
                    continue
                signature_parts.append(stripped)
            cache["indices"] = boundary_indices
        return cache["indices"]

    def _get_line_to_boundary_index_map(self, source: str) -> List[Optional[int]]:
        """Return cached mapping from line index to enclosing function boundary line."""
        cache = self._get_source_lookup_cache("_line_to_boundary_index_cache", source)
        if "mapping" not in cache:
            lines, _starts = self._get_source_lines_and_starts(source)
            boundary_indices = self._get_function_boundary_indices(source)
            mapping: List[Optional[int]] = [None] * len(lines)
            current_boundary: Optional[int] = None
            boundary_iter = iter(boundary_indices)
            next_boundary = next(boundary_iter, None)
            for index in range(len(lines)):
                while next_boundary is not None and next_boundary <= index:
                    current_boundary = next_boundary
                    next_boundary = next(boundary_iter, None)
                mapping[index] = current_boundary
            cache["mapping"] = mapping
        return cache["mapping"]

    def _get_enclosing_function_boundary_index(self, source: str, before_pos: int) -> Optional[int]:
        """Return the cached function boundary line index enclosing the given source position."""
        cache = self._get_source_lookup_cache("_enclosing_function_boundary_cache", source)
        line_index = self._get_source_line_index(source, before_pos)
        if line_index == -1:
            return None
        if line_index in cache:
            return cache[line_index]
        mapping = self._get_line_to_boundary_index_map(source)
        candidate = mapping[line_index] if 0 <= line_index < len(mapping) else None
        cache[line_index] = candidate
        return candidate

    def _get_function_parameter_types_at_boundary(
        self, source: str, boundary_index: int
    ) -> Dict[str, str]:
        """Return cached parameter types for the function owning a boundary line."""
        cache = self._get_source_lookup_cache("_function_parameter_types_cache", source)
        if boundary_index in cache:
            return cache[boundary_index]

        lines, _starts = self._get_source_lines_and_starts(source)
        signature_parts: list[str] = []
        paren_balance = 0
        signature_line: Optional[str] = None
        for index in range(boundary_index, -1, -1):
            candidate = lines[index].strip()
            if index == boundary_index:
                if candidate == "{":
                    continue
                if candidate.endswith("{"):
                    candidate = candidate[:-1].rstrip()
            if not candidate:
                continue
            if candidate.startswith(("#", "//", "/*", "*")):
                continue
            if candidate.endswith(";") and not signature_parts:
                cache[boundary_index] = {}
                return cache[boundary_index]
            signature_parts.insert(0, candidate)
            paren_balance += candidate.count(")") - candidate.count("(")
            combined = " ".join(signature_parts)
            if (
                "(" in combined
                and paren_balance >= 0
                and re.match(
                    r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\([^)]*\)$",
                    combined,
                )
                and not re.match(r"^(?:if|for|while|switch|else|do|try)\b", combined)
            ):
                signature_line = combined
                break

        if not signature_line:
            cache[boundary_index] = {}
            return cache[boundary_index]

        signature_match = re.match(
            r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\((?P<params>[^)]*)\)\s*(?:\{|$)",
            signature_line,
        )
        if not signature_match:
            cache[boundary_index] = {}
            return cache[boundary_index]

        parameter_types: Dict[str, str] = {}
        for param in self._split_top_level_arguments(signature_match.group("params")):
            declaration_match = self._match_variable_declaration(param.strip())
            if declaration_match:
                parameter_types[declaration_match.group("name")] = (
                    f"{declaration_match.group('type').strip()}{declaration_match.group('array') or ''}".strip()
                )
        cache[boundary_index] = parameter_types
        return parameter_types

    def _get_function_local_declarations_at_boundary(
        self, source: str, boundary_index: int
    ) -> Dict[str, List[tuple[int, str]]]:
        """Return cached per-function local declarations indexed by variable name."""
        cache = self._get_source_lookup_cache("_function_local_declarations_cache", source)
        if boundary_index in cache:
            return cache[boundary_index]

        lines, _starts = self._get_source_lines_and_starts(source)
        boundary_indices = self._get_function_boundary_indices(source)
        if boundary_index in boundary_indices:
            boundary_pos = boundary_indices.index(boundary_index)
            next_boundary = (
                boundary_indices[boundary_pos + 1]
                if boundary_pos + 1 < len(boundary_indices)
                else len(lines)
            )
        else:
            next_boundary = len(lines)
            for index in range(boundary_index + 1, len(lines)):
                if self._is_function_boundary_line(lines, index):
                    next_boundary = index
                    break
        declarations_by_name: Dict[str, List[tuple[int, str]]] = {}
        for index in range(boundary_index + 1, next_boundary):
            declarations = self._get_cached_line_declarations(source, index, lines[index])
            for name, declared_type in declarations.items():
                declarations_by_name.setdefault(name, []).append((index, declared_type))
        cache[boundary_index] = declarations_by_name
        return declarations_by_name

    async def full_reconstruction_pipeline(
        self, binary_path: str, output_dir: Optional[Path] = None
    ) -> Dict[str, Any]:
        """
        Complete pipeline: Binary → Source → Compiled Binary → Exploits

        This is the main entry point for proving security vulnerabilities.

        Args:
            binary_path: Path to input binary
            output_dir: Directory to save outputs

        Returns:
            dict: Complete reconstruction results:
                - source_files: Dict of language -> source code
                - compiled_binaries: Dict of platform -> binary path
                - validation_results: Behavioral validation
                - vulnerabilities: List of discovered vulnerabilities
                - exploits: List of working exploits
                - proof_of_concept: Executable demonstration
        """
        logger.info("=" * 70)
        logger.info("BINARY RECOMPILATION PIPELINE")
        logger.info("=" * 70)
        logger.info(f"Input binary: {binary_path}")

        output_dir = output_dir or self.work_dir / Path(binary_path).stem
        output_dir.mkdir(parents=True, exist_ok=True)

        results = {
            "binary_path": binary_path,
            "output_dir": str(output_dir),
            "cfg_artifacts": {},
            "cfg_summary": {},
            "source_files": {},
            "compiled_binaries": {},
            "compilation_reports": {},
            "native_output_traces": {},
            "differential_validation": {},
            "equivalence_validation": {},
            "validation_results": {},
            "vulnerabilities": [],
            "exploits": [],
            "proof_of_concept": None,
            "status": "in_progress",
        }

        try:
            # Phase 1: Ghidra Decompilation
            logger.info("\n[Phase 1/6] Ghidra Decompilation")
            ghidra_data = await self._phase1_decompilation(binary_path, output_dir)
            results["ghidra_data"] = ghidra_data
            results["cfg_artifacts"] = ghidra_data.get("cfg_artifacts", {})
            results["cfg_summary"] = ghidra_data.get("cfg_summary", {})

            # Phase 2: AI-Enhanced Reconstruction
            logger.info("\n[Phase 2/6] AI-Enhanced Code Reconstruction")
            reconstructed_code = await self._phase2_reconstruction(ghidra_data, output_dir)
            results["source_files"] = reconstructed_code

            # Phase 3: Compilation
            logger.info("\n[Phase 3/6] Source Code Compilation")
            compilation_result = await self._phase3_compilation(
                reconstructed_code, output_dir, ghidra_data
            )
            results["source_files"] = compilation_result.get("source_files", reconstructed_code)
            results["compiled_binaries"] = compilation_result["compiled_binaries"]
            results["compilation_reports"] = compilation_result["reports"]
            results["native_output_traces"] = compilation_result.get("native_output_traces", {})
            results["equivalence_validation"] = (
                self._build_recompilation_equivalence_validation_summary(
                    results["compilation_reports"],
                    results["validation_results"],
                )
            )

            if not results["compiled_binaries"]:
                logger.error("❌ Compilation failed for all configured compilers")
                results["status"] = "failed"
                results["error"] = "Compilation failed for all configured compilers"
                self._save_results(results, output_dir)
                return results

            # Phase 4: Behavioral Validation
            logger.info("\n[Phase 4/6] Behavioral Validation")
            validation = await self._phase4_validation(
                binary_path, results["compiled_binaries"], ghidra_data
            )
            results["validation_results"] = validation
            results["differential_validation"] = validation.get("differential_validation", {})
            results["equivalence_validation"] = (
                self._build_recompilation_equivalence_validation_summary(
                    results["compilation_reports"],
                    results["validation_results"],
                )
            )

            # Phase 5: Security Analysis
            logger.info("\n[Phase 5/6] Security Vulnerability Analysis")
            vulnerabilities = await self._phase5_security_analysis(results["source_files"])
            results["vulnerabilities"] = vulnerabilities

            # Phase 6: Exploit Generation
            logger.info("\n[Phase 6/6] Proof-of-Concept Exploit Generation")
            exploits = await self._phase6_exploit_generation(
                vulnerabilities,
                results["source_files"],
                results["compiled_binaries"],
            )
            results["exploits"] = exploits

            results["status"] = "success"
            logger.info("\n" + "=" * 70)
            logger.info("✅ RECOMPILATION PIPELINE COMPLETE")
            logger.info("=" * 70)

        except Exception as e:
            logger.error(f"❌ Pipeline failed: {e}", exc_info=True)
            results["status"] = "failed"
            results["error"] = str(e)

        # Save results
        self._save_results(results, output_dir)

        return results

    async def _phase1_decompilation(self, binary_path: str, output_dir: Path) -> Dict[str, Any]:
        """Phase 1: Decompile binary using Ghidra."""
        if self.ghidra:
            logger.info(f"  Analyzing {binary_path} with Ghidra...")
            ghidra_data = await asyncio.to_thread(self.ghidra.analyze_binary, binary_path)
        elif self._looks_like_native_binary(binary_path):
            logger.info(
                "  Ghidra unavailable for %s; using native fallback analysis (timeout=%ss)...",
                binary_path,
                self.native_analysis_timeout,
            )
            from reveng.native.ghidra_workflow import run_native_ghidra_analysis

            native_result = await asyncio.to_thread(
                run_native_ghidra_analysis,
                binary_path,
                timeout=self.native_analysis_timeout,
            )
            ghidra_data = dict(native_result.get("analysis_data") or {})
            if not ghidra_data:
                raise ValueError(
                    native_result.get("error")
                    or "Native fallback analysis returned no analysis_data"
                )
        else:
            raise ValueError("GhidraEngine not configured")

        logger.info(f"  ✅ Functions: {len(ghidra_data.get('functions', []))}")
        logger.info(f"  ✅ Decompiled: {len(ghidra_data.get('decompiled_code', {}))}")
        logger.info(f"  ✅ Strings: {len(ghidra_data.get('strings', []))}")
        logger.info(f"  ✅ Imports: {len(ghidra_data.get('imports', []))}")

        try:
            cfg_bundle = await asyncio.to_thread(
                self._extract_cfg_artifacts,
                binary_path,
                output_dir,
            )
            ghidra_data["cfg_payload"] = cfg_bundle["payload"]
            ghidra_data["cfg_context_text"] = cfg_bundle["context_text"]
            ghidra_data["cfg_artifacts"] = cfg_bundle["artifacts"]
            ghidra_data["cfg_summary"] = {
                "node_count": cfg_bundle["payload"]["graph_metrics"]["node_count"],
                "edge_count": cfg_bundle["payload"]["graph_metrics"]["edge_count"],
                "function_count": cfg_bundle["payload"]["function_count"],
            }
            logger.info(
                "  ✅ angr CFG: %d nodes, %d edges, %d functions",
                ghidra_data["cfg_summary"]["node_count"],
                ghidra_data["cfg_summary"]["edge_count"],
                ghidra_data["cfg_summary"]["function_count"],
            )
            logger.info(
                "  ✅ CFG payload saved: %s",
                ghidra_data["cfg_artifacts"].get("json"),
            )
        except Exception as exc:
            logger.warning("  ⚠️ angr CFG preprocessing failed: %s", exc)
            ghidra_data["cfg_payload"] = {
                "status": "failed",
                "source": "angr",
                "binary_name": Path(binary_path).name,
                "error": str(exc),
            }
            ghidra_data["cfg_context_text"] = ""
            ghidra_data["cfg_artifacts"] = {}
            ghidra_data["cfg_summary"] = {}

        return ghidra_data

    def _extract_cfg_artifacts(self, binary_path: str, output_dir: Path) -> Dict[str, Any]:
        """Extract CFG data and persist JSON/text artifacts for inspection."""
        payload = self.cfg_preprocessor.extract_cfg_payload(binary_path)
        context_text = self.cfg_preprocessor.build_llm_context(payload)

        cfg_json_path = output_dir / "cfg_payload.json"
        cfg_text_path = output_dir / "cfg_context.txt"
        cfg_json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        cfg_text_path.write_text(context_text, encoding="utf-8")

        return {
            "payload": payload,
            "context_text": context_text,
            "artifacts": {
                "json": str(cfg_json_path),
                "text": str(cfg_text_path),
            },
        }

    async def _phase2_reconstruction(
        self, ghidra_data: Dict[str, Any], output_dir: Path
    ) -> Dict[str, str]:
        """Phase 2: Reconstruct source code with AI enhancement."""
        source_files = {}
        total_functions = len(ghidra_data.get("decompiled_code", {}))
        progress_path = output_dir / "reconstruction_progress.json"
        phase2_started = time.monotonic()
        last_report_time = phase2_started
        last_report_count = 0
        current_stage: Optional[str] = None
        current_stage_elapsed_seconds: Optional[float] = None
        stage_timings: Dict[str, float] = {}

        self._write_reconstruction_progress(
            progress_path,
            status="running",
            total_functions=total_functions,
            completed_functions=0,
            stage="initializing",
        )

        def report_progress(index: int, total: int, current_address: str) -> None:
            nonlocal last_report_time, last_report_count
            now = time.monotonic()
            should_report = (
                index == total
                or index == 1
                or index - last_report_count >= 100
                or now - last_report_time >= 30
            )
            if not should_report:
                return
            elapsed = now - phase2_started
            self._write_reconstruction_progress(
                progress_path,
                status="running",
                total_functions=total,
                completed_functions=index,
                stage="function_reconstruction",
                current_function_address=current_address,
                elapsed_seconds=elapsed,
                current_stage_elapsed_seconds=current_stage_elapsed_seconds,
                stage_timings=stage_timings,
            )
            if elapsed >= 60:
                logger.warning(
                    "  Phase 2 reconstruction progress: %d/%d functions processed (latest: %s, %.1fs elapsed)",
                    index,
                    total,
                    current_address,
                    elapsed,
                )
            last_report_time = now
            last_report_count = index

        def report_stage(stage: str) -> None:
            nonlocal current_stage
            current_stage = stage
            self._write_reconstruction_progress(
                progress_path,
                status="running",
                total_functions=total_functions,
                completed_functions=last_report_count or total_functions,
                stage=stage,
                elapsed_seconds=time.monotonic() - phase2_started,
                current_stage_elapsed_seconds=current_stage_elapsed_seconds,
                stage_timings=stage_timings,
            )

        def report_stage_timing(stage: str, elapsed: float) -> None:
            nonlocal current_stage_elapsed_seconds
            stage_timings[stage] = elapsed
            if current_stage == stage:
                current_stage_elapsed_seconds = elapsed
            self._write_reconstruction_progress(
                progress_path,
                status="running",
                total_functions=total_functions,
                completed_functions=last_report_count or total_functions,
                stage=current_stage or stage,
                elapsed_seconds=time.monotonic() - phase2_started,
                current_stage_elapsed_seconds=current_stage_elapsed_seconds,
                stage_timings=stage_timings,
            )

        # Reconstruct C code
        logger.info("  Reconstructing C source code...")
        try:
            c_code = await self._reconstruct_c_code(
                ghidra_data,
                progress_callback=report_progress,
                stage_callback=report_stage,
                stage_timing_callback=report_stage_timing,
                debug_output_dir=output_dir,
            )
        except Exception:
            self._write_reconstruction_progress(
                progress_path,
                status="failed",
                total_functions=total_functions,
                completed_functions=last_report_count,
                stage="failed",
                elapsed_seconds=time.monotonic() - phase2_started,
                current_stage_elapsed_seconds=current_stage_elapsed_seconds,
                stage_timings=stage_timings,
            )
            raise
        c_code = self._strip_import_like_forward_declarations(c_code)
        c_code = self._inject_missing_import_like_stub_macros(c_code)
        c_code = self._inject_fallback_function_entry_traces(c_code)
        c_file = output_dir / "reconstructed.c"
        c_file.write_text(c_code, encoding="utf-8")
        self._write_reconstruction_progress(
            progress_path,
            status="completed",
            total_functions=total_functions,
            completed_functions=total_functions,
            stage="completed",
            elapsed_seconds=time.monotonic() - phase2_started,
            source_file=str(c_file),
            current_stage_elapsed_seconds=current_stage_elapsed_seconds,
            stage_timings=stage_timings,
        )
        source_files["c"] = str(c_file)
        logger.info(f"  ✅ C code: {c_file}")

        # Generate Python equivalent if Gemini available
        if self.gemini and self.gemini.is_available():
            logger.info("  Generating Python equivalent...")
            py_code = await self._reconstruct_python_code(ghidra_data)
            py_file = output_dir / "reconstructed.py"
            py_file.write_text(py_code, encoding="utf-8")
            source_files["python"] = str(py_file)
            logger.info(f"  ✅ Python code: {py_file}")

        return source_files

    async def _phase3_compilation(
        self,
        source_files: Dict[str, str],
        output_dir: Path,
        ghidra_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Phase 3: Compile source code to binary."""
        compiled_binaries: Dict[str, str] = {}
        compilation_reports: Dict[str, Dict[str, Any]] = {}
        native_output_traces: Dict[str, Dict[str, Any]] = {}

        # Compile C code
        if "c" in source_files:
            current_source = Path(source_files["c"])
            for compiler_name, target_key, label in (
                ("gcc", "c_gcc", "GCC"),
                ("clang", "c_clang", "Clang"),
            ):
                logger.info("  Compiling C code with %s...", label)
                report = await self._compile_with_feedback_loop(
                    compiler_name,
                    current_source,
                    output_dir,
                    ghidra_data or {},
                )
                compilation_reports[target_key] = report
                native_output_traces[target_key] = self._build_native_output_trace(
                    target_key, report
                )
                # Feed Clang the latest GCC-repaired source so both compilers validate
                # the same reconstructed program instead of restarting from the stale
                # original decompilation after GCC has already applied compiler-guided fixes.
                current_source = Path(report["final_source_file"])
                source_files["c"] = str(current_source)

                if report["status"] == "success" and report.get("binary_path"):
                    compiled_binaries[target_key] = report["binary_path"]
                    logger.info("  ✅ %s binary: %s", label, report["binary_path"])
                else:
                    logger.warning(
                        "  ⚠️ %s compilation failed after %d attempt(s): %s",
                        label,
                        report["total_attempts"],
                        report.get("failure_reason", "compilation_failed"),
                    )

        return {
            "compiled_binaries": compiled_binaries,
            "reports": compilation_reports,
            "native_output_traces": native_output_traces,
            "source_files": source_files,
        }

    def _build_native_output_trace(self, target_key: str, report: Dict[str, Any]) -> Dict[str, Any]:
        """Build a lightweight persisted trace for a compiled native candidate."""
        binary_path = str(report.get("binary_path") or "")
        final_source_file = str(report.get("final_source_file") or "")
        helper_call_summary = self._build_helper_call_summary(Path(final_source_file))
        helper_reachability_summary = self._build_helper_reachability_summary(
            Path(final_source_file)
        )
        binary_file = Path(binary_path) if binary_path else None
        exists = bool(binary_file and binary_file.exists())
        sha256 = None
        size = None
        if exists and binary_file is not None:
            file_bytes = binary_file.read_bytes()
            sha256 = hashlib.sha256(file_bytes).hexdigest()
            size = len(file_bytes)
        selected_attempt = 0
        for attempt in reversed(list(report.get("attempts") or [])):
            if attempt.get("returncode") == 0:
                selected_attempt = int(attempt.get("attempt") or 0)
                break
        if not selected_attempt:
            selected_attempt = int(report.get("total_attempts") or 0)
        return {
            "trace_id": f"rebuild:{target_key}",
            "target": target_key,
            "compiler": report.get("compiler"),
            "status": report.get("status"),
            "binary_path": binary_path or None,
            "final_source_file": final_source_file or None,
            "attempt_count": int(report.get("total_attempts") or 0),
            "selected_attempt": selected_attempt,
            "exists": exists,
            "size": size,
            "sha256": sha256,
            "helper_call_summary": helper_call_summary,
            "helper_reachability_summary": helper_reachability_summary,
        }

    def _build_helper_call_summary(self, source_file: Path) -> Dict[str, Any]:
        """Summarize helper-managed call presence in a generated native source file."""
        if not source_file.exists():
            return {"present": [], "counts": {}, "total_calls": 0}
        source = source_file.read_text(encoding="utf-8")
        helper_names = self._helper_managed_call_names()
        counts: Dict[str, int] = {}
        for helper_name in helper_names:
            count = len(
                re.findall(
                    rf"\b(?:imp_|reveng_fallback_)?{re.escape(helper_name)}\s*\(",
                    source,
                )
            )
            if count:
                counts[helper_name] = count
        return {
            "present": sorted(counts),
            "counts": counts,
            "total_calls": sum(counts.values()),
        }

    @staticmethod
    def _helper_managed_call_names() -> tuple[str, ...]:
        return (
            "GetCommandLineW",
            "GetCommandLineA",
            "GetStdHandle",
            "GetConsoleMode",
            "GetConsoleOutputCP",
            "MultiByteToWideChar",
            "WideCharToMultiByte",
            "WriteConsoleW",
            "NtWriteFile",
        )

    def _build_helper_reachability_summary(self, source_file: Path) -> Dict[str, Any]:
        """Summarize helper-managed calls reachable from synthesized entry functions."""
        if not source_file.exists():
            return {
                "entry_roots": [],
                "reachable_functions": [],
                "reachable_helpers": [],
                "reachable_helper_counts": {},
                "reachable_helper_total": 0,
                "entry_reachable_helper_ratio": 0.0,
            }
        source = source_file.read_text(encoding="utf-8")
        function_bodies = self._extract_function_bodies(source)
        if not function_bodies:
            return {
                "entry_roots": [],
                "reachable_functions": [],
                "reachable_helpers": [],
                "reachable_helper_counts": {},
                "reachable_helper_total": 0,
                "entry_reachable_helper_ratio": 0.0,
            }
        helper_names = set(self._helper_managed_call_names())
        entry_roots = [
            name for name in ("main", "entry_point", "WinMain", "wmain") if name in function_bodies
        ]
        if not entry_roots:
            entry_roots = [name for name in function_bodies if name.startswith("text_")][:1]
        call_graph: Dict[str, set[str]] = {}
        keywords = {"if", "for", "while", "switch", "return", "sizeof"}
        for function_name, body in function_bodies.items():
            callees = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", body))
            call_graph[function_name] = {
                callee for callee in callees if callee not in keywords and callee != function_name
            }
        visited: set[str] = set()
        pending = list(entry_roots)
        while pending:
            current = pending.pop()
            if current in visited:
                continue
            visited.add(current)
            for callee in call_graph.get(current, set()):
                if callee in function_bodies and callee not in visited:
                    pending.append(callee)
        helper_counts: Dict[str, int] = {}
        total_helper_calls = 0
        for function_name in visited:
            body = function_bodies.get(function_name, "")
            for helper_name in helper_names:
                helper_count = len(
                    re.findall(
                        rf"\b(?:imp_|reveng_fallback_)?{re.escape(helper_name)}\s*\(",
                        body,
                    )
                )
                if helper_count:
                    helper_counts[helper_name] = helper_counts.get(helper_name, 0) + helper_count
                    total_helper_calls += helper_count
        overall_helper_total = int(
            self._build_helper_call_summary(source_file).get("total_calls") or 0
        )
        return {
            "entry_roots": entry_roots,
            "reachable_functions": sorted(visited),
            "reachable_helpers": sorted(helper_counts),
            "reachable_helper_counts": helper_counts,
            "reachable_helper_total": total_helper_calls,
            "entry_reachable_helper_ratio": (
                float(total_helper_calls) / float(overall_helper_total)
                if overall_helper_total
                else 0.0
            ),
        }

    def _extract_function_bodies(self, source: str) -> Dict[str, str]:
        """Extract generated C function bodies by function name."""
        pattern = re.compile(
            r"^(?P<signature>[A-Za-z_][A-Za-z0-9_ \t\*]*\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\))\s*\{",
            flags=re.MULTILINE,
        )
        matches = list(pattern.finditer(source))
        functions: Dict[str, str] = {}
        for match in matches:
            name = str(match.group("name"))
            brace_start = source.find("{", match.start())
            if brace_start < 0:
                continue
            depth = 0
            end_index = brace_start
            while end_index < len(source):
                char = source[end_index]
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        functions[name] = source[brace_start + 1 : end_index]
                        break
                end_index += 1
        return functions

    def _detect_compiler_cache(self) -> Optional[str]:
        """Detect a compiler cache wrapper if one is available."""
        for cache_tool in ("ccache", "sccache"):
            if shutil.which(cache_tool):
                return cache_tool
        return None

    def _build_compile_command(
        self, compiler_name: str, source_file: Path, output_binary: Path
    ) -> List[str]:
        """Build the compile command for a single C source file."""
        cmd = [
            compiler_name,
            "-o",
            str(output_binary),
            str(source_file),
            "-w",
            "-O0",
            "-g",
            "-fno-builtin",
        ]
        if os.name == "nt":
            if compiler_name == "clang":
                cmd.extend(
                    [
                        "-Xlinker",
                        "/force:multiple",
                        "-Xlinker",
                        "/subsystem:console",
                        "-Xlinker",
                        "/entry:mainCRTStartup",
                    ]
                )
            else:
                cmd.extend(
                    [
                        "-Wl,--allow-multiple-definition",
                        "-Wl,-subsystem,console",
                        "-Wl,-e,mainCRTStartup",
                    ]
                )
        else:
            cmd.append("-Wl,--allow-multiple-definition")
        if self.compiler_cache:
            return [self.compiler_cache, *cmd]
        return cmd

    async def _run_compiler_attempt(
        self, compiler_name: str, source_file: Path, output_binary: Path
    ) -> Dict[str, Any]:
        """Run a single compiler attempt and capture stdout/stderr."""
        cmd = self._build_compile_command(compiler_name, source_file, output_binary)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()
        except FileNotFoundError:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"{compiler_name.upper()} not found in PATH",
                "returncode": None,
                "command": cmd,
                "non_retryable": True,
            }

        return {
            "success": process.returncode == 0,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
            "returncode": process.returncode,
            "command": cmd,
            "non_retryable": False,
        }

    async def _compile_with_feedback_loop(
        self,
        compiler_name: str,
        source_file: Path,
        output_dir: Path,
        ghidra_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Compile C code, feeding compiler stderr back into the LLM on failure."""
        output_binary = output_dir / f"reconstructed_{compiler_name}"
        if os.name == "nt":
            output_binary = output_binary.with_suffix(".exe")

        current_source = Path(source_file)
        attempts: List[Dict[str, Any]] = []

        for attempt_index in range(self.max_compilation_retries + 1):
            compile_result = await self._run_compiler_attempt(
                compiler_name, current_source, output_binary
            )
            attempt_record = {
                "attempt": attempt_index + 1,
                "command": compile_result["command"],
                "returncode": compile_result["returncode"],
                "stdout": compile_result["stdout"],
                "stderr": compile_result["stderr"],
                "source_file": str(current_source),
                "feedback_applied": False,
            }
            attempts.append(attempt_record)

            if compile_result["success"]:
                return {
                    "compiler": compiler_name,
                    "status": "success",
                    "binary_path": str(output_binary),
                    "attempts": attempts,
                    "total_attempts": len(attempts),
                    "max_retries": self.max_compilation_retries,
                    "max_retries_exceeded": False,
                    "failure_reason": None,
                    "final_source_file": str(current_source),
                    "cache_backend": self.compiler_cache,
                }

            if compile_result.get("non_retryable"):
                return {
                    "compiler": compiler_name,
                    "status": "failed",
                    "binary_path": None,
                    "attempts": attempts,
                    "total_attempts": len(attempts),
                    "max_retries": self.max_compilation_retries,
                    "max_retries_exceeded": False,
                    "failure_reason": "compiler_unavailable",
                    "final_source_file": str(current_source),
                    "cache_backend": self.compiler_cache,
                }

            if attempt_index >= self.max_compilation_retries:
                return {
                    "compiler": compiler_name,
                    "status": "failed",
                    "binary_path": None,
                    "attempts": attempts,
                    "total_attempts": len(attempts),
                    "max_retries": self.max_compilation_retries,
                    "max_retries_exceeded": True,
                    "failure_reason": "max_retries_exceeded",
                    "final_source_file": str(current_source),
                    "cache_backend": self.compiler_cache,
                }

            source_code = current_source.read_text(encoding="utf-8")
            prompt = self._create_compilation_feedback_prompt(
                source_code,
                compiler_name,
                compile_result["stderr"],
                attempt_index + 1,
                attempts,
                ghidra_data or {},
            )
            attempt_record["feedback_prompt_excerpt"] = prompt[:500]

            repaired_source = await self._repair_source_from_compiler_error(prompt)
            if not repaired_source:
                return {
                    "compiler": compiler_name,
                    "status": "failed",
                    "binary_path": None,
                    "attempts": attempts,
                    "total_attempts": len(attempts),
                    "max_retries": self.max_compilation_retries,
                    "max_retries_exceeded": False,
                    "failure_reason": "llm_feedback_unavailable",
                    "final_source_file": str(current_source),
                    "cache_backend": self.compiler_cache,
                }

            current_source.write_text(repaired_source, encoding="utf-8")
            attempt_record["feedback_applied"] = True

        return {
            "compiler": compiler_name,
            "status": "failed",
            "binary_path": None,
            "attempts": attempts,
            "total_attempts": len(attempts),
            "max_retries": self.max_compilation_retries,
            "max_retries_exceeded": True,
            "failure_reason": "max_retries_exceeded",
            "final_source_file": str(current_source),
            "cache_backend": self.compiler_cache,
        }

    def _create_compilation_feedback_prompt(
        self,
        source_code: str,
        compiler_name: str,
        compiler_stderr: str,
        attempt_number: int,
        attempt_history: List[Dict[str, Any]],
        ghidra_data: Optional[Dict[str, Any]],
    ) -> str:
        """Build an LLM prompt that asks for a compilable C source revision."""
        context_sections: List[str] = []
        if ghidra_data:
            imports = ghidra_data.get("imports", [])[:20]
            strings = ghidra_data.get("strings", [])[:20]
            if imports:
                context_sections.append(
                    "Imported functions: " + ", ".join(str(item) for item in imports)
                )
            if strings:
                context_sections.append(
                    "Observed strings: " + ", ".join(str(item) for item in strings)
                )
            if ghidra_data.get("cfg_context_text"):
                context_sections.append("CFG summary:\n" + str(ghidra_data["cfg_context_text"]))

        history_lines = []
        for previous_attempt in attempt_history[:-1][-2:]:
            stderr = previous_attempt.get("stderr", "").strip() or "<no stderr>"
            history_lines.append(f"Attempt {previous_attempt['attempt']} stderr:\n{stderr[:1200]}")

        history_text = (
            "\n\nPrevious failed attempts:\n" + "\n\n".join(history_lines) if history_lines else ""
        )
        context_text = (
            "\n\nBinary analysis context:\n" + "\n\n".join(context_sections)
            if context_sections
            else ""
        )

        return f"""You are repairing reconstructed C source code so it compiles successfully.

Compiler: {compiler_name}
Retry attempt: {attempt_number} of {self.max_compilation_retries}

Current source:
```c
{source_code}
```

Compiler stderr:
```text
{compiler_stderr}
```
{history_text}{context_text}

Instructions:
1. Fix the compilation errors reported above.
2. Preserve the reconstructed program behavior and structure.
3. Return the full corrected C source file.
4. Output only the corrected code in a ```c fenced block (or raw C with no explanation).
"""

    async def _repair_source_from_compiler_error(self, prompt: str) -> Optional[str]:
        """Request a corrected source file from the active LLM."""
        if not self.gemini or not self.gemini.is_available():
            logger.warning("Gemini not available for compilation feedback loop")
            return None

        try:
            response = await self.gemini._generate_async(prompt)
        except Exception as exc:
            logger.error("Compilation feedback loop failed: %s", exc)
            return None

        extracted_code = self._extract_code_block(response)
        if extracted_code and extracted_code.strip():
            return extracted_code.rstrip() + "\n"

        stripped_response = response.strip()
        if not stripped_response:
            return None
        return stripped_response + "\n"

    def _extract_code_block(self, response: str) -> str:
        """Extract the first fenced code block from an LLM response."""
        if "```" not in response:
            return response.strip()

        first_fence = response.find("```")
        line_break = response.find("\n", first_fence)
        if line_break == -1:
            return response.strip()

        closing_fence = response.find("```", line_break + 1)
        if closing_fence == -1:
            return response[line_break + 1 :].strip()

        return response[line_break + 1 : closing_fence].strip()

    async def _phase4_validation(
        self,
        original_binary: str,
        compiled_binaries: Dict[str, str],
        ghidra_data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Phase 4: Validate reconstructed binaries match original behavior."""
        validation = {
            "original": original_binary,
            "tests": [],
            "similarity_score": 0.0,
            "matching_functions": 0,
            "total_functions": len(ghidra_data.get("functions", [])),
            "differential_validation": {},
        }

        logger.info("  Running behavioral validation tests...")

        # Test 1: Compare exported symbols
        for target, binary_path in compiled_binaries.items():
            test_result = {
                "target": target,
                "binary": binary_path,
                "tests_passed": 0,
                "tests_failed": 0,
                "notes": [],
            }

            # Compare file sizes
            orig_size = Path(original_binary).stat().st_size
            new_size = Path(binary_path).stat().st_size
            size_diff = abs(orig_size - new_size) / orig_size
            test_result["size_difference"] = f"{size_diff*100:.1f}%"

            if size_diff < 0.5:  # Within 50%
                test_result["tests_passed"] += 1
                test_result["notes"].append("Size similarity: PASS")
            else:
                test_result["tests_failed"] += 1
                test_result["notes"].append("Size similarity: FAIL")

            validation["tests"].append(test_result)

        # Calculate overall similarity score
        if validation["tests"]:
            avg_passed = sum(t["tests_passed"] for t in validation["tests"]) / len(
                validation["tests"]
            )
            validation["similarity_score"] = avg_passed / 2  # Normalize to 0-1

        validation["differential_validation"] = self._build_native_differential_validation(
            original_binary,
            compiled_binaries,
        )

        logger.info(
            f"  ✅ Validation complete (similarity: {validation['similarity_score']*100:.1f}%)"
        )

        return validation

    def _build_native_differential_validation(
        self,
        original_binary: str,
        compiled_binaries: Dict[str, str],
    ) -> Dict[str, Any]:
        """Build a lightweight native differential-validation summary."""

        def add_check(
            target_checks: List[Dict[str, Any]],
            *,
            target: str,
            kind: str,
            severity: str,
            status: str,
            message: str,
        ) -> None:
            target_checks.append(
                {
                    "target": target,
                    "kind": kind,
                    "severity": severity,
                    "status": status,
                    "message": message,
                }
            )

        if not compiled_binaries:
            return {
                "status": "insufficient_evidence",
                "mode": "checksum",
                "summary": "No compiled candidate binaries are available for differential validation.",
                "checks": [],
                "targets": [],
                "evidence": {
                    "target_count": 0,
                    "failed_check_count": 0,
                    "warn_check_count": 0,
                    "smoke_tests_configured": 0,
                    "smoke_tests_run": 0,
                },
            }

        from reveng.tools.binary.validation_manifest_loader import load_validation_manifest
        from reveng.tools.core.binary_validator import BinaryValidator

        original_path = Path(original_binary)
        validation_config = load_validation_manifest(original_path.name)
        smoke_tests = (
            validation_config.smoke_tests
            if validation_config and validation_config.smoke_tests
            else None
        )
        validator = BinaryValidator()
        all_checks: List[Dict[str, Any]] = []
        targets: List[Dict[str, Any]] = []

        for target, rebuilt_binary in compiled_binaries.items():
            report = validator.validate_rebuild(
                original_path,
                Path(rebuilt_binary),
                smoke_tests=smoke_tests,
            )
            target_checks: List[Dict[str, Any]] = []
            comparison = report.get("comparison", {})
            original_info = report.get("original", {})
            rebuilt_info = report.get("rebuilt", {})
            size_diff = int(comparison.get("size_diff", 0) or 0)
            original_size = int(original_info.get("size", 0) or 0)
            size_diff_ratio = 0.0
            if original_size > 0:
                size_diff_ratio = size_diff / original_size

            add_check(
                target_checks,
                target=target,
                kind="artifact_presence",
                severity="error",
                status=(
                    "pass" if original_info.get("exists") and rebuilt_info.get("exists") else "fail"
                ),
                message=(
                    f"Original and rebuilt artifacts are available for target {target}."
                    if original_info.get("exists") and rebuilt_info.get("exists")
                    else f"Original or rebuilt artifact is missing for target {target}."
                ),
            )
            add_check(
                target_checks,
                target=target,
                kind="size_similarity",
                severity="warning",
                status="pass" if size_diff_ratio < 0.5 else "warn",
                message=(f"Rebuilt artifact size differs by {size_diff_ratio * 100:.1f}%."),
            )
            add_check(
                target_checks,
                target=target,
                kind="checksum_comparison",
                severity="info",
                status="pass" if comparison.get("checksum_match") else "info",
                message=(
                    "Original and rebuilt artifacts are byte-identical."
                    if comparison.get("checksum_match")
                    else "Original and rebuilt artifacts differ at the checksum level, which is expected for many alternative builds."
                ),
            )

            section_comparison = comparison.get("sections")
            section_mismatch_count = 0
            if isinstance(section_comparison, dict):
                if "error" in section_comparison:
                    add_check(
                        target_checks,
                        target=target,
                        kind="section_layout",
                        severity="warning",
                        status="warn",
                        message=f"Section comparison could not be completed: {section_comparison['error']}",
                    )
                else:
                    section_mismatch_count = sum(
                        1 for value in section_comparison.values() if value != "match"
                    )
                    add_check(
                        target_checks,
                        target=target,
                        kind="section_layout",
                        severity="warning",
                        status="pass" if section_mismatch_count == 0 else "warn",
                        message=(
                            "Binary section layout matches across common sections."
                            if section_mismatch_count == 0
                            else f"Binary section comparison found {section_mismatch_count} mismatched or missing sections."
                        ),
                    )

            smoke_report = report.get("smoke_tests", {}) if smoke_tests else {}
            smoke_tests_run = int(smoke_report.get("tests_run", 0) or 0)
            smoke_tests_failed = int(smoke_report.get("tests_failed", 0) or 0)
            if smoke_tests:
                smoke_status = "pass"
                if smoke_tests_failed and smoke_tests_run:
                    smoke_status = "warn"
                add_check(
                    target_checks,
                    target=target,
                    kind="characterization_smoke_test",
                    severity="warning",
                    status=smoke_status,
                    message=(
                        f"Configured smoke tests run={smoke_tests_run}, failed={smoke_tests_failed}."
                    ),
                )

            target_status = "pass"
            if any(check["status"] == "fail" for check in target_checks):
                target_status = "fail"
            elif any(check["status"] == "warn" for check in target_checks):
                target_status = "pass_with_warnings"

            targets.append(
                {
                    "target": target,
                    "status": target_status,
                    "size_difference": f"{size_diff_ratio * 100:.1f}%",
                    "checksum_match": bool(comparison.get("checksum_match")),
                    "section_mismatch_count": section_mismatch_count,
                    "smoke_tests_run": smoke_tests_run,
                    "smoke_tests_failed": smoke_tests_failed,
                    "checks": target_checks,
                }
            )
            all_checks.extend(target_checks)

        failed_check_count = sum(1 for check in all_checks if check["status"] == "fail")
        warn_check_count = sum(1 for check in all_checks if check["status"] == "warn")
        smoke_tests_configured = len(smoke_tests or [])
        smoke_tests_run = sum(int(target["smoke_tests_run"]) for target in targets)

        status = "pass"
        if failed_check_count > 0:
            status = "fail"
        elif warn_check_count > 0:
            status = "pass_with_warnings"

        return {
            "status": status,
            "mode": validation_config.mode.value,
            "summary": (
                f"Native differential validation completed with status={status} "
                f"across {len(targets)} rebuilt target(s)."
            ),
            "checks": all_checks,
            "targets": targets,
            "evidence": {
                "target_count": len(targets),
                "failed_check_count": failed_check_count,
                "warn_check_count": warn_check_count,
                "smoke_tests_configured": smoke_tests_configured,
                "smoke_tests_run": smoke_tests_run,
            },
        }

    def _build_recompilation_equivalence_validation_summary(
        self,
        compilation_reports: Optional[Dict[str, Dict[str, Any]]] = None,
        validation_results: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build a compact equivalence-confidence summary for recompilation results."""
        reports = compilation_reports or {}
        validation = validation_results or {}
        successful_reports = [
            report for report in reports.values() if report.get("status") == "success"
        ]
        failed_reports = [report for report in reports.values() if report.get("status") == "failed"]
        failure_reasons = sorted(
            {
                str(report.get("failure_reason"))
                for report in failed_reports
                if report.get("failure_reason")
            }
        )
        validation_tests = validation.get("tests", [])
        similarity_score = float(validation.get("similarity_score", 0.0) or 0.0)
        validation_failure_count = sum(
            int(test.get("tests_failed", 0)) for test in validation_tests
        )
        differential_validation = validation.get("differential_validation", {}) or {}
        differential_status = differential_validation.get("status")

        recommended_validations: List[Dict[str, Any]] = []
        reasons: List[str] = []
        seen_kinds: set[str] = set()

        def add_validation(
            priority: int,
            kind: str,
            title: str,
            summary: str,
            evidence_items: List[str],
        ) -> None:
            if kind in seen_kinds:
                return
            seen_kinds.add(kind)
            recommended_validations.append(
                {
                    "priority": priority,
                    "kind": kind,
                    "title": title,
                    "summary": summary,
                    "evidence": evidence_items,
                }
            )

        if not reports:
            return {
                "dimension": "equivalence_validation",
                "status": "insufficient_evidence",
                "equivalence_level": "insufficient_evidence",
                "confidence": "low",
                "summary": "No compilation reports are available yet, so equivalence cannot be assessed.",
                "reasons": [
                    "Compilation-side evidence is required before any equivalence claim can be made."
                ],
                "recommended_validations": [
                    {
                        "priority": 1,
                        "kind": "complete_compile_validation",
                        "title": "Produce at least one compiled candidate",
                        "summary": "Run the recompilation loop until at least one compiler emits a candidate binary.",
                        "evidence": ["missing_compilation_reports"],
                    }
                ],
                "evidence": {
                    "successful_compiler_count": 0,
                    "failed_compiler_count": 0,
                    "validation_target_count": 0,
                    "validation_failure_count": 0,
                    "similarity_score": 0.0,
                    "failure_reasons": [],
                },
            }

        if not successful_reports:
            status = "blocked"
            equivalence_level = "not_recompiled"
            confidence = "high"
            summary = (
                "Equivalence is blocked because recompilation did not produce a candidate binary."
            )
            reasons.append(
                "No compiler produced a candidate binary, so behavioral equivalence remains blocked at the compiler frontier."
            )
            if failure_reasons:
                reasons.append("Observed compiler blockers: " + ", ".join(failure_reasons))
            add_validation(
                1,
                "resolve_compiler_frontier",
                "Resolve the current compiler frontier",
                "Fix the earliest compile blockers on the generated source before making any equivalence claim.",
                [
                    f"successful_compiler_count:{len(successful_reports)}",
                    f"failed_compiler_count:{len(failed_reports)}",
                ],
            )
            add_validation(
                2,
                "preserve_failure_corpus",
                "Preserve failing artifacts for regression tests",
                "Keep the current source, stderr, and benchmark snippets as regression evidence while moving the frontier forward.",
                [f"failure_reason_count:{len(failure_reasons)}"],
            )
        elif not validation_tests:
            status = "candidate"
            equivalence_level = "compile_only_candidate"
            confidence = "low"
            summary = "A candidate binary exists, but only compile-side evidence is available, so equivalence remains a low-confidence compile-only candidate."
            reasons.append(
                "At least one compiler produced a candidate binary, but runtime validation evidence is still missing."
            )
            add_validation(
                1,
                "characterization_smoke_test",
                "Run black-box characterization checks",
                "Exercise representative inputs against the original and rebuilt binaries before claiming behavioral continuity.",
                [f"successful_compiler_count:{len(successful_reports)}"],
            )
            add_validation(
                2,
                "coverage_profile_compare",
                "Compare runtime coverage or branch profiles",
                "Use lightweight runtime tracing or coverage comparison to validate control-flow similarity beyond successful recompilation.",
                [f"similarity_score:{similarity_score:.3f}"],
            )
        else:
            if (
                differential_status == "fail"
                or validation_failure_count > 0
                or similarity_score < 0.5
            ):
                status = "candidate_with_warnings"
                equivalence_level = "divergent_candidate"
                confidence = "low"
                reasons.append(
                    "Behavioral validation found weak or mixed similarity evidence, so the rebuilt artifact should be treated as divergent until deeper checks pass."
                )
            elif differential_status == "pass_with_warnings":
                status = "candidate_with_warnings"
                equivalence_level = "structural_candidate"
                confidence = "medium"
                reasons.append(
                    "Differential validation completed with warnings, so the rebuilt artifact remains a structural candidate pending deeper runtime checks."
                )
            elif similarity_score >= 1.0:
                status = "candidate"
                equivalence_level = "behavioral_candidate"
                confidence = "medium"
                reasons.append(
                    "Compile-side validation and current behavioral checks are clean, supporting a medium-confidence behavioral candidate."
                )
            else:
                status = "candidate"
                equivalence_level = "structural_candidate"
                confidence = "medium"
                reasons.append(
                    "The rebuilt artifact passed the current lightweight validation checks, but deeper runtime evidence is still needed."
                )

            summary = (
                f"{equivalence_level.replace('_', ' ').title()} with {confidence} confidence "
                f"based on successful_compilers={len(successful_reports)}, "
                f"similarity={similarity_score:.3f}, and differential_validation={differential_status or 'unavailable'}."
            )
            add_validation(
                1,
                "characterization_smoke_test",
                "Run black-box characterization checks",
                "Exercise representative CLI or API behaviors against the original and rebuilt artifacts.",
                [
                    f"successful_compiler_count:{len(successful_reports)}",
                    f"similarity_score:{similarity_score:.3f}",
                ],
            )
            add_validation(
                2,
                "coverage_profile_compare",
                "Compare runtime coverage or branch profiles",
                "Use runtime traces or branch/coverage counters to confirm the recompiled binary preserves execution shape, not just compile success.",
                [f"validation_target_count:{len(validation_tests)}"],
            )
            if validation_failure_count > 0:
                add_validation(
                    3,
                    "side_effect_review",
                    "Review stateful side effects",
                    "Inspect global-state, heap, and pointer-sensitive paths because the current validation evidence already shows mismatches.",
                    [f"validation_failure_count:{validation_failure_count}"],
                )

        recommended_validations.sort(key=lambda item: item["priority"])
        return {
            "dimension": "equivalence_validation",
            "status": status,
            "equivalence_level": equivalence_level,
            "confidence": confidence,
            "summary": summary,
            "reasons": reasons,
            "recommended_validations": recommended_validations,
            "evidence": {
                "successful_compiler_count": len(successful_reports),
                "failed_compiler_count": len(failed_reports),
                "validation_target_count": len(validation_tests),
                "validation_failure_count": validation_failure_count,
                "similarity_score": similarity_score,
                "failure_reasons": failure_reasons,
                "differential_status": differential_status,
            },
        }

    async def _phase5_security_analysis(self, source_files: Dict[str, str]) -> List[Dict[str, Any]]:
        """Phase 5: Analyze reconstructed code for vulnerabilities."""
        vulnerabilities = []

        # Analyze C code
        if "c" in source_files:
            c_code = Path(source_files["c"]).read_text()

            # Use Gemini if available
            if self.gemini and self.gemini.is_available():
                logger.info("  Analyzing C code with Gemini AI...")
                gemini_vulns = await self.gemini.analyze_security(c_code)
                vulnerabilities.extend(gemini_vulns)
                logger.info(f"  ✅ Found {len(gemini_vulns)} potential vulnerabilities")

            # Static pattern matching
            logger.info("  Running static vulnerability detection...")
            static_vulns = self._static_vulnerability_scan(c_code)
            vulnerabilities.extend(static_vulns)
            logger.info(f"  ✅ Found {len(static_vulns)} pattern-matched vulnerabilities")

        return vulnerabilities

    async def _phase6_exploit_generation(
        self,
        vulnerabilities: List[Dict[str, Any]],
        source_files: Dict[str, str],
        compiled_binaries: Dict[str, str],
    ) -> List[Dict[str, Any]]:
        """Phase 6: Generate working proof-of-concept exploits."""
        exploits = []

        if not vulnerabilities:
            logger.info("  No vulnerabilities found, skipping exploit generation")
            return exploits

        logger.info(f"  Generating exploits for {len(vulnerabilities)} vulnerabilities...")

        for vuln in vulnerabilities[:5]:  # Limit to top 5
            if self.gemini and self.gemini.is_available():
                c_code = Path(source_files.get("c", "")).read_text() if "c" in source_files else ""
                exploit = await self.gemini.generate_exploit(vuln, c_code)
                if exploit:
                    exploits.append(exploit)
                    logger.info(f"  ✅ Generated exploit for {vuln.get('type')}")

        return exploits

    def _write_reconstruction_progress(
        self,
        progress_path: Path,
        *,
        status: str,
        total_functions: int,
        completed_functions: int,
        stage: Optional[str] = None,
        current_function_address: Optional[str] = None,
        elapsed_seconds: Optional[float] = None,
        source_file: Optional[str] = None,
        current_stage_elapsed_seconds: Optional[float] = None,
        stage_timings: Optional[Dict[str, float]] = None,
    ) -> None:
        """Persist a lightweight heartbeat for long-running Phase 2 reconstruction."""
        progress = {
            "status": status,
            "total_functions": total_functions,
            "completed_functions": completed_functions,
        }
        if stage:
            progress["stage"] = stage
        if current_function_address:
            progress["current_function_address"] = current_function_address
        if elapsed_seconds is not None:
            progress["elapsed_seconds"] = round(float(elapsed_seconds), 3)
        if source_file:
            progress["source_file"] = source_file
        if current_stage_elapsed_seconds is not None:
            progress["current_stage_elapsed_seconds"] = round(
                float(current_stage_elapsed_seconds), 3
            )
        if stage_timings:
            progress["stage_timings"] = {
                name: round(float(duration), 3) for name, duration in stage_timings.items()
            }
        progress_path.write_text(json.dumps(progress, indent=2), encoding="utf-8")

    def _debug_function_stage_dumps_enabled(self) -> bool:
        """Return whether opt-in per-function debug dumps are enabled."""
        return os.environ.get("REVENG_DEBUG_FUNCTION_STAGES", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _debug_whole_source_stage_dumps_enabled(self) -> bool:
        """Return whether opt-in whole-source stage dumps are enabled."""
        return os.environ.get("REVENG_DEBUG_WHOLE_SOURCE_STAGES", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }

    def _get_debug_function_focus_terms(self) -> list[str]:
        """Return optional focus terms that should trigger per-function dumps."""
        raw_terms = os.environ.get("REVENG_DEBUG_FUNCTION_TERMS", "").strip()
        if not raw_terms:
            return []
        return [term.strip() for term in raw_terms.split(",") if term.strip()]

    def _get_suspicious_debug_marker(self, snapshots: Dict[str, str]) -> str:
        """Return the first suspicious malformed-token marker found in the snapshots."""
        suspicious_markers = (
            "FUN_1GHIDRA_U64",
            "local_678local_678",
            "FUN_140GHIDRA_U64",
            "GHIDRA_U64(ppppppppppuVar23 + 9)0,ppppppppppuVar23 + 9",
            "0x36= FUN_1400c6fb0",
            "0x24= FUN_1400c6fb0",
        )
        combined_content = "\n".join(snapshots.values())
        for marker in suspicious_markers:
            if marker in combined_content:
                return marker
        return ""

    def _get_matching_debug_focus_term(self, snapshots: Dict[str, str]) -> str:
        """Return the first configured focus term found in the snapshots."""
        combined_content = "\n".join(snapshots.values())
        for term in self._get_debug_function_focus_terms():
            if term in combined_content:
                return term
        return ""

    def _write_function_stage_debug_dump(
        self,
        debug_output_dir: Path,
        address: str,
        snapshots: Dict[str, str],
        dump_reason: str,
    ) -> None:
        """Persist stage-by-stage function snapshots for suspicious rewrites."""
        dump_root = debug_output_dir / "function_stage_dumps"
        dump_root.mkdir(parents=True, exist_ok=True)
        safe_address = re.sub(r"[^0-9A-Za-z_.-]", "_", address)
        function_dir = dump_root / safe_address
        function_dir.mkdir(parents=True, exist_ok=True)
        manifest = {
            "address": address,
            "reason": dump_reason,
            "stages": list(snapshots.keys()),
        }
        (function_dir / "manifest.json").write_text(
            json.dumps(manifest, indent=2), encoding="utf-8"
        )
        for stage_name, content in snapshots.items():
            (function_dir / f"{stage_name}.c").write_text(content, encoding="utf-8")

    def _maybe_dump_function_stage_debug(
        self,
        debug_output_dir: Optional[Path],
        address: str,
        snapshots: Dict[str, str],
    ) -> None:
        """Write stage dumps when suspicious corruption markers are present."""
        if debug_output_dir is None or not self._debug_function_stage_dumps_enabled():
            return
        marker = self._get_suspicious_debug_marker(snapshots)
        if marker:
            dump_reason = f"suspicious_marker:{marker}"
        else:
            focus_term = self._get_matching_debug_focus_term(snapshots)
            dump_reason = f"focus_term:{focus_term}" if focus_term else ""
        if not dump_reason:
            return
        self._write_function_stage_debug_dump(debug_output_dir, address, snapshots, dump_reason)

    def _write_whole_source_stage_debug_dump(
        self,
        debug_output_dir: Path,
        snapshots: Dict[str, str],
        first_suspicious_stage: str,
        dump_reason: str,
    ) -> None:
        """Persist whole-source stage snapshots through the first suspicious stage."""
        dump_root = debug_output_dir / "whole_source_stage_dumps"
        dump_root.mkdir(parents=True, exist_ok=True)
        manifest = {
            "reason": dump_reason,
            "first_suspicious_stage": first_suspicious_stage,
            "stages": list(snapshots.keys()),
        }
        (dump_root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        for stage_name, content in snapshots.items():
            (dump_root / f"{stage_name}.c").write_text(content, encoding="utf-8")

    def _maybe_dump_whole_source_stage_debug(
        self,
        debug_output_dir: Optional[Path],
        snapshots: Dict[str, str],
        first_suspicious_stage: str,
    ) -> bool:
        """Write whole-source stage dumps when suspicious markers first appear."""
        if debug_output_dir is None or not self._debug_whole_source_stage_dumps_enabled():
            return False
        marker = self._get_suspicious_debug_marker(snapshots)
        if not marker:
            return False
        focus_term = self._get_matching_debug_focus_term(snapshots)
        if self._get_debug_function_focus_terms() and not focus_term:
            return False
        self._write_whole_source_stage_debug_dump(
            debug_output_dir,
            snapshots,
            first_suspicious_stage,
            f"suspicious_marker:{marker}",
        )
        return True

    async def _reconstruct_c_code(
        self,
        ghidra_data: Dict[str, Any],
        progress_callback: Optional[Callable[[int, int, str], None]] = None,
        stage_callback: Optional[Callable[[str], None]] = None,
        stage_timing_callback: Optional[Callable[[str, float], None]] = None,
        debug_output_dir: Optional[Path] = None,
    ) -> str:
        """Reconstruct complete C source file from Ghidra data."""
        code_parts = []
        function_name_map = self._build_function_name_map(ghidra_data)
        emitted_declarations: set[str] = set()
        type_prelude = self._build_c_type_prelude()

        # Add standard headers
        code_parts.append("/* Reconstructed by REVENG AI-Powered Analysis */")
        code_parts.append("#include <stdio.h>")
        code_parts.append("#include <stdlib.h>")
        code_parts.append("#include <string.h>")
        code_parts.append(type_prelude)
        code_parts.append("")

        # Add function declarations
        for index, func in enumerate(ghidra_data.get("functions", [])):
            if func.get("name") != "main":
                sig = func.get("signature", f"void {func.get('name')}(void)")
                original_name = self._get_function_original_name(func, index)
                if original_name:
                    sig = self._apply_function_name_map(
                        str(sig), {original_name: function_name_map[original_name]}
                    )
                sig = self._sanitize_generated_c_tokens(str(sig))
                declaration_name = self._extract_function_name(sig)
                if not declaration_name:
                    continue
                if self._should_skip_function_declaration(declaration_name):
                    continue
                if declaration_name in emitted_declarations:
                    continue
                emitted_declarations.add(declaration_name)
                code_parts.append(f"{sig};")
        code_parts.append("")

        # Add decompiled functions
        decompiled = ghidra_data.get("decompiled_code", {})
        total_functions = len(decompiled)
        for index, (address, code) in enumerate(decompiled.items(), start=1):
            stage_snapshots: Dict[str, str] = {"raw": str(code)}
            name_mapped_code = self._apply_function_name_map(str(code), function_name_map)
            stage_snapshots["name_mapped"] = name_mapped_code
            sanitized_code = self._sanitize_generated_c_tokens(name_mapped_code)
            stage_snapshots["sanitized"] = sanitized_code
            semantics_normalized_code = self._normalize_generated_c_semantics(sanitized_code)
            stage_snapshots["semantic"] = semantics_normalized_code
            normalized_code = self._restore_generated_labels(semantics_normalized_code)
            stage_snapshots["labels_restored"] = normalized_code
            self._maybe_dump_function_stage_debug(debug_output_dir, str(address), stage_snapshots)
            # Use Gemini to enhance if available
            if self.gemini and self.gemini.is_available():
                enhanced = await self.gemini.reconstruct_function(
                    normalized_code, f"func_{address}", context=ghidra_data
                )
                code_parts.append(enhanced.get("source_code", normalized_code))
            else:
                code_parts.append(normalized_code)
            code_parts.append("")
            if progress_callback:
                progress_callback(index, total_functions, str(address))

        def apply_stage(
            stage_name: str, transform: Callable[[str], str], current_source: str
        ) -> str:
            if stage_callback:
                stage_callback(stage_name)
            stage_started = time.monotonic()
            next_source = transform(current_source)
            if stage_timing_callback:
                stage_timing_callback(stage_name, time.monotonic() - stage_started)
            whole_source_snapshots[stage_name] = next_source
            return next_source

        source = "\n".join(code_parts)
        whole_source_snapshots: Dict[str, str] = {"assembled": source}
        whole_source_dump_written = False
        source = apply_stage(
            "whole_source_normalization",
            lambda current: self._normalize_generated_c_semantics(
                current,
                normalize_pointer_assignments=False,
            ),
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "whole_source_normalization",
            )
        )
        source = apply_stage(
            "normalize_undeclared_split_locals",
            self._normalize_undeclared_split_locals,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "normalize_undeclared_split_locals",
            )
        )
        source = apply_stage(
            "unify_fragment_locals",
            self._unify_fragment_locals,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "unify_fragment_locals",
            )
        )
        source = apply_stage(
            "widen_undefined8_param_prototypes",
            self._widen_undefined8_param_prototypes,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "widen_undefined8_param_prototypes",
            )
        )
        source = apply_stage(
            "prototype_relaxation",
            self._relax_mismatched_pointer_prototypes,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "prototype_relaxation",
            )
        )
        source = apply_stage(
            "integer_pointer_access_normalization",
            self._normalize_integer_pointer_accesses,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "integer_pointer_access_normalization",
            )
        )
        source = apply_stage(
            "non_code_pointer_retargeting",
            self._retarget_non_code_pointer_cast_assignments,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "non_code_pointer_retargeting",
            )
        )
        source = apply_stage(
            "uintptr_bridge_normalization",
            self._normalize_uintptr_bridge_accesses,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "uintptr_bridge_normalization",
            )
        )
        source = apply_stage(
            "void_prototype_relaxation",
            self._relax_mismatched_void_prototypes,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "void_prototype_relaxation",
            )
        )
        source = apply_stage(
            "uintptr_param_normalization",
            self._normalize_pointer_arguments_for_uintptr_params,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "uintptr_param_normalization",
            )
        )
        source = apply_stage(
            "prototype_alignment",
            self._align_conflicting_function_prototypes,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "prototype_alignment",
            )
        )
        source = apply_stage(
            "void_return_relaxation",
            self._relax_void_return_functions_used_as_values,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "void_return_relaxation",
            )
        )
        source = apply_stage(
            "bare_return_normalization",
            self._normalize_bare_returns_for_scalar_functions,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "bare_return_normalization",
            )
        )
        source = apply_stage(
            "helper_alias_qualification",
            self._qualify_unresolved_function_aliases,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "helper_alias_qualification",
            )
        )
        source = apply_stage(
            "void_pointer_index_normalization",
            self._normalize_void_pointer_parameter_indexing,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "void_pointer_index_normalization",
            )
        )
        source = apply_stage(
            "late_pointer_param_normalization",
            self._normalize_integer_arguments_for_pointer_params,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "late_pointer_param_normalization",
            )
        )
        source = apply_stage(
            "late_uintptr_param_normalization",
            self._normalize_pointer_arguments_for_uintptr_params,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "late_uintptr_param_normalization",
            )
        )
        source = apply_stage(
            "late_void_pointer_index_normalization",
            self._normalize_void_pointer_parameter_indexing,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "late_void_pointer_index_normalization",
            )
        )
        source = apply_stage(
            "late_pointer_integer_assignment_normalization",
            self._normalize_pointer_integer_assignments,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "late_pointer_integer_assignment_normalization",
            )
        )
        source = apply_stage(
            "late_non_code_pointer_retargeting",
            self._retarget_non_code_pointer_cast_assignments,
            source,
        )
        whole_source_dump_written = (
            whole_source_dump_written
            or self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "late_non_code_pointer_retargeting",
            )
        )
        if stage_callback:
            stage_callback("generated_prelude_build")
        generated_prelude_build_started = time.monotonic()
        source = self._strip_import_like_forward_declarations(source)
        synthetic_prelude = self._build_generated_symbol_prelude(source)
        helper_prelude = self._build_generated_helper_prelude(source)
        if stage_timing_callback:
            stage_timing_callback(
                "generated_prelude_build",
                time.monotonic() - generated_prelude_build_started,
            )
        generated_preludes = "\n\n".join(
            prelude for prelude in [synthetic_prelude, helper_prelude] if prelude
        )
        if generated_preludes:
            if stage_callback:
                stage_callback("generated_prelude_injection")
            generated_prelude_injection_started = time.monotonic()
            source = source.replace(
                f"{type_prelude}\n\n",
                f"{type_prelude}\n\n{generated_preludes}\n\n",
                1,
            )
            if stage_timing_callback:
                stage_timing_callback(
                    "generated_prelude_injection",
                    time.monotonic() - generated_prelude_injection_started,
                )
            whole_source_snapshots["generated_prelude_injection"] = source
            if not whole_source_dump_written:
                self._maybe_dump_whole_source_stage_debug(
                    debug_output_dir,
                    whole_source_snapshots,
                    "generated_prelude_injection",
                )
        source = apply_stage(
            "final_helper_alias_qualification",
            self._qualify_unresolved_function_aliases,
            source,
        )
        if not whole_source_dump_written:
            self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "final_helper_alias_qualification",
            )
        source = apply_stage(
            "final_void_pointer_index_normalization",
            self._normalize_void_pointer_parameter_indexing,
            source,
        )
        if not whole_source_dump_written:
            self._maybe_dump_whole_source_stage_debug(
                debug_output_dir,
                whole_source_snapshots,
                "final_void_pointer_index_normalization",
            )
        return source

    def _build_c_type_prelude(self) -> str:
        """Return a compatibility prelude for common Ghidra-emitted C types."""
        return """#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef _WIN32
#include <windows.h>
#else
typedef size_t SIZE_T;
typedef void * LPVOID;
typedef struct {
    long long QuadPart;
} LARGE_INTEGER;
typedef void * PEXCEPTION_POINTERS;
typedef void * PEXCEPTION_RECORD;
typedef void * PCONTEXT;
typedef void * PDISPATCHER_CONTEXT;
#endif

#include <stdnoreturn.h>

#ifdef NAN
#undef NAN
#endif
#define NAN(value) (((double)(value)) != ((double)(value)))

#ifndef __cdecl
#define __cdecl
#endif

#ifndef __stdcall
#define __stdcall
#endif

#ifndef __fastcall
#define __fastcall
#endif

#ifndef __thiscall
#define __thiscall
#endif

#ifndef swi
#define swi(...) ((uint64_t)0)
#endif

typedef struct {
    uint32_t LowPart;
    int32_t HighPart;
} _struct_19;

typedef uint8_t byte;
typedef uint8_t undefined;
typedef uint8_t undefined1;
typedef uint16_t undefined2;
typedef uint32_t undefined4;
typedef uint64_t undefined8;
typedef int8_t sbyte;
typedef int16_t short16;
typedef int32_t int32;
typedef int64_t int64;
typedef uint8_t uchar;
typedef uint16_t ushort;
typedef uint32_t uint;
typedef uint64_t ulonglong;
typedef int64_t longlong;
typedef uint64_t qword;
typedef uint32_t dword;
typedef unsigned long ulong;
typedef uint64_t ulong64;
typedef uint32_t undefined3;
typedef uint64_t undefined5;
typedef uint64_t undefined6;
typedef uint64_t undefined7;
typedef int32_t int3;
typedef uint32_t uint3;
typedef uint64_t int7;
typedef uint64_t uint6;
typedef uint64_t uint7;
typedef void code();
typedef void type_info;
typedef int __scrt_module_type;
typedef int (__cdecl * _func___cdecl_int)(void);
typedef void (__cdecl * _func___cdecl_void)(void);
typedef void (__cdecl * _func___cdecl_void_void_ptr_ulong_void_ptr)(void *, ulong, void *);
typedef PEXCEPTION_POINTERS _EXCEPTION_POINTERS;
typedef PEXCEPTION_RECORD _EXCEPTION_RECORD;
#ifdef _WIN32
typedef CONTEXT _CONTEXT;
typedef DISPATCHER_CONTEXT _DISPATCHER_CONTEXT;
typedef SECURITY_ATTRIBUTES _SECURITY_ATTRIBUTES;
typedef BY_HANDLE_FILE_INFORMATION _BY_HANDLE_FILE_INFORMATION;
typedef CONSOLE_SCREEN_BUFFER_INFO _CONSOLE_SCREEN_BUFFER_INFO;
typedef CONSOLE_READCONSOLE_CONTROL _CONSOLE_READCONSOLE_CONTROL;
#else
typedef PCONTEXT _CONTEXT;
typedef PDISPATCHER_CONTEXT _DISPATCHER_CONTEXT;
#endif
typedef void ThrowInfo;
typedef int _crt_argv_mode;
typedef void _exception;

#if defined(__SIZEOF_INT128__)
typedef unsigned __int128 ghidra_uint128;
#else
typedef uint64_t ghidra_uint128;
#endif

typedef union {
    ghidra_uint128 whole;
    uint8_t bytes[16];
} ghidra_vec128;

typedef ghidra_uint128 unkuint10;

typedef union {
    uint64_t whole;
    uint8_t bytes[8];
} ghidra_vec64;

typedef uintptr_t (*ghidra_indirect_fn_0)(void);
typedef uintptr_t (*ghidra_indirect_fn)(uintptr_t, ...);

#define GHIDRA_U64(value) ((uint64_t)(uintptr_t)(value))
#define GHIDRA_U128(value) ((ghidra_uint128)(uintptr_t)(value))
#define GHIDRA_LARGE_INTEGER(value) ((LARGE_INTEGER){ .QuadPart = (long long)(uintptr_t)(value) })
#define SUB81(value, offset) ((uint8_t)(GHIDRA_U64(value) >> ((offset) * 8)))
#define SUB82(value, offset) ((uint16_t)(GHIDRA_U64(value) >> ((offset) * 8)))
#define SUB84(value, offset) ((uint32_t)(GHIDRA_U64(value) >> ((offset) * 8)))
#define ZEXT216(value) ((ghidra_uint128)(uint16_t)(value))
#define SUB168(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB164(value, offset) ((uint32_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB158(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB161(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB1510(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB1512(value, offset) ((uint64_t)(GHIDRA_U128(value) >> ((offset) * 8)))
#define SUB87(value, offset) ((uint64_t)(GHIDRA_U64(value) >> ((offset) * 8)))
#define ZEXT816(value) ((uint64_t)(uint8_t)(value))
#define ZEXT716(value) ((ghidra_uint128)(GHIDRA_U64(value) & 0x00ffffffffffffffULL))
#define SEXT816(value) ((int64_t)GHIDRA_U64(value))
#define CONCAT11(high, low) ((((uint16_t)(uint8_t)(high)) << 8) | (uint16_t)(uint8_t)(low))
#define CONCAT12(high, low) ((((uint32_t)(uint8_t)(high)) << 16) | (uint32_t)(uint16_t)(low))
#define CONCAT13(high, low) ((((uint32_t)(uint8_t)(high)) << 24) | ((uint32_t)GHIDRA_U64(low) & 0x00ffffffU))
#define CONCAT14(high, low) ((((uint64_t)(uint8_t)(high)) << 32) | (uint64_t)(uint32_t)(low))
#define CONCAT15(high, low) ((((uint64_t)(uint8_t)(high)) << 40) | (GHIDRA_U64(low) & 0x000000ffffffffffULL))
#define CONCAT16(high, low) ((((uint64_t)(uint8_t)(high)) << 48) | (GHIDRA_U64(low) & 0x0000ffffffffffffULL))
#define CONCAT21(high, low) ((((uint32_t)(uint16_t)(high)) << 8) | (uint32_t)(uint8_t)(low))
#define CONCAT22(high, low) ((((uint32_t)(uint16_t)(high)) << 16) | (uint32_t)(uint16_t)(low))
#define CONCAT24(high, low) ((((uint64_t)(uint16_t)(high)) << 32) | (uint64_t)(uint32_t)(low))
#define CONCAT26(high, low) ((((uint64_t)(uint16_t)(high)) << 48) | (GHIDRA_U64(low) & 0x0000ffffffffffffULL))
#define CONCAT25(high, low) ((((uint64_t)(uint16_t)(high)) << 40) | (GHIDRA_U64(low) & 0x000000ffffffffffULL))
#define CONCAT31(high, low) ((((uint32_t)GHIDRA_U64(high) & 0x00ffffffU) << 8) | (uint32_t)(uint8_t)(low))
#define CONCAT34(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x00ffffffU) << 32) | (uint64_t)(uint32_t)(low))
#define CONCAT35(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x00ffffffU) << 40) | (GHIDRA_U64(low) & 0x000000ffffffffffULL))
#define CONCAT41(high, low) ((((uint64_t)(uint32_t)(high)) << 8) | (uint64_t)(uint8_t)(low))
#define CONCAT44(high, low) ((((uint64_t)(uint32_t)(high)) << 32) | (uint64_t)(uint32_t)(low))
#define CONCAT51(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x000000ffffffffffULL) << 8) | (uint64_t)(uint8_t)(low))
#define CONCAT52(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x000000ffffffffffULL) << 16) | (uint64_t)(uint16_t)(low))
#define CONCAT53(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x000000ffffffffffULL) << 24) | ((uint64_t)GHIDRA_U64(low) & 0x00ffffffULL))
#define CONCAT62(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x0000ffffffffffffULL) << 16) | (uint64_t)(uint16_t)(low))
#define CONCAT71(high, low) (((uint64_t)GHIDRA_U64(high) << 8) | (uint64_t)(uint8_t)(low))
#define CONCAT72(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x00ffffffffffffffULL) << 16) | (uint64_t)(uint16_t)(low))
#define CONCAT17(high, low) ((((uint64_t)(uint8_t)(high)) << 56) | (GHIDRA_U64(low) & 0x00ffffffffffffffULL))
#define CONCAT61(high, low) ((((uint64_t)GHIDRA_U64(high) & 0x0000ffffffffffffULL) << 8) | (uint64_t)(uint8_t)(low))"""

    def _build_function_name_map(self, ghidra_data: Dict[str, Any]) -> Dict[str, str]:
        """Build a stable mapping of original function names to valid C identifiers."""
        mappings: Dict[str, str] = {}
        used_names: set[str] = set()

        for index, func in enumerate(ghidra_data.get("functions", [])):
            if not isinstance(func, dict):
                continue

            original_name = self._get_function_original_name(func, index)
            if not original_name or original_name in mappings:
                continue

            candidate = self._sanitize_c_identifier(original_name, fallback=f"func_{index}")
            unique_candidate = candidate
            suffix = 2
            while unique_candidate in used_names:
                unique_candidate = f"{candidate}_{suffix}"
                suffix += 1

            mappings[original_name] = unique_candidate
            used_names.add(unique_candidate)

        return mappings

    def _get_function_original_name(self, func: Dict[str, Any], index: int) -> str:
        """Return the best available original function name for remapping."""
        raw_name = str(func.get("name") or "").strip()
        if raw_name:
            return raw_name

        source_name = self._extract_function_name(
            str(func.get("source") or func.get("decompiled") or "")
        )
        if source_name:
            return source_name

        return f"func_{index}"

    def _extract_function_name(self, source: str) -> Optional[str]:
        """Extract a function name from a C-like source snippet."""
        signature = self._extract_function_signature(source)
        if not signature:
            return None

        before_paren = signature.split("(", 1)[0].strip()
        if not before_paren:
            return None

        return before_paren.split()[-1]

    def _extract_function_signature(self, source: str) -> Optional[str]:
        """Extract the signature line from a C-like function body."""
        header, separator, _body = source.partition("{")
        candidate = header.strip().rstrip(";")
        if "(" not in candidate or ")" not in candidate:
            return None
        if not separator:
            return candidate
        return candidate

    def _sanitize_c_identifier(self, name: Any, fallback: str) -> str:
        """Convert arbitrary names into valid C identifiers."""
        candidate = str(name or "").strip()
        if not candidate:
            candidate = fallback

        candidate = re.sub(r"[^0-9A-Za-z_]", "_", candidate)
        candidate = re.sub(r"_+", "_", candidate)
        if not candidate:
            candidate = fallback
        if candidate[0].isdigit():
            candidate = f"func_{candidate}"
        if candidate == fallback and fallback:
            return fallback
        return candidate

    def _apply_function_name_map(self, source: str, function_name_map: Dict[str, str]) -> str:
        """Apply a stable function-name remapping across generated C source."""
        updated = source
        for original_name in sorted(function_name_map, key=len, reverse=True):
            sanitized_name = function_name_map[original_name]
            updated = updated.replace(original_name, sanitized_name)
        return updated

    def _join_wrapped_sanitized_call_identifiers(self, source: str) -> str:
        """Join helper identifiers that were split across lines before `();`."""
        lines = source.splitlines()
        joined_lines: list[str] = []
        index = 0
        while index < len(lines):
            current = lines[index]
            if (
                index + 3 < len(lines)
                and re.match(r"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*$", current)
                and re.match(r"^\s*[A-Za-z_][A-Za-z0-9_,]*_\s*$", lines[index + 1])
                and re.match(r"^\s*[A-Za-z_][A-Za-z0-9_,]*_\s*$", lines[index + 2])
                and re.match(r"^\s*\([^;{}]*\)\s*$", lines[index + 3])
            ):
                indent_match = re.match(r"^(\s*)", current)
                indent = indent_match.group(1) if indent_match else ""
                joined_signature = (
                    f"{current.strip()} {lines[index + 1].strip()}"
                    f"{lines[index + 2].strip().replace(',', '_')}{lines[index + 3].strip()}"
                )
                joined_lines.append(f"{indent}{joined_signature}")
                index += 4
                continue
            if (
                index + 2 < len(lines)
                and re.match(r"^\s*[A-Za-z_][A-Za-z0-9_,]*_\s*$", current)
                and re.match(r"^\s*[A-Za-z_][A-Za-z0-9_,]*_\s*$", lines[index + 1])
                and re.match(r"^\s*\(\);\s*$", lines[index + 2])
            ):
                indent_match = re.match(r"^(\s*)", current)
                indent = indent_match.group(1) if indent_match else ""
                joined_lines.append(
                    f"{indent}{current.strip()}{lines[index + 1].strip()}{lines[index + 2].strip()}"
                )
                index += 3
                continue
            if (
                index + 1 < len(lines)
                and re.match(r"^\s*[A-Za-z_][A-Za-z0-9_,]*_\s*$", current)
                and re.match(
                    r"^\s*[A-Za-z_][A-Za-z0-9_,]*_[A-Za-z0-9_,]*(?:\([^;{}]*\))\s*;\s*$",
                    lines[index + 1],
                )
            ):
                indent_match = re.match(r"^(\s*)", current)
                indent = indent_match.group(1) if indent_match else ""
                joined_lines.append(f"{indent}{current.strip()}{lines[index + 1].strip()}")
                index += 2
                continue
            joined_lines.append(current)
            index += 1
        return "\n".join(joined_lines)

    def _sanitize_generated_c_tokens(self, source: str) -> str:
        """Sanitize residual non-C identifiers left in generated source."""
        source = self._join_wrapped_sanitized_call_identifiers(source)
        token_pattern = re.compile(
            r"(?<![A-Za-z0-9_])([A-Za-z_.$:][A-Za-z0-9_.$:<>-]*)(?![A-Za-z0-9_])"
        )

        def replace_token(match: re.Match[str]) -> str:
            token = match.group(1)
            if token == "...":
                return token
            if token == ":":
                return token
            if not any(char in token for char in ".$:<>-"):
                return token
            return self._sanitize_c_identifier(token, fallback="generated_symbol")

        return token_pattern.sub(replace_token, source)

    def _balance_unclosed_ghidra_u64_calls(self, source: str) -> str:
        """Repair generated lines where GHIDRA_U64(...) is missing trailing closing parentheses."""

        def count_parens_outside_literals(text: str) -> tuple[int, int]:
            open_count = 0
            close_count = 0
            in_string = False
            in_char = False
            escaped = False
            for char in text:
                if escaped:
                    escaped = False
                    continue
                if char == "\\" and (in_string or in_char):
                    escaped = True
                    continue
                if char == '"' and not in_char:
                    in_string = not in_string
                    continue
                if char == "'" and not in_string:
                    in_char = not in_char
                    continue
                if in_string or in_char:
                    continue
                if char == "(":
                    open_count += 1
                elif char == ")":
                    close_count += 1
            return open_count, close_count

        def find_matching_paren(text: str, open_paren: int) -> int:
            depth = 0
            for index in range(open_paren, len(text)):
                char = text[index]
                if char == "(":
                    depth += 1
                elif char == ")":
                    depth -= 1
                    if depth == 0:
                        return index
            return -1

        def find_top_level_comma(arguments: str) -> int:
            paren_depth = 0
            bracket_depth = 0
            brace_depth = 0
            for index, char in enumerate(arguments):
                if char == "(":
                    paren_depth += 1
                elif char == ")":
                    paren_depth = max(paren_depth - 1, 0)
                elif char == "[":
                    bracket_depth += 1
                elif char == "]":
                    bracket_depth = max(bracket_depth - 1, 0)
                elif char == "{":
                    brace_depth += 1
                elif char == "}":
                    brace_depth = max(brace_depth - 1, 0)
                elif char == "," and paren_depth == 0 and bracket_depth == 0 and brace_depth == 0:
                    return index
            return -1

        def split_malformed_ghidra_u64_commas(line: str) -> str:
            updated_parts: list[str] = []
            cursor = 0
            needle = "GHIDRA_U64("
            while True:
                start = line.find(needle, cursor)
                if start == -1:
                    updated_parts.append(line[cursor:])
                    break
                updated_parts.append(line[cursor:start])
                open_paren = start + len(needle) - 1
                close_paren = find_matching_paren(line, open_paren)
                if close_paren == -1:
                    updated_parts.append(line[start:])
                    break
                arguments = line[open_paren + 1 : close_paren]
                comma_index = find_top_level_comma(arguments)
                if comma_index == -1:
                    updated_parts.append(line[start : close_paren + 1])
                else:
                    first_argument = arguments[:comma_index].rstrip()
                    trailing_expression = arguments[comma_index + 1 :]
                    updated_parts.append(f"GHIDRA_U64({first_argument}),{trailing_expression}")
                cursor = close_paren + 1
            return "".join(updated_parts)

        balanced_lines: list[str] = []
        for line in source.splitlines():
            rewritten = split_malformed_ghidra_u64_commas(line)
            stripped = line.strip()
            if "GHIDRA_U64(" in stripped and stripped.endswith(";"):
                open_count, close_count = count_parens_outside_literals(stripped)
                if close_count < open_count:
                    missing = open_count - close_count
                    rewritten = rewritten[:-1] + (")" * missing) + ";"
            balanced_lines.append(rewritten)
        return "\n".join(balanced_lines)

    def _extract_declared_variable_types_from_line(self, line: str) -> Dict[str, str]:
        """Extract declared variable types from a single C declaration line."""
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith(("#", "//", "/*", "*"))
            or re.match(r"^(?:return|goto|break|continue|case|default|else)\b", stripped)
            or not stripped.endswith(";")
            or "=" in stripped
            or "(" in stripped
            or ")" in stripped
        ):
            return {}
        return self._extract_declared_variable_types(f"{line}\n")

    def _retarget_non_code_pointer_cast_assignments(self, source: str) -> str:
        """Rewrite leftover code-pointer casts to the declared lhs type when they are not true function pointers."""
        global_types: Dict[str, str] = {}
        local_types: Dict[str, str] = {}
        brace_depth = 0
        updated_lines: list[str] = []
        pattern = re.compile(
            r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(code \*\)\(uintptr_t\)(?P<rhs>GHIDRA_U64\([^;]+\));$"
        )
        for line in source.splitlines():
            stripped = line.strip()
            if (
                brace_depth == 0
                and "(" in stripped
                and ")" in stripped
                and stripped.endswith("{")
                and "=" not in stripped
                and not stripped.startswith(("#", "if", "for", "while", "switch"))
            ):
                local_types = {}
            declarations = self._extract_declared_variable_types_from_line(line)
            if declarations:
                if brace_depth == 0:
                    global_types.update(declarations)
                else:
                    local_types.update(declarations)
            match = pattern.match(line)
            if not match:
                updated_lines.append(line)
                brace_depth += line.count("{") - line.count("}")
                continue
            lhs = match.group("lhs")
            lhs_type = local_types.get(lhs, global_types.get(lhs, ""))
            if not lhs_type and self._is_integer_fragment_name(lhs):
                lhs_type = "uint64_t"
            if self._is_integer_declared_type(lhs_type):
                updated_lines.append(f"{match.group('indent')}{lhs} = {match.group('rhs')};")
            elif (
                self._is_pointer_declared_type(lhs_type) and " ".join(lhs_type.split()) != "code *"
            ):
                updated_lines.append(
                    f"{match.group('indent')}{lhs} = ({lhs_type})(uintptr_t){match.group('rhs')};"
                )
            else:
                updated_lines.append(line)
            brace_depth += line.count("{") - line.count("}")
        return "\n".join(updated_lines)

    def _normalize_generated_c_semantics(
        self, source: str, normalize_pointer_assignments: bool = True
    ) -> str:
        """Normalize common Ghidra-emitted constructs into more compilable C."""
        updated = source
        vector128_names = set(
            re.findall(r"\bundefined1\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[16\];", source)
        )
        byte_array_names = set(
            re.findall(
                r"\bundefined1\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[(?:9|10|11|12|13|14|15)\];", source
            )
        )
        indexed_vector_names = {
            name for name in vector128_names if re.search(rf"\b{re.escape(name)}\[[^\]]+\]", source)
        }
        byte_vector64_names = set(
            re.findall(r"\bundefined1\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[8\];", source)
        )

        def replace_vector_declaration(match: re.Match[str]) -> str:
            name = match.group(1)
            if name in indexed_vector_names:
                return f"ghidra_vec128 {name};"
            return f"ghidra_uint128 {name};"

        def replace_vector_load(match: re.Match[str]) -> str:
            name, expr = match.groups()
            if name in indexed_vector_names:
                return match.group(0)
            return f"{name} = *(ghidra_uint128 *)({expr});"

        def replace_vector_store(match: re.Match[str]) -> str:
            expr, value = match.groups()
            if value.strip() in indexed_vector_names:
                return match.group(0)
            return f"*(ghidra_uint128 *)({expr}) = {value};"

        updated = re.sub(
            r"\bundefined1\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[16\];",
            replace_vector_declaration,
            updated,
        )
        updated = re.sub(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\*\(undefined1\s*\(\*\)\s*\[16\]\)\(((?:[^()]|\([^()]*\))*)\);",
            replace_vector_load,
            updated,
        )
        updated = re.sub(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\*\(undefined1\s*\(\*\)\s*\[16\]\)\s*([^;\n]+);",
            replace_vector_load,
            updated,
        )
        updated = re.sub(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\.whole\s*=\s*\*\s*([A-Za-z_][A-Za-z0-9_]*);",
            r"\1.whole = *(ghidra_uint128 *)(\2);",
            updated,
        )
        updated = re.sub(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\.whole\s*=\s*([A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]);",
            r"\1.whole = *(ghidra_uint128 *)(\2);",
            updated,
        )
        updated = re.sub(
            r"\*\(undefined1\s*\(\*\)\s*\[16\]\)\(((?:[^()]|\([^()]*\))*)\)\s*=\s*([^;\n]+);",
            replace_vector_store,
            updated,
        )
        updated = re.sub(
            r"\(undefined1\s+\[16\]\)\s*([^;\n,)]+)",
            r"GHIDRA_U128(\1)",
            updated,
        )
        updated = re.sub(
            r"\bundefined1\s+([A-Za-z_][A-Za-z0-9_]*)\s*\[8\];",
            lambda match: f"ghidra_vec64 {match.group(1)};",
            updated,
        )
        updated = re.sub(
            r"\(undefined1\s+\[8\]\)\s*([^;\n,)]+)",
            r"GHIDRA_U64(\1)",
            updated,
        )
        vector_value_types = self._extract_declared_variable_types(updated)
        vector_pointer_names = set(
            re.findall(
                r"\bundefined1\s*\(\s*\*\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\[16\]\s*;",
                updated,
            )
        )

        def replace_plain_vector_value_load(match: re.Match[str]) -> str:
            lhs, rhs = match.groups()
            lhs_type = vector_value_types.get(lhs, "")
            rhs_base_match = re.match(
                r"^\*?(?P<base>[A-Za-z_][A-Za-z0-9_]*)(?:\s*\[[^\]]+\])?$", rhs.strip()
            )
            rhs_base = rhs_base_match.group("base") if rhs_base_match else ""
            rhs_is_vector_ptr = bool(rhs_base and rhs_base in vector_pointer_names)
            if " ".join(lhs_type.split()) != "ghidra_uint128":
                return match.group(0)
            if not rhs_is_vector_ptr:
                return match.group(0)
            return f"{lhs} = *(ghidra_uint128 *)({rhs});"

        updated = re.sub(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\*[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\])\s*;",
            replace_plain_vector_value_load,
            updated,
        )
        updated = re.sub(
            r"\b((?:_{2,3})xmm_[0-9A-Fa-f]+)\s*\[([^\]]+)\]",
            r"((const ghidra_vec128 *)&\1)->bytes[\2]",
            updated,
        )
        for name in sorted(indexed_vector_names):
            updated = re.sub(
                rf"\b{name}\[([^\]]+)\]",
                rf"{name}.bytes[\1]",
                updated,
            )
        for name in sorted(byte_vector64_names):
            updated = re.sub(
                rf"\b{name}\[([^\]]+)\]",
                rf"{name}.bytes[\1]",
                updated,
            )
        updated = self._rewrite_vector_whole_value_uses(
            updated, indexed_vector_names, "ghidra_vec128"
        )
        updated = self._rewrite_vector_whole_value_uses(
            updated, byte_vector64_names, "ghidra_vec64"
        )
        updated = self._rewrite_split_local_aliases(
            updated, indexed_vector_names | byte_vector64_names
        )
        updated = self._restore_prefixed_local_aliases(updated)
        updated = self._normalize_undeclared_split_locals(updated)
        updated = self._declare_fragment_base_aliases(updated)
        updated = self._rewrite_illegal_array_cast_assignments(updated)
        updated = self._relax_readonly_local_pointer_declarations(updated)
        updated = re.sub(
            r"(^\s*)code\s+([A-Za-z_][A-Za-z0-9_]*)\s*;$",
            r"\1code *\2;",
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(r"\(code\)\s*", "(code *)", updated)
        updated = re.sub(r"\*\(code \*\)\s*([^=;\n]+?)\s*=", r"*(code **)\1 =", updated)
        updated = re.sub(
            r"(?m)^(?P<indent>\s*)\(\(code \*\)(?P<base>.+?)\)\[(?P<index>[^\]]+)\]\s*=\s*\(code \*\)(?P<value>0x[0-9A-Fa-f]+|\d+)\s*;",
            r"\g<indent>((byte *)\g<base>)[\g<index>] = \g<value>;",
            updated,
        )
        updated = self._normalize_code_pointer_byte_uses(updated)
        updated = self._normalize_large_integer_split_aliases(updated)
        updated = self._normalize_large_integer_value_uses(updated)
        updated = self._normalize_large_integer_arguments_for_scalar_params(updated)
        updated = self._normalize_struct_arguments_for_byte_pointer_params(updated)
        updated = self._normalize_data_symbol_arguments_for_pointer_params(updated)
        updated = self._normalize_integer_arguments_for_pointer_params(updated)
        updated = re.sub(
            r"WakeByAddressSingle\((?P<expr>.+)\);",
            r"WakeByAddressSingle((PVOID)\g<expr>);",
            updated,
        )
        updated = self._normalize_pointer_switch_expressions(updated)
        updated = self._normalize_generated_indirect_calls(updated)
        updated = re.sub(
            r"(?m)^(?P<head>\s*case\s+(?:'(?:\\.|[^'\\])+'|0x[0-9A-Fa-f]+|-?\d+|[A-Za-z_][A-Za-z0-9_]*))_\s*$",
            r"\g<head>:",
            updated,
        )
        updated = re.sub(r"(?m)^(?P<indent>\s*default)_\s*$", r"\g<indent>:", updated)
        updated = re.sub(
            r"(?m)^(?P<label>\s*(?:switchD_[A-Za-z0-9_]+|LAB_[A-Za-z0-9_]+))_\s*$",
            r"\g<label>:",
            updated,
        )
        updated = self._join_wrapped_sanitized_call_identifiers(updated)
        updated = self._balance_unclosed_ghidra_u64_calls(updated)
        updated = re.sub(
            r"GHIDRA_U64\(\(\((longlong)\)\)([A-Za-z_][A-Za-z0-9_\.]*)",
            r"GHIDRA_U64((\1)\2",
            updated,
        )
        for name in sorted(byte_array_names, key=len, reverse=True):
            updated = re.sub(
                rf"\b(SUB158|SUB1510|SUB1512)\(\s*{re.escape(name)}\s*<<\s*([^,]+),\s*([^)]+)\)",
                rf"\1(GHIDRA_U128({name}) << \2,\3)",
                updated,
            )
        variable_types = self._extract_declared_variable_types(updated)
        updated = re.sub(
            r"\(double\)\s*(\*?[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)",
            lambda match: self._rewrite_pointer_double_cast(match, variable_types),
            updated,
        )
        if normalize_pointer_assignments:
            updated = self._normalize_pointer_integer_assignments(updated)
            updated = self._retarget_non_code_pointer_cast_assignments(updated)
        return updated

    def _restore_prefixed_local_aliases(self, source: str) -> str:
        """Rewrite bogus leading-underscore local aliases back to declared local names."""
        variable_types = self._extract_declared_variable_types(source)
        lines, starts = self._get_source_lines_and_starts(source)

        def replace_prefixed_local(match: re.Match[str]) -> str:
            base_name = match.group("name")
            position = match.start()
            boundary_index = self._get_enclosing_function_boundary_index(source, position)
            if boundary_index is None:
                return match.group(0)
            local_types = dict(
                self._get_function_parameter_types_at_boundary(source, boundary_index)
            )
            local_types.update(
                self._get_function_local_declarations_at_boundary(source, boundary_index)
            )
            local_types.update(variable_types)
            if base_name not in local_types:
                return match.group(0)
            line_index = max(0, bisect_right(starts, min(max(position, 0), len(source))) - 1)
            if not (0 <= line_index < len(lines)):
                return match.group(0)
            stripped = lines[line_index].strip()
            if stripped.startswith(("typedef ", "#")):
                return match.group(0)
            return base_name

        return re.sub(
            r"\b_(?P<name>(?:local|[A-Za-z]+Stack)_[A-Za-z0-9_]+)\b",
            replace_prefixed_local,
            source,
        )

    def _normalize_undeclared_split_locals(self, source: str) -> str:
        """Declare and rewrite bare split-local aliases that remain undeclared after alias restoration."""
        variable_types = self._extract_declared_variable_types(source)
        lines = source.splitlines()
        assignment_pattern = re.compile(
            r"^(?P<indent>\s*)_(?P<name>(?:local|[A-Za-z]+Stack)_[A-Za-z0-9_]+)\s*="
        )
        declarations_to_insert: Dict[int, List[str]] = {}

        for index, line in enumerate(lines):
            match = assignment_pattern.match(line)
            if not match:
                continue
            name = match.group("name")
            if name in variable_types:
                lines[index] = re.sub(rf"\b_{re.escape(name)}\b", name, line)
                continue
            indent = match.group("indent")
            declaration = f"{indent}uint64_t {name};"
            declarations = declarations_to_insert.setdefault(index, [])
            if declaration not in declarations:
                declarations.append(declaration)
            lines[index] = re.sub(rf"\b_{re.escape(name)}\b", name, line)
            variable_types[name] = "uint64_t"

        if not declarations_to_insert:
            return "\n".join(lines)

        updated_lines: List[str] = []
        for index, line in enumerate(lines):
            for declaration in declarations_to_insert.get(index, []):
                updated_lines.append(declaration)
            updated_lines.append(line)
        return "\n".join(updated_lines)

    def _declare_fragment_base_aliases(self, source: str) -> str:
        """Declare bare variables for split-fragment aliases when Ghidra only emitted fragment names."""
        lines = source.splitlines()
        fragment_decl_pattern = re.compile(
            r"^(?P<indent>\s*)(?P<storage>static\s+)?uint64_t\s+"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*_[0-9A-Fa-f]+(?:_[0-9]+){1,}_)"
            r"\s*=\s*0\s*;"
        )
        variable_types = self._extract_declared_variable_types(source)
        declarations_to_insert: Dict[int, List[str]] = {}

        for index, line in enumerate(lines):
            match = fragment_decl_pattern.match(line)
            if not match:
                continue
            fragment_name = match.group("name")
            base_name = self._get_split_fragment_base_name(fragment_name)
            if not base_name or base_name in variable_types:
                continue
            if not re.search(rf"\b{re.escape(base_name)}\b", source):
                continue
            indent = match.group("indent")
            declaration = f"{indent}volatile uint64_t {base_name} = 0;"
            declarations = declarations_to_insert.setdefault(index + 1, [])
            if declaration not in declarations:
                declarations.append(declaration)
            variable_types[base_name] = "volatile uint64_t"

        if not declarations_to_insert:
            return source

        updated_lines: List[str] = []
        for index, line in enumerate(lines):
            updated_lines.append(line)
            for declaration in declarations_to_insert.get(index + 1, []):
                updated_lines.append(declaration)
        return "\n".join(updated_lines)

    def _rewrite_illegal_array_cast_assignments(self, source: str) -> str:
        """Rewrite illegal array-cast assignments into memcpy for local buffers."""
        byte_arrays = {
            match.group("name"): int(match.group("size"))
            for match in re.finditer(
                r"(?m)^\s*(?:char|undefined1)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[(?P<size>\d+)\]\s*;$",
                source,
            )
        }

        def replace_assignment(match: re.Match[str]) -> str:
            lhs = match.group("lhs")
            rhs = match.group("rhs")
            size = int(match.group("size"))
            if byte_arrays.get(lhs) != size:
                return match.group(0)
            return f"{match.group('indent')}memcpy({lhs}, &{rhs}, {size});"

        return re.sub(
            r"(?m)^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\((?:char|undefined1)\s*\[\s*(?P<size>\d+)\s*\]\)\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*(?:\s*\[[^\]]+\])?)\s*;$",
            replace_assignment,
            source,
        )

    def _relax_readonly_local_pointer_declarations(self, source: str) -> str:
        """Widen readonly local pointer aliases when later code writes through them."""
        alias_map = {
            "LPCWSTR": "LPWSTR",
            "LPCSTR": "LPSTR",
            "LPCVOID": "LPVOID",
        }
        writable_names = {
            name
            for match in re.finditer(
                r"(?m)(?:^\s*\*(?P<deref_name>[A-Za-z_][A-Za-z0-9_]*)\s*=|"
                r"^\s*(?P<indexed_name>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\]\s*=|"
                r"memset\(\s*(?P<memset_name>[A-Za-z_][A-Za-z0-9_]*)\b|"
                r"\b(?P<inline_indexed_name>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\]\s*=|"
                r"\*(?P<inline_deref_name>[A-Za-z_][A-Za-z0-9_]*)\s*=)",
                source,
            )
            for name in match.groups()
            if name
        }

        updated = source
        for readonly_type, writable_type in alias_map.items():
            updated = re.sub(
                rf"(?m)^(?P<indent>\s*){re.escape(readonly_type)}\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*;$",
                lambda match: (
                    f"{match.group('indent')}{writable_type} {match.group('name')};"
                    if match.group("name") in writable_names
                    else match.group(0)
                ),
                updated,
            )
        return updated

    def _normalize_pointer_switch_expressions(self, source: str) -> str:
        """Cast pointer-typed switch subjects and case labels through uintptr_t."""
        variable_types = self._extract_declared_variable_types(source)

        def replace_switch(match: re.Match[str]) -> str:
            expression = match.group("expr").strip()
            if expression.startswith("(uintptr_t)"):
                return match.group(0)
            inferred_type = self._infer_expression_declared_type(expression, variable_types)
            if not self._is_pointer_declared_type(inferred_type):
                return match.group(0)
            return f"switch((uintptr_t){expression}) {{"

        updated = re.sub(
            r"switch\((?P<expr>[^)\n]+)\)\s*\{",
            replace_switch,
            source,
        )
        updated = re.sub(
            r"case\s+\([A-Za-z_][A-Za-z0-9_\s\*]*\*\)\s*(0x[0-9A-Fa-f]+|\d+):",
            r"case \1:",
            updated,
        )
        return updated

    def _normalize_large_integer_split_aliases(self, source: str) -> str:
        """Restore sanitized LARGE_INTEGER and split-struct field aliases to compilable access forms."""
        variable_types = self._extract_declared_variable_types(source)
        for boundary_index in self._get_function_boundary_indices(source):
            variable_types.update(
                self._get_function_parameter_types_at_boundary(source, boundary_index)
            )
        large_integer_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) == "LARGE_INTEGER"
        }
        large_integer_array_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()).startswith("LARGE_INTEGER[")
        }
        struct19_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) == "_struct_19"
        }
        large_integer_pointer_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) == "LARGE_INTEGER *"
        }
        context_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) in {"_CONTEXT", "CONTEXT"}
        }
        context_pointer_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) in {"_CONTEXT *", "CONTEXT *", "PCONTEXT"}
        }
        security_attributes_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) in {"_SECURITY_ATTRIBUTES", "SECURITY_ATTRIBUTES"}
        }
        security_attributes_pointer_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split())
            in {"_SECURITY_ATTRIBUTES *", "SECURITY_ATTRIBUTES *", "LPSECURITY_ATTRIBUTES"}
        }
        filetime_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) == "FILETIME"
        }
        filetime_pointer_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) == "FILETIME *"
        }
        by_handle_file_information_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split())
            in {"_BY_HANDLE_FILE_INFORMATION", "BY_HANDLE_FILE_INFORMATION"}
        }
        by_handle_file_information_pointer_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split())
            in {
                "_BY_HANDLE_FILE_INFORMATION *",
                "BY_HANDLE_FILE_INFORMATION *",
                "LPBY_HANDLE_FILE_INFORMATION",
            }
        }
        console_screen_buffer_info_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split())
            in {"_CONSOLE_SCREEN_BUFFER_INFO", "CONSOLE_SCREEN_BUFFER_INFO"}
        }
        console_screen_buffer_info_pointer_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split())
            in {
                "_CONSOLE_SCREEN_BUFFER_INFO *",
                "CONSOLE_SCREEN_BUFFER_INFO *",
                "PCONSOLE_SCREEN_BUFFER_INFO",
            }
        }
        console_readconsole_control_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split())
            in {"_CONSOLE_READCONSOLE_CONTROL", "CONSOLE_READCONSOLE_CONTROL"}
        }

        def replace_split_alias(match: re.Match[str]) -> str:
            token = match.group("token")
            name = ""
            suffix = ""
            for candidate_suffix in (
                "ftCreationTime_dwLowDateTime",
                "ftCreationTime_dwHighDateTime",
                "ftLastAccessTime_dwLowDateTime",
                "ftLastAccessTime_dwHighDateTime",
                "ftLastWriteTime_dwLowDateTime",
                "ftLastWriteTime_dwHighDateTime",
                "s_LowPart",
                "s_HighPart",
                "QuadPart",
                "LowPart",
                "HighPart",
                "s",
                "P1Home",
                "P2Home",
                "P3Home",
                "P4Home",
                "Rip",
                "Rsp",
                "nLength",
                "lpSecurityDescriptor",
                "bInheritHandle",
                "dwLowDateTime",
                "dwHighDateTime",
                "dwFileAttributes",
                "dwVolumeSerialNumber",
                "nFileSizeHigh",
                "nFileSizeLow",
                "nNumberOfLinks",
                "nFileIndexHigh",
                "nFileIndexLow",
                "dwSize_X",
                "dwSize_Y",
                "dwCursorPosition_X",
                "dwCursorPosition_Y",
                "wAttributes",
                "srWindow_Left",
                "srWindow_Top",
                "srWindow_Right",
                "srWindow_Bottom",
                "dwMaximumWindowSize_X",
                "dwMaximumWindowSize_Y",
                "nInitialChars",
                "dwCtrlWakeupMask",
                "dwControlKeyState",
            ):
                marker = f"_{candidate_suffix}"
                if token.endswith(marker):
                    name = token[: -len(marker)]
                    suffix = candidate_suffix
                    break
            if not name:
                return token
            if name in large_integer_names:
                if suffix == "QuadPart":
                    return f"((LARGE_INTEGER *)&{name})->QuadPart"
                if suffix == "s_LowPart":
                    return f"((_struct_19 *)&{name})->LowPart"
                if suffix == "s_HighPart":
                    return f"((_struct_19 *)&{name})->HighPart"
                if suffix == "s":
                    return f"(*(_struct_19 *)&{name})"
            if name in struct19_names:
                if suffix == "LowPart":
                    return f"({name}).LowPart"
                if suffix == "HighPart":
                    return f"({name}).HighPart"
            if name in large_integer_pointer_names and suffix == "QuadPart":
                return f"((LARGE_INTEGER *){name})->QuadPart"
            if name in context_names and suffix in {
                "P1Home",
                "P2Home",
                "P3Home",
                "P4Home",
                "Rip",
                "Rsp",
            }:
                return f"({name}).{suffix}"
            if name in context_pointer_names and suffix in {
                "P1Home",
                "P2Home",
                "P3Home",
                "P4Home",
                "Rip",
                "Rsp",
            }:
                return f"({name})->{suffix}"
            if name in security_attributes_names and suffix in {
                "nLength",
                "lpSecurityDescriptor",
                "bInheritHandle",
            }:
                return f"({name}).{suffix}"
            if name in security_attributes_pointer_names and suffix in {
                "nLength",
                "lpSecurityDescriptor",
                "bInheritHandle",
            }:
                return f"({name})->{suffix}"
            if name in filetime_names and suffix in {"dwLowDateTime", "dwHighDateTime"}:
                return f"({name}).{suffix}"
            if name in filetime_pointer_names and suffix in {"dwLowDateTime", "dwHighDateTime"}:
                return f"({name})->{suffix}"
            if name in by_handle_file_information_names:
                if suffix in {
                    "dwFileAttributes",
                    "dwVolumeSerialNumber",
                    "nFileSizeHigh",
                    "nFileSizeLow",
                    "nNumberOfLinks",
                    "nFileIndexHigh",
                    "nFileIndexLow",
                }:
                    return f"({name}).{suffix}"
                if suffix.startswith(("ftCreationTime_", "ftLastAccessTime_", "ftLastWriteTime_")):
                    outer, inner = suffix.split("_", 1)
                    return f"({name}).{outer}.{inner}"
            if name in by_handle_file_information_pointer_names:
                if suffix in {
                    "dwFileAttributes",
                    "dwVolumeSerialNumber",
                    "nFileSizeHigh",
                    "nFileSizeLow",
                    "nNumberOfLinks",
                    "nFileIndexHigh",
                    "nFileIndexLow",
                }:
                    return f"({name})->{suffix}"
                if suffix.startswith(("ftCreationTime_", "ftLastAccessTime_", "ftLastWriteTime_")):
                    outer, inner = suffix.split("_", 1)
                    return f"({name})->{outer}.{inner}"
            if name in console_screen_buffer_info_names:
                if suffix.startswith(("dwSize_", "dwCursorPosition_", "dwMaximumWindowSize_")):
                    outer, inner = suffix.split("_", 1)
                    return f"({name}).{outer}.{inner}"
                if suffix.startswith("srWindow_"):
                    _, inner = suffix.split("_", 1)
                    return f"({name}).srWindow.{inner}"
                if suffix == "wAttributes":
                    return f"({name}).wAttributes"
            if name in console_screen_buffer_info_pointer_names:
                if suffix.startswith(("dwSize_", "dwCursorPosition_", "dwMaximumWindowSize_")):
                    outer, inner = suffix.split("_", 1)
                    return f"({name})->{outer}.{inner}"
                if suffix.startswith("srWindow_"):
                    _, inner = suffix.split("_", 1)
                    return f"({name})->srWindow.{inner}"
                if suffix == "wAttributes":
                    return f"({name})->wAttributes"
            if name in console_readconsole_control_names and suffix in {
                "nLength",
                "nInitialChars",
                "dwCtrlWakeupMask",
                "dwControlKeyState",
            }:
                return f"({name}).{suffix}"
            return match.group(0)

        updated = re.sub(
            r"\b(?P<token>[A-Za-z_][A-Za-z0-9_]*_(?:QuadPart|s_LowPart|s_HighPart|s|LowPart|HighPart|P1Home|P2Home|P3Home|P4Home|Rip|Rsp|nLength|nInitialChars|lpSecurityDescriptor|bInheritHandle|dwLowDateTime|dwHighDateTime|dwFileAttributes|dwVolumeSerialNumber|nFileSizeHigh|nFileSizeLow|nNumberOfLinks|nFileIndexHigh|nFileIndexLow|ftCreationTime_dwLowDateTime|ftCreationTime_dwHighDateTime|ftLastAccessTime_dwLowDateTime|ftLastAccessTime_dwHighDateTime|ftLastWriteTime_dwLowDateTime|ftLastWriteTime_dwHighDateTime|dwSize_X|dwSize_Y|dwCursorPosition_X|dwCursorPosition_Y|wAttributes|srWindow_Left|srWindow_Top|srWindow_Right|srWindow_Bottom|dwMaximumWindowSize_X|dwMaximumWindowSize_Y|dwCtrlWakeupMask|dwControlKeyState))\b",
            replace_split_alias,
            source,
        )
        updated = re.sub(
            r"(?P<expr>(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\])_QuadPart\b",
            lambda match: (
                f"{match.group('expr')}.QuadPart"
                if match.group("name") in large_integer_array_names
                else match.group(0)
            ),
            updated,
        )

        updated = re.sub(
            r"(?P<expr>\(\(LARGE_INTEGER \*\)[^;\n]+?\)\[[^\]]+\])_s\b",
            r"(*(_struct_19 *)&\g<expr>)",
            updated,
        )
        return updated

    def _normalize_large_integer_value_uses(self, source: str) -> str:
        """Scalarize LARGE_INTEGER locals in expression contexts while preserving aggregate stores."""
        global_types: Dict[str, str] = {}
        local_types: Dict[str, str] = {}
        variable_types: Dict[str, str] = {}
        large_integer_names: set[str] = set()
        type_cache_dirty = True
        brace_depth = 0
        updated_lines: List[str] = []
        token_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
        line_to_boundary = self._get_line_to_boundary_index_map(source)
        active_boundary: Optional[int] = None

        def refresh_type_caches() -> None:
            nonlocal variable_types, large_integer_names, type_cache_dirty
            if not type_cache_dirty:
                return
            variable_types = {**global_types, **local_types}
            large_integer_names = {
                name
                for name, declared_type in variable_types.items()
                if " ".join(declared_type.split()) == "LARGE_INTEGER"
            }
            type_cache_dirty = False

        for line_index, line in enumerate(source.splitlines()):
            rewritten = line
            stripped = line.strip()
            current_boundary = (
                line_to_boundary[line_index] if line_index < len(line_to_boundary) else None
            )
            if current_boundary != active_boundary:
                active_boundary = current_boundary
                local_types = (
                    dict(self._get_function_parameter_types_at_boundary(source, current_boundary))
                    if current_boundary is not None
                    else {}
                )
                type_cache_dirty = True
            if (
                brace_depth == 0
                and "(" in stripped
                and ")" in stripped
                and stripped.endswith("{")
                and "=" not in stripped
                and not stripped.startswith(("#", "if", "for", "while", "switch"))
            ):
                local_types = (
                    dict(self._get_function_parameter_types_at_boundary(source, current_boundary))
                    if current_boundary is not None
                    else {}
                )
                type_cache_dirty = True
            declarations = self._extract_declared_variable_types_from_line(line)
            if declarations:
                if brace_depth == 0:
                    global_types.update(declarations)
                else:
                    local_types.update(declarations)
                type_cache_dirty = True
            refresh_type_caches()
            if stripped.startswith("LARGE_INTEGER "):
                updated_lines.append(rewritten)
                brace_depth += line.count("{") - line.count("}")
                continue

            rewritten = re.sub(
                r"(?P<expr>\(\(LARGE_INTEGER \*\)[^;\n]+?\)\[[^\]]+\])_QuadPart\b",
                r"\g<expr>.QuadPart",
                rewritten,
            )
            rewritten = re.sub(
                r"\(\*\(_struct_19 \*\)&(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\)\s*=\s*\*\(\*\(_struct_19 \*\)&(?P<rhs>[A-Za-z_][A-Za-z0-9_]*)\)",
                r"(*(_struct_19 *)&\g<lhs>) = (*(_struct_19 *)&\g<rhs>)",
                rewritten,
            )
            rewritten = re.sub(
                r"\(\*\(_struct_19 \*\)&(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\)\s*=\s*\(_struct_19\)(?P<rhs>[A-Za-z_][A-Za-z0-9_]*\([^;\n]*\))",
                lambda match: (
                    f"((LARGE_INTEGER *)&{match.group('lhs')})->QuadPart = {match.group('rhs')}"
                    if self._infer_expression_declared_type(match.group("lhs"), variable_types)
                    == "LARGE_INTEGER"
                    else match.group(0)
                ),
                rewritten,
            )
            rewritten = re.sub(
                r"\(LARGE_INTEGER\)\s*([A-Za-z_][A-Za-z0-9_]*\([^;\n]*\))",
                lambda match: (
                    match.group(1)
                    if self._infer_expression_declared_type(match.group(1), variable_types)
                    == "LARGE_INTEGER"
                    else f"GHIDRA_U64({match.group(1)})"
                ),
                rewritten,
            )
            rewritten = re.sub(
                r"\(LARGE_INTEGER\)\s*(0x[0-9A-Fa-f]+|\d+|[A-Za-z_][A-Za-z0-9_]*)",
                lambda match: (
                    match.group(1)
                    if self._infer_expression_declared_type(match.group(1), variable_types)
                    == "LARGE_INTEGER"
                    else f"GHIDRA_U64({match.group(1)})"
                ),
                rewritten,
            )
            rewritten = re.sub(
                r"\(LARGE_INTEGER\)\s*(\(\([^;\n]+?\)->QuadPart\)|\([^;\n]+?\))",
                lambda match: (
                    match.group(1)
                    if self._infer_expression_declared_type(match.group(1), variable_types)
                    == "LARGE_INTEGER"
                    else f"GHIDRA_U64({match.group(1)})"
                ),
                rewritten,
            )
            rewritten = rewritten.replace("((LARGE_INTEGER *))", "((LARGE_INTEGER *)")
            rewritten = re.sub(
                r"GHIDRA_U64\((?P<expr>\(\(LARGE_INTEGER \*\)[^;\n]+->QuadPart)(?P<suffix>\);|;)",
                lambda match: f"GHIDRA_U64({match.group('expr')}){match.group('suffix')}",
                rewritten,
            )
            rewritten = re.sub(
                r"GHIDRA_LARGE_INTEGER\((?P<expr>[A-Za-z_][A-Za-z0-9_]*)\)",
                lambda match: (
                    match.group("expr")
                    if self._infer_expression_declared_type(match.group("expr"), variable_types)
                    == "LARGE_INTEGER"
                    else match.group(0)
                ),
                rewritten,
            )
            rewritten = re.sub(
                r"GHIDRA_U64\((?P<expr>[A-Za-z_][A-Za-z0-9_]*)\)",
                lambda match: (
                    f"GHIDRA_U64(((LARGE_INTEGER *)&{match.group('expr')})->QuadPart)"
                    if self._infer_expression_declared_type(match.group("expr"), variable_types)
                    == "LARGE_INTEGER"
                    else match.group(0)
                ),
                rewritten,
            )
            rewritten = re.sub(
                r"GHIDRA_U64\(\(\*\(_struct_19 \*\)\)&(?P<name>[A-Za-z_][A-Za-z0-9_]*)\)",
                lambda match: (
                    f"GHIDRA_U64(((LARGE_INTEGER *)&{match.group('name')})->QuadPart)"
                    if self._infer_expression_declared_type(match.group("name"), variable_types)
                    == "LARGE_INTEGER"
                    else match.group(0)
                ),
                rewritten,
            )
            rewritten = re.sub(
                r"GHIDRA_U64\(\(\*\(_struct_19 \*\)\)\s*&(?P<name>[A-Za-z_][A-Za-z0-9_]*)\)",
                lambda match: (
                    f"GHIDRA_U64(((LARGE_INTEGER *)&{match.group('name')})->QuadPart)"
                    if self._infer_expression_declared_type(match.group("name"), variable_types)
                    == "LARGE_INTEGER"
                    else match.group(0)
                ),
                rewritten,
            )

            line_large_integer_names = large_integer_names.intersection(
                token_pattern.findall(rewritten)
            )
            for name in sorted(line_large_integer_names, key=len, reverse=True):
                rewritten = re.sub(
                    rf"\((?P<cast>[^)]+)\)\s*{re.escape(name)}\b",
                    lambda match: (
                        match.group(0)
                        if match.group("cast").strip() == "LARGE_INTEGER"
                        else f"({match.group('cast')})((LARGE_INTEGER *)&{name})->QuadPart"
                    ),
                    rewritten,
                )
                rewritten = re.sub(
                    rf"(?<![A-Za-z0-9_&])\b{re.escape(name)}\b(?=\s*(?:!=|==|<=|>=|<|>))",
                    rf"((LARGE_INTEGER *)&{name})->QuadPart",
                    rewritten,
                )
                rewritten = re.sub(
                    rf"\((?P<cast>LPVOID|LPWSTR|HANDLE|HMODULE|void \*|byte \*)\)\s*{re.escape(name)}\b",
                    rf"(\g<cast>)((LARGE_INTEGER *)&{name})->QuadPart",
                    rewritten,
                )

            bare_assignment_match = re.match(
                r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[^;]+);$",
                rewritten,
            )
            if bare_assignment_match:
                lhs = bare_assignment_match.group("lhs")
                lhs_type = variable_types.get(lhs, "")
                rhs = bare_assignment_match.group("rhs").strip()
                if " ".join(lhs_type.split()) == "LARGE_INTEGER" and not rhs.startswith(
                    "GHIDRA_LARGE_INTEGER("
                ):
                    rhs_type = self._infer_expression_declared_type(rhs, variable_types)
                    if " ".join(rhs_type.split()) != "LARGE_INTEGER":
                        rewritten = f"{bare_assignment_match.group('indent')}{lhs} = GHIDRA_LARGE_INTEGER({rhs});"
                elif " ".join(lhs_type.split()) == "code *":
                    rhs_type = self._infer_expression_declared_type(rhs, variable_types)
                    if not self._is_pointer_declared_type(rhs_type) and not rhs.startswith(
                        "(code *)"
                    ):
                        rewritten = (
                            f"{bare_assignment_match.group('indent')}{lhs} = "
                            f"(code *)(uintptr_t)GHIDRA_U64({rhs});"
                        )

            store_match = re.match(
                r"^(?P<indent>\s*)(?P<lhs>\*\(LARGE_INTEGER \*\)[^=]+)\s*=\s*(?P<rhs>[^;]+);$",
                rewritten,
            )
            if store_match:
                rhs = store_match.group("rhs").strip()
                rhs_type = self._infer_expression_declared_type(rhs, variable_types)
                if " ".join(rhs_type.split()) != "LARGE_INTEGER" and not rhs.startswith(
                    "GHIDRA_LARGE_INTEGER("
                ):
                    rewritten = (
                        f"{store_match.group('indent')}{store_match.group('lhs')} = "
                        f"GHIDRA_LARGE_INTEGER({rhs});"
                    )

            broken_u64_statement_match = re.match(
                r"^(?P<head>\s*(?:return\s+|[^=;\n]+=\s*))GHIDRA_U64\((?P<expr>.+)\)\);$",
                rewritten,
            )
            if broken_u64_statement_match and not re.search(
                r"(?:\(\*\*\(code \*\*\)|\(\*\(ghidra_indirect_fn\s*\*\)).+\)\s*\(",
                broken_u64_statement_match.group("expr"),
            ):
                rewritten = (
                    f"{broken_u64_statement_match.group('head')}"
                    f"GHIDRA_U64({broken_u64_statement_match.group('expr')});"
                )

            large_integer_return_match = re.match(
                r"^(?P<indent>\s*)return\s+GHIDRA_U64\(\(\(LARGE_INTEGER \*\)\s*&(?P<name>[A-Za-z_][A-Za-z0-9_]*)\)->QuadPart\);$",
                rewritten,
            )
            if (
                large_integer_return_match
                and self._infer_expression_declared_type(
                    large_integer_return_match.group("name"), variable_types
                )
                == "LARGE_INTEGER"
            ):
                rewritten = f"{large_integer_return_match.group('indent')}return {large_integer_return_match.group('name')};"

            updated_lines.append(rewritten)
            brace_depth += line.count("{") - line.count("}")

        return "\n".join(updated_lines)

    def _extract_function_parameter_types(self, source: str) -> Dict[str, List[str]]:
        """Extract simple parameter type lists from function declarations and definitions."""
        signature_pattern = re.compile(
            r"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>[^)]*)\)\s*(?:;|\{)",
            re.MULTILINE,
        )
        parameter_types: Dict[str, List[str]] = {}
        for match in signature_pattern.finditer(source):
            extracted: List[str] = []
            for param in self._split_top_level_arguments(match.group("params")):
                stripped = param.strip()
                if not stripped:
                    continue
                if stripped in {"void", "..."}:
                    extracted.append(stripped)
                    continue
                declaration_match = self._match_variable_declaration(stripped)
                if declaration_match:
                    extracted.append(
                        f"{declaration_match.group('type').strip()}{declaration_match.group('array') or ''}".strip()
                    )
                else:
                    extracted.append(stripped)
            parameter_types.setdefault(match.group("name"), extracted)
        return parameter_types

    def _normalize_void_pointer_parameter_indexing(self, source: str) -> str:
        """Rewrite invalid indexing and dereference operations on `void *param_n` parameters."""

        def find_matching_delimiter(
            text: str, open_index: int, open_char: str, close_char: str
        ) -> int:
            depth = 0
            for index in range(open_index, len(text)):
                char = text[index]
                if char == open_char:
                    depth += 1
                elif char == close_char:
                    depth -= 1
                    if depth == 0:
                        return index
            return -1

        def rewrite_offset_indexing(line: str, name: str) -> str:
            pattern = re.compile(rf"\(\s*{re.escape(name)}\b")
            rewritten_parts: List[str] = []
            cursor = 0
            search_start = 0

            while True:
                match = pattern.search(line, search_start)
                if not match:
                    rewritten_parts.append(line[cursor:])
                    break

                open_paren = match.start()
                plus_index = match.end()
                while plus_index < len(line) and line[plus_index].isspace():
                    plus_index += 1
                if plus_index >= len(line) or line[plus_index] != "+":
                    search_start = match.start() + 1
                    continue

                close_paren = find_matching_delimiter(line, open_paren, "(", ")")
                if close_paren == -1:
                    rewritten_parts.append(line[cursor:])
                    break

                bracket_index = close_paren + 1
                while bracket_index < len(line) and line[bracket_index].isspace():
                    bracket_index += 1
                if bracket_index >= len(line) or line[bracket_index] != "[":
                    search_start = match.start() + 1
                    continue

                close_bracket = find_matching_delimiter(line, bracket_index, "[", "]")
                if close_bracket == -1:
                    rewritten_parts.append(line[cursor:])
                    break

                offset_expression = line[plus_index + 1 : close_paren].strip()
                index_expression = line[bracket_index + 1 : close_bracket].strip()
                rewritten_parts.append(line[cursor:open_paren])
                rewritten_parts.append(
                    f"(((uintptr_t *){name}) + {offset_expression})[{index_expression}]"
                )
                cursor = close_bracket + 1
                search_start = cursor

            return "".join(rewritten_parts)

        def extract_void_pointer_params(params: str) -> set[str]:
            names: set[str] = set()
            for param in self._split_top_level_arguments(params):
                declaration_match = self._match_variable_declaration(param.strip())
                if not declaration_match:
                    continue
                if " ".join(declaration_match.group("type").split()) == "void *":
                    names.add(declaration_match.group("name"))
            return names

        inline_signature_pattern = re.compile(
            r"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\((?P<params>[^)]*)\)\s*\{$"
        )
        multiline_signature_pattern = re.compile(
            r"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\((?P<params>[^)]*)\)\s*$"
        )
        signature_start_pattern = re.compile(
            r"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\((?P<params>.*)$"
        )

        pending_void_params: set[str] | None = None
        collecting_signature_params: List[str] | None = None
        active_void_params: set[str] = set()
        function_brace_depth = 0
        rewritten_lines: List[str] = []

        for line in source.splitlines():
            stripped = line.strip()
            inline_match = inline_signature_pattern.match(stripped)
            multiline_match = None
            is_signature_line = False
            if inline_match:
                active_void_params = extract_void_pointer_params(inline_match.group("params"))
                pending_void_params = None
                collecting_signature_params = None
                function_brace_depth = line.count("{") - line.count("}")
                is_signature_line = True
            elif collecting_signature_params is not None:
                collecting_signature_params.append(stripped)
                is_signature_line = True
                if ")" in stripped:
                    params_source = " ".join(collecting_signature_params).split(")", 1)[0]
                    pending_void_params = extract_void_pointer_params(params_source)
                    collecting_signature_params = None
                    if "{" in stripped:
                        active_void_params = pending_void_params
                        pending_void_params = None
                        function_brace_depth = line.count("{") - line.count("}")
            elif pending_void_params is not None:
                if stripped == "{":
                    active_void_params = pending_void_params
                    pending_void_params = None
                    function_brace_depth = line.count("{") - line.count("}")
                    is_signature_line = True
                elif stripped and not stripped.startswith(("//", "/*", "*")):
                    pending_void_params = None
            else:
                multiline_match = multiline_signature_pattern.match(stripped)
                if multiline_match:
                    pending_void_params = extract_void_pointer_params(
                        multiline_match.group("params")
                    )
                    is_signature_line = True
                else:
                    signature_start_match = signature_start_pattern.match(stripped)
                    if signature_start_match and ")" not in stripped:
                        collecting_signature_params = [signature_start_match.group("params")]
                        is_signature_line = True

            rewritten = line
            if (
                function_brace_depth > 0
                and active_void_params
                and not is_signature_line
                and stripped != "{"
            ):
                for name in sorted(active_void_params, key=len, reverse=True):
                    rewritten = rewrite_offset_indexing(rewritten, name)
                    rewritten = re.sub(
                        rf"\(\s*{re.escape(name)}\s*\+\s*(?P<offset>[^)\n]+)\)\s*\[(?P<index>[^\]]+)\]",
                        rf"(((uintptr_t *){name}) + \g<offset>)[\g<index>]",
                        rewritten,
                    )
                    rewritten = re.sub(
                        rf"(?<![A-Za-z0-9_])\*\s*{re.escape(name)}\b",
                        rf"*((uintptr_t *){name})",
                        rewritten,
                    )
                    rewritten = re.sub(
                        rf"\b{re.escape(name)}\s*\[(?P<index>[^\]]+)\]",
                        rf"((uintptr_t *){name})[\g<index>]",
                        rewritten,
                    )
            rewritten_lines.append(rewritten)
            if active_void_params:
                function_brace_depth += line.count("{") - line.count("}")
            if active_void_params and function_brace_depth <= 0:
                active_void_params = set()
                function_brace_depth = 0

        return "\n".join(rewritten_lines)

    def _collect_called_function_names(self, source: str) -> set[str]:
        """Return function names that appear to have at least one real call site in the source."""
        signature_pattern = re.compile(
            r"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>[^)]*)\)\s*(?:;|\{)",
            re.MULTILINE,
        )
        signature_counts: Dict[str, int] = {}
        for match in signature_pattern.finditer(source):
            name = match.group("name")
            signature_counts[name] = signature_counts.get(name, 0) + 1

        paren_counts: Dict[str, int] = {}
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", source):
            paren_counts[name] = paren_counts.get(name, 0) + 1

        return {
            name
            for name, paren_count in paren_counts.items()
            if paren_count > signature_counts.get(name, 0)
        }

    def _normalize_large_integer_arguments_for_scalar_params(self, source: str) -> str:
        """Scalarize bare LARGE_INTEGER call arguments when a prototype expects scalar values."""
        variable_types = self._extract_declared_variable_types(source)
        large_integer_names = {
            name
            for line in source.splitlines()
            for name, declared_type in self._extract_declared_variable_types_from_line(line).items()
            if " ".join(declared_type.split()) == "LARGE_INTEGER"
        }
        parameter_types = self._extract_function_parameter_types(source)
        called_function_names = self._collect_called_function_names(source)
        scalar_param_positions = {
            function_name: {
                index
                for index, param_type in enumerate(params)
                if self._is_integer_declared_type(param_type)
                or " ".join(param_type.split()) == "uintptr_t"
            }
            for function_name, params in parameter_types.items()
            if function_name in called_function_names
        }
        relevant_function_names = {
            function_name
            for function_name, positions in scalar_param_positions.items()
            if positions
        }
        replacements: List[tuple[int, int, str]] = []
        calls = self._collect_calls_for_names(source, relevant_function_names)
        for call in reversed(calls):
            function_name = str(call["name"])
            scalar_positions = scalar_param_positions.get(function_name, set())
            rewritten_args: List[str] = []
            changed = False
            for index, arg in enumerate(call["args"]):
                replacement = arg
                stripped_arg = arg.strip()
                if index in scalar_positions:
                    bare_identifier_match = re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", stripped_arg)
                    ghidra_u64_identifier_match = re.fullmatch(
                        r"GHIDRA_U64\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
                        stripped_arg,
                    )
                    large_integer_name = ""
                    if bare_identifier_match:
                        large_integer_name = stripped_arg
                    elif ghidra_u64_identifier_match:
                        large_integer_name = ghidra_u64_identifier_match.group(1)
                    if large_integer_name and large_integer_name in large_integer_names:
                        nearest_type = self._find_nearest_declared_variable_type(
                            source, large_integer_name, int(call["start"])
                        )
                        arg_type = nearest_type or variable_types.get(large_integer_name, "")
                        if " ".join(arg_type.split()) == "LARGE_INTEGER":
                            quadpart_expr = f"((LARGE_INTEGER *)&{large_integer_name})->QuadPart"
                            if bare_identifier_match:
                                replacement = quadpart_expr
                            else:
                                replacement = f"GHIDRA_U64({quadpart_expr})"
                            changed = True
                rewritten_args.append(replacement)
            if not changed:
                continue
            replacements.append(
                (
                    int(call["open_paren"]) + 1,
                    int(call["close_paren"]),
                    ", ".join(rewritten_args),
                )
            )
        updated = source
        for start, end, replacement in replacements:
            updated = updated[:start] + replacement + updated[end:]
        return updated

    def _normalize_struct_arguments_for_byte_pointer_params(self, source: str) -> str:
        """Rewrite aggregate _struct_19 call arguments to byte pointers when prototypes expect byte buffers."""
        parameter_types = self._extract_function_parameter_types(source)
        called_function_names = self._collect_called_function_names(source)
        byte_pointer_param_positions = {
            function_name: {
                index
                for index, param_type in enumerate(params)
                if " ".join(param_type.split()) == "byte *"
            }
            for function_name, params in parameter_types.items()
            if function_name in called_function_names
        }
        relevant_function_names = {
            function_name
            for function_name, positions in byte_pointer_param_positions.items()
            if positions
        }
        replacements: List[tuple[int, int, str]] = []
        calls = self._collect_calls_for_names(source, relevant_function_names)
        for call in reversed(calls):
            function_name = str(call["name"])
            byte_pointer_positions = byte_pointer_param_positions.get(function_name, set())
            rewritten_args: List[str] = []
            changed = False
            for index, arg in enumerate(call["args"]):
                replacement = arg
                stripped_arg = arg.strip()
                if index in byte_pointer_positions:
                    struct_alias_match = re.fullmatch(
                        r"\(\*\(_struct_19 \*\)&(?P<name>[A-Za-z_][A-Za-z0-9_]*)\)",
                        stripped_arg,
                    )
                    if struct_alias_match:
                        replacement = f"(byte *)&{struct_alias_match.group('name')}"
                        changed = True
                rewritten_args.append(replacement)
            if not changed:
                continue
            replacements.append(
                (
                    int(call["open_paren"]) + 1,
                    int(call["close_paren"]),
                    ", ".join(rewritten_args),
                )
            )
        updated = source
        for start, end, replacement in replacements:
            updated = updated[:start] + replacement + updated[end:]
        return updated

    def _normalize_data_symbol_arguments_for_pointer_params(self, source: str) -> str:
        """Cast raw data symbols when a call site passes them to pointer-typed parameters."""
        parameter_types = self._extract_function_parameter_types(source)
        known_parameter_types = {
            "memcpy": ["void *", "const void *", "size_t"],
            "memmove": ["void *", "const void *", "size_t"],
            "memcmp": ["const void *", "const void *", "size_t"],
        }
        for function_name, params in known_parameter_types.items():
            if function_name in source:
                parameter_types.setdefault(function_name, params)

        called_function_names = self._collect_called_function_names(source)
        called_function_names.update(name for name in known_parameter_types if name in source)
        pointer_param_positions = {
            function_name: {
                index
                for index, param_type in enumerate(params)
                if self._is_pointer_declared_type(param_type)
            }
            for function_name, params in parameter_types.items()
            if function_name in called_function_names
        }
        relevant_function_names = {
            function_name
            for function_name, positions in pointer_param_positions.items()
            if positions
        }
        data_symbol_pattern = re.compile(r"^(?:_?UNK|_?DAT|DAT)_[A-Za-z0-9_]+$")
        replacements: List[tuple[int, int, str]] = []
        calls = self._collect_calls_for_names(source, relevant_function_names)
        for call in reversed(calls):
            function_name = str(call["name"])
            params = parameter_types[function_name]
            pointer_positions = pointer_param_positions.get(function_name, set())
            rewritten_args: List[str] = []
            changed = False
            for index, arg in enumerate(call["args"]):
                replacement = arg
                stripped_arg = arg.strip()
                if (
                    index in pointer_positions
                    and data_symbol_pattern.fullmatch(stripped_arg)
                    and "(uintptr_t)" not in stripped_arg
                ):
                    replacement = f"({params[index]})(uintptr_t){stripped_arg}"
                    changed = True
                rewritten_args.append(replacement)
            if not changed:
                continue
            replacements.append(
                (
                    int(call["open_paren"]) + 1,
                    int(call["close_paren"]),
                    ", ".join(rewritten_args),
                )
            )
        updated = source
        for start, end, replacement in replacements:
            updated = updated[:start] + replacement + updated[end:]
        return updated

    def _normalize_integer_arguments_for_pointer_params(self, source: str) -> str:
        """Cast integer-valued expressions when call sites pass them to pointer-typed params."""
        variable_types = self._extract_declared_variable_types(source)
        parameter_types = self._extract_function_parameter_types(source)
        known_parameter_types = {
            "memcpy": ["void *", "const void *", "size_t"],
            "memmove": ["void *", "const void *", "size_t"],
            "memcmp": ["const void *", "const void *", "size_t"],
            "HeapFree": ["HANDLE", "DWORD", "LPVOID"],
        }
        for function_name, params in known_parameter_types.items():
            if function_name in source:
                parameter_types.setdefault(function_name, params)

        pointer_aliases = {
            "LPVOID",
            "PVOID",
            "HANDLE",
            "HMODULE",
            "LPWSTR",
            "LPCVOID",
            "LPCSTR",
            "LPCWSTR",
        }
        called_function_names = self._collect_called_function_names(source)
        called_function_names.update(name for name in known_parameter_types if name in source)
        pointer_param_positions = {
            function_name: {
                index
                for index, param_type in enumerate(params)
                if self._is_pointer_declared_type(param_type) or param_type in pointer_aliases
            }
            for function_name, params in parameter_types.items()
            if function_name in called_function_names
        }
        relevant_function_names = {
            function_name
            for function_name, positions in pointer_param_positions.items()
            if positions
        }
        bridge_read_pattern = re.compile(
            r"^(?:\*?\(\(uintptr_t \*\)\(uintptr_t\).+\)|\(\(uintptr_t \*\)\(uintptr_t\).+\)\[[^\]]+\])$"
        )
        replacements: List[tuple[int, int, str]] = []
        calls = self._collect_calls_for_names(source, relevant_function_names)
        for call in reversed(calls):
            function_name = str(call["name"])
            params = parameter_types[function_name]
            pointer_positions = pointer_param_positions.get(function_name, set())
            rewritten_args: List[str] = []
            changed = False
            for index, arg in enumerate(call["args"]):
                replacement = arg
                stripped_arg = arg.strip()
                is_bridge_read = bridge_read_pattern.match(stripped_arg) is not None
                if index in pointer_positions and (
                    "(uintptr_t)" not in stripped_arg or is_bridge_read
                ):
                    arg_type = variable_types.get(stripped_arg, "")
                    should_cast = (
                        self._is_integer_declared_type(arg_type)
                        or stripped_arg.startswith("GHIDRA_U64(")
                        or is_bridge_read
                    )
                    if should_cast:
                        replacement = f"({params[index]})(uintptr_t){stripped_arg}"
                        changed = True
                rewritten_args.append(replacement)
            if not changed:
                continue
            replacements.append(
                (
                    int(call["open_paren"]) + 1,
                    int(call["close_paren"]),
                    ", ".join(rewritten_args),
                )
            )
        updated = source
        for start, end, replacement in replacements:
            updated = updated[:start] + replacement + updated[end:]
        return updated

    def _rewrite_vector_whole_value_uses(
        self, source: str, vector_names: set[str], declaration_type: str
    ) -> str:
        """Rewrite bare vector names to `.whole` outside declarations and byte indexing."""
        if not vector_names:
            return source
        updated_lines: List[str] = []
        for line in source.splitlines():
            rewritten = line
            stripped = line.strip()
            for name in sorted(vector_names):
                if re.match(rf"^{re.escape(declaration_type)}\s+{re.escape(name)}\s*;$", stripped):
                    continue
                rewritten = re.sub(
                    rf"\b{re.escape(name)}\b(?!\s*(?:\[|\.))",
                    rf"{name}.whole",
                    rewritten,
                )
            updated_lines.append(rewritten)
        return "\n".join(updated_lines)

    def _rewrite_split_local_aliases(self, source: str, vector_names: set[str]) -> str:
        """Map undeclared underscore split-locals back onto declared vector base names."""
        updated = source
        for name in sorted(vector_names):
            updated = re.sub(rf"\b_{re.escape(name)}\b", rf"{name}.whole", updated)
        return updated

    def _normalize_generated_indirect_calls(self, source: str) -> str:
        """Rewrite Ghidra indirect `code` calls to permissive function-pointer casts."""
        updated = source

        def indirect_cast_name(args: str) -> str:
            return "ghidra_indirect_fn_0" if not args.strip() else "ghidra_indirect_fn"

        def skip_whitespace(position: int) -> int:
            while position < len(updated) and updated[position].isspace():
                position += 1
            return position

        def find_wrapper_close(start: int) -> tuple[Optional[str], Optional[int]]:
            expr_start = skip_whitespace(start)
            if expr_start >= len(updated):
                return None, None
            if updated[expr_start] == "(":
                expr_end = self._find_matching_paren(updated, expr_start)
                if expr_end == -1:
                    return None, None
                return updated[expr_start : expr_end + 1], expr_end + 1
            expr_end = expr_start
            paren_depth = 0
            bracket_depth = 0
            while expr_end < len(updated):
                char = updated[expr_end]
                if char == "(":
                    paren_depth += 1
                elif char == ")":
                    if paren_depth == 0 and bracket_depth == 0:
                        break
                    if paren_depth > 0:
                        paren_depth -= 1
                elif char == "[":
                    bracket_depth += 1
                elif char == "]" and bracket_depth > 0:
                    bracket_depth -= 1
                expr_end += 1
            if expr_end >= len(updated):
                return None, None
            return updated[expr_start:expr_end], expr_end

        def rewrite_pattern(prefix: str, builder) -> str:
            nonlocal updated
            result: List[str] = []
            index = 0
            prefix_len = len(prefix)
            while True:
                start = updated.find(prefix, index)
                if start == -1:
                    result.append(updated[index:])
                    break
                result.append(updated[index:start])
                expr_start = start + prefix_len
                depth = 0
                expr_end = expr_start
                while expr_end < len(updated):
                    char = updated[expr_end]
                    if char == "(":
                        depth += 1
                    elif char == ")":
                        if depth == 0:
                            break
                        depth -= 1
                    expr_end += 1
                if expr_end >= len(updated):
                    result.append(updated[start:])
                    break
                expr = updated[expr_start:expr_end]
                if prefix == "(**(code **)(":
                    first_close = skip_whitespace(expr_end)
                    if first_close >= len(updated) or updated[first_close] != ")":
                        result.append(updated[start : expr_end + 1])
                        index = expr_end + 1
                        continue
                    second_close = skip_whitespace(first_close + 1)
                    if second_close >= len(updated) or updated[second_close] != ")":
                        index = expr_end + 1
                        continue
                    open_paren = skip_whitespace(second_close + 1)
                    if open_paren >= len(updated) or updated[open_paren] != "(":
                        result.append(updated[start : expr_end + 1])
                        index = expr_end + 1
                        continue
                    args_start = open_paren + 1
                else:
                    open_paren = skip_whitespace(expr_end + 1)
                    if open_paren >= len(updated) or updated[open_paren] != "(":
                        result.append(updated[start : expr_end + 1])
                        index = expr_end + 1
                        continue
                    args_start = open_paren + 1
                args_depth = 0
                args_end = args_start
                while args_end < len(updated):
                    char = updated[args_end]
                    if char == "(":
                        args_depth += 1
                    elif char == ")":
                        if args_depth == 0:
                            break
                        args_depth -= 1
                    args_end += 1
                if args_end >= len(updated):
                    result.append(updated[start:])
                    break
                args = updated[args_start:args_end]
                result.append(builder(expr, args))
                index = args_end + 1
            updated = "".join(result)
            return updated

        rewrite_pattern(
            "(*(code *)",
            lambda expr, args: f"(({indirect_cast_name(args)}){expr})({args})",
        )
        rewrite_pattern(
            "(**(code **)(",
            lambda expr, args: f"(*({indirect_cast_name(args)} *)({expr}))({args})",
        )
        rewrite_pattern(
            "(**(code **)",
            lambda expr, args: f"(*({indirect_cast_name(args)} *){expr})({args})",
        )
        result: List[str] = []
        index = 0
        prefix = "(**(code **)"
        while True:
            start = updated.find(prefix, index)
            if start == -1:
                result.append(updated[index:])
                break
            result.append(updated[index:start])
            expr, wrapper_close = find_wrapper_close(start + len(prefix))
            if expr is None or wrapper_close is None:
                result.append(updated[start:])
                break
            wrapper_close = skip_whitespace(wrapper_close)
            if wrapper_close >= len(updated) or updated[wrapper_close] != ")":
                result.append(
                    updated[start : wrapper_close if wrapper_close is not None else len(updated)]
                )
                index = wrapper_close if wrapper_close is not None else len(updated)
                continue
            open_paren = skip_whitespace(wrapper_close + 1)
            if open_paren >= len(updated) or updated[open_paren] != "(":
                result.append(updated[start : wrapper_close + 1])
                index = wrapper_close + 1
                continue
            args_close = self._find_matching_paren(updated, open_paren)
            if args_close == -1:
                result.append(updated[start:])
                break
            args = updated[open_paren + 1 : args_close]
            result.append(f"(*({indirect_cast_name(args)} *){expr})({args})")
            index = args_close + 1
        updated = "".join(result)
        rewritten_lines: list[str] = []
        indirect_call_pattern = re.compile(r"\(\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\)\s*\(")
        for line in updated.splitlines():
            stripped = line.lstrip()
            if stripped.startswith("typedef "):
                rewritten_lines.append(line)
                continue
            line_result: list[str] = []
            index = 0
            while True:
                match = indirect_call_pattern.search(line, index)
                if not match:
                    line_result.append(line[index:])
                    break
                line_result.append(line[index : match.start()])
                args_start = match.end()
                depth = 0
                args_end = args_start
                while args_end < len(line):
                    char = line[args_end]
                    if char == "(":
                        depth += 1
                    elif char == ")":
                        if depth == 0:
                            break
                        depth -= 1
                    args_end += 1
                if args_end >= len(line):
                    line_result.append(line[match.start() :])
                    break
                args = line[args_start:args_end]
                cast_name = indirect_cast_name(args)
                line_result.append(f"(({cast_name}){match.group('name')})({args})")
                index = args_end + 1
            rewritten_lines.append("".join(line_result))
        updated = "\n".join(rewritten_lines)
        return updated

    def _extract_declared_variable_types(self, source: str) -> Dict[str, str]:
        """Extract simple declared variable types from generated C lines."""
        variable_types: Dict[str, str] = {}
        for raw_line in source.splitlines():
            stripped = raw_line.strip()
            if (
                not stripped
                or stripped.startswith("#")
                or stripped.startswith("//")
                or stripped.startswith("typedef ")
                or re.match(r"^(?:return|goto|break|continue|case|default|else)\b", stripped)
                or "(" in stripped
                or ")" in stripped
                or not stripped.endswith(";")
            ):
                continue
            declaration = stripped[:-1].rstrip()
            if "=" in declaration:
                declaration = declaration.split("=", 1)[0].rstrip()
            match = self._match_variable_declaration(declaration)
            if not match:
                continue
            name = match.group("name")
            type_part = match.group("type").strip()
            array_part = match.group("array") or ""
            variable_types[name] = f"{type_part}{array_part}".strip()
        return variable_types

    def _match_variable_declaration(self, declaration: str) -> Optional[re.Match[str]]:
        """Parse simple generated-C declarations, including no-space pointer forms."""
        return re.match(
            r"^(?P<type>.+?(?:\*+\s*|\s+))(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?P<array>\[[^\]]+\])?$",
            declaration,
        )

    def _is_pointer_declared_type(self, declared_type: str) -> bool:
        """Return whether a declared type is pointer-like."""
        normalized = declared_type
        for qualifier in ("const", "volatile", "static", "extern", "register", "inline"):
            normalized = normalized.replace(qualifier, "")
        normalized = re.sub(r"\s+", " ", normalized).strip()
        pointer_aliases = {
            "LPVOID",
            "PVOID",
            "HANDLE",
            "HMODULE",
            "LPCVOID",
            "LPCSTR",
            "LPCWSTR",
            "LPWSTR",
            "LPSTR",
            "PCONTEXT",
            "PDISPATCHER_CONTEXT",
            "PEXCEPTION_POINTERS",
            "PEXCEPTION_RECORD",
            "_EXCEPTION_POINTERS",
            "_EXCEPTION_RECORD",
            "_CONTEXT",
            "_DISPATCHER_CONTEXT",
        }
        return "*" in normalized or normalized in pointer_aliases

    def _is_integer_declared_type(self, declared_type: str) -> bool:
        """Return whether a declared type is scalar integer-like."""
        normalized = declared_type
        for qualifier in ("const", "volatile", "static", "extern", "register", "inline"):
            normalized = normalized.replace(qualifier, "")
        normalized = normalized.strip()
        normalized = re.sub(r"\s+", " ", normalized)
        integer_types = {
            "undefined",
            "undefined1",
            "undefined2",
            "undefined3",
            "undefined4",
            "undefined5",
            "undefined6",
            "undefined7",
            "undefined8",
            "byte",
            "uchar",
            "ushort",
            "uint",
            "ulong",
            "ulong64",
            "ulonglong",
            "uint64_t",
            "uint32_t",
            "uint16_t",
            "uint8_t",
            "uintptr_t",
            "intptr_t",
            "int",
            "int32",
            "int64",
            "long",
            "longlong",
            "qword",
            "dword",
            "char",
            "bool",
            "ghidra_uint128",
        }
        return "[" not in normalized and "*" not in normalized and normalized in integer_types

    def _is_float_declared_type(self, declared_type: str) -> bool:
        """Return whether a declared type is scalar floating-point-like."""
        normalized = declared_type
        for qualifier in ("const", "volatile", "static", "extern", "register", "inline"):
            normalized = normalized.replace(qualifier, "")
        normalized = re.sub(r"\s+", " ", normalized.strip())
        return (
            "[" not in normalized
            and "*" not in normalized
            and normalized
            in {
                "float",
                "double",
                "long double",
            }
        )

    def _normalize_code_pointer_byte_uses(self, source: str) -> str:
        """Rewrite direct code-pointer byte stores when code* locals are acting as raw buffers."""

        def find_matching_delimiter(
            text: str, open_index: int, open_char: str, close_char: str
        ) -> int:
            depth = 0
            for index in range(open_index, len(text)):
                char = text[index]
                if char == open_char:
                    depth += 1
                elif char == close_char:
                    depth -= 1
                    if depth == 0:
                        return index
            return -1

        def rewrite_parenthesized_indexing(line: str) -> str:
            rewritten_parts: List[str] = []
            cursor = 0
            search_start = 0

            while True:
                open_paren = line.find("(", search_start)
                if open_paren == -1:
                    rewritten_parts.append(line[cursor:])
                    break

                close_paren = find_matching_delimiter(line, open_paren, "(", ")")
                if close_paren == -1:
                    rewritten_parts.append(line[cursor:])
                    break

                expression = line[open_paren + 1 : close_paren]
                if expression.strip().startswith("(byte *)(uintptr_t)"):
                    search_start = open_paren + 1
                    continue
                contains_code_pointer = any(
                    re.search(rf"\b{re.escape(name)}\b", expression) for name in code_pointer_names
                )
                if not contains_code_pointer:
                    search_start = open_paren + 1
                    continue

                bracket_index = close_paren + 1
                while bracket_index < len(line) and line[bracket_index].isspace():
                    bracket_index += 1
                if bracket_index >= len(line) or line[bracket_index] != "[":
                    search_start = open_paren + 1
                    continue

                close_bracket = find_matching_delimiter(line, bracket_index, "[", "]")
                if close_bracket == -1:
                    rewritten_parts.append(line[cursor:])
                    break

                rewritten_parts.append(line[cursor:open_paren])
                rewritten_parts.append(
                    f"((byte *)(uintptr_t)({expression})){line[bracket_index:close_bracket + 1]}"
                )
                cursor = close_bracket + 1
                search_start = cursor

            return "".join(rewritten_parts)

        variable_types = self._extract_declared_variable_types(source)
        code_pointer_names = {
            name
            for name, declared_type in variable_types.items()
            if " ".join(declared_type.split()) == "code *"
        }
        updated_lines: List[str] = []
        direct_copy_pattern = re.compile(
            r"^(?P<indent>\s*)\*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*)\s*;$"
        )
        null_store_pattern = re.compile(
            r"^(?P<indent>\s*)\*(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(code \*\)0x0\s*;$"
        )

        for line in source.splitlines():
            rewritten = line
            direct_copy_match = direct_copy_pattern.match(line)
            if direct_copy_match:
                lhs_type = variable_types.get(direct_copy_match.group("lhs"), "")
                rhs_type = variable_types.get(direct_copy_match.group("rhs"), "")
                if (
                    " ".join(lhs_type.split()) == "code *"
                    and " ".join(rhs_type.split()) == "code *"
                ):
                    rewritten = (
                        f"{direct_copy_match.group('indent')}*(byte *)(uintptr_t){direct_copy_match.group('lhs')} = "
                        f"*(byte *)(uintptr_t){direct_copy_match.group('rhs')};"
                    )
                    updated_lines.append(rewritten)
                    continue

            null_store_match = null_store_pattern.match(line)
            if null_store_match:
                lhs_type = variable_types.get(null_store_match.group("lhs"), "")
                if " ".join(lhs_type.split()) == "code *":
                    rewritten = f"{null_store_match.group('indent')}*(byte *)(uintptr_t){null_store_match.group('lhs')} = 0;"
                    updated_lines.append(rewritten)
                    continue

            updated_lines.append(rewritten)

        updated = "\n".join(updated_lines)
        if code_pointer_names:
            alternation = "|".join(
                sorted((re.escape(name) for name in code_pointer_names), key=len, reverse=True)
            )
            updated = re.sub(
                rf"GHIDRA_U64\(\*(?P<name>{alternation})\)",
                r"GHIDRA_U64(*(byte *)(uintptr_t)\g<name>)",
                updated,
            )
            updated = re.sub(
                rf"\b(?P<name>{alternation})\s*\[(?P<index>[^\]]+)\]",
                r"((byte *)(uintptr_t)\g<name>)[\g<index>]",
                updated,
            )
            updated = re.sub(
                rf"\((?P<expr>(?!\(byte \*\)\(uintptr_t\))[^;\n()]*\b(?:{alternation})\b[^;\n()]*)\)\s*\[(?P<index>[^\]]+)\]",
                r"((byte *)(uintptr_t)(\g<expr>))[\g<index>]",
                updated,
            )
            updated = "\n".join(
                rewrite_parenthesized_indexing(line) for line in updated.splitlines()
            )

        return updated

    def _is_byte_array_declared_type(self, declared_type: str) -> bool:
        """Return whether a declared type is a non-vector undefined1 byte array."""
        normalized = " ".join(declared_type.split())
        compact = normalized.replace(" ", "")
        return compact.startswith("undefined1[") and compact not in {
            "undefined1[8]",
            "undefined1[16]",
        }

    def _rewrite_pointer_double_cast(
        self, match: re.Match[str], variable_types: Dict[str, str]
    ) -> str:
        """Cast pointer-like values through uintptr_t before converting to double."""
        expression = match.group(1).strip()
        inferred_type = self._infer_expression_declared_type(expression, variable_types)
        if self._is_pointer_declared_type(inferred_type) or expression.startswith("*"):
            return f"(double)(uintptr_t){expression}"
        return match.group(0)

    def _normalize_pointer_integer_assignments(self, source: str) -> str:
        """Insert explicit casts when Ghidra mixes pointer and integer locals."""
        variable_types = self._extract_declared_variable_types(source)
        declared_function_names = self._extract_declared_function_names(source)
        updated_lines: List[str] = []
        assignment_pattern = re.compile(
            r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*)\s*;$"
        )
        cast_assignment_pattern = re.compile(
            r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\((?P<cast>[^)]+)\)\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*)\s*;$"
        )
        cast_expression_assignment_pattern = re.compile(
            r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\((?P<cast>[^)]+)\)\s*(?P<rhs>.+)\s*;$"
        )

        def resolve_type(name: str, before_pos: int) -> str:
            nearest_type = self._find_nearest_declared_variable_type(source, name, before_pos)
            if nearest_type:
                return nearest_type
            parameter_type = self._find_nearest_parameter_type(source, name, before_pos)
            if parameter_type:
                return parameter_type
            declared_type = variable_types.get(name, "")
            if declared_type:
                return declared_type
            if self._is_integer_fragment_name(name):
                return "uint64_t"
            fragment_type = self._infer_split_fragment_declared_type(
                name,
                variable_types,
                source=source,
                before_pos=before_pos,
            )
            if fragment_type:
                return fragment_type
            return ""

        line_start = 0
        for line in source.splitlines():
            current_line_start = line_start
            line_start += len(line) + 1
            rewritten = line
            cast_match = cast_assignment_pattern.match(line)
            if cast_match:
                lhs = cast_match.group("lhs")
                rhs = cast_match.group("rhs")
                lhs_type = resolve_type(lhs, current_line_start)
                if not lhs_type and self._is_integer_fragment_name(lhs):
                    lhs_type = "uint64_t"
                rhs_type = resolve_type(rhs, current_line_start)
                cast_type = cast_match.group("cast").strip()
                if self._is_integer_declared_type(lhs_type) and (
                    self._is_pointer_declared_type(rhs_type)
                    or self._is_pointer_declared_type(cast_type)
                ):
                    rewritten = (
                        f"{cast_match.group('indent')}{lhs} = GHIDRA_U64(({cast_type}){rhs});"
                    )
                elif self._is_pointer_declared_type(lhs_type) and (
                    self._is_integer_declared_type(rhs_type)
                    or self._is_float_declared_type(rhs_type)
                ):
                    if self._is_pointer_declared_type(cast_type):
                        rewritten = f"{cast_match.group('indent')}{lhs} = ({lhs_type})(uintptr_t)GHIDRA_U64({rhs});"
                    else:
                        rewritten = f"{cast_match.group('indent')}{lhs} = ({lhs_type})(uintptr_t)(({cast_type}){rhs});"
                updated_lines.append(rewritten)
                continue

            cast_expression_match = cast_expression_assignment_pattern.match(line)
            if cast_expression_match:
                lhs = cast_expression_match.group("lhs")
                lhs_type = resolve_type(lhs, current_line_start)
                if not lhs_type and self._is_integer_fragment_name(lhs):
                    lhs_type = "uint64_t"
                cast_type = cast_expression_match.group("cast").strip()
                rhs_expr = cast_expression_match.group("rhs").strip()
                if self._is_integer_declared_type(lhs_type) and self._is_pointer_declared_type(
                    cast_type
                ):
                    rewritten = (
                        f"{cast_expression_match.group('indent')}{lhs} = "
                        f"GHIDRA_U64(({cast_type}){rhs_expr});"
                    )
                elif (
                    self._is_pointer_declared_type(lhs_type)
                    and self._is_pointer_declared_type(cast_type)
                    and not re.match(r"^(?:0x[0-9A-Fa-f]+|\d+|\(uintptr_t\)GHIDRA_U64\()", rhs_expr)
                    and (
                        re.match(r"^\*[A-Za-z_][A-Za-z0-9_]*$", rhs_expr)
                        or re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]$", rhs_expr)
                    )
                    and not self._is_pointer_declared_type(
                        self._infer_expression_declared_type(rhs_expr, variable_types)
                    )
                ):
                    rewritten = (
                        f"{cast_expression_match.group('indent')}{lhs} = "
                        f"({lhs_type})(uintptr_t)GHIDRA_U64({rhs_expr});"
                    )
                elif (
                    self._is_pointer_declared_type(lhs_type)
                    and " ".join(lhs_type.split()) != "code *"
                    and cast_type == "code *"
                    and rhs_expr.startswith("(uintptr_t)GHIDRA_U64(")
                ):
                    rewritten = (
                        f"{cast_expression_match.group('indent')}{lhs} = "
                        f"({lhs_type}){rhs_expr};"
                    )
                elif (
                    self._is_pointer_declared_type(lhs_type)
                    and self._is_pointer_declared_type(cast_type)
                    and " ".join(lhs_type.split()) != " ".join(cast_type.split())
                ):
                    rewritten = (
                        f"{cast_expression_match.group('indent')}{lhs} = "
                        f"({lhs_type})(uintptr_t)(({cast_type}){rhs_expr});"
                    )
                updated_lines.append(rewritten)
                continue

            symbol_assignment_match = re.match(
                r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>(?:&\s*)?(?:LAB_[A-Za-z0-9_]+|PTR(?:_[A-Za-z0-9_]+)?|_?UNK|_?DAT|DAT|FUN)_[A-Za-z0-9_]+|&\s*LAB_[A-Za-z0-9_]+)\s*;$",
                line,
            )
            if symbol_assignment_match:
                lhs = symbol_assignment_match.group("lhs")
                lhs_type = resolve_type(lhs, current_line_start)
                rhs = symbol_assignment_match.group("rhs").strip()
                if self._is_pointer_declared_type(lhs_type):
                    if rhs.lstrip("&").startswith("FUN_"):
                        cast_rhs = rhs if rhs.startswith("&") else rhs
                        updated_lines.append(
                            f"{symbol_assignment_match.group('indent')}{lhs} = ({lhs_type}){cast_rhs};"
                        )
                    elif rhs.startswith("&"):
                        updated_lines.append(
                            f"{symbol_assignment_match.group('indent')}{lhs} = ({lhs_type}){rhs};"
                        )
                    else:
                        updated_lines.append(
                            f"{symbol_assignment_match.group('indent')}{lhs} = ({lhs_type})(uintptr_t){rhs};"
                        )
                    continue

            match = assignment_pattern.match(line)
            if not match:
                pointer_symbol_store_match = re.match(
                    r"^(?P<indent>\s*)(?P<lhs>\*\(.+?)\s*=\s*(?P<rhs>(?:&\s*)?(?:_?UNK|_?DAT|DAT)_[A-Za-z0-9_]+)\s*;$",
                    rewritten,
                )
                if pointer_symbol_store_match:
                    lhs_type = self._infer_lvalue_target_type(
                        pointer_symbol_store_match.group("lhs"), variable_types
                    )
                    rhs = pointer_symbol_store_match.group("rhs").strip()
                    if self._is_pointer_declared_type(lhs_type):
                        if rhs.startswith("&"):
                            rewritten = (
                                f"{pointer_symbol_store_match.group('indent')}"
                                f"{pointer_symbol_store_match.group('lhs')} = ({lhs_type}){rhs};"
                            )
                        else:
                            rewritten = (
                                f"{pointer_symbol_store_match.group('indent')}"
                                f"{pointer_symbol_store_match.group('lhs')} = ({lhs_type})(uintptr_t){rhs};"
                            )
                non_code_pointer_cast_match = re.match(
                    r"^(?P<indent>\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\(code \*\)\(uintptr_t\)(?P<rhs>GHIDRA_U64\([^;]+\));$",
                    rewritten,
                )
                if non_code_pointer_cast_match:
                    lhs_type = resolve_type(
                        non_code_pointer_cast_match.group("lhs"), current_line_start
                    )
                    if (
                        self._is_pointer_declared_type(lhs_type)
                        and " ".join(lhs_type.split()) != "code *"
                    ):
                        rewritten = (
                            f"{non_code_pointer_cast_match.group('indent')}"
                            f"{non_code_pointer_cast_match.group('lhs')} = "
                            f"({lhs_type})(uintptr_t){non_code_pointer_cast_match.group('rhs')};"
                        )
                updated_lines.append(rewritten)
                continue

            lhs = match.group("lhs")
            rhs = match.group("rhs")
            lhs_type = resolve_type(lhs, current_line_start)
            if not lhs_type and self._is_integer_fragment_name(lhs):
                lhs_type = "uint64_t"
            rhs_type = resolve_type(rhs, current_line_start)
            if self._is_integer_declared_type(lhs_type) and self._is_byte_array_declared_type(
                rhs_type
            ):
                rewritten = f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs});"
            elif self._is_integer_declared_type(lhs_type) and self._is_pointer_declared_type(
                rhs_type
            ):
                rewritten = f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs});"
            elif self._is_integer_declared_type(lhs_type) and re.match(
                r"^(?:FUN|PTR_FUN)_[A-Za-z0-9_]+$",
                rhs,
            ):
                rewritten = f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs});"
            elif self._is_integer_declared_type(lhs_type) and rhs in declared_function_names:
                rewritten = f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs});"
            elif self._is_pointer_declared_type(lhs_type) and re.match(
                r"^(?:_{2,3})xmm_[0-9A-Fa-f]+$", rhs
            ):
                rewritten = f"{match.group('indent')}{lhs} = ({lhs_type})(uintptr_t)&{rhs};"
            elif (
                self._is_pointer_declared_type(lhs_type)
                and " ".join(lhs_type.split()) != "code *"
                and " ".join(rhs_type.split()) == "code *"
            ):
                rewritten = (
                    f"{match.group('indent')}{lhs} = ({lhs_type})(uintptr_t)GHIDRA_U64({rhs});"
                )
            elif (
                self._is_pointer_declared_type(lhs_type)
                and self._is_pointer_declared_type(rhs_type)
                and " ".join(lhs_type.split()) != " ".join(rhs_type.split())
            ):
                rewritten = f"{match.group('indent')}{lhs} = ({lhs_type}){rhs};"
            elif self._is_pointer_declared_type(lhs_type) and self._is_integer_declared_type(
                rhs_type
            ):
                rewritten = f"{match.group('indent')}{lhs} = ({lhs_type})(uintptr_t){rhs};"
            updated_lines.append(rewritten)

        updated = "\n".join(updated_lines)
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*\((?P<cast>[^)\n]+)\)\s*(?P<rhs>(?:\s*\n\s*)+[^;]+)\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\])\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>\(\(byte \*\)\(uintptr_t\)[A-Za-z_][A-Za-z0-9_]*\)\s*\[[^\]]+\])\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>&\s*[A-Za-z_][A-Za-z0-9_]*)\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]\s*\+\s*.+)\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>[A-Za-z_][A-Za-z0-9_]*\s*\+\s*[^;\n]+)\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>&\s*(?:_?UNK|_?DAT|DAT)_[A-Za-z0-9_]+\s*\+\s*.+)\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>(?:SUB\d+|CONCAT\d+)\([^\n;]+\)|GHIDRA_U64\([^\n;]+\))\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>\*[A-Za-z_][A-Za-z0-9_]*|\*\([^)]+\)(?:\([^;\n]+\)|[A-Za-z_][A-Za-z0-9_]*(?:\s*[+\-]\s*[^;\n]+)?))\s*;",
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r'(?P<indent>^\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>"(?:[^"\\]|\\.)*")\s*;',
            lambda match: self._rewrite_pointer_integer_expression_assignment(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        previous = None
        while updated != previous:
            previous = updated
            updated = re.sub(
                r"(?P<prefix>[(,]\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>(?:_{2,3})xmm_[0-9A-Fa-f]+|(?:_?UNK|_?DAT|DAT)_[A-Za-z0-9_]+)(?P<suffix>\s*[,)\n])",
                lambda match: self._rewrite_inline_symbol_assignment(match, updated),
                updated,
            )
            updated = re.sub(
                r"(?P<prefix>[(,]\s*)(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?P<rhs>\(\(byte \*\)\(uintptr_t\)[A-Za-z_][A-Za-z0-9_]*\)\s*\[[^\]]+\])(?P<suffix>\s*[,)\n])",
                lambda match: self._rewrite_inline_symbol_assignment(match, updated),
                updated,
            )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>(?:\*\([^)]+\)\s*\([^;\n=]+\)|\*[A-Za-z_][A-Za-z0-9_]*|\([A-Za-z_][A-Za-z0-9_]*[^;\n]*\)\s*\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]))\s*(?<![=!<>])=(?!=)\s*(?P<rhs>[^\n;]+)\s*;",
            lambda match: self._rewrite_pointer_integer_lvalue_store(
                match,
                variable_types,
                updated,
            ),
            updated,
            flags=re.MULTILINE,
        )
        updated = re.sub(
            r"(?P<indent>^\s*)(?P<lhs>(?:\*\s*(?P<base_deref>param_\d+)|(?P<base_index>param_\d+)\s*\[[^\]]+\]))\s*=\s*(?P<rhs>\([^\n;]*\*\)\s*(?:\(uintptr_t\))?[^\n;]+)\s*;",
            lambda match: self._rewrite_integer_param_slot_pointer_store(match, updated),
            updated,
            flags=re.MULTILINE,
        )
        return updated

    def _rewrite_integer_param_slot_pointer_store(
        self,
        match: re.Match[str],
        source: str,
    ) -> str:
        """Scalarize pointer-cast stores into integer-valued param slots in whole-source mode."""
        base_name = match.group("base_deref") or match.group("base_index") or ""
        if not base_name:
            return match.group(0)
        base_type = self._find_nearest_parameter_type(source, base_name, match.start()) or ""
        if not self._is_pointer_declared_type(base_type):
            return match.group(0)
        target_type = re.sub(r"\*\s*$", "", base_type).rstrip()
        if not self._is_integer_declared_type(target_type):
            return match.group(0)
        rhs_expr = match.group("rhs").strip()
        if rhs_expr.startswith("GHIDRA_U64("):
            return match.group(0)
        return f"{match.group('indent')}{match.group('lhs').strip()} = GHIDRA_U64({rhs_expr});"

    def _rewrite_inline_symbol_assignment(self, match: re.Match[str], source: str) -> str:
        """Rewrite symbol assignments that occur inside comma expressions or parenthesized clauses."""
        lhs = match.group("lhs")
        rhs = match.group("rhs").strip()
        lhs_type = self._find_nearest_declared_variable_type(source, lhs, match.start("lhs")) or ""
        replacement_rhs = rhs
        if self._is_pointer_declared_type(lhs_type):
            if re.match(r"^(?:_{2,3})xmm_[0-9A-Fa-f]+$", rhs):
                replacement_rhs = f"({lhs_type})(uintptr_t)&{rhs}"
            elif re.match(
                r"^\(\(byte \*\)\(uintptr_t\)[A-Za-z_][A-Za-z0-9_]*\)\s*\[[^\]]+\]$", rhs
            ):
                replacement_rhs = f"({lhs_type})(uintptr_t)GHIDRA_U64({rhs})"
            elif " ".join(lhs_type.split()) == "code *":
                replacement_rhs = f"(code *)(uintptr_t)GHIDRA_U64({rhs})"
            else:
                replacement_rhs = f"({lhs_type})(uintptr_t){rhs}"
        elif self._is_integer_declared_type(lhs_type):
            if re.match(r"^(?:_{2,3})xmm_[0-9A-Fa-f]+$", rhs):
                replacement_rhs = f"GHIDRA_U64(&{rhs})"
            else:
                replacement_rhs = f"GHIDRA_U64({rhs})"
        return f"{match.group('prefix')}{lhs} = {replacement_rhs}{match.group('suffix')}"

    def _rewrite_pointer_integer_expression_assignment(
        self,
        match: re.Match[str],
        variable_types: Dict[str, str],
        source: str,
    ) -> str:
        """Rewrite pointer/integer assignments whose RHS is an expression, not just a bare variable."""
        lhs = match.group("lhs")
        lhs_type = self._find_nearest_declared_variable_type(
            source, lhs, match.start()
        ) or variable_types.get(lhs, "")
        if not lhs_type and self._is_integer_fragment_name(lhs):
            lhs_type = "uint64_t"
        rhs_expr = match.group("rhs").strip()
        cast_type = match.groupdict().get("cast", "")
        if self._is_integer_declared_type(lhs_type) and rhs_expr.startswith("GHIDRA_U64("):
            return match.group(0)
        if " ".join(lhs_type.split()) == "ghidra_uint128":
            return match.group(0)
        rhs_type = self._infer_expression_declared_type(rhs_expr, variable_types)
        if cast_type and self._is_integer_declared_type(lhs_type) and "*" in cast_type:
            compact_rhs = re.sub(r"\s+", " ", rhs_expr)
            return f"{match.group('indent')}{lhs} = GHIDRA_U64(({cast_type.strip()}){compact_rhs});"
        if self._is_integer_declared_type(lhs_type) and self._is_byte_array_declared_type(rhs_type):
            return f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs_expr});"
        if self._is_integer_declared_type(lhs_type) and (
            self._is_pointer_declared_type(rhs_type)
            or self._expression_contains_pointer_terms(rhs_expr, variable_types)
        ):
            return f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs_expr});"
        if self._is_integer_declared_type(lhs_type) and re.match(
            r"^\*\([^)]+\)(?:\([^;\n]+\)|[A-Za-z_][A-Za-z0-9_]*(?:\s*[+\-]\s*.+)?)$",
            rhs_expr,
        ):
            return f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs_expr});"
        if self._is_pointer_declared_type(lhs_type) and re.match(
            r"^\(\(byte \*\)\(uintptr_t\)[A-Za-z_][A-Za-z0-9_]*\)\s*\[[^\]]+\]$",
            rhs_expr,
        ):
            return f"{match.group('indent')}{lhs} = ({lhs_type})(uintptr_t){rhs_expr};"
        if (
            self._is_pointer_declared_type(lhs_type)
            and self._is_pointer_declared_type(rhs_type)
            and " ".join(lhs_type.split()) != " ".join(rhs_type.split())
        ):
            return f"{match.group('indent')}{lhs} = ({lhs_type}){rhs_expr};"
        if self._is_integer_declared_type(lhs_type) and re.match(
            r"^&\s*(?:PTR(?:_FUN)?|FUN|_?UNK|_?DAT|DAT)_[A-Za-z0-9_]+$",
            rhs_expr,
        ):
            return f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs_expr});"
        if self._is_integer_declared_type(lhs_type) and re.match(r'^"(?:[^"\\]|\\.)*"$', rhs_expr):
            return f"{match.group('indent')}{lhs} = GHIDRA_U64({rhs_expr});"
        if self._is_pointer_declared_type(lhs_type) and re.match(
            r"^&\s*(?:_?UNK|_?DAT|DAT)_[A-Za-z0-9_]+\s*\+.+$",
            rhs_expr,
        ):
            return f"{match.group('indent')}{lhs} = ({lhs_type})({rhs_expr});"
        if (
            self._is_pointer_declared_type(lhs_type)
            and " ".join(lhs_type.split()) != "code *"
            and " ".join(rhs_type.split()) == "code *"
        ):
            return f"{match.group('indent')}{lhs} = ({lhs_type})(uintptr_t)GHIDRA_U64({rhs_expr});"
        if self._is_pointer_declared_type(lhs_type) and (
            re.match(r"^(?:SUB\d+|CONCAT\d+)\(", rhs_expr) or rhs_expr.startswith("GHIDRA_U64(")
        ):
            return f"{match.group('indent')}{lhs} = ({lhs_type})(uintptr_t){rhs_expr};"
        if self._is_pointer_declared_type(lhs_type) and self._is_integer_declared_type(rhs_type):
            return f"{match.group('indent')}{lhs} = ({lhs_type})(uintptr_t){rhs_expr};"
        return match.group(0)

    def _rewrite_pointer_integer_lvalue_store(
        self,
        match: re.Match[str],
        variable_types: Dict[str, str],
        source: str,
    ) -> str:
        """Rewrite stores through integer lvalues when the RHS is pointer-typed."""
        lhs_expr = match.group("lhs").strip()
        rhs_expr = match.group("rhs").strip()
        lhs_type = self._infer_lvalue_target_type(lhs_expr, variable_types)
        lhs_base_match = re.match(
            r"^(?:\*\s*(?P<deref>[A-Za-z_][A-Za-z0-9_]*)|(?P<index>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\])$",
            lhs_expr,
        )
        if lhs_base_match:
            lhs_base = lhs_base_match.group("deref") or lhs_base_match.group("index")
            base_type = (
                self._find_nearest_declared_variable_type(source, lhs_base, match.start())
                or self._find_nearest_parameter_type(source, lhs_base, match.start())
                or variable_types.get(lhs_base, "")
            )
            if self._is_pointer_declared_type(base_type):
                lhs_type = re.sub(r"\*\s*$", "", base_type).rstrip()
        rhs_type = self._infer_expression_declared_type(rhs_expr, variable_types)
        if not rhs_type and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", rhs_expr):
            rhs_type = (
                self._find_nearest_declared_variable_type(source, rhs_expr, match.start()) or ""
            )
        if not lhs_type:
            lhs_base_match = re.match(
                r"^(?:\*\s*(?P<deref>[A-Za-z_][A-Za-z0-9_]*)|(?P<index>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\])$",
                lhs_expr,
            )
            if lhs_base_match:
                lhs_base = lhs_base_match.group("deref") or lhs_base_match.group("index")
                base_type = self._find_nearest_parameter_type(source, lhs_base, match.start()) or ""
                if self._is_pointer_declared_type(base_type):
                    lhs_type = re.sub(r"\*\s*$", "", base_type).rstrip()
        if self._is_integer_declared_type(lhs_type) and self._is_byte_array_declared_type(rhs_type):
            return f"{match.group('indent')}{lhs_expr} = GHIDRA_U64({rhs_expr});"
        if self._is_integer_declared_type(lhs_type) and (
            self._is_pointer_declared_type(rhs_type)
            or self._expression_contains_pointer_terms(rhs_expr, variable_types)
        ):
            return f"{match.group('indent')}{lhs_expr} = GHIDRA_U64({rhs_expr});"
        if self._is_pointer_declared_type(lhs_type) and re.fullmatch(
            r"(?:&\s*)?(?:_?UNK|_?DAT|DAT|FUN|PTR_FUN)_[A-Za-z0-9_]+",
            rhs_expr,
        ):
            return f"{match.group('indent')}{lhs_expr} = ({lhs_type})(uintptr_t){rhs_expr};"
        if self._is_pointer_declared_type(lhs_type) and (
            rhs_expr.startswith("GHIDRA_U64(") or self._is_integer_declared_type(rhs_type)
        ):
            return f"{match.group('indent')}{lhs_expr} = ({lhs_type})(uintptr_t){rhs_expr};"
        return match.group(0)

    def _infer_expression_declared_type(
        self,
        expression: str,
        variable_types: Dict[str, str],
    ) -> str:
        """Infer a simple declared type for generated expressions like pointer indexing."""
        stripped = expression.strip()
        bare_type = variable_types.get(stripped)
        if bare_type:
            return bare_type
        fragment_type = self._infer_split_fragment_declared_type(stripped, variable_types)
        if fragment_type:
            return fragment_type
        deref_match = re.match(r"^\*\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)$", stripped)
        if deref_match:
            base_type = variable_types.get(deref_match.group("base"), "")
            if self._is_pointer_declared_type(base_type):
                return re.sub(r"\*\s*$", "", base_type).rstrip()
        pointer_cast_match = re.match(
            r"^\((?P<cast>[A-Za-z_][A-Za-z0-9_\s\*]+?\*)\)\s*(?:\(uintptr_t\))?.+$", stripped
        )
        if pointer_cast_match:
            return pointer_cast_match.group("cast").strip()
        if stripped.startswith("GHIDRA_LARGE_INTEGER("):
            return "LARGE_INTEGER"
        if re.match(r"^\*\(LARGE_INTEGER \*\).+$", stripped):
            return "LARGE_INTEGER"
        large_integer_quadpart_match = re.match(
            r"^\(\(LARGE_INTEGER \*\)[^)]+\)->QuadPart$",
            stripped,
        )
        if large_integer_quadpart_match:
            return "longlong"
        index_match = re.match(r"^(?P<base>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\]$", stripped)
        if not index_match:
            address_match = re.match(r"^&\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)$", stripped)
            if not address_match:
                return ""
            base_type = variable_types.get(address_match.group("base"), "")
            if not base_type:
                return ""
            return f"{base_type} *"
        base_type = variable_types.get(index_match.group("base"), "")
        if not self._is_pointer_declared_type(base_type):
            return ""
        return re.sub(r"\*\s*$", "", base_type).rstrip()

    def _infer_lvalue_target_type(
        self,
        expression: str,
        variable_types: Dict[str, str],
    ) -> str:
        """Infer the target type written through an lvalue expression."""
        stripped = expression.strip()
        cast_deref_match = re.match(r"^\*\((?P<cast>[^)]+)\)(?:\([^)]*\))?.*$", stripped)
        if cast_deref_match:
            cast_type = cast_deref_match.group("cast").strip()
            if self._is_pointer_declared_type(cast_type):
                return re.sub(r"\*\s*$", "", cast_type).rstrip()
        deref_match = re.match(r"^\*\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)$", stripped)
        if deref_match:
            base_type = variable_types.get(deref_match.group("base"), "")
            if self._is_pointer_declared_type(base_type):
                return re.sub(r"\*\s*$", "", base_type).rstrip()
            return ""
        parenthesized_index_match = re.match(
            r"^\((?P<base>[A-Za-z_][A-Za-z0-9_]*)[^;\n]*\)\s*\[[^\]]+\]$",
            stripped,
        )
        if parenthesized_index_match:
            base_type = variable_types.get(parenthesized_index_match.group("base"), "")
            if self._is_pointer_declared_type(base_type):
                return re.sub(r"\*\s*$", "", base_type).rstrip()
            return ""
        return self._infer_expression_declared_type(stripped, variable_types)

    def _expression_contains_pointer_terms(
        self, expression: str, variable_types: Dict[str, str]
    ) -> bool:
        """Return whether an arithmetic expression contains pointer-typed terms."""
        if re.match(r'^"(?:[^"\\]|\\.)*"$', expression.strip()):
            return True
        for symbol in re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*\s*\[[^\]]+\]|[A-Za-z_][A-Za-z0-9_]*", expression
        ):
            inferred = self._infer_expression_declared_type(symbol, variable_types)
            if self._is_pointer_declared_type(inferred):
                return True
        return False

    def _is_integer_fragment_name(self, name: str) -> bool:
        """Return whether a Ghidra split-fragment symbol name represents integer storage."""
        return bool(re.match(r"^[A-Za-z_][A-Za-z0-9]*_[0-9A-Fa-f]+(?:_[0-9]+){1,}_$", name))

    def _get_split_fragment_base_name(self, name: str) -> Optional[str]:
        """Return the base symbol name for Ghidra split-fragment aliases like foo_0_8_."""
        match = re.match(r"^(?P<base>.+)_[0-9A-Fa-f]+(?:_[0-9]+){1,}_$", name)
        if not match:
            return None
        return match.group("base")

    def _infer_split_fragment_declared_type(
        self,
        name: str,
        variable_types: Dict[str, str],
        source: Optional[str] = None,
        before_pos: Optional[int] = None,
    ) -> str:
        """Infer a split-fragment alias type from its base symbol declaration."""
        base_name = self._get_split_fragment_base_name(name)
        if not base_name:
            return ""
        if source is not None and before_pos is not None:
            nearest_type = self._find_nearest_declared_variable_type(source, base_name, before_pos)
            if nearest_type:
                return nearest_type
            parameter_type = self._find_nearest_parameter_type(source, base_name, before_pos)
            if parameter_type:
                return parameter_type
        return variable_types.get(base_name, "")

    def _normalize_integer_pointer_accesses(self, source: str) -> str:
        """Cast integer scalars back to generic pointer storage when later dereferenced/subscripted."""
        variable_types = self._extract_declared_variable_types(source)
        integer_names = {
            name
            for name, declared_type in variable_types.items()
            if self._is_integer_declared_type(declared_type)
        }
        source_pointer_like_names = {
            match.group("name")
            for pattern in (
                re.compile(
                    r"(^|[^A-Za-z0-9_\]\)\s])\s*\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b",
                    flags=re.MULTILINE,
                ),
                re.compile(r"\(\(ghidra_indirect_fn\)\*\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\)"),
                re.compile(r"\b(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\[[^\]]+\]"),
            )
            for match in pattern.finditer(source)
        }
        pointer_like_integer_names = integer_names.intersection(source_pointer_like_names)
        if not pointer_like_integer_names:
            return source

        updated_lines: List[str] = []
        token_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
        for line in source.splitlines():
            rewritten = line
            stripped = line.strip()
            declaration = stripped[:-1].rstrip() if stripped.endswith(";") else stripped
            if (
                declaration
                and "=" not in declaration
                and self._match_variable_declaration(declaration)
            ):
                updated_lines.append(rewritten)
                continue
            line_names = pointer_like_integer_names.intersection(token_pattern.findall(rewritten))
            if not line_names:
                updated_lines.append(rewritten)
                continue
            for name in sorted(line_names, key=len, reverse=True):
                cast_expr = f"((uintptr_t *)(uintptr_t){name})"
                rewritten = re.sub(
                    rf"(^|[^A-Za-z0-9_\]\)\s])(\s*)\*\s*{re.escape(name)}\b",
                    lambda match: f"{match.group(1)}{match.group(2)}*{cast_expr}",
                    rewritten,
                    flags=re.MULTILINE,
                )
                rewritten = re.sub(
                    rf"\b{re.escape(name)}\s*(\[[^\]]+\])",
                    rf"{cast_expr}\1",
                    rewritten,
                )
                rewritten = re.sub(
                    rf"\(\(ghidra_indirect_fn\)\*\s*{re.escape(name)}\)",
                    f"((ghidra_indirect_fn)*{cast_expr})",
                    rewritten,
                )
            updated_lines.append(rewritten)
        return "\n".join(updated_lines)

    def _normalize_uintptr_bridge_accesses(self, source: str) -> str:
        """Normalize reads/writes through ((uintptr_t *)(uintptr_t)x) bridge expressions."""
        variable_types = self._extract_declared_variable_types(source)
        updated_lines: List[str] = []
        base_bridge_expr = r"\(\(uintptr_t \*\)\(uintptr_t\)[A-Za-z_][A-Za-z0-9_]*\)"
        indexed_bridge_expr = rf"{base_bridge_expr}(?:\[[^\]]+\])+"
        nested_bridge_base_expr = rf"\(\(uintptr_t \*\)\(uintptr_t\)(?:{indexed_bridge_expr})\)"
        bridge_expr = rf"(?:{base_bridge_expr}|{nested_bridge_base_expr})(?:\[[^\]]+\])*"
        nested_subscript_pattern = re.compile(
            rf"(?P<bridge>(?:{indexed_bridge_expr}|{nested_bridge_base_expr}(?:\[[^\]]+\])*))(?P<tail>\[[^\]]+\])"
        )
        bridge_store_pattern = re.compile(
            rf"^(?P<indent>\s*)(?P<lhs>(?:\*\s*)?(?:{bridge_expr}|{base_bridge_expr}))\s*=\s*(?P<rhs>.+?)\s*;$"
        )

        for line in source.splitlines():
            rewritten = line
            stripped = line.strip()
            declaration = stripped[:-1].rstrip() if stripped.endswith(";") else stripped
            if (
                declaration
                and "=" not in declaration
                and self._match_variable_declaration(declaration)
            ):
                updated_lines.append(rewritten)
                continue
            if "((uintptr_t *)(uintptr_t)" not in rewritten:
                updated_lines.append(rewritten)
                continue

            rewritten = nested_subscript_pattern.sub(
                lambda match: f"((uintptr_t *)(uintptr_t){match.group('bridge')}){match.group('tail')}",
                rewritten,
            )

            store_match = bridge_store_pattern.match(rewritten)
            if store_match:
                rhs_expr = store_match.group("rhs").strip()
                rhs_type = self._infer_expression_declared_type(rhs_expr, variable_types)
                if (
                    self._is_pointer_declared_type(rhs_type)
                    or self._expression_contains_pointer_terms(rhs_expr, variable_types)
                    or "*" in rhs_expr
                ):
                    rewritten = (
                        f"{store_match.group('indent')}{store_match.group('lhs')} = "
                        f"GHIDRA_U64({rhs_expr});"
                    )
                    updated_lines.append(rewritten)
                    continue

            rewritten = self._cast_pointer_bridge_reads(rewritten, variable_types)
            rewritten = re.sub(
                r"\(\(ghidra_indirect_fn\)\*\(\(uintptr_t \*\)\(uintptr_t\)(?P<base>[A-Za-z_][A-Za-z0-9_]*)\)\)\((?P<arg>[^()]+)\)",
                lambda match: (
                    f"((ghidra_indirect_fn)*((uintptr_t *)(uintptr_t){match.group('base')}))"
                    f"(GHIDRA_U64({match.group('arg').strip()}))"
                ),
                rewritten,
            )
            updated_lines.append(rewritten)

        return "\n".join(updated_lines)

    def _cast_pointer_bridge_reads(self, line: str, variable_types: Dict[str, str]) -> str:
        """Cast bridge-read expressions assigned into pointer-typed variables."""
        if "=" not in line or "((uintptr_t *)(uintptr_t)" not in line:
            return line
        rewritten = line
        assignment_pattern = re.compile(r"(?<![A-Za-z0-9_])(?P<lhs>[A-Za-z_][A-Za-z0-9_]*)\s*=\s*")
        search_pos = 0
        while True:
            match = assignment_pattern.search(rewritten, search_pos)
            if not match:
                break
            lhs = match.group("lhs")
            lhs_type = variable_types.get(lhs, "")
            if not self._is_pointer_declared_type(lhs_type):
                search_pos = match.end()
                continue
            rhs_start = match.end()
            rhs_end = self._find_bridge_assignment_end(rewritten, rhs_start)
            rhs_expr = rewritten[rhs_start:rhs_end].strip()
            if not (
                rhs_expr.startswith("((uintptr_t *)(uintptr_t)")
                or rhs_expr.startswith("*((uintptr_t *)(uintptr_t)")
            ):
                search_pos = match.end()
                continue
            replacement = f"({lhs_type})(uintptr_t){rhs_expr}"
            rewritten = rewritten[:rhs_start] + replacement + rewritten[rhs_end:]
            search_pos = rhs_start + len(replacement)
        return rewritten

    def _find_bridge_assignment_end(self, line: str, start: int) -> int:
        """Find the end of a bridge-assignment expression within a single line."""
        paren_depth = 0
        bracket_depth = 0
        for index in range(start, len(line)):
            char = line[index]
            if char == "(":
                paren_depth += 1
            elif char == ")" and paren_depth > 0:
                paren_depth -= 1
            elif char == "[":
                bracket_depth += 1
            elif char == "]" and bracket_depth > 0:
                bracket_depth -= 1
            elif char in ",;" and paren_depth == 0 and bracket_depth == 0:
                return index
        return len(line)

    def _find_nearest_declared_variable_type(
        self, source: str, variable_name: str, before_pos: int
    ) -> Optional[str]:
        """Return the nearest prior declaration for a variable within the current function scope."""
        cache = self._get_source_lookup_cache("_nearest_declared_type_cache", source)
        cache_key = (variable_name, before_pos)
        if cache_key in cache:
            return cache[cache_key]

        lines, starts = self._get_source_lines_and_starts(source)
        line_index = self._get_source_line_index(source, before_pos)
        if line_index != -1:
            current_line_prefix = source[starts[line_index] : before_pos]
            current_line_declarations = self._extract_declared_variable_types_from_line(
                current_line_prefix
            )
            if variable_name in current_line_declarations:
                cache[cache_key] = current_line_declarations[variable_name]
                return current_line_declarations[variable_name]

        boundary_index = self._get_enclosing_function_boundary_index(source, before_pos)
        if boundary_index is not None and line_index != -1:
            declarations = self._get_function_local_declarations_at_boundary(
                source, boundary_index
            ).get(variable_name, [])
            for declaration_line, declared_type in reversed(declarations):
                if declaration_line < line_index:
                    cache[cache_key] = declared_type
                    return declared_type
        elif line_index != -1:
            for index in range(line_index - 1, -1, -1):
                declarations = self._get_cached_line_declarations(source, index, lines[index])
                if variable_name in declarations:
                    cache[cache_key] = declarations[variable_name]
                    return declarations[variable_name]
        parameter_type = self._find_nearest_parameter_type(source, variable_name, before_pos)
        if parameter_type:
            cache[cache_key] = parameter_type
            return parameter_type
        cache[cache_key] = None
        return None

    def _find_nearest_parameter_type(
        self, source: str, variable_name: str, before_pos: int
    ) -> Optional[str]:
        """Return a parameter type for the current function when local declarations do not define it."""
        cache = self._get_source_lookup_cache("_nearest_parameter_type_cache", source)
        cache_key = (variable_name, before_pos)
        if cache_key in cache:
            return cache[cache_key]
        boundary_index = self._get_enclosing_function_boundary_index(source, before_pos)
        if boundary_index is None:
            cache[cache_key] = None
            return None
        parameter_type = self._get_function_parameter_types_at_boundary(source, boundary_index).get(
            variable_name
        )
        cache[cache_key] = parameter_type
        return parameter_type

    def _is_function_boundary_line(self, lines: List[str], index: int) -> bool:
        """Return whether the current line closes off a function-local declaration search."""
        stripped = lines[index].strip()
        if not stripped:
            return False
        if stripped.endswith("{"):
            head = stripped[:-1].strip()
            if (
                head
                and re.match(
                    r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\([^;]*\)$",
                    head,
                )
                and not re.match(r"^(?:if|for|while|switch|else|do|try)\b", head)
            ):
                return True
        if stripped == "{":
            signature_parts: List[str] = []
            paren_balance = 0
            for previous_index in range(index - 1, -1, -1):
                previous = lines[previous_index].strip()
                if not previous:
                    continue
                if previous.startswith(("#", "//", "/*", "*")):
                    continue
                if previous.endswith(";") and not signature_parts:
                    return False
                signature_parts.insert(0, previous)
                paren_balance += previous.count(")") - previous.count("(")
                combined = " ".join(signature_parts)
                if (
                    "(" in combined
                    and paren_balance >= 0
                    and re.match(
                        r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\([^;]*\)$",
                        combined,
                    )
                    and not re.match(r"^(?:if|for|while|switch|else|do|try)\b", combined)
                ):
                    return True
                if previous in {"}", "{"} and not signature_parts:
                    return False
        return False

    # ------------------------------------------------------------------
    # Fix #1 — Undeclared split-local normalization
    # ------------------------------------------------------------------
    def _normalize_undeclared_split_locals(self, source: str) -> str:
        """Resolve undeclared _varname = GHIDRA_U128/U64/auVar/uVar/lVar patterns.

        Ghidra occasionally emits overlapping stack-variable assignments of the
        form ``_local_228 = GHIDRA_U128(0x0);`` when it loses type context for a
        variable it has already declared as ``local_228`` elsewhere.  The leading
        underscore makes ``_local_228`` an undeclared identifier, causing a hard
        compiler error.  This fix is safe because it merely aligns the assignment
        target with the existing declaration — no semantic change is made.
        """
        if not _SPLIT_LOCAL_ASSIGN_RE.search(source):
            return source  # fast path: no matches

        try:
            variable_types = self._extract_declared_variable_types(source)
        except Exception as exc:  # fail closed: malformed input
            logger.warning("_normalize_undeclared_split_locals: type extraction failed: %s", exc)
            return source

        lines = source.splitlines(keepends=True)
        output_lines: List[str] = []
        injected: set[str] = set()

        for line in lines:
            m = _SPLIT_LOCAL_ASSIGN_RE.match(line.rstrip("\r\n"))
            if m:
                varname = m.group("varname")
                if varname in variable_types:
                    # Declared version exists — just drop the leading underscore.
                    line = line.replace(f"_{varname}", varname, 1)
                elif varname not in injected:
                    # No declaration found — inject one immediately before this line.
                    indent = m.group("indent")
                    output_lines.append(f"{indent}uint64_t {varname};\n")
                    injected.add(varname)
                    line = line.replace(f"_{varname}", varname, 1)
            output_lines.append(line)

        return "".join(output_lines)

    # ------------------------------------------------------------------
    # Fix #3 — Fragment-local unification
    # ------------------------------------------------------------------
    def _unify_fragment_locals(self, source: str) -> str:
        """Inject bare variable declarations alongside Ghidra fragment-suffixed statics.

        Ghidra splits overlapping stack variables into fragments such as
        ``uStack_88_4_4_``, then references the unsuffixed name ``uStack_88``
        elsewhere in the same function.  The bare name is never declared, so the
        compiler rejects it.  The safer approach (chosen here) is to emit a
        ``volatile uint64_t uStack_88 = 0;`` at the same scope as the fragment
        declaration, making the bare reference legal without changing semantics.
        ``volatile`` prevents the compiler from incorrectly eliding the variable.
        """
        if not _FRAGMENT_DECL_RE.search(source):
            return source  # fast path: no fragment declarations

        try:
            variable_types = self._extract_declared_variable_types(source)
        except Exception as exc:  # fail closed: malformed input
            logger.warning("_unify_fragment_locals: type extraction failed: %s", exc)
            return source

        lines = source.splitlines(keepends=True)
        output_lines: List[str] = []
        injected: set[str] = set()

        for line in lines:
            m = _FRAGMENT_DECL_RE.match(line.rstrip("\r\n"))
            output_lines.append(line)
            if m:
                base = m.group("base")
                if base not in variable_types and base not in injected:
                    indent = m.group("indent")
                    output_lines.append(f"{indent}volatile uint64_t {base} = 0;\n")
                    injected.add(base)

        return "".join(output_lines)

    # ------------------------------------------------------------------
    # Fix #2 helper — extend prototype widening to param_1..param_9
    # ------------------------------------------------------------------
    def _widen_undefined8_param_prototypes(self, source: str) -> str:
        """Widen ``undefined8 *param_N`` (N >= 1) to ``void *param_N`` when call
        sites pass pointer-typed arguments at that position.

        The existing ``_relax_mismatched_pointer_prototypes`` already handles
        param_0, but Ghidra frequently emits ``undefined8 *param_2`` and higher
        indices that are also called with pointer locals.  This pass extends the
        same conservative analysis to param_1 through param_9: if *every* resolved
        call site passes a pointer-typed expression at position N, the declaration
        is rewritten to ``void *``; if any call site is ambiguous the prototype is
        left unchanged.
        """
        # Delegate to the existing method which already handles param_1..N
        # correctly after the regex was generalised (see candidate_positions_by_name
        # collection in _relax_mismatched_pointer_prototypes).  This wrapper
        # exists so the pipeline can call it as a distinct, named stage and so
        # the stage name appears in whole-source debug dumps.
        return self._relax_mismatched_pointer_prototypes(source)

    def _relax_mismatched_pointer_prototypes(self, source: str) -> str:
        """Widen obviously wrong pointer/scalar parameter types based on call-site usage."""
        variable_types = self._extract_declared_variable_types(source)
        signature_pattern = re.compile(
            r"(?P<prefix>^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+)(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>[^)]*)\)(?P<suffix>\s*(?:;|\{))",
            re.MULTILINE,
        )
        signature_matches = list(signature_pattern.finditer(source))

        boundary_names: Dict[int, str] = {}

        def get_function_name_at_boundary(boundary_index: int) -> str:
            if boundary_index in boundary_names:
                return boundary_names[boundary_index]
            lines, _starts = self._get_source_lines_and_starts(source)
            signature_parts: list[str] = []
            paren_balance = 0
            signature_line: Optional[str] = None
            for index in range(boundary_index, -1, -1):
                candidate = lines[index].strip()
                if index == boundary_index:
                    if candidate == "{":
                        continue
                    if candidate.endswith("{"):
                        candidate = candidate[:-1].rstrip()
                if not candidate or candidate.startswith(("#", "//", "/*", "*")):
                    continue
                if candidate.endswith(";") and not signature_parts:
                    boundary_names[boundary_index] = ""
                    return ""
                signature_parts.insert(0, candidate)
                paren_balance += candidate.count(")") - candidate.count("(")
                combined = " ".join(signature_parts)
                if (
                    "(" in combined
                    and paren_balance >= 0
                    and re.match(
                        r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\([^)]*\)$",
                        combined,
                    )
                    and not re.match(r"^(?:if|for|while|switch|else|do|try)\b", combined)
                ):
                    signature_line = combined
                    break
            if not signature_line:
                boundary_names[boundary_index] = ""
                return ""
            signature_match = re.match(
                r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\([^)]*\)$",
                signature_line,
            )
            boundary_names[boundary_index] = (
                signature_match.group("name") if signature_match else ""
            )
            return boundary_names[boundary_index]

        candidate_positions_by_name: Dict[str, set[int]] = {}
        for match in signature_matches:
            name = match.group("name")
            candidate_positions = {
                index
                for index, param in enumerate(match.group("params").split(","))
                if re.search(r"\bundefined8\s*\*\s*param_\d+\b", param.strip())
                or re.search(r"\bundefined8\s+param_\d+\b", param.strip())
            }
            if candidate_positions:
                candidate_positions_by_name.setdefault(name, set()).update(candidate_positions)
        callback_positions_by_name: Dict[str, set[int]] = {}
        for callback_match in re.finditer(
            r"\(\(ghidra_indirect_fn(?:_0)?\)\s*param_(?P<index>\d+)\)\s*\(",
            source,
        ):
            boundary_index = self._get_enclosing_function_boundary_index(
                source, callback_match.start()
            )
            if boundary_index is None:
                continue
            function_name = get_function_name_at_boundary(boundary_index)
            if not function_name:
                continue
            callback_positions_by_name.setdefault(function_name, set()).add(
                int(callback_match.group("index")) - 1
            )

        signature_names = set(candidate_positions_by_name)
        call_args_by_name: Dict[str, List[tuple[List[str], int]]] = {}
        for call in self._collect_calls_for_names(source, signature_names):
            call_args_by_name.setdefault(str(call["name"]), []).append(
                (list(call["args"]), int(call["start"]))
            )
        observed_pointer_positions_by_name: Dict[str, set[int]] = {}
        pointer_expression_results: Dict[tuple[str, Optional[int], str], bool] = {}
        for name, call_args in call_args_by_name.items():
            pointer_positions: set[int] = set()
            candidate_positions = candidate_positions_by_name.get(name, set())
            for args, call_pos in call_args:
                boundary_index = self._get_enclosing_function_boundary_index(source, call_pos)
                for index in candidate_positions:
                    if index in pointer_positions or index >= len(args):
                        continue
                    argument = args[index].strip()
                    cache_key = (name, boundary_index, argument)
                    is_pointer_like = pointer_expression_results.get(cache_key)
                    if is_pointer_like is None:
                        is_pointer_like = self._is_pointer_like_expression(
                            source,
                            argument,
                            variable_types,
                            call_pos,
                        )
                        pointer_expression_results[cache_key] = is_pointer_like
                    if is_pointer_like:
                        pointer_positions.add(index)
                if pointer_positions == candidate_positions:
                    break
            if pointer_positions:
                observed_pointer_positions_by_name[name] = pointer_positions

        def replace_signature(match: re.Match[str]) -> str:
            params = match.group("params")
            name = match.group("name")
            pointer_positions = observed_pointer_positions_by_name.get(name, set())
            callback_positions = callback_positions_by_name.get(name, set())
            rewritten_params: List[str] = []
            changed = False
            for index, param in enumerate(params.split(",")):
                stripped_param = param.strip()
                replacement = stripped_param
                if index in pointer_positions and re.search(
                    r"\bundefined8\s*\*\s*param_\d+\b", stripped_param
                ):
                    replacement = re.sub(r"\bundefined8\s*\*", "void *", stripped_param, count=1)
                    changed = True
                elif index in pointer_positions and re.search(
                    r"\bundefined8\s+param_\d+\b", stripped_param
                ):
                    replacement = re.sub(r"\bundefined8\b", "uintptr_t", stripped_param, count=1)
                    changed = True
                elif index in callback_positions and re.search(
                    r"\bundefined\s*\*\s*param_\d+\b", stripped_param
                ):
                    replacement = re.sub(
                        r"\bundefined\s*\*\s*", "uintptr_t ", stripped_param, count=1
                    )
                    changed = True
                rewritten_params.append(replacement)
            if not changed:
                return match.group(0)
            separator = ", " if ", " in params else ","
            return f"{match.group('prefix')}{name}({separator.join(rewritten_params)}){match.group('suffix')}"

        return signature_pattern.sub(replace_signature, source)

    def _normalize_pointer_arguments_for_uintptr_params(self, source: str) -> str:
        """Cast pointer-like call arguments when widened signatures now expect uintptr_t."""
        variable_types = self._extract_declared_variable_types(source)
        signature_pattern = re.compile(
            r"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>[^)]*)\)\s*(?:;|\{)",
            re.MULTILINE,
        )
        uintptr_param_positions: Dict[str, set[int]] = {}
        for match in signature_pattern.finditer(source):
            positions = {
                index
                for index, param in enumerate(match.group("params").split(","))
                if re.search(r"\buintptr_t\s*param_\d+\b", param.strip())
            }
            if positions:
                uintptr_param_positions.setdefault(match.group("name"), set()).update(positions)

        updated = source
        calls_by_name: Dict[str, List[Dict[str, object]]] = {}
        for call in self._collect_calls_for_names(source, set(uintptr_param_positions)):
            calls_by_name.setdefault(str(call["name"]), []).append(call)
        rewrites: List[tuple[int, int, str]] = []
        for function_name, positions in uintptr_param_positions.items():
            calls = calls_by_name.get(function_name, [])
            for call in calls:
                rewritten_args: List[str] = []
                changed = False
                for index, arg in enumerate(call["args"]):
                    replacement = arg
                    if index in positions and self._is_pointer_like_expression(
                        source, arg, variable_types, int(call["start"])
                    ):
                        if (
                            not re.match(r"^(?:GHIDRA_U64|GHIDRA_U128)\(", arg.strip())
                            and "(uintptr_t)" not in arg
                        ):
                            replacement = f"GHIDRA_U64({arg.strip()})"
                            changed = True
                    rewritten_args.append(replacement)
                if not changed:
                    continue
                rewrites.append(
                    (
                        int(call["open_paren"]) + 1,
                        int(call["close_paren"]),
                        ", ".join(rewritten_args),
                    )
                )
        for start, end, replacement in sorted(rewrites, key=lambda item: item[0], reverse=True):
            updated = updated[:start] + replacement + updated[end:]
        updated = self._normalize_pointer_arguments_for_indirect_uintptr_calls(
            updated, variable_types
        )
        return updated

    def _normalize_pointer_arguments_for_indirect_uintptr_calls(
        self, source: str, variable_types: Dict[str, str]
    ) -> str:
        """Cast pointer-like first arguments at indirect call sites using ghidra_indirect_fn."""
        prefixes = ("((ghidra_indirect_fn)", "(*(ghidra_indirect_fn *)")
        updated = source
        index = 0
        while index < len(updated):
            next_match = min(
                (pos for prefix in prefixes if (pos := updated.find(prefix, index)) != -1),
                default=-1,
            )
            if next_match == -1:
                break
            matched_prefix = next(
                prefix for prefix in prefixes if updated.startswith(prefix, next_match)
            )
            expr_start = next_match + len(matched_prefix)
            depth = 0
            expr_end = expr_start
            while expr_end < len(updated):
                char = updated[expr_end]
                if char == "(":
                    depth += 1
                elif char == ")":
                    if depth == 0:
                        break
                    depth -= 1
                expr_end += 1
            if expr_end >= len(updated):
                break
            open_paren = expr_end + 1
            if open_paren < len(updated) and updated[open_paren] == ")":
                open_paren += 1
            while open_paren < len(updated) and updated[open_paren].isspace():
                open_paren += 1
            if open_paren >= len(updated) or updated[open_paren] != "(":
                index = expr_end + 1
                continue
            close_paren = self._find_matching_paren(updated, open_paren)
            if close_paren == -1:
                break
            args = self._split_top_level_arguments(updated[open_paren + 1 : close_paren])
            if not args:
                index = close_paren + 1
                continue
            first_arg = args[0].strip()
            if (
                not first_arg
                or re.match(r"^(?:GHIDRA_U64|GHIDRA_U128)\(", first_arg)
                or "(uintptr_t)" in first_arg
                or not self._is_pointer_like_expression(
                    updated, first_arg, variable_types, next_match
                )
            ):
                index = close_paren + 1
                continue
            args[0] = f"GHIDRA_U64({first_arg})"
            updated = (
                updated[: open_paren + 1]
                + ", ".join(arg.strip() for arg in args)
                + updated[close_paren:]
            )
            index = open_paren + len(", ".join(arg.strip() for arg in args)) + 1
        return updated

    def _collect_call_arguments(
        self, source: str, function_name: str
    ) -> List[tuple[List[str], int]]:
        """Collect balanced argument lists for real call sites while skipping declarations."""
        return [
            (call["args"], int(call["start"]))
            for call in self._collect_calls(source, function_name)
        ]

    def _looks_like_multiline_function_declaration(
        self, source: str, match_start: int, close_paren: int
    ) -> bool:
        """Return whether a matched name(...) span is part of a multiline declaration/definition."""
        suffix_index = close_paren + 1
        while suffix_index < len(source) and source[suffix_index].isspace():
            suffix_index += 1
        if suffix_index >= len(source) or source[suffix_index] not in ";{":
            return False

        lines, starts = self._get_source_lines_and_starts(source)
        line_index = self._get_source_line_index(source, match_start)
        if line_index == -1:
            return False

        signature_parts = [source[starts[line_index] : close_paren + 1].strip()]
        if not signature_parts[0]:
            return False
        paren_balance = signature_parts[0].count(")") - signature_parts[0].count("(")

        for previous_index in range(line_index - 1, -1, -1):
            previous = lines[previous_index].strip()
            if not previous:
                continue
            if previous.endswith(("{", "}", ";")):
                return False
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_\s\*]*", previous):
                return False
            signature_parts.insert(0, previous)
            paren_balance += previous.count(")") - previous.count("(")
            combined = " ".join(signature_parts)
            if (
                "(" in combined
                and paren_balance >= 0
                and re.match(
                    r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\([^;]*\)$",
                    combined,
                )
                and not re.match(r"^(?:if|for|while|switch|else|do|try)\b", combined)
            ):
                return True
        return False

    def _collect_calls_for_names(
        self, source: str, function_names: set[str]
    ) -> List[Dict[str, object]]:
        """Collect balanced call spans for many function names in a single source scan."""
        if not function_names:
            return []
        call_sites: List[Dict[str, object]] = []
        alternation = "|".join(
            sorted((re.escape(name) for name in function_names), key=len, reverse=True)
        )
        pattern = re.compile(rf"\b(?P<name>{alternation})\s*\(")
        for match in pattern.finditer(source):
            function_name = match.group("name")
            line_start = source.rfind("\n", 0, match.start()) + 1
            prefix = source[line_start : match.start()].strip()
            if prefix and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_ \t\*]*", prefix):
                continue
            open_paren = source.find("(", match.start())
            if open_paren == -1:
                continue
            close_paren = self._find_matching_paren(source, open_paren)
            if close_paren == -1:
                continue
            if self._looks_like_multiline_function_declaration(source, match.start(), close_paren):
                continue
            args = [
                piece.strip()
                for piece in self._split_top_level_arguments(source[open_paren + 1 : close_paren])
            ]
            call_sites.append(
                {
                    "name": function_name,
                    "args": args,
                    "start": match.start(),
                    "open_paren": open_paren,
                    "close_paren": close_paren,
                }
            )
        return call_sites

    def _collect_calls(self, source: str, function_name: str) -> List[Dict[str, object]]:
        """Collect balanced call spans for a generated function name while skipping declarations."""
        return self._collect_calls_for_names(source, {function_name})

    def _find_matching_paren(self, source: str, open_paren: int) -> int:
        """Find the matching closing parenthesis for an opening parenthesis position."""
        cache = self._get_source_lookup_cache("_matching_paren_cache", source)
        if open_paren in cache:
            return cache[open_paren]
        depth = 0
        for index in range(open_paren, len(source)):
            char = source[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    cache[open_paren] = index
                    return index
        cache[open_paren] = -1
        return -1

    def _is_pointer_like_expression(
        self, source: str, expression: str, variable_types: Dict[str, str], before_pos: int
    ) -> bool:
        """Return whether an argument expression is pointer-like enough to warrant uintptr_t casting."""
        stripped = expression.strip()
        cache = self._get_source_lookup_cache("_pointer_like_expression_cache", source)
        cache_key = (stripped, before_pos)
        if cache_key in cache:
            return cache[cache_key]

        def is_address_storage(declared_type: str) -> bool:
            normalized = " ".join(declared_type.split())
            return self._is_pointer_declared_type(normalized) or (
                "[" in normalized and "]" in normalized
            )

        inferred_type = self._infer_expression_declared_type(stripped, variable_types)
        if is_address_storage(inferred_type):
            cache[cache_key] = True
            return True
        if re.match(r'^"(?:[^"\\]|\\.)*"$', stripped):
            cache[cache_key] = True
            return True
        if stripped.startswith("&"):
            cache[cache_key] = True
            return True
        deref_match = re.match(r"^\*\s*(?P<base>[A-Za-z_][A-Za-z0-9_]*)$", stripped)
        if deref_match:
            base_name = deref_match.group("base")
            if base_name not in variable_types:
                parameter_type = self._find_nearest_parameter_type(source, base_name, before_pos)
                if parameter_type and self._is_pointer_declared_type(parameter_type):
                    cache[cache_key] = True
                    return True
                if parameter_type is None:
                    cache[cache_key] = False
                    return False
            base_type = variable_types.get(
                base_name, ""
            ) or self._find_nearest_declared_variable_type(source, base_name, before_pos)
            if base_type and self._is_pointer_declared_type(base_type):
                cache[cache_key] = True
                return True
        if re.match(r"^(?:&\s*)?(?:FUN|PTR(?:_FUN)?|_?UNK|_?DAT|DAT)_[A-Za-z0-9_]+$", stripped):
            cache[cache_key] = True
            return True
        base_match = re.match(r"^(?P<base>[A-Za-z_][A-Za-z0-9_]*)\b", stripped)
        if not base_match:
            cache[cache_key] = False
            return False
        base_name = base_match.group("base")
        base_type = variable_types.get(base_name, "")
        if base_type and is_address_storage(base_type):
            cache[cache_key] = True
            return True
        if base_name not in variable_types:
            parameter_type = self._find_nearest_parameter_type(source, base_name, before_pos)
            if parameter_type and is_address_storage(parameter_type):
                cache[cache_key] = True
                return True
            if parameter_type is None:
                cache[cache_key] = False
                return False
        nearest_type = self._find_nearest_declared_variable_type(source, base_name, before_pos)
        if nearest_type and is_address_storage(nearest_type):
            cache[cache_key] = True
            return True
        cache[cache_key] = False
        return False

    def _split_top_level_arguments(self, arguments: str) -> List[str]:
        """Split a comma-separated argument list while respecting nested parentheses."""
        parts: List[str] = []
        current: List[str] = []
        depth = 0
        for char in arguments:
            if char == "," and depth == 0:
                part = "".join(current).strip()
                if part:
                    parts.append(part)
                current = []
                continue
            if char == "(":
                depth += 1
            elif char == ")" and depth > 0:
                depth -= 1
            current.append(char)
        part = "".join(current).strip()
        if part:
            parts.append(part)
        return parts

    def _relax_mismatched_void_prototypes(self, source: str) -> str:
        """Rewrite generated zero-arg declarations when calls supply arguments."""
        updated = source
        declaration_lines = source.splitlines()
        zero_arg_declared_names = {
            match.group(1)
            for line in declaration_lines
            if (
                match := re.match(
                    r"^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*(?:void)?\s*\)\s*(?:;|\{)?\s*$",
                    line.strip(),
                )
            )
        }
        for name in sorted(zero_arg_declared_names):
            has_argument_call = False
            for line in declaration_lines:
                stripped = line.strip()
                if not stripped or name not in stripped or f"{name}(" not in stripped:
                    continue
                prefix = stripped.split(name, 1)[0].strip()
                if prefix and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_ \t\*]*", prefix):
                    continue
                if re.match(
                    rf"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+{re.escape(name)}\s*\(\s*void\s*\)\s*(?:;|\{{)?\s*$",
                    stripped,
                ):
                    continue
                call_match = re.search(rf"\b{re.escape(name)}\s*\(([^)]*)\)", stripped)
                if call_match and call_match.group(1).strip():
                    has_argument_call = True
                    break
            if has_argument_call:
                updated = re.sub(
                    rf"(^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\b{re.escape(name)})\s*\(\s*void\s*\)\s*;",
                    r"\1(uintptr_t param_1, ...);",
                    updated,
                    flags=re.MULTILINE,
                )
                updated = re.sub(
                    rf"(^\s*[A-Za-z_][A-Za-z0-9_\s\*]*\b{re.escape(name)})\s*\(\s*\)\s*;",
                    r"\1(uintptr_t param_1, ...);",
                    updated,
                    flags=re.MULTILINE,
                )
        return updated

    def _align_conflicting_function_prototypes(self, source: str) -> str:
        """Align forward declarations with later definitions when their parameter surface matches."""
        definition_pattern = re.compile(
            r"^(?P<signature>\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>[^)]*)\))\s*\{$",
            re.MULTILINE,
        )
        declaration_pattern = re.compile(
            r"^(?P<signature>\s*[A-Za-z_][A-Za-z0-9_\s\*]*\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>[^)]*)\))\s*;$",
            re.MULTILINE,
        )

        def normalize_params(params: str) -> str:
            return re.sub(r"\s+", "", params)

        definitions = {
            match.group("name"): (normalize_params(match.group("params")), match.group("signature"))
            for match in definition_pattern.finditer(source)
        }

        rewritten_lines: List[str] = []
        for line in source.splitlines():
            match = declaration_pattern.match(line)
            if not match:
                rewritten_lines.append(line)
                continue
            definition = definitions.get(match.group("name"))
            if not definition or definition[0] != normalize_params(match.group("params")):
                rewritten_lines.append(line)
                continue
            rewritten_lines.append(f"{definition[1]};")
        return "\n".join(rewritten_lines)

    def _relax_void_return_functions_used_as_values(self, source: str) -> str:
        """Widen generated void signatures when call sites use their return values."""
        void_signature_pattern = re.compile(
            r"^(?P<indent>\s*)void\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>[^)]*)\)(?P<suffix>\s*(?:;|\{))",
            re.MULTILINE,
        )
        candidate_names = {match.group("name") for match in void_signature_pattern.finditer(source)}
        used_as_values = {
            name
            for name in candidate_names
            if re.search(rf"=\s*(?:\([^)]+\)\s*)*{re.escape(name)}\s*\(", source)
        }
        if not used_as_values:
            return source
        return re.sub(
            r"(^\s*)void(\s+)([A-Za-z_][A-Za-z0-9_]*\()",
            lambda match: (
                f"{match.group(1)}uintptr_t{match.group(2)}{match.group(3)}"
                if match.group(3)[:-1] in used_as_values
                else match.group(0)
            ),
            source,
            flags=re.MULTILINE,
        )

    def _normalize_bare_returns_for_scalar_functions(self, source: str) -> str:
        """Rewrite bare returns inside non-void scalar/pointer functions to zero-valued returns."""
        lines = source.splitlines()
        if not lines:
            return source

        boundary_indices = set(self._get_function_boundary_indices(source))
        current_return_type = ""
        function_brace_depth = 0
        function_started = False

        def extract_return_type(signature_line: str) -> str:
            match = re.match(
                r"^(?P<ret>[A-Za-z_][A-Za-z0-9_\s\*]*?)\s+[A-Za-z_][A-Za-z0-9_]*\([^;]*\)\s*$",
                signature_line.strip(),
            )
            if not match:
                return ""
            return match.group("ret").strip()

        def resolve_boundary_return_type(boundary_index: int) -> str:
            stripped = lines[boundary_index].strip()
            signature_parts: List[str] = []
            if stripped and stripped != "{":
                signature_parts.insert(
                    0, stripped[:-1].rstrip() if stripped.endswith("{") else stripped
                )
            for previous_index in range(boundary_index - 1, -1, -1):
                previous = lines[previous_index].strip()
                if not previous:
                    continue
                if previous.endswith(";") and not signature_parts:
                    break
                signature_parts.insert(0, previous)
                combined = " ".join(part for part in signature_parts if part).strip()
                return_type = extract_return_type(combined)
                if return_type:
                    return return_type
            combined = " ".join(part for part in signature_parts if part).strip()
            return extract_return_type(combined)

        def collect_boundary_return_types() -> Dict[int, str]:
            collected: Dict[int, str] = {}
            signature_parts: List[str] = []
            collecting_signature = False

            for index, line in enumerate(lines):
                stripped = line.strip()
                if not stripped or stripped.startswith(("#", "//", "/*", "*")):
                    continue
                if not collecting_signature:
                    if stripped.endswith("{"):
                        head = stripped[:-1].strip()
                        if self._looks_like_function_signature(head):
                            collected[index] = extract_return_type(head)
                        continue
                    if self._looks_like_function_signature_start(stripped):
                        signature_parts = [stripped]
                        collecting_signature = True
                    continue
                if stripped.endswith(";"):
                    signature_parts = []
                    collecting_signature = False
                    continue
                if stripped == "{":
                    combined = " ".join(part for part in signature_parts if part).strip()
                    collected[index] = extract_return_type(combined)
                    signature_parts = []
                    collecting_signature = False
                    continue
                signature_parts.append(stripped)

            return collected

        boundary_return_types = collect_boundary_return_types()

        for index, line in enumerate(lines):
            stripped = line.strip()
            is_boundary_line = index in boundary_indices or index in boundary_return_types
            if is_boundary_line:
                current_return_type = boundary_return_types.get(index)
                if current_return_type is None:
                    current_return_type = resolve_boundary_return_type(index)
                    boundary_return_types[index] = current_return_type
                function_brace_depth = line.count("{") - line.count("}")
                function_started = function_brace_depth > 0
            if (
                current_return_type
                and stripped == "return;"
                and (
                    self._is_integer_declared_type(current_return_type)
                    or self._is_pointer_declared_type(current_return_type)
                )
            ):
                indent = line[: len(line) - len(line.lstrip())]
                lines[index] = f"{indent}return ({current_return_type})0;"
            if current_return_type:
                if not is_boundary_line:
                    function_brace_depth += line.count("{") - line.count("}")
                    if line.count("{") > 0:
                        function_started = True
                if function_started and function_brace_depth <= 0:
                    current_return_type = ""
                    function_brace_depth = 0
                    function_started = False

        return "\n".join(lines)

    def _restore_generated_labels(self, source: str) -> str:
        """Restore decompiler labels whose trailing ':' was sanitized into '_'."""
        label_pattern = re.compile(
            r"^(\s*)(LAB_[A-Za-z0-9]+_|joined_r0x[0-9A-Fa-f]+_|code_r0x[0-9A-Fa-f]+_|label_0x[0-9A-Fa-f]+_)\s*(?:;\s*)?$",
            re.MULTILINE,
        )

        def replace_label(match: re.Match[str]) -> str:
            indent, label = match.groups()
            return f"{indent}{label.rstrip('_')}:"

        return label_pattern.sub(replace_label, source)

    def _extract_declared_function_names(self, source: str) -> set[str]:
        """Extract function names from declaration/definition lines only."""
        declared_names: set[str] = set()
        for line in source.splitlines():
            stripped = line.strip()
            if (
                not stripped
                or stripped.startswith(("//", "/*", "*", "#"))
                or "=" in stripped
                or "(" not in stripped
                or ")" not in stripped
                or not stripped.endswith((";", "{"))
            ):
                continue
            match = re.match(
                r"^[A-Za-z_][A-Za-z0-9_ \t\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*(?:;|\{)$",
                stripped,
            )
            if match:
                declared_names.add(match.group(1))
        declared_names.update(
            re.findall(
                r"^[A-Za-z_][A-Za-z0-9_ \t\*]*\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\n\s*\{",
                source,
                flags=re.MULTILINE,
            )
        )
        return declared_names

    def _qualify_unresolved_function_aliases(self, source: str) -> str:
        """Rewrite unqualified helper call names to unique declared fully-qualified symbols."""
        declared_names = self._extract_declared_function_names(source)
        called_names = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", source))
        all_names = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", source))
        bare_reference_names = all_names.difference(declared_names, called_names)
        c_builtin_type_names = {
            "bool",
            "byte",
            "char",
            "code",
            "double",
            "float",
            "int",
            "long",
            "longlong",
            "short",
            "signed",
            "size_t",
            "ssize_t",
            "uchar",
            "uint",
            "uint16_t",
            "uint32_t",
            "uint64_t",
            "uint8_t",
            "uintptr_t",
            "ulong",
            "ulonglong",
            "unsigned",
            "undefined",
            "undefined1",
            "undefined2",
            "undefined4",
            "undefined8",
            "void",
            "wchar_t",
        }
        lines, starts = self._get_source_lines_and_starts(source)
        qualified_alias_candidates: Dict[str, List[str]] = {}
        for candidate in declared_names:
            if not candidate.startswith(("core_", "std_", "alloc_")):
                continue
            underscore_positions = [index for index, char in enumerate(candidate) if char == "_"]
            for underscore_index in underscore_positions:
                bare_name = candidate[underscore_index + 1 :]
                qualified_alias_candidates.setdefault(bare_name, []).append(candidate)

        boundary_function_names: Dict[int, str] = {}

        def get_function_name_at_boundary(boundary_index: int) -> str:
            if boundary_index in boundary_function_names:
                return boundary_function_names[boundary_index]
            signature_parts: List[str] = []
            paren_balance = 0
            signature_line: Optional[str] = None
            for index in range(boundary_index, -1, -1):
                candidate = lines[index].strip()
                if index == boundary_index:
                    if candidate == "{":
                        continue
                    if candidate.endswith("{"):
                        candidate = candidate[:-1].rstrip()
                if not candidate:
                    continue
                if candidate.startswith(("#", "//", "/*", "*")):
                    continue
                if candidate.endswith(";") and not signature_parts:
                    break
                signature_parts.insert(0, candidate)
                paren_balance += candidate.count(")") - candidate.count("(")
                combined = " ".join(signature_parts)
                if (
                    "(" in combined
                    and paren_balance >= 0
                    and self._looks_like_function_signature(combined)
                ):
                    signature_line = combined
                    break
            boundary_function_names[boundary_index] = (
                self._extract_function_name(signature_line or "") or ""
            )
            return boundary_function_names[boundary_index]

        def current_function_name_for_position(position: int) -> str:
            boundary_index = self._get_enclosing_function_boundary_index(source, position)
            if boundary_index is None:
                return ""
            return get_function_name_at_boundary(boundary_index)

        def in_simple_declaration(position: int) -> bool:
            line_index = max(0, bisect_right(starts, min(max(position, 0), len(source))) - 1)
            if not (0 <= line_index < len(lines)):
                return False
            stripped = lines[line_index].strip()
            if not stripped or "=" in stripped or not stripped.endswith(";"):
                return False
            return self._match_variable_declaration(stripped[:-1].rstrip()) is not None

        def shared_namespace_score(current_function: str, candidate: str) -> int:
            if not current_function:
                return 0
            current_parts = current_function.split("_")
            candidate_parts = candidate.split("_")
            score = 0
            for current_part, candidate_part in zip(current_parts, candidate_parts):
                if current_part != candidate_part:
                    break
                score += 1
            return score

        def resolve_alias(name: str, current_function: str = "") -> str | None:
            if name.startswith("_") and name[1:] in declared_names:
                return name[1:]
            candidates = qualified_alias_candidates.get(name, [])
            if len(candidates) == 1:
                return candidates[0]
            if candidates and current_function:
                scored_candidates = [
                    (shared_namespace_score(current_function, candidate), candidate)
                    for candidate in candidates
                ]
                best_score = max(score for score, _candidate in scored_candidates)
                if best_score > 0:
                    best_candidates = [
                        candidate for score, candidate in scored_candidates if score == best_score
                    ]
                    if len(best_candidates) == 1:
                        return best_candidates[0]
            return None

        updated = source

        call_sites = list(re.finditer(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", updated))
        for match in reversed(call_sites):
            name = match.group(1)
            if name in declared_names:
                continue
            resolved = resolve_alias(name, current_function_name_for_position(match.start()))
            if not resolved:
                resolved = resolve_alias(name)
            if resolved:
                updated = updated[: match.start(1)] + resolved + updated[match.end(1) :]

        bare_reference_pattern = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b(?!\s*\()")
        for match in reversed(list(bare_reference_pattern.finditer(updated))):
            name = match.group(1)
            if name in declared_names or name not in bare_reference_names:
                continue
            if name in c_builtin_type_names:
                continue
            if in_simple_declaration(match.start()):
                continue
            resolved = resolve_alias(name, current_function_name_for_position(match.start()))
            if not resolved:
                resolved = resolve_alias(name)
            if resolved:
                updated = updated[: match.start(1)] + resolved + updated[match.end(1) :]
        return updated

    def _build_generated_symbol_prelude(self, source: str) -> str:
        """Declare synthetic Ghidra/global symbols discovered in generated source."""
        function_names = self._extract_declared_function_names(source)
        called_functions = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", source))
        defined_labels = set(re.findall(r"^\s*(LAB_[A-Za-z0-9]+):", source, flags=re.MULTILINE))
        signature_pattern = re.compile(
            r"(?P<return_type>^\s*[A-Za-z_][A-Za-z0-9_\s\*]*?)\s+"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\((?P<params>[^)]*)\)\s*(?:;|\{)",
            re.MULTILINE,
        )
        explicit_pointer_param_bases_by_name: Dict[str, Dict[int, str]] = {}
        function_return_types: Dict[str, str] = {}
        for match in signature_pattern.finditer(source):
            function_name = match.group("name")
            function_return_types[function_name] = " ".join(match.group("return_type").split())
            explicit_pointer_params: Dict[int, str] = {}
            for index, param in enumerate(self._split_top_level_arguments(match.group("params"))):
                declaration_match = self._match_variable_declaration(param.strip())
                if not declaration_match:
                    continue
                declared_type = " ".join(
                    f"{declaration_match.group('type').strip()}{declaration_match.group('array') or ''}".split()
                )
                pointer_match = re.match(
                    r"^(?P<base>[A-Za-z_][A-Za-z0-9_\s]*?)\s*\*$", declared_type
                )
                if not pointer_match:
                    continue
                base_type = " ".join(pointer_match.group("base").split())
                if base_type in {"void", "code"}:
                    continue
                explicit_pointer_params[index] = base_type
            if explicit_pointer_params:
                explicit_pointer_param_bases_by_name[function_name] = explicit_pointer_params
        hmodule_like_names = set(
            re.findall(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*(?:==|!=)\s*\(HMODULE\)0x0"
                r"|GetProcAddress\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*,"
                r"|\b([A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*LoadLibraryA\s*\(",
                source,
            )
        )
        hmodule_like_names = {name for groups in hmodule_like_names for name in groups if name}
        farproc_like_names = set(
            re.findall(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*(?:==|!=)\s*\(FARPROC\)0x0"
                r"|\(\(ghidra_indirect_fn(?:_0)?\)([A-Za-z_][A-Za-z0-9_]*)\)"
                r"|\b([A-Za-z_][A-Za-z0-9_]*)\b\s*=\s*[A-Za-z_][A-Za-z0-9_]*\s*,",
                source,
            )
        )
        farproc_like_names = {name for groups in farproc_like_names for name in groups if name}
        handle_like_names = set(
            re.findall(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\b\s*(?:==|!=)\s*\(HANDLE\)0x0"
                r"|\(HANDLE\)\(uintptr_t\)([A-Za-z_][A-Za-z0-9_]*)\b",
                source,
            )
        )
        handle_like_names = {name for groups in handle_like_names for name in groups if name}
        inferred_symbol_templates: Dict[str, str] = {}

        def zero_literal_for_scalar_type(base_type: str) -> str:
            return "0"

        def record_symbol_template(name: str, template: str) -> None:
            inferred_symbol_templates.setdefault(name, template)

        def strip_pointer_suffix(declared_type: str) -> str:
            return re.sub(r"\s*\*\s*$", "", " ".join(declared_type.split())).strip()

        lines, _starts = self._get_source_lines_and_starts(source)
        line_to_boundary = self._get_line_to_boundary_index_map(source)
        boundary_signature_cache: Dict[int, Tuple[str, str]] = {}

        def get_function_signature_at_boundary(boundary_index: int) -> Tuple[str, str]:
            if boundary_index in boundary_signature_cache:
                return boundary_signature_cache[boundary_index]
            signature_parts: list[str] = []
            paren_balance = 0
            signature_line: Optional[str] = None
            for index in range(boundary_index, -1, -1):
                candidate = lines[index].strip()
                if index == boundary_index:
                    if candidate == "{":
                        continue
                    if candidate.endswith("{"):
                        candidate = candidate[:-1].rstrip()
                if not candidate or candidate.startswith(("#", "//", "/*", "*")):
                    continue
                if candidate.endswith(";") and not signature_parts:
                    boundary_signature_cache[boundary_index] = ("", "")
                    return boundary_signature_cache[boundary_index]
                signature_parts.insert(0, candidate)
                paren_balance += candidate.count(")") - candidate.count("(")
                combined = " ".join(signature_parts)
                if (
                    "(" in combined
                    and paren_balance >= 0
                    and re.match(
                        r"^[A-Za-z_][A-Za-z0-9_\s\*]*\s+[A-Za-z_][A-Za-z0-9_]*\([^)]*\)$",
                        combined,
                    )
                    and not re.match(r"^(?:if|for|while|switch|else|do|try)\b", combined)
                ):
                    signature_line = combined
                    break
            if not signature_line:
                boundary_signature_cache[boundary_index] = ("", "")
                return boundary_signature_cache[boundary_index]
            signature_match = re.match(
                r"^(?P<return_type>[A-Za-z_][A-Za-z0-9_\s\*]*?)\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\([^)]*\)$",
                signature_line,
            )
            if not signature_match:
                boundary_signature_cache[boundary_index] = ("", "")
                return boundary_signature_cache[boundary_index]
            boundary_signature_cache[boundary_index] = (
                signature_match.group("name"),
                " ".join(signature_match.group("return_type").split()),
            )
            return boundary_signature_cache[boundary_index]

        for line_index, line in enumerate(lines):
            boundary_index = (
                line_to_boundary[line_index] if line_index < len(line_to_boundary) else None
            )
            if boundary_index is None:
                continue
            function_name, return_type = get_function_signature_at_boundary(boundary_index)
            if not function_name:
                continue
            stripped = line.strip()
            if "*" in return_type:
                bare_return_match = re.match(r"^return\s+(?P<name>DAT_[0-9A-Fa-f]+)\s*;$", stripped)
                if bare_return_match:
                    record_symbol_template(
                        bare_return_match.group("name"),
                        f"static {return_type} {{name}} = ({return_type})0;",
                    )
                address_return_match = re.match(
                    r"^return\s+&(?P<name>DAT_[0-9A-Fa-f]+)\b", stripped
                )
                if address_return_match:
                    base_type = strip_pointer_suffix(return_type)
                    record_symbol_template(
                        address_return_match.group("name"),
                        f"static {base_type} {{name}} = {zero_literal_for_scalar_type(base_type)};",
                    )

        if explicit_pointer_param_bases_by_name:
            for call in self._collect_calls_for_names(
                source, set(explicit_pointer_param_bases_by_name)
            ):
                parameter_bases = explicit_pointer_param_bases_by_name.get(str(call["name"]), {})
                for index, arg in enumerate(call["args"]):
                    base_type = parameter_bases.get(index)
                    if not base_type:
                        continue
                    arg_match = re.match(r"^\s*&\s*(?P<name>DAT_[0-9A-Fa-f]+)\b", str(arg).strip())
                    if not arg_match:
                        continue
                    record_symbol_template(
                        arg_match.group("name"),
                        f"static {base_type} {{name}} = {zero_literal_for_scalar_type(base_type)};",
                    )

        def infer_synthetic_symbol_template(name: str, default_template: str) -> str:
            if self._get_split_fragment_base_name(name):
                return default_template
            if name in inferred_symbol_templates:
                return inferred_symbol_templates[name]
            if name in hmodule_like_names:
                return "static HMODULE {name} = (HMODULE)0;"
            if name in farproc_like_names:
                return "static FARPROC {name} = (FARPROC)0;"
            if name in handle_like_names:
                return "static HANDLE {name} = (HANDLE)0;"
            return default_template

        declaration_groups = [
            (
                re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*_exref\b", source),
                "static code *{name} = (code *)0;",
            ),
            (
                re.findall(r"\b_{2,3}xmm_[0-9A-Fa-f]+\b", source),
                "static const ghidra_uint128 {name} = (ghidra_uint128)0;",
            ),
            (
                re.findall(r"\bDAT_[0-9A-Fa-f]+\b", source),
                "static uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\b(?:_?UNK|_DAT|DAT)_[0-9A-Fa-f]+\b", source),
                "static uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\b(?:UINT|PTR_FUN)_[0-9A-Fa-f]+\b", source),
                "static const uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\bPTR_[A-Za-z0-9_]+\b", source),
                "static const uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\b_{2,3}real_[0-9A-Fa-f]+\b", source),
                "static const uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\b_xmm_[0-9A-Fa-f]+(?:_[0-9A-Fa-f]+){2,}_\b", source),
                "static const uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\bstack0x?[0-9A-Fa-f]+\b", source),
                "static char {name} = 0;",
            ),
            (
                re.findall(r"\b[ui]Ram[0-9A-Fa-f]+\b", source),
                "static uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\bcore_[A-Za-z0-9_]+\b", source),
                "static const uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\bs_[A-Za-z0-9_]+(?:__+)[A-Za-z0-9_]+\b", source),
                "static const unsigned char {name}[32] = {{0}};",
            ),
            (
                [
                    name
                    for name in re.findall(r"&\s*(LAB_[A-Za-z0-9]+)\b", source)
                    if name not in defined_labels
                ],
                "static const uint64_t {name} = 0;",
            ),
            (
                re.findall(r"\bswitchD_[A-Za-z0-9_]+\b", source),
                "static const int {name}[1] = {{0}};",
            ),
            (
                re.findall(r"\b[A-Za-z][A-Za-z0-9]*(?:_[0-9A-Za-z]+){2,}_\b", source),
                "static uint64_t {name} = 0;",
            ),
        ]

        declarations: list[str] = []
        seen: set[str] = set()
        for names, template in declaration_groups:
            for name in sorted(set(names)):
                if name in seen:
                    continue
                if name in function_names:
                    continue
                if name in called_functions:
                    continue
                declarations.append(
                    infer_synthetic_symbol_template(name, template).format(name=name)
                )
                seen.add(name)

        return "\n".join(declarations)

    def _build_generated_helper_prelude(self, source: str) -> str:
        """Declare lightweight helper stubs for unresolved runtime/toolchain functions."""
        declared_functions = self._extract_declared_function_names(source)
        called_functions = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", source))
        declared_function_signatures = {
            match.group("name"): {
                "signature": " ".join(match.group("signature").split()),
                "return_type": " ".join(match.group("return_type").split()),
            }
            for match in re.finditer(
                r"^(?P<signature>(?P<return_type>[A-Za-z_][A-Za-z0-9_ \t\*]*?)\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\))\s*(?:;|\{)",
                source,
                flags=re.MULTILINE,
            )
        }
        defined_functions = {
            match.group("name")
            for match in re.finditer(
                r"^(?P<signature>[A-Za-z_][A-Za-z0-9_ \t\*]*\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\))\s*(?:(?:\n\s*)+\{|\{)",
                source,
                flags=re.MULTILINE,
            )
        }
        helper_definition_signatures = {
            match.group("name"): f"{match.group('signature')};"
            for match in re.finditer(
                r"^(?P<signature>[A-Za-z_][A-Za-z0-9_ \t\*]*\s+(?P<name>(?:core_|std_|alloc_)[A-Za-z0-9_]+)\s*\([^;{}]*\))\s*(?:(?:\n\s*)+\{|\{)",
                source,
                flags=re.MULTILINE,
            )
        }
        bare_symbol_references = {
            name
            for name in called_functions
            if re.search(rf"\b{re.escape(name)}\b(?!\s*\()", source)
        }
        excluded_names = {
            *declared_functions,
            "if",
            "for",
            "while",
            "switch",
            "return",
            "sizeof",
            "memcpy",
            "memmove",
            "memcmp",
            "malloc",
            "calloc",
            "realloc",
            "free",
            "printf",
            "fprintf",
            "sprintf",
            "snprintf",
            "exit",
            "atexit",
        }
        stub_names = sorted(
            name
            for name in called_functions
            if name not in excluded_names
            and (
                name
                in {
                    "movmskpd",
                    "movmskps",
                    "cpuid_basic_info",
                    "cpuid_Version_info",
                    "cpuid_Extended_Feature_Enumeration_info",
                    "cpuid",
                    "LOCK",
                    "UNLOCK",
                    "invalidInstructionException",
                    "never_",
                    "NtReadFile",
                    "NtWriteFile",
                    "RtlNtStatusToDosError",
                    "WaitOnAddress",
                    "WakeByAddressAll",
                }
                or name.startswith(("core_", "std_", "alloc_"))
                or name.startswith("imp_")
            )
        )
        helper_managed_api_aliases = {
            "GetStdHandle": "reveng_fallback_GetStdHandle",
            "imp_GetStdHandle": "reveng_fallback_GetStdHandle",
            "GetCommandLineW": "reveng_fallback_GetCommandLineW",
            "imp_GetCommandLineW": "reveng_fallback_GetCommandLineW",
            "GetCommandLineA": "reveng_fallback_GetCommandLineA",
            "imp_GetCommandLineA": "reveng_fallback_GetCommandLineA",
            "GetConsoleMode": "reveng_fallback_GetConsoleMode",
            "imp_GetConsoleMode": "reveng_fallback_GetConsoleMode",
            "GetConsoleOutputCP": "reveng_fallback_GetConsoleOutputCP",
            "imp_GetConsoleOutputCP": "reveng_fallback_GetConsoleOutputCP",
            "MultiByteToWideChar": "reveng_fallback_MultiByteToWideChar",
            "imp_MultiByteToWideChar": "reveng_fallback_MultiByteToWideChar",
            "WideCharToMultiByte": "reveng_fallback_WideCharToMultiByte",
            "imp_WideCharToMultiByte": "reveng_fallback_WideCharToMultiByte",
            "WriteConsoleW": "reveng_fallback_WriteConsoleW",
            "imp_WriteConsoleW": "reveng_fallback_WriteConsoleW",
            "NtWriteFile": "reveng_fallback_NtWriteFile",
            "imp_NtWriteFile": "reveng_fallback_NtWriteFile",
            "WaitForSingleObject": "reveng_fallback_WaitForSingleObject",
            "imp_WaitForSingleObject": "reveng_fallback_WaitForSingleObject",
            "GetLastError": "reveng_fallback_GetLastError",
            "imp_GetLastError": "reveng_fallback_GetLastError",
        }
        helper_managed_present = {
            name for name in helper_managed_api_aliases if name in called_functions
        }

        declarations: list[str] = []
        if "reveng_reg_" in source or "reveng_stack_0x" in source:
            declarations.extend(
                [
                    "static uint64_t reveng_reg_rax = 0ULL;",
                    "static uint64_t reveng_reg_rbx = 0ULL;",
                    "static uint64_t reveng_reg_rcx = 0ULL;",
                    "static uint64_t reveng_reg_rdx = 0ULL;",
                    "static uint64_t reveng_reg_rsi = 0ULL;",
                    "static uint64_t reveng_reg_rdi = 0ULL;",
                    "static uint64_t reveng_reg_rbp = 0ULL;",
                    "static uint64_t reveng_reg_rsp = 0ULL;",
                    "static uint64_t reveng_reg_r8 = 0ULL;",
                    "static uint64_t reveng_reg_r9 = 0ULL;",
                    "static uint64_t reveng_reg_r10 = 0ULL;",
                    "static uint64_t reveng_reg_r11 = 0ULL;",
                    "static uint64_t reveng_reg_r12 = 0ULL;",
                    "static uint64_t reveng_reg_r13 = 0ULL;",
                    "static uint64_t reveng_reg_r14 = 0ULL;",
                    "static uint64_t reveng_reg_r15 = 0ULL;",
                    "static uint64_t reveng_stack_0x20 = 0ULL;",
                    "static uint64_t reveng_stack_0x28 = 0ULL;",
                    "static uint64_t reveng_stack_0x30 = 0ULL;",
                    "static uint64_t reveng_stack_0x38 = 0ULL;",
                    "static uint64_t reveng_stack_0x40 = 0ULL;",
                ]
            )
        if helper_managed_present:
            declarations.extend(
                [
                    "static uint64_t reveng_fallback_stdout_handle = 0xfffffff5ULL;",
                    "static uint64_t reveng_fallback_stderr_handle = 0xfffffff4ULL;",
                    "static uint64_t reveng_fallback_stdin_handle = 0xfffffff6ULL;",
                    "static uint64_t reveng_fallback_write_call_count = 0;",
                    "static uint64_t reveng_fallback_last_write_length = 0ULL;",
                    "static inline FILE *reveng_fallback_trace_stream(void) { "
                    'const char *trace_path = getenv("REVENG_FALLBACK_TRACE_FILE"); '
                    "if (!trace_path || !*trace_path) { return NULL; } "
                    'return fopen(trace_path, "a"); }',
                    "static inline void reveng_fallback_trace_ascii(FILE *trace_file, const unsigned char *buffer, size_t length) { "
                    "size_t preview = length < 24U ? length : 24U; "
                    "for (size_t index = 0; index < preview; ++index) { "
                    "unsigned char ch = buffer[index]; fputc((ch >= 0x20U && ch < 0x7fU) ? (int)ch : '.', trace_file); } }",
                    "static inline void reveng_fallback_trace_wascii(FILE *trace_file, const uint16_t *buffer, size_t length) { "
                    "size_t preview = length < 24U ? length : 24U; "
                    "for (size_t index = 0; index < preview; ++index) { "
                    "uint16_t ch = buffer[index]; fputc((ch >= 0x20U && ch < 0x7fU) ? (int)ch : '.', trace_file); } }",
                    "static inline void reveng_fallback_trace_event_prefix(FILE *trace_file, const char *api_name) { "
                    'fprintf(trace_file, "{\\"api\\":\\"%s\\",", api_name); }',
                    "static inline void reveng_fallback_trace_write_console("
                    "uint64_t handle, uint64_t buffer, uint64_t length, uint64_t chars_written) { "
                    "FILE *trace_file = reveng_fallback_trace_stream(); if (!trace_file) { return; } "
                    'reveng_fallback_trace_event_prefix(trace_file, "WriteConsoleW"); '
                    'fprintf(trace_file, "\\"handle\\":%llu,\\"buffer\\":%llu,\\"length\\":%llu,\\"chars_written\\":%llu,\\"preview\\":\\"", '
                    "(unsigned long long)handle, (unsigned long long)buffer, (unsigned long long)length, (unsigned long long)chars_written); "
                    "if (buffer && buffer >= 0x10000ULL) { reveng_fallback_trace_wascii(trace_file, (const uint16_t *)(uintptr_t)buffer, (size_t)length); } "
                    'fprintf(trace_file, "\\"}\\n"); fclose(trace_file); }',
                    "static inline void reveng_fallback_trace_ntwrite("
                    "uint64_t handle, uint64_t buffer, uint64_t length, uint64_t io_status_block) { "
                    "FILE *trace_file = reveng_fallback_trace_stream(); if (!trace_file) { return; } "
                    'reveng_fallback_trace_event_prefix(trace_file, "NtWriteFile"); '
                    'fprintf(trace_file, "\\"handle\\":%llu,\\"buffer\\":%llu,\\"length\\":%llu,\\"io_status_block\\":%llu,\\"preview\\":\\"", '
                    "(unsigned long long)handle, (unsigned long long)buffer, (unsigned long long)length, (unsigned long long)io_status_block); "
                    "if (buffer && buffer >= 0x10000ULL) { reveng_fallback_trace_ascii(trace_file, (const unsigned char *)(uintptr_t)buffer, (size_t)length); } "
                    'fprintf(trace_file, "\\"}\\n"); fclose(trace_file); }',
                    "static inline void reveng_fallback_trace_multibyte("
                    "const char *api_name, uint64_t source, uint64_t source_count, uint64_t dest, uint64_t dest_count) { "
                    "FILE *trace_file = reveng_fallback_trace_stream(); if (!trace_file) { return; } "
                    "reveng_fallback_trace_event_prefix(trace_file, api_name); "
                    'fprintf(trace_file, "\\"source\\":%llu,\\"source_count\\":%llu,\\"dest\\":%llu,\\"dest_count\\":%llu}\\n", '
                    "(unsigned long long)source, (unsigned long long)source_count, (unsigned long long)dest, (unsigned long long)dest_count); "
                    "fclose(trace_file); }",
                    "static inline void reveng_fallback_trace_u64_1("
                    "const char *api_name, const char *field_name, uint64_t value) { "
                    "FILE *trace_file = reveng_fallback_trace_stream(); if (!trace_file) { return; } "
                    "reveng_fallback_trace_event_prefix(trace_file, api_name); "
                    'fprintf(trace_file, "\\"%s\\":%llu}\\n", field_name, (unsigned long long)value); '
                    "fclose(trace_file); }",
                    "static inline void reveng_fallback_trace_u64_2("
                    "const char *api_name, const char *field_name_1, uint64_t value_1, "
                    "const char *field_name_2, uint64_t value_2) { "
                    "FILE *trace_file = reveng_fallback_trace_stream(); if (!trace_file) { return; } "
                    "reveng_fallback_trace_event_prefix(trace_file, api_name); "
                    'fprintf(trace_file, "\\"%s\\":%llu,\\"%s\\":%llu}\\n", '
                    "field_name_1, (unsigned long long)value_1, field_name_2, (unsigned long long)value_2); "
                    "fclose(trace_file); }",
                    "static inline void reveng_fallback_trace_function(const char *name, uint64_t address) { "
                    "FILE *trace_file = reveng_fallback_trace_stream(); if (!trace_file) { return; } "
                    'reveng_fallback_trace_event_prefix(trace_file, "FunctionEntry"); '
                    'fprintf(trace_file, "\\"name\\":\\"%s\\",\\"address\\":%llu}\\n", '
                    "name, (unsigned long long)address); fclose(trace_file); }",
                    "static inline FILE *reveng_fallback_stream_for_handle(uint64_t handle) { "
                    "if (handle == reveng_fallback_stderr_handle) { return stderr; } "
                    "return stdout; }",
                    "static inline uint64_t reveng_fallback_GetStdHandle(uint64_t selector) { "
                    "uint64_t handle = (uint64_t)(uintptr_t)GetStdHandle((DWORD)selector); "
                    'reveng_fallback_trace_u64_2("GetStdHandle", "selector", selector, "handle", handle); '
                    "if (handle) { return handle; } "
                    "if (selector == 0xfffffff4ULL) { return reveng_fallback_stderr_handle; } "
                    "if (selector == 0xfffffff6ULL) { return reveng_fallback_stdin_handle; } "
                    "return reveng_fallback_stdout_handle; }",
                    "static inline uint64_t reveng_fallback_GetCommandLineW(void) { "
                    "uint64_t command_line = (uint64_t)(uintptr_t)GetCommandLineW(); "
                    'reveng_fallback_trace_u64_1("GetCommandLineW", "result", command_line); '
                    "return command_line; }",
                    "static inline uint64_t reveng_fallback_GetCommandLineA(void) { "
                    "uint64_t command_line = (uint64_t)(uintptr_t)GetCommandLineA(); "
                    'reveng_fallback_trace_u64_1("GetCommandLineA", "result", command_line); '
                    "return command_line; }",
                    "static inline uint64_t reveng_fallback_GetConsoleMode(uint64_t handle, uint64_t mode_ptr) { "
                    'reveng_fallback_trace_u64_2("GetConsoleMode", "handle", handle, "mode_ptr", mode_ptr); '
                    "if (GetConsoleMode((HANDLE)(uintptr_t)handle, (LPDWORD)(uintptr_t)mode_ptr)) { return 1ULL; } "
                    "if (mode_ptr) { *(uint32_t *)(uintptr_t)mode_ptr = 7U; } "
                    "return 1; }",
                    "static inline uint64_t reveng_fallback_GetConsoleOutputCP(void) { "
                    "UINT code_page = GetConsoleOutputCP(); "
                    'reveng_fallback_trace_u64_1("GetConsoleOutputCP", "code_page", (uint64_t)code_page); '
                    "return code_page ? (uint64_t)code_page : 65001ULL; }",
                    "static inline uint64_t reveng_fallback_GetLastError(void) { "
                    "return (uint64_t)GetLastError(); }",
                    "static inline uint64_t reveng_fallback_WaitForSingleObject(uint64_t handle, uint64_t milliseconds) { "
                    "return (uint64_t)WaitForSingleObject((HANDLE)(uintptr_t)handle, (DWORD)milliseconds); }",
                    "static inline uint64_t reveng_fallback_MultiByteToWideChar("
                    "uint64_t code_page, uint64_t flags, uint64_t multi_byte_str, uint64_t multi_byte_count, "
                    "uint64_t wide_char_str, uint64_t wide_char_count) { "
                    "(void)code_page; (void)flags; "
                    'reveng_fallback_trace_multibyte("MultiByteToWideChar", multi_byte_str, multi_byte_count, wide_char_str, wide_char_count); '
                    "if (!multi_byte_str || !wide_char_str || wide_char_count == 0) { return 0; } "
                    "{ const unsigned char *src = (const unsigned char *)(uintptr_t)multi_byte_str; "
                    "uint16_t *dst = (uint16_t *)(uintptr_t)wide_char_str; size_t limit = (size_t)wide_char_count; size_t count = 0; "
                    "if ((int64_t)multi_byte_count < 0) { while (count < limit && src[count] != 0) { dst[count] = src[count]; count++; } } "
                    "else { size_t source_limit = (size_t)multi_byte_count; while (count < limit && count < source_limit) { dst[count] = src[count]; count++; } } "
                    "if (count < limit) { dst[count] = 0; } return (uint64_t)count; } }",
                    "static inline uint64_t reveng_fallback_WideCharToMultiByte("
                    "uint64_t code_page, uint64_t flags, uint64_t wide_char_str, uint64_t wide_char_count, "
                    "uint64_t multi_byte_str, uint64_t multi_byte_count, uint64_t default_char, uint64_t used_default_char) { "
                    "(void)code_page; (void)flags; (void)default_char; "
                    'reveng_fallback_trace_multibyte("WideCharToMultiByte", wide_char_str, wide_char_count, multi_byte_str, multi_byte_count); '
                    "if (used_default_char && used_default_char >= 0x10000ULL) { *(int *)(uintptr_t)used_default_char = 0; } "
                    "if (!wide_char_str || !multi_byte_str || multi_byte_count == 0) { return 0; } "
                    "{ const uint16_t *src = (const uint16_t *)(uintptr_t)wide_char_str; "
                    "char *dst = (char *)(uintptr_t)multi_byte_str; size_t limit = (size_t)multi_byte_count; size_t count = 0; "
                    "if ((int64_t)wide_char_count < 0) { while (count < limit && src[count] != 0) { dst[count] = (char)(src[count] & 0x7f); count++; } } "
                    "else { size_t source_limit = (size_t)wide_char_count; while (count < limit && count < source_limit) { dst[count] = (char)(src[count] & 0x7f); count++; } } "
                    "if (count < limit) { dst[count] = '\\0'; } return (uint64_t)count; } }",
                    "static inline uint64_t reveng_fallback_NtWriteFile("
                    "uint64_t file_handle, uint64_t event_handle, uint64_t apc_routine, uint64_t apc_context, "
                    "uint64_t io_status_block, uint64_t buffer, uint64_t length, uint64_t byte_offset, uint64_t key) { "
                    "(void)event_handle; (void)apc_routine; (void)apc_context; (void)byte_offset; (void)key; "
                    "reveng_fallback_last_write_length = length; reveng_fallback_write_call_count++; "
                    "reveng_fallback_trace_ntwrite(file_handle, buffer, length, io_status_block); "
                    "if (io_status_block) { ((uint64_t *)(uintptr_t)io_status_block)[0] = 0ULL; "
                    "((uint64_t *)(uintptr_t)io_status_block)[1] = length; } "
                    "if (buffer && length && buffer >= 0x10000ULL) { "
                    "FILE *stream = reveng_fallback_stream_for_handle(file_handle); "
                    "fwrite((const void *)(uintptr_t)buffer, 1, (size_t)length, stream); fflush(stream); } "
                    "return 0; }",
                    "static inline uint64_t reveng_fallback_WriteConsoleW("
                    "uint64_t handle, uint64_t buffer, uint64_t length, uint64_t chars_written, uint64_t reserved) { "
                    "(void)reserved; reveng_fallback_last_write_length = length; reveng_fallback_write_call_count++; "
                    "reveng_fallback_trace_write_console(handle, buffer, length, chars_written); "
                    "if (WriteConsoleW((HANDLE)(uintptr_t)handle, (const void *)(uintptr_t)buffer, (DWORD)length, "
                    "(LPDWORD)(uintptr_t)chars_written, NULL)) { return 1ULL; } "
                    "if (chars_written && chars_written >= 0x10000ULL) { *(uint32_t *)(uintptr_t)chars_written = (uint32_t)length; } "
                    "if (buffer && length && buffer >= 0x10000ULL) { "
                    "const uint16_t *wide_buffer = (const uint16_t *)(uintptr_t)buffer; "
                    "FILE *stream = reveng_fallback_stream_for_handle(handle); "
                    "for (size_t index = 0; index < (size_t)length; ++index) { "
                    "uint16_t ch = wide_buffer[index]; fputc(ch < 0x80 ? (int)ch : '?', stream); } "
                    "fflush(stream); } "
                    "return length ? 1ULL : 0ULL; }",
                ]
            )
            for name in sorted(helper_managed_present):
                declarations.append(f"#undef {name}")
                declarations.append(
                    f"#define {name}(...) {helper_managed_api_aliases[name]}(__VA_ARGS__)"
                )
                if name in stub_names:
                    stub_names.remove(name)
        if "SBORROW1" in source:
            declarations.append(
                "static inline int SBORROW1(signed char left, signed char right) { "
                "signed char result = (signed char)(left - right); "
                "return ((left ^ right) & (left ^ result)) < 0; }"
            )
        if "SBORROW8" in source:
            declarations.append(
                "static inline int SBORROW8(longlong left, longlong right) { "
                "longlong result = left - right; "
                "return ((left ^ right) & (left ^ result)) < 0; }"
            )
        if "SCARRY8" in source:
            declarations.append(
                "static inline int SCARRY8(longlong left, longlong right) { "
                "longlong result = left + right; "
                "return ((~(left ^ right)) & (left ^ result)) < 0; }"
            )
        if "CARRY8" in source:
            declarations.append(
                "static inline int CARRY8(uint64_t left, uint64_t right) { "
                "return left > UINT64_MAX - right; }"
            )
        if "movmskpd" in stub_names:
            declarations.append("#define movmskpd(...) (0)")
            stub_names.remove("movmskpd")
        if "movmskps" in stub_names:
            declarations.append("#define movmskps(...) (0)")
            stub_names.remove("movmskps")
        for cpuid_name in (
            "cpuid_basic_info",
            "cpuid_Version_info",
            "cpuid_Extended_Feature_Enumeration_info",
            "cpuid",
        ):
            if cpuid_name in stub_names:
                declarations.append(f"#define {cpuid_name}(...) ((uint64_t)0)")
                stub_names.remove(cpuid_name)
        if "divpd" in source:
            declarations.append("#define divpd(lhs, rhs) (GHIDRA_U128(0))")
        for native_name in ("NtReadFile", "NtWriteFile", "RtlNtStatusToDosError"):
            if native_name in stub_names:
                declarations.append(f"#define {native_name}(...) ((uint64_t)0)")
                stub_names.remove(native_name)
        if "WaitOnAddress" in stub_names:
            declarations.append("#define WaitOnAddress(...) (0)")
            stub_names.remove("WaitOnAddress")
        if "WakeByAddressAll" in stub_names:
            declarations.append("#define WakeByAddressAll(...) ((uint64_t)0)")
            stub_names.remove("WakeByAddressAll")
        if "LOCK" in source:
            declarations.append("#define LOCK() ((void)0)")
            if "LOCK" in stub_names:
                stub_names.remove("LOCK")
        if "UNLOCK" in source:
            declarations.append("#define UNLOCK() ((void)0)")
            if "UNLOCK" in stub_names:
                stub_names.remove("UNLOCK")
        if "_tls_index" in source:
            declarations.append("static unsigned long _tls_index = 0;")
        for helper_global in (
            "__memset_fast_string_threshold",
            "__memset_nt_threshold",
            "__favor",
            "__isa_available",
            "__isa_enabled",
            "__isa_inverted",
            "__avx10_version",
        ):
            if helper_global in source:
                declarations.append(f"static uint64_t {helper_global} = 0;")
        if "pshuflw" in source:
            declarations.append("#define pshuflw(value, unused, mask) (GHIDRA_U128(value))")
        if "pshufhw" in source:
            declarations.append("#define pshufhw(value, unused, mask) (GHIDRA_U128(value))")
        entrypoint_names = {"main", "wmain", "WinMain", "WinMainCRTStartup", "DllMain"}
        if re.search(r"local pseudo[-_]C fallback", source) and not declared_functions.intersection(
            entrypoint_names
        ):
            fallback_entry_match = re.search(
                r"(?P<signature>(?P<return_type>[A-Za-z_][\w\s\*]*?)\s+"
                r"(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^)]*)\)\s*\{\s*"
                r"/\*\s*local pseudo[-_]C fallback for 0x[0-9a-fA-F]+\s*\*/)",
                source,
                flags=re.MULTILINE,
            )
            fallback_entry_name = (
                str(fallback_entry_match.group("name")).strip() if fallback_entry_match else None
            )
            if fallback_entry_name and fallback_entry_name in declared_functions:
                fallback_signature = declared_function_signatures.get(fallback_entry_name)
                if fallback_signature:
                    declarations.append(f"{fallback_signature['signature']};")
                else:
                    declarations.append(f"void {fallback_entry_name}(void);")
                declarations.append(f"int main(void) {{ {fallback_entry_name}(); return 0; }}")
            else:
                declarations.append("int main(void) { return 0; }")
        resolved_import_stub_names = [
            name
            for name in sorted(called_functions)
            if name
            and name[0].isupper()
            and name not in helper_managed_present
            and name not in defined_functions
            and name not in {"LOCK", "UNLOCK"}
        ]
        for name in resolved_import_stub_names:
            declarations.append(f"#undef {name}")
            declarations.append(f"#define {name}(...) ((uint64_t)0)")
            if name in stub_names:
                stub_names.remove(name)
        helper_forward_declarations = [
            helper_definition_signatures[name]
            for name in sorted(helper_definition_signatures)
            if name in called_functions or name in bare_symbol_references
        ]
        declarations.extend(helper_forward_declarations)
        for name in sorted(
            called_functions.intersection(declared_functions).difference(defined_functions)
        ):
            if name.startswith("imp_"):
                signature_info = declared_function_signatures.get(name)
                if not signature_info:
                    declarations.append(f"void {name}(void) {{ return; }}")
                    continue
                return_type = str(signature_info["return_type"])
                return_statement = (
                    "return;" if return_type == "void" else f"return ({return_type})0;"
                )
                declarations.append(f"{signature_info['signature']} {{ {return_statement} }}")
                continue
            if not name.startswith("sub_"):
                continue
            signature_info = declared_function_signatures.get(name)
            if not signature_info:
                continue
            return_type = str(signature_info["return_type"])
            return_statement = "return;" if return_type == "void" else f"return ({return_type})0;"
            declarations.append(f"{signature_info['signature']} {{ {return_statement} }}")
        undeclared_sub_stubs = sorted(
            name
            for name in called_functions.difference(declared_functions).difference(
                defined_functions
            )
            if name.startswith("sub_")
        )
        declarations.extend(
            f"static inline uint64_t {name}(void) {{ return 0; }}" for name in undeclared_sub_stubs
        )
        function_stub_names = [name for name in stub_names if name in bare_symbol_references]
        for name in function_stub_names:
            declarations.append(f"static inline uint64_t {name}() {{ return 0; }}")
            stub_names.remove(name)
        declarations.extend(f"#define {name}(...) ((uint64_t)0)" for name in stub_names)
        return "\n".join(declarations)

    def _strip_import_like_forward_declarations(self, source: str) -> str:
        """Drop import-like fallback prototypes so header declarations or stub macros can win."""
        called_functions = set(re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", source))
        defined_functions = {
            match.group("name")
            for match in re.finditer(
                r"^(?P<signature>[A-Za-z_][A-Za-z0-9_ \t\*]*\s+"
                r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\))\s*(?:(?:\n\s*)+\{|\{)",
                source,
                flags=re.MULTILINE,
            )
        }
        import_like_names = {
            name
            for name in called_functions
            if name
            and (name[0].isupper() or name.startswith("imp_"))
            and name not in defined_functions
            and name not in {"LOCK", "UNLOCK", "WinMain", "DllMain"}
        }
        if not import_like_names:
            return source

        prototype_pattern = re.compile(
            r"^(?P<signature>(?P<return_type>[A-Za-z_][A-Za-z0-9_ \t\*]*?)\s+"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\))\s*;\s*$",
            flags=re.MULTILINE,
        )
        stripped_source = prototype_pattern.sub(
            lambda match: "" if match.group("name") in import_like_names else match.group(0),
            source,
        )
        return re.sub(r"\n{3,}", "\n\n", stripped_source)

    def _inject_missing_import_like_stub_macros(self, source: str) -> str:
        """Backfill import-like stub macros on the final source if an earlier pass missed them."""
        helper_prelude = self._build_generated_helper_prelude(source)
        helper_managed_names = {
            "GetStdHandle",
            "imp_GetStdHandle",
            "GetConsoleMode",
            "imp_GetConsoleMode",
            "GetConsoleOutputCP",
            "imp_GetConsoleOutputCP",
            "WriteConsoleW",
            "imp_WriteConsoleW",
            "NtWriteFile",
            "imp_NtWriteFile",
            "WaitForSingleObject",
            "imp_WaitForSingleObject",
            "GetLastError",
            "imp_GetLastError",
        }
        macro_lines = [
            line
            for line in helper_prelude.splitlines()
            if re.match(r"^#(?:undef|define)\s+(?:imp_[A-Za-z0-9_]+|[A-Z][A-Za-z0-9_]*)\b", line)
            and not any(
                re.match(rf"^#(?:undef|define)\s+{re.escape(name)}\b", line)
                for name in helper_managed_names
            )
            and line not in source
        ]
        if not macro_lines:
            return source

        insertion_anchor = "#include <stdnoreturn.h>"
        macro_block = "\n".join(macro_lines)
        if insertion_anchor in source:
            return source.replace(insertion_anchor, f"{insertion_anchor}\n\n{macro_block}", 1)
        return f"{macro_block}\n\n{source}"

    def _inject_fallback_function_entry_traces(self, source: str) -> str:
        """Trace entry into locally lifted fallback functions when runtime tracing is enabled."""
        pattern = re.compile(
            r"(?P<header>^(?P<signature>[A-Za-z_][A-Za-z0-9_ \t\*]*\s+"
            r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\([^;{}]*\)\s*\{\s*)"
            r"(?P<indent>\s*)/\*\s*local pseudo[-_]C fallback for (?P<address>0x[0-9a-fA-F]+)\s*\*/\s*$)",
            flags=re.MULTILINE,
        )

        def _replacer(match: re.Match[str]) -> str:
            name = match.group("name")
            address = match.group("address")
            header = match.group("header")
            indent = match.group("indent") or "  "
            trace_line = f'{indent}reveng_fallback_trace_function("{name}", {address}ULL);'
            if "reveng_fallback_trace_function(" in match.group(0):
                return match.group(0)
            comment_line = f"{indent}/* local pseudo-C fallback for {address} */"
            return f"{header}{comment_line}\n{trace_line}"

        return pattern.sub(_replacer, source)

    def _should_skip_function_declaration(self, declaration_name: str) -> bool:
        """Skip prototypes known to collide with platform headers or C++ overloads."""
        if declaration_name in self._SKIPPED_DECLARATION_NAMES:
            return True
        if declaration_name.startswith("operator_"):
            return True
        return False

    async def _reconstruct_python_code(self, ghidra_data: Dict[str, Any]) -> str:
        """Generate Python equivalent of the binary."""
        if not self.gemini or not self.gemini.is_available():
            return "# Gemini not available for Python reconstruction"

        # Use Gemini to convert C to Python
        c_code = await self._reconstruct_c_code(ghidra_data)

        prompt = f"""Convert this C code to equivalent Python code.

C code:
```c
{c_code[:5000]}  # Limit to 5000 chars
```

Requirements:
- Preserve all functionality
- Use Python best practices
- Add type hints
- Include docstrings
- Use standard library (no external deps)

Output only the Python code, no explanations.
"""

        response = await self.gemini._generate_async(prompt)

        # Extract code from response
        if "```python" in response:
            start = response.find("```python") + 9
            end = response.find("```", start)
            return response[start:end].strip()

        return response

    async def _compile_c(self, source_file: str, output_dir: Path) -> str:
        """Compile C code with GCC."""
        output_binary = output_dir / "reconstructed_gcc"

        if os.name == "nt":
            output_binary = output_binary.with_suffix(".exe")

        result = await self._run_compiler_attempt("gcc", Path(source_file), output_binary)
        if result["success"]:
            return str(output_binary)
        raise CompilationError(f"GCC failed: {result['stderr']}")

    async def _compile_c_clang(self, source_file: str, output_dir: Path) -> str:
        """Compile C code with Clang."""
        output_binary = output_dir / "reconstructed_clang"

        if os.name == "nt":
            output_binary = output_binary.with_suffix(".exe")

        result = await self._run_compiler_attempt("clang", Path(source_file), output_binary)
        if result["success"]:
            return str(output_binary)
        raise CompilationError(f"Clang failed: {result['stderr']}")

    def _static_vulnerability_scan(self, code: str) -> List[Dict[str, Any]]:
        """Perform static pattern-based vulnerability detection."""
        vulnerabilities = []

        # Dangerous function patterns
        dangerous_patterns = {
            "strcpy": {"type": "buffer_overflow", "cwe": "CWE-120", "severity": "high"},
            "gets": {
                "type": "buffer_overflow",
                "cwe": "CWE-120",
                "severity": "critical",
            },
            "sprintf": {
                "type": "buffer_overflow",
                "cwe": "CWE-120",
                "severity": "high",
            },
            "strcat": {
                "type": "buffer_overflow",
                "cwe": "CWE-120",
                "severity": "medium",
            },
            "system(": {
                "type": "command_injection",
                "cwe": "CWE-78",
                "severity": "critical",
            },
            "popen(": {
                "type": "command_injection",
                "cwe": "CWE-78",
                "severity": "high",
            },
        }

        lines = code.split("\n")
        for line_num, line in enumerate(lines, 1):
            for pattern, info in dangerous_patterns.items():
                if pattern in line and not line.strip().startswith("//"):
                    vulnerabilities.append(
                        {
                            "type": info["type"],
                            "severity": info["severity"],
                            "cwe": info["cwe"],
                            "location": f"line {line_num}",
                            "code": line.strip(),
                            "description": f"Dangerous function {pattern} detected",
                            "exploit_available": False,
                        }
                    )

        return vulnerabilities

    def _save_results(self, results: Dict[str, Any], output_dir: Path):
        """Save reconstruction results to JSON."""
        import json

        output_file = output_dir / "reconstruction_results.json"

        # Make results JSON-serializable
        clean_results = {
            "binary_path": results["binary_path"],
            "status": results["status"],
            "cfg_artifacts": results.get("cfg_artifacts", {}),
            "cfg_summary": results.get("cfg_summary", {}),
            "source_files": results["source_files"],
            "compiled_binaries": results["compiled_binaries"],
            "compilation_reports": results.get("compilation_reports", {}),
            "native_output_traces": results.get("native_output_traces", {}),
            "differential_validation": results.get("differential_validation", {}),
            "equivalence_validation": results.get("equivalence_validation", {}),
            "validation_results": results["validation_results"],
            "vulnerabilities": results["vulnerabilities"],
            "exploits": results["exploits"],
        }

        with open(output_file, "w") as f:
            json.dump(clean_results, f, indent=2)

        logger.info(f"\n📊 Results saved to: {output_file}")

    _SKIPPED_DECLARATION_NAMES = {
        "_onexit",
        "atexit",
        "exit",
        "memcmp",
        "memcpy",
        "memmove",
    }
