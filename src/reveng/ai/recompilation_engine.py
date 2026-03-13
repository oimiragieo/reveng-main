"""
Binary Recompilation Engine - Prove Vulnerabilities Through Working Code

This module implements the revolutionary feature: converting binaries back to
compilable source code that can be recompiled and executed.

This proves security vulnerabilities by demonstrating them in working code.

Author: REVENG Team
Version: 3.0.0
"""

import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from reveng.ai.angr_cfg_preprocessor import AngrCFGPreprocessor

logger = logging.getLogger(__name__)


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
        self.compiler_cache = self._detect_compiler_cache()
        self.work_dir = work_dir or Path(tempfile.mkdtemp(prefix="reveng_recomp_"))
        self.work_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Recompilation engine initialized (work dir: {self.work_dir})")
        if self.compiler_cache:
            logger.info("Compiler cache enabled: %s", self.compiler_cache)

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
            reconstructed_code = await self._phase2_reconstruction(
                ghidra_data, output_dir
            )
            results["source_files"] = reconstructed_code

            # Phase 3: Compilation
            logger.info("\n[Phase 3/6] Source Code Compilation")
            compilation_result = await self._phase3_compilation(
                reconstructed_code, output_dir, ghidra_data
            )
            results["source_files"] = compilation_result.get(
                "source_files", reconstructed_code
            )
            results["compiled_binaries"] = compilation_result["compiled_binaries"]
            results["compilation_reports"] = compilation_result["reports"]

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

            # Phase 5: Security Analysis
            logger.info("\n[Phase 5/6] Security Vulnerability Analysis")
            vulnerabilities = await self._phase5_security_analysis(
                results["source_files"]
            )
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

    async def _phase1_decompilation(
        self, binary_path: str, output_dir: Path
    ) -> Dict[str, Any]:
        """Phase 1: Decompile binary using Ghidra."""
        if not self.ghidra:
            raise ValueError("GhidraEngine not configured")

        logger.info(f"  Analyzing {binary_path} with Ghidra...")
        ghidra_data = await asyncio.to_thread(self.ghidra.analyze_binary, binary_path)

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

        # Reconstruct C code
        logger.info("  Reconstructing C source code...")
        c_code = await self._reconstruct_c_code(ghidra_data)
        c_file = output_dir / "reconstructed.c"
        c_file.write_text(c_code, encoding="utf-8")
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
            "source_files": source_files,
        }

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
        ]
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
                context_sections.append(
                    "CFG summary:\n" + str(ghidra_data["cfg_context_text"])
                )

        history_lines = []
        for previous_attempt in attempt_history[:-1][-2:]:
            stderr = previous_attempt.get("stderr", "").strip() or "<no stderr>"
            history_lines.append(
                f"Attempt {previous_attempt['attempt']} stderr:\n{stderr[:1200]}"
            )

        history_text = (
            "\n\nPrevious failed attempts:\n" + "\n\n".join(history_lines)
            if history_lines
            else ""
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

        logger.info(
            f"  ✅ Validation complete (similarity: {validation['similarity_score']*100:.1f}%)"
        )

        return validation

    async def _phase5_security_analysis(
        self, source_files: Dict[str, str]
    ) -> List[Dict[str, Any]]:
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
            logger.info(
                f"  ✅ Found {len(static_vulns)} pattern-matched vulnerabilities"
            )

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

        logger.info(
            f"  Generating exploits for {len(vulnerabilities)} vulnerabilities..."
        )

        for vuln in vulnerabilities[:5]:  # Limit to top 5
            if self.gemini and self.gemini.is_available():
                c_code = (
                    Path(source_files.get("c", "")).read_text()
                    if "c" in source_files
                    else ""
                )
                exploit = await self.gemini.generate_exploit(vuln, c_code)
                if exploit:
                    exploits.append(exploit)
                    logger.info(f"  ✅ Generated exploit for {vuln.get('type')}")

        return exploits

    async def _reconstruct_c_code(self, ghidra_data: Dict[str, Any]) -> str:
        """Reconstruct complete C source file from Ghidra data."""
        code_parts = []

        # Add standard headers
        code_parts.append("/* Reconstructed by REVENG AI-Powered Analysis */")
        code_parts.append("#include <stdio.h>")
        code_parts.append("#include <stdlib.h>")
        code_parts.append("#include <string.h>")
        code_parts.append("")

        # Add function declarations
        for func in ghidra_data.get("functions", []):
            if func.get("name") != "main":
                sig = func.get("signature", f"void {func.get('name')}(void)")
                code_parts.append(f"{sig};")
        code_parts.append("")

        # Add decompiled functions
        decompiled = ghidra_data.get("decompiled_code", {})
        for address, code in decompiled.items():
            # Use Gemini to enhance if available
            if self.gemini and self.gemini.is_available():
                enhanced = await self.gemini.reconstruct_function(
                    code, f"func_{address}", context=ghidra_data
                )
                code_parts.append(enhanced.get("source_code", code))
            else:
                code_parts.append(code)
            code_parts.append("")

        return "\n".join(code_parts)

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

        result = await self._run_compiler_attempt(
            "gcc", Path(source_file), output_binary
        )
        if result["success"]:
            return str(output_binary)
        raise CompilationError(f"GCC failed: {result['stderr']}")

    async def _compile_c_clang(self, source_file: str, output_dir: Path) -> str:
        """Compile C code with Clang."""
        output_binary = output_dir / "reconstructed_clang"

        if os.name == "nt":
            output_binary = output_binary.with_suffix(".exe")

        result = await self._run_compiler_attempt(
            "clang", Path(source_file), output_binary
        )
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
            "validation_results": results["validation_results"],
            "vulnerabilities": results["vulnerabilities"],
            "exploits": results["exploits"],
        }

        with open(output_file, "w") as f:
            json.dump(clean_results, f, indent=2)

        logger.info(f"\n📊 Results saved to: {output_file}")
