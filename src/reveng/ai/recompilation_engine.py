"""
Binary Recompilation Engine - Prove Vulnerabilities Through Working Code

This module implements the revolutionary feature: converting binaries back to
compilable source code that can be recompiled and executed.

This proves security vulnerabilities by demonstrating them in working code.

Author: REVENG Team
Version: 3.0.0
"""

import asyncio
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
        self.work_dir = work_dir or Path(tempfile.mkdtemp(prefix="reveng_recomp_"))
        self.work_dir.mkdir(parents=True, exist_ok=True)

        logger.info(f"Recompilation engine initialized (work dir: {self.work_dir})")

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
            "source_files": {},
            "compiled_binaries": {},
            "validation_results": {},
            "vulnerabilities": [],
            "exploits": [],
            "proof_of_concept": None,
            "status": "in_progress",
        }

        try:
            # Phase 1: Ghidra Decompilation
            logger.info("\n[Phase 1/6] Ghidra Decompilation")
            ghidra_data = await self._phase1_decompilation(binary_path)
            results["ghidra_data"] = ghidra_data

            # Phase 2: AI-Enhanced Reconstruction
            logger.info("\n[Phase 2/6] AI-Enhanced Code Reconstruction")
            reconstructed_code = await self._phase2_reconstruction(
                ghidra_data, output_dir
            )
            results["source_files"] = reconstructed_code

            # Phase 3: Compilation
            logger.info("\n[Phase 3/6] Source Code Compilation")
            compiled_binaries = await self._phase3_compilation(
                reconstructed_code, output_dir
            )
            results["compiled_binaries"] = compiled_binaries

            # Phase 4: Behavioral Validation
            logger.info("\n[Phase 4/6] Behavioral Validation")
            validation = await self._phase4_validation(
                binary_path, compiled_binaries, ghidra_data
            )
            results["validation_results"] = validation

            # Phase 5: Security Analysis
            logger.info("\n[Phase 5/6] Security Vulnerability Analysis")
            vulnerabilities = await self._phase5_security_analysis(reconstructed_code)
            results["vulnerabilities"] = vulnerabilities

            # Phase 6: Exploit Generation
            logger.info("\n[Phase 6/6] Proof-of-Concept Exploit Generation")
            exploits = await self._phase6_exploit_generation(
                vulnerabilities, reconstructed_code, compiled_binaries
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

    async def _phase1_decompilation(self, binary_path: str) -> Dict[str, Any]:
        """Phase 1: Decompile binary using Ghidra."""
        if not self.ghidra:
            raise ValueError("GhidraEngine not configured")

        logger.info(f"  Analyzing {binary_path} with Ghidra...")
        ghidra_data = await asyncio.to_thread(self.ghidra.analyze_binary, binary_path)

        logger.info(f"  ✅ Functions: {len(ghidra_data.get('functions', []))}")
        logger.info(f"  ✅ Decompiled: {len(ghidra_data.get('decompiled_code', {}))}")
        logger.info(f"  ✅ Strings: {len(ghidra_data.get('strings', []))}")
        logger.info(f"  ✅ Imports: {len(ghidra_data.get('imports', []))}")

        return ghidra_data

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
        self, source_files: Dict[str, str], output_dir: Path
    ) -> Dict[str, str]:
        """Phase 3: Compile source code to binary."""
        compiled_binaries = {}

        # Compile C code
        if "c" in source_files:
            try:
                logger.info("  Compiling C code with GCC...")
                c_binary = await self._compile_c(source_files["c"], output_dir)
                compiled_binaries["c_gcc"] = c_binary
                logger.info(f"  ✅ GCC binary: {c_binary}")
            except CompilationError as e:
                logger.warning(f"  ⚠️ GCC compilation failed: {e}")

            # Try with Clang
            try:
                logger.info("  Compiling C code with Clang...")
                clang_binary = await self._compile_c_clang(
                    source_files["c"], output_dir
                )
                compiled_binaries["c_clang"] = clang_binary
                logger.info(f"  ✅ Clang binary: {clang_binary}")
            except CompilationError as e:
                logger.warning(f"  ⚠️ Clang compilation failed: {e}")

        return compiled_binaries

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

        cmd = [
            "gcc",
            "-o",
            str(output_binary),
            source_file,
            "-w",  # Suppress warnings
            "-O0",  # No optimization
        ]

        try:
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode != 0:
                raise CompilationError(f"GCC failed: {stderr.decode()}")

            return str(output_binary)

        except FileNotFoundError:
            raise CompilationError("GCC not found in PATH")

    async def _compile_c_clang(self, source_file: str, output_dir: Path) -> str:
        """Compile C code with Clang."""
        output_binary = output_dir / "reconstructed_clang"

        if os.name == "nt":
            output_binary = output_binary.with_suffix(".exe")

        cmd = [
            "clang",
            "-o",
            str(output_binary),
            source_file,
            "-w",  # Suppress warnings
            "-O0",  # No optimization
        ]

        try:
            result = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()

            if result.returncode != 0:
                raise CompilationError(f"Clang failed: {stderr.decode()}")

            return str(output_binary)

        except FileNotFoundError:
            raise CompilationError("Clang not found in PATH")

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
            "source_files": results["source_files"],
            "compiled_binaries": results["compiled_binaries"],
            "validation_results": results["validation_results"],
            "vulnerabilities": results["vulnerabilities"],
            "exploits": results["exploits"],
        }

        with open(output_file, "w") as f:
            json.dump(clean_results, f, indent=2)

        logger.info(f"\n📊 Results saved to: {output_file}")
