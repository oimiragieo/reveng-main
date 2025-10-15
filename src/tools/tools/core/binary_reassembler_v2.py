#!/usr/bin/env python3
"""
Binary Reassembler Engine v2 - Enhanced with Documentation Generation
====================================================================

IMPROVED version with:
1. Architecture-aware compiler selection
2. Configurable validation (smoke tests, checksum)
3. Proper LIEF patching implementation
4. Platform detection and toolchain verification
5. Enhanced documentation generation for reconstructed code
6. Build script and dependency management generation
7. Comprehensive source code commenting and explanations

Author: Enhancement
Version: 2.1
"""

import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set

# Import reconstruction comparator
try:
    from reconstruction_comparator import ReconstructionComparator, ComparisonResult
except ImportError:
    logger = logging.getLogger(__name__)
    logger.warning("reconstruction_comparator module not found, comparison features will be limited")
    ReconstructionComparator = None
    ComparisonResult = None

# Import our validation module
try:
    from validation_config import BinaryValidator, ValidationConfig, ValidationMode
except ImportError:
    logger = logging.getLogger(__name__)
    logger.warning("validation_config module not found, validation will be limited")
    BinaryValidator = None
    ValidationConfig = None
    ValidationMode = None

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('binary_reassembler_v2.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class Architecture(Enum):
    """Supported architectures"""
    X86 = ("x86", "i386", "i686")
    X86_64 = ("x86_64", "x64", "amd64")
    ARM = ("arm", "armv7")
    ARM64 = ("aarch64", "arm64")
    MIPS = ("mips",)
    RISCV = ("riscv", "riscv64")

    @classmethod
    def from_string(cls, arch_str: str):
        """Parse architecture from string"""
        arch_str = arch_str.lower()
        for arch in cls:
            if arch_str in arch.value:
                return arch
        return None


@dataclass
class CompilerConfig:
    """Architecture-aware compiler configuration"""
    compiler: str
    flags: List[str]
    linker_flags: List[str]
    architecture: Architecture
    target_triple: Optional[str] = None  # e.g., "x86_64-pc-linux-gnu"

    @classmethod
    def detect_toolchain(cls, target_arch: Architecture) -> Optional['CompilerConfig']:
        """
        Detect available toolchain for target architecture

        Returns None if no compatible toolchain found.
        """
        system = platform.system().lower()
        machine = platform.machine().lower()

        logger.info(f"Detecting toolchain: system={system}, machine={machine}, target={target_arch.name}")

        # Try compilers in order of preference
        compilers = ['clang', 'gcc', 'cc']

        for compiler_name in compilers:
            if not shutil.which(compiler_name):
                continue

            # Build configuration (start with universal flags only)
            flags = ["-O2"]
            linker_flags = []
            target_triple = None  # Initialize to avoid potential uninitialized usage

            # Add -fPIC ONLY for Linux/macOS shared libraries (NOT for Windows PE)
            if system in ['linux', 'darwin']:
                flags.append("-fPIC")

            # Architecture-specific flags
            if target_arch == Architecture.X86_64:
                if system == 'windows':
                    flags.append("-m64")
                else:
                    flags.append("-m64")
                target_triple = "x86_64-pc-linux-gnu" if system == 'linux' else None

            elif target_arch == Architecture.X86:
                flags.append("-m32")
                target_triple = "i686-pc-linux-gnu" if system == 'linux' else None

            elif target_arch == Architecture.ARM64:
                if compiler_name == 'clang':
                    flags.append("--target=aarch64-linux-gnu")
                    target_triple = "aarch64-linux-gnu"
                else:
                    # Try cross-compiler
                    cross_compiler = "aarch64-linux-gnu-gcc"
                    if shutil.which(cross_compiler):
                        compiler_name = cross_compiler
                        target_triple = "aarch64-linux-gnu"
                    else:
                        continue  # Skip if no ARM toolchain

            # Add platform-specific flags
            if system == 'linux':
                flags.append("-fno-stack-protector")
            elif system == 'windows':
                linker_flags.extend(["-lkernel32", "-luser32"])

            # Verify compiler works
            if cls._test_compiler(compiler_name, flags):
                logger.info(f"Selected toolchain: {compiler_name}")
                return cls(
                    compiler=compiler_name,
                    flags=flags,
                    linker_flags=linker_flags,
                    architecture=target_arch,
                    target_triple=target_triple
                )

        logger.error(f"No compatible toolchain found for {target_arch.name}")
        return None

    @staticmethod
    def _test_compiler(compiler: str, flags: List[str]) -> bool:
        """Test if compiler works"""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
                f.write("int main() { return 0; }")
                test_file = f.name

            result = subprocess.run(
                [compiler, *flags, test_file, "-o", test_file + ".out"],
                capture_output=True,
                timeout=10,
                check=False
            )

            Path(test_file).unlink(missing_ok=True)
            Path(test_file + ".out").unlink(missing_ok=True)

            return result.returncode == 0

        except Exception:
            return False


@dataclass
class DocumentationConfig:
    """Configuration for documentation generation"""
    generate_comments: bool = True
    generate_build_scripts: bool = True
    generate_readme: bool = True
    generate_makefile: bool = True
    include_analysis_metadata: bool = True
    comment_style: str = "detailed"  # "minimal", "detailed", "verbose"
    enable_comparison: bool = True
    generate_comparison_report: bool = True
    
@dataclass
class ReassemblyResult:
    """Result of reassembly operation"""
    success: bool
    output_binary: Optional[Path]
    errors: List[str]
    warnings: List[str]
    compilation_time: float
    size_original: int
    size_reassembled: int
    validation_results: Optional[Dict] = None
    documentation_generated: List[Path] = field(default_factory=list)
    build_scripts_generated: List[Path] = field(default_factory=list)
    dependencies_identified: Set[str] = field(default_factory=set)
    comparison_result: Optional['ComparisonResult'] = None


class BinaryReassemblerV2:
    """
    Binary Reassembler v2

    Improvements:
    - Architecture-aware compiler detection
    - Configurable validation
    - Proper LIEF patching
    - Better error handling
    """

    def __init__(
        self,
        original_binary: Path,
        architecture: Architecture = None,
        validation_config: ValidationConfig = None,
        documentation_config: DocumentationConfig = None
    ):
        """Initialize the binary reassembler"""
        self.original_binary = original_binary
        self.temp_dir = Path(tempfile.mkdtemp(prefix="reassembly_"))

        # Auto-detect architecture if not specified
        if architecture is None:
            architecture = self._detect_binary_architecture()

        self.architecture = architecture

        # Detect toolchain
        self.compiler_config = CompilerConfig.detect_toolchain(architecture)

        if self.compiler_config is None:
            raise RuntimeError(
                f"No compatible toolchain found for {architecture.name}. "
                f"Please install gcc or clang for your platform."
            )

        # Setup validation
        self.validation_config = validation_config or ValidationConfig()
        if BinaryValidator:
            self.validator = BinaryValidator(self.validation_config)
        else:
            self.validator = None

        # Setup documentation
        self.documentation_config = documentation_config or DocumentationConfig()

        # Check for LIEF
        self.has_lief = self._check_library("lief")
        self.has_keystone = self._check_library("keystone")

        logger.info("Binary Reassembler v2.1 initialized")
        logger.info(f"Original binary: {self.original_binary}")
        logger.info(f"Architecture: {self.architecture.name}")
        logger.info(f"Compiler: {self.compiler_config.compiler}")
        logger.info(f"Target triple: {self.compiler_config.target_triple}")
        logger.info(f"LIEF available: {self.has_lief}")
        logger.info(f"Documentation enabled: {self.documentation_config.generate_comments}")
        logger.info(f"Validation mode: {self.validation_config.mode.value}")

    def _detect_binary_architecture(self) -> Architecture:
        """Detect architecture from binary file"""
        if not self.original_binary.exists():
            logger.warning("Original binary not found, using host architecture")
            return Architecture.from_string(platform.machine()) or Architecture.X86_64

        # Try using file command
        try:
            result = subprocess.run(
                ["file", str(self.original_binary)],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )

            output = result.stdout.lower()

            if "x86-64" in output or "x86_64" in output:
                return Architecture.X86_64
            elif "80386" in output or "i386" in output:
                return Architecture.X86
            elif "aarch64" in output or "arm64" in output:
                return Architecture.ARM64
            elif "arm" in output:
                return Architecture.ARM

        except Exception as e:
            logger.warning(f"Could not detect architecture: {e}")

        # Try using LIEF
        if self.has_lief:
            try:
                import lief
                binary = lief.parse(str(self.original_binary))
                if binary:
                    machine = str(binary.header.machine_type).lower()
                    if "x86_64" in machine:
                        return Architecture.X86_64
                    elif "i386" in machine:
                        return Architecture.X86
            except Exception as e:
                logger.warning(f"LIEF architecture detection failed: {e}")

        # Default to host architecture
        logger.warning("Using host architecture as fallback")
        return Architecture.from_string(platform.machine()) or Architecture.X86_64

    def _check_library(self, library_name: str) -> bool:
        """Check if a Python library is available"""
        try:
            __import__(library_name)
            return True
        except ImportError:
            return False

    def reassemble_from_c(self, c_source_dir: Path, output_path: Path) -> ReassemblyResult:
        """
        Reassemble binary from C source code

        Main entry point for reassembly.
        """
        logger.info("Starting binary reassembly from C source (v2)")
        import time
        start_time = time.time()

        errors = []
        warnings = []

        try:
            # Step 1: Compile C to object files
            logger.info("Step 1: Compiling C to object files...")
            obj_files = self._compile_c_to_objects(c_source_dir, errors, warnings)

            if not obj_files:
                errors.append("No object files generated")
                return self._create_failure_result(errors, warnings, time.time() - start_time)

            # Step 2: Link object files
            logger.info("Step 2: Linking object files...")
            executable = self._link_objects(obj_files, output_path, errors, warnings)

            if not executable or not executable.exists():
                errors.append("Linking failed")
                return self._create_failure_result(errors, warnings, time.time() - start_time)

            # Step 3: Generate enhanced documentation
            logger.info("Step 3: Generating enhanced documentation...")
            documentation_files = []
            build_scripts = []
            dependencies = set()
            
            if self.documentation_config.generate_comments:
                self._enhance_source_documentation(c_source_dir, warnings)
                
            if self.documentation_config.generate_build_scripts:
                build_scripts.extend(self._generate_build_scripts(c_source_dir, output_path, warnings))
                
            if self.documentation_config.generate_readme:
                readme_path = self._generate_project_readme(c_source_dir, warnings)
                if readme_path:
                    documentation_files.append(readme_path)
                    
            if self.documentation_config.generate_makefile:
                makefile_path = self._generate_makefile(c_source_dir, output_path, warnings)
                if makefile_path:
                    build_scripts.append(makefile_path)
                    
            # Analyze dependencies
            dependencies = self._analyze_dependencies(c_source_dir)

            # Step 4: Perform reconstruction comparison (if enabled)
            comparison_result = None
            if (self.documentation_config.enable_comparison and 
                ReconstructionComparator and 
                self.original_binary.exists()):
                
                logger.info("Step 4: Performing reconstruction comparison...")
                try:
                    comparator = ReconstructionComparator()
                    comparison_result = comparator.compare_binaries(self.original_binary, executable)
                    
                    if self.documentation_config.generate_comparison_report:
                        report_path = c_source_dir / "reconstruction_comparison_report.md"
                        comparator.generate_comparison_report(comparison_result, report_path)
                        documentation_files.append(report_path)
                        
                    logger.info(f"Comparison completed. Accuracy: {comparison_result.metrics.overall_accuracy:.2%}")
                    
                except Exception as e:
                    warnings.append(f"Reconstruction comparison failed: {e}")

            # Step 5: Validate output (using configurable validation)
            logger.info("Step 5: Validating output...")
            validation_result = None

            if self.validator:
                validation_result = self.validator.validate(executable, self.original_binary)
                warnings.extend(validation_result.get('warnings', []))
                errors.extend(validation_result.get('errors', []))

                if not validation_result.get('valid', True):
                    logger.warning("Validation failed, but binary was created")

            # Calculate sizes
            size_original = self.original_binary.stat().st_size if self.original_binary.exists() else 0
            size_reassembled = executable.stat().st_size

            compilation_time = time.time() - start_time

            logger.info(f"Reassembly completed in {compilation_time:.2f}s")
            logger.info(f"Original size: {size_original} bytes, Reassembled: {size_reassembled} bytes")
            logger.info(f"Documentation files generated: {len(documentation_files)}")
            logger.info(f"Build scripts generated: {len(build_scripts)}")
            logger.info(f"Dependencies identified: {len(dependencies)}")

            return ReassemblyResult(
                success=len(errors) == 0,
                output_binary=executable,
                errors=errors,
                warnings=warnings,
                compilation_time=compilation_time,
                size_original=size_original,
                size_reassembled=size_reassembled,
                validation_results=validation_result,
                documentation_generated=documentation_files,
                build_scripts_generated=build_scripts,
                dependencies_identified=dependencies,
                comparison_result=comparison_result
            )

        except Exception as e:
            logger.error(f"Reassembly failed: {e}")
            errors.append(str(e))
            return self._create_failure_result(errors, warnings, time.time() - start_time)

    def _compile_c_to_objects(
        self,
        source_dir: Path,
        errors: List[str],
        warnings: List[str]
    ) -> List[Path]:
        """Compile C source files to object files"""
        obj_files = []

        # Find all C files
        c_files = list(source_dir.rglob("*.c"))
        logger.info(f"Found {len(c_files)} C files to compile")

        for c_file in c_files:
            obj_file = self.temp_dir / f"{c_file.stem}.o"

            # Build compile command with architecture-specific flags
            cmd = [
                self.compiler_config.compiler,
                "-c",
                str(c_file),
                "-o", str(obj_file),
                *self.compiler_config.flags,
                "-Wno-implicit-function-declaration",
            ]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False
                )

                if result.returncode == 0:
                    obj_files.append(obj_file)
                    logger.info(f"Compiled: {c_file.name} → {obj_file.name}")
                else:
                    error_msg = f"Compilation failed for {c_file.name}: {result.stderr[:200]}"
                    logger.error(error_msg)
                    warnings.append(error_msg)

            except subprocess.TimeoutExpired:
                logger.error(f"Compilation timeout for {c_file.name}")
                warnings.append(f"Timeout compiling {c_file.name}")
            except Exception as e:
                logger.error(f"Error compiling {c_file.name}: {e}")
                warnings.append(f"Error compiling {c_file.name}: {e}")

        return obj_files

    def _link_objects(
        self,
        obj_files: List[Path],
        output_path: Path,
        errors: List[str],
        warnings: List[str]
    ) -> Optional[Path]:
        """Link object files into executable"""

        cmd = [
            self.compiler_config.compiler,
            "-o", str(output_path),
            *[str(obj) for obj in obj_files],
            *self.compiler_config.linker_flags,
            "-lm",  # Math library
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
                check=False
            )

            if result.returncode == 0:
                logger.info(f"Linking successful: {output_path}")
                return output_path
            else:
                error_msg = f"Linking failed: {result.stderr[:200]}"
                logger.error(error_msg)
                errors.append(error_msg)
                return None

        except subprocess.TimeoutExpired:
            logger.error("Linking timeout")
            errors.append("Linking timeout")
            return None
        except Exception as e:
            logger.error(f"Error linking: {e}")
            errors.append(f"Linking error: {e}")
            return None

    def patch_binary_with_lief(self, modifications: Dict[str, bytes]) -> Optional[Path]:
        """
        Patch original binary using LIEF library

        Args:
            modifications: Dict mapping function names/addresses to new machine code

        Returns:
            Path to patched binary, or None if patching failed
        """
        if not self.has_lief:
            raise NotImplementedError(
                "LIEF library not available. Install with: pip install lief"
            )

        try:
            import lief

            logger.info(f"Patching binary with LIEF: {self.original_binary}")

            # Parse original binary
            binary = lief.parse(str(self.original_binary))
            if binary is None:
                logger.error("Failed to parse original binary with LIEF")
                return None

            # Apply patches
            patched_count = 0

            for identifier, machine_code in modifications.items():
                try:
                    # Try to parse as address first
                    if identifier.startswith('0x'):
                        address = int(identifier, 16)
                        success = self._patch_by_address(binary, address, machine_code)
                    else:
                        # Try to find by symbol name
                        success = self._patch_by_symbol(binary, identifier, machine_code)

                    if success:
                        patched_count += 1
                        logger.info(f"Patched: {identifier}")
                    else:
                        logger.warning(f"Could not patch: {identifier}")

                except Exception as e:
                    logger.error(f"Error patching {identifier}: {e}")

            # Write patched binary
            output_path = self.temp_dir / f"patched_{self.original_binary.name}"
            binary.write(str(output_path))

            logger.info(f"Patched binary written: {output_path} ({patched_count} patches applied)")
            return output_path

        except Exception as e:
            logger.error(f"Binary patching failed: {e}")
            return None

    def _patch_by_address(self, binary, address: int, machine_code: bytes) -> bool:
        """Patch binary at specific address"""
        try:
            # Convert virtual address to file offset
            section = binary.section_from_virtual_address(address)
            if not section:
                logger.error(f"No section found for address 0x{address:x}")
                return False

            offset = address - section.virtual_address + section.offset

            # Patch the bytes
            content = bytearray(section.content)
            patch_len = len(machine_code)

            if offset + patch_len > len(content):
                logger.error(f"Patch too large for section at 0x{address:x}")
                return False

            content[offset:offset + patch_len] = machine_code
            section.content = list(content)

            return True

        except Exception as e:
            logger.error(f"Address patch failed: {e}")
            return False

    def _patch_by_symbol(self, binary, symbol_name: str, machine_code: bytes) -> bool:
        """Patch binary by symbol name"""
        try:
            # Look for symbol in exported symbols
            for symbol in binary.exported_symbols:
                if symbol.name == symbol_name:
                    return self._patch_by_address(binary, symbol.value, machine_code)

            # Look in static symbols if available
            for symbol in binary.symbols:
                if symbol.name == symbol_name:
                    return self._patch_by_address(binary, symbol.value, machine_code)

            logger.error(f"Symbol not found: {symbol_name}")
            return False

        except Exception as e:
            logger.error(f"Symbol patch failed: {e}")
            return False

    def _enhance_source_documentation(self, source_dir: Path, warnings: List[str]) -> None:
        """Enhance C source files with comprehensive documentation"""
        try:
            c_files = list(source_dir.rglob("*.c"))
            h_files = list(source_dir.rglob("*.h"))
            
            for file_path in c_files + h_files:
                self._add_file_documentation(file_path, warnings)
                
        except Exception as e:
            warnings.append(f"Documentation enhancement failed: {e}")
            
    def _add_file_documentation(self, file_path: Path, warnings: List[str]) -> None:
        """Add comprehensive documentation to a single source file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                
            # Generate file header comment
            header_comment = self._generate_file_header(file_path)
            
            # Add function documentation
            enhanced_content = self._add_function_documentation(content, file_path)
            
            # Combine header and enhanced content
            if not content.startswith('/*'):
                enhanced_content = header_comment + "\n\n" + enhanced_content
                
            # Write enhanced file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(enhanced_content)
                
        except Exception as e:
            warnings.append(f"Failed to enhance documentation for {file_path.name}: {e}")
            
    def _generate_file_header(self, file_path: Path) -> str:
        """Generate comprehensive file header documentation"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        return f"""/*
 * {file_path.name}
 * {'=' * (len(file_path.name) + 20)}
 * 
 * Reconstructed from binary analysis of: {self.original_binary.name}
 * Architecture: {self.architecture.name}
 * Reconstruction timestamp: {timestamp}
 * 
 * This file was automatically generated through AI-enhanced binary analysis
 * and reverse engineering. The original functionality has been reconstructed
 * based on disassembly, control flow analysis, and pattern recognition.
 * 
 * SECURITY NOTE: This reconstructed code may contain:
 * - Hardcoded credentials or API keys
 * - Proprietary algorithms or business logic
 * - Security vulnerabilities or backdoors
 * - Obfuscated or anti-analysis techniques
 * 
 * Use this code for security research and educational purposes only.
 * Verify all functionality before use in production environments.
 */"""

    def _add_function_documentation(self, content: str, file_path: Path) -> str:
        """Add documentation comments to functions in the source code"""
        lines = content.split('\n')
        enhanced_lines = []
        
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Detect function definitions (simple heuristic)
            if (line and not line.startswith('//') and not line.startswith('/*') and 
                '(' in line and ')' in line and '{' in line and 
                not line.startswith('if') and not line.startswith('while') and 
                not line.startswith('for')):
                
                # Add function documentation
                func_doc = self._generate_function_documentation(line, file_path)
                enhanced_lines.append(func_doc)
                
            enhanced_lines.append(lines[i])
            i += 1
            
        return '\n'.join(enhanced_lines)
        
    def _generate_function_documentation(self, function_line: str, file_path: Path) -> str:
        """Generate documentation for a specific function"""
        if self.documentation_config.comment_style == "minimal":
            return f"/* Function reconstructed from binary analysis */"
        elif self.documentation_config.comment_style == "detailed":
            return f"""/*
 * Function reconstructed through binary analysis
 * Original binary: {self.original_binary.name}
 * Source file: {file_path.name}
 * 
 * This function's behavior was inferred from:
 * - Assembly code analysis
 * - Control flow reconstruction
 * - Data flow analysis
 * - Pattern matching with known implementations
 */"""
        else:  # verbose
            return f"""/*
 * RECONSTRUCTED FUNCTION ANALYSIS
 * ==============================
 * 
 * Function signature: {function_line.strip()}
 * Source file: {file_path.name}
 * Original binary: {self.original_binary.name}
 * Architecture: {self.architecture.name}
 * 
 * RECONSTRUCTION METHODOLOGY:
 * - Disassembled from machine code using advanced analysis
 * - Control flow graph reconstruction and optimization
 * - Variable type inference through data flow analysis
 * - Function parameter analysis through calling conventions
 * - Return value analysis through register/stack tracking
 * 
 * SECURITY CONSIDERATIONS:
 * - Verify input validation and bounds checking
 * - Check for potential buffer overflows or memory corruption
 * - Validate cryptographic implementations if present
 * - Review for hardcoded secrets or backdoors
 * 
 * ACCURACY NOTE:
 * This reconstruction represents the most likely implementation
 * based on binary analysis. Manual review recommended for
 * critical functionality.
 */"""

    def _generate_build_scripts(self, source_dir: Path, output_path: Path, warnings: List[str]) -> List[Path]:
        """Generate comprehensive build scripts for the reconstructed project"""
        build_scripts = []
        
        try:
            # Generate shell build script
            build_sh = self._generate_shell_build_script(source_dir, output_path)
            if build_sh:
                build_scripts.append(build_sh)
                
            # Generate batch build script for Windows
            build_bat = self._generate_batch_build_script(source_dir, output_path)
            if build_bat:
                build_scripts.append(build_bat)
                
            # Generate CMakeLists.txt
            cmake_file = self._generate_cmake_file(source_dir, output_path)
            if cmake_file:
                build_scripts.append(cmake_file)
                
        except Exception as e:
            warnings.append(f"Build script generation failed: {e}")
            
        return build_scripts
        
    def _generate_shell_build_script(self, source_dir: Path, output_path: Path) -> Optional[Path]:
        """Generate shell build script"""
        try:
            script_path = source_dir / "build.sh"
            
            script_content = f"""#!/bin/bash
# Build script for reconstructed binary: {self.original_binary.name}
# Generated by Binary Reassembler v2.1
# Architecture: {self.architecture.name}
# Compiler: {self.compiler_config.compiler}

set -e

echo "Building reconstructed binary from {self.original_binary.name}..."
echo "Architecture: {self.architecture.name}"
echo "Compiler: {self.compiler_config.compiler}"

# Create build directory
mkdir -p build
cd build

# Compile all C files
echo "Compiling source files..."
{self.compiler_config.compiler} \\
    {' '.join(self.compiler_config.flags)} \\
    ../*.c \\
    -o {output_path.name} \\
    {' '.join(self.compiler_config.linker_flags)} \\
    -lm

echo "Build completed successfully!"
echo "Output binary: build/{output_path.name}"
echo ""
echo "SECURITY WARNING:"
echo "This binary was reconstructed from reverse engineering."
echo "Review the code carefully before execution."
echo "Use only for security research and educational purposes."
"""

            with open(script_path, 'w') as f:
                f.write(script_content)
                
            # Make executable
            os.chmod(script_path, 0o755)
            
            return script_path
            
        except Exception as e:
            logger.error(f"Failed to generate shell build script: {e}")
            return None
            
    def _generate_batch_build_script(self, source_dir: Path, output_path: Path) -> Optional[Path]:
        """Generate Windows batch build script"""
        try:
            script_path = source_dir / "build.bat"
            
            script_content = f"""@echo off
REM Build script for reconstructed binary: {self.original_binary.name}
REM Generated by Binary Reassembler v2.1
REM Architecture: {self.architecture.name}
REM Compiler: {self.compiler_config.compiler}

echo Building reconstructed binary from {self.original_binary.name}...
echo Architecture: {self.architecture.name}
echo Compiler: {self.compiler_config.compiler}

REM Create build directory
if not exist build mkdir build
cd build

REM Compile all C files
echo Compiling source files...
{self.compiler_config.compiler} ^
    {' '.join(self.compiler_config.flags)} ^
    ..\\*.c ^
    -o {output_path.name} ^
    {' '.join(self.compiler_config.linker_flags)} ^
    -lm

if %ERRORLEVEL% EQU 0 (
    echo Build completed successfully!
    echo Output binary: build\\{output_path.name}
    echo.
    echo SECURITY WARNING:
    echo This binary was reconstructed from reverse engineering.
    echo Review the code carefully before execution.
    echo Use only for security research and educational purposes.
) else (
    echo Build failed with error code %ERRORLEVEL%
    exit /b %ERRORLEVEL%
)
"""

            with open(script_path, 'w') as f:
                f.write(script_content)
                
            return script_path
            
        except Exception as e:
            logger.error(f"Failed to generate batch build script: {e}")
            return None
            
    def _generate_cmake_file(self, source_dir: Path, output_path: Path) -> Optional[Path]:
        """Generate CMakeLists.txt for cross-platform building"""
        try:
            cmake_path = source_dir / "CMakeLists.txt"
            
            # Find all C source files
            c_files = [f.name for f in source_dir.glob("*.c")]
            
            cmake_content = f"""# CMakeLists.txt for reconstructed binary: {self.original_binary.name}
# Generated by Binary Reassembler v2.1

cmake_minimum_required(VERSION 3.10)
project({output_path.stem}_reconstructed)

# Set C standard
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Architecture-specific settings
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(TARGET_ARCH "x86_64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "i386|i686")
    set(TARGET_ARCH "x86")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(TARGET_ARCH "arm64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(TARGET_ARCH "arm")
endif()

# Compiler flags based on original analysis
set(CMAKE_C_FLAGS "${{CMAKE_C_FLAGS}} {' '.join(f for f in self.compiler_config.flags if not f.startswith('-m'))}")

# Source files
set(SOURCES
    {chr(10).join(f'    {f}' for f in c_files)}
)

# Create executable
add_executable({output_path.stem}_reconstructed ${{SOURCES}})

# Link libraries
target_link_libraries({output_path.stem}_reconstructed m)

# Security warning message
message(WARNING "
================================================================================
SECURITY WARNING: RECONSTRUCTED BINARY
================================================================================
This project was automatically generated through binary reverse engineering.
The code may contain:
- Security vulnerabilities
- Hardcoded credentials
- Proprietary algorithms
- Malicious functionality

Use only for security research and educational purposes.
Review all code carefully before execution.
================================================================================
")
"""

            with open(cmake_path, 'w') as f:
                f.write(cmake_content)
                
            return cmake_path
            
        except Exception as e:
            logger.error(f"Failed to generate CMakeLists.txt: {e}")
            return None

    def _generate_project_readme(self, source_dir: Path, warnings: List[str]) -> Optional[Path]:
        """Generate comprehensive README.md for the reconstructed project"""
        try:
            readme_path = source_dir / "README.md"
            
            # Analyze project structure
            c_files = list(source_dir.glob("*.c"))
            h_files = list(source_dir.glob("*.h"))
            
            readme_content = f"""# Reconstructed Binary Project: {self.original_binary.name}

## ⚠️ SECURITY WARNING ⚠️

**This project was automatically generated through AI-enhanced binary reverse engineering.**

This code may contain:
- 🔐 Hardcoded credentials, API keys, or secrets
- 🏢 Proprietary algorithms or business logic
- 🐛 Security vulnerabilities or backdoors
- 🎭 Obfuscated or anti-analysis techniques
- 💣 Malicious functionality

**Use only for security research and educational purposes. Review all code carefully before execution.**

## Project Information

- **Original Binary**: `{self.original_binary.name}`
- **Architecture**: {self.architecture.name}
- **Reconstruction Date**: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
- **Compiler Used**: {self.compiler_config.compiler}
- **Binary Size**: {self.original_binary.stat().st_size if self.original_binary.exists() else 'Unknown'} bytes

## Reconstruction Methodology

This project was created using advanced AI-powered binary analysis techniques:

1. **Disassembly**: Machine code converted to assembly language
2. **Control Flow Analysis**: Program structure and logic flow reconstructed
3. **Data Flow Analysis**: Variable usage and data dependencies identified
4. **Pattern Recognition**: Common programming patterns and library calls detected
5. **Type Inference**: Variable and function types inferred from usage
6. **Code Generation**: Human-readable C code generated from analysis

## Project Structure

### Source Files ({len(c_files)} files)
{chr(10).join(f'- `{f.name}` - Reconstructed source file' for f in c_files)}

### Header Files ({len(h_files)} files)
{chr(10).join(f'- `{f.name}` - Reconstructed header file' for f in h_files)}

### Build Scripts
- `build.sh` - Unix/Linux build script
- `build.bat` - Windows build script  
- `CMakeLists.txt` - Cross-platform CMake configuration
- `Makefile` - Traditional make configuration

## Building the Project

### Using Shell Script (Linux/macOS)
```bash
chmod +x build.sh
./build.sh
```

### Using Batch Script (Windows)
```cmd
build.bat
```

### Using CMake (Cross-platform)
```bash
mkdir build
cd build
cmake ..
make
```

### Using Make
```bash
make
```

## Security Analysis Recommendations

Before using this reconstructed code:

1. **Code Review**: Manually review all source files for suspicious patterns
2. **Vulnerability Scanning**: Run static analysis tools (e.g., Clang Static Analyzer, Cppcheck)
3. **Dynamic Analysis**: Test in isolated environment with monitoring
4. **Dependency Analysis**: Verify all external library dependencies
5. **Credential Scanning**: Search for hardcoded secrets or API keys
6. **Network Analysis**: Monitor network communications during execution

## Research and Educational Use

This reconstruction demonstrates:
- Modern AI capabilities in reverse engineering
- Vulnerability of proprietary software to analysis
- Importance of code obfuscation and protection
- Need for secure coding practices

## Legal and Ethical Considerations

- Ensure you have legal right to analyze the original binary
- Use only for defensive security research
- Follow responsible disclosure for any vulnerabilities found
- Respect intellectual property rights
- Comply with applicable laws and regulations

## Technical Details

### Compiler Configuration
- **Compiler**: {self.compiler_config.compiler}
- **Flags**: {' '.join(self.compiler_config.flags)}
- **Linker Flags**: {' '.join(self.compiler_config.linker_flags)}
- **Target Triple**: {self.compiler_config.target_triple or 'Auto-detected'}

### Analysis Metadata
- **LIEF Available**: {self.has_lief}
- **Keystone Available**: {self.has_keystone}
- **Validation Mode**: {self.validation_config.mode.value if hasattr(self.validation_config, 'mode') else 'Unknown'}

## Disclaimer

This reconstruction is provided "as-is" for educational and research purposes only. 
The accuracy of the reconstructed code cannot be guaranteed. Use at your own risk.

---
*Generated by Binary Reassembler v2.1 - AI-Enhanced Universal Binary Analysis Engine*
"""

            with open(readme_path, 'w') as f:
                f.write(readme_content)
                
            return readme_path
            
        except Exception as e:
            warnings.append(f"Failed to generate README: {e}")
            return None

    def _generate_makefile(self, source_dir: Path, output_path: Path, warnings: List[str]) -> Optional[Path]:
        """Generate Makefile for the reconstructed project"""
        try:
            makefile_path = source_dir / "Makefile"
            
            # Find all C source files
            c_files = [f.name for f in source_dir.glob("*.c")]
            obj_files = [f.replace('.c', '.o') for f in c_files]
            
            makefile_content = f"""# Makefile for reconstructed binary: {self.original_binary.name}
# Generated by Binary Reassembler v2.1

# Compiler and flags from original analysis
CC = {self.compiler_config.compiler}
CFLAGS = {' '.join(self.compiler_config.flags)} -Wall -Wextra
LDFLAGS = {' '.join(self.compiler_config.linker_flags)} -lm
TARGET = {output_path.name}

# Source files
SOURCES = {' '.join(c_files)}
OBJECTS = {' '.join(obj_files)}

# Default target
all: security_warning $(TARGET)

# Security warning
security_warning:
	@echo "================================================================================"
	@echo "SECURITY WARNING: RECONSTRUCTED BINARY"
	@echo "================================================================================"
	@echo "This code was generated through binary reverse engineering."
	@echo "Review carefully before execution. Use only for security research."
	@echo "================================================================================"
	@echo ""

# Build target
$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)
	@echo "Build completed: $(TARGET)"

# Compile source files
%.o: %.c
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) -c $< -o $@

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TARGET)
	@echo "Cleaned build artifacts"

# Install (with warning)
install: $(TARGET)
	@echo "WARNING: Installing reconstructed binary. Use with caution."
	cp $(TARGET) /usr/local/bin/$(TARGET)

# Debug build
debug: CFLAGS += -g -DDEBUG
debug: $(TARGET)

# Release build
release: CFLAGS += -O3 -DNDEBUG
release: $(TARGET)

# Static analysis
analyze:
	@echo "Running static analysis..."
	@if command -v clang-tidy >/dev/null 2>&1; then \\
		clang-tidy $(SOURCES) -- $(CFLAGS); \\
	else \\
		echo "clang-tidy not found. Install for static analysis."; \\
	fi

# Security scan
security-scan:
	@echo "Running security scan..."
	@if command -v cppcheck >/dev/null 2>&1; then \\
		cppcheck --enable=all --inconclusive $(SOURCES); \\
	else \\
		echo "cppcheck not found. Install for security scanning."; \\
	fi

# Help
help:
	@echo "Available targets:"
	@echo "  all          - Build the reconstructed binary (default)"
	@echo "  clean        - Remove build artifacts"
	@echo "  debug        - Build with debug symbols"
	@echo "  release      - Build optimized release version"
	@echo "  analyze      - Run static analysis (requires clang-tidy)"
	@echo "  security-scan - Run security scan (requires cppcheck)"
	@echo "  install      - Install binary to /usr/local/bin"
	@echo "  help         - Show this help message"

.PHONY: all clean debug release analyze security-scan install help security_warning
"""

            with open(makefile_path, 'w') as f:
                f.write(makefile_content)
                
            return makefile_path
            
        except Exception as e:
            warnings.append(f"Failed to generate Makefile: {e}")
            return None

    def _analyze_dependencies(self, source_dir: Path) -> Set[str]:
        """Analyze and identify dependencies from the source code"""
        dependencies = set()
        
        try:
            # Standard C library functions that might indicate dependencies
            common_deps = {
                'socket': 'network',
                'pthread': 'threading', 
                'ssl': 'openssl',
                'crypto': 'cryptography',
                'curl': 'libcurl',
                'json': 'json-c',
                'xml': 'libxml2',
                'sqlite': 'sqlite3',
                'mysql': 'mysql',
                'postgres': 'postgresql'
            }
            
            # Scan all C files for dependency indicators
            for c_file in source_dir.rglob("*.c"):
                try:
                    with open(c_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read().lower()
                        
                    for keyword, dep in common_deps.items():
                        if keyword in content:
                            dependencies.add(dep)
                            
                except Exception:
                    continue
                    
        except Exception as e:
            logger.warning(f"Dependency analysis failed: {e}")
            
        return dependencies

    def _create_failure_result(
        self,
        errors: List[str],
        warnings: List[str],
        time: float
    ) -> ReassemblyResult:
        """Create a failure result"""
        return ReassemblyResult(
            success=False,
            output_binary=None,
            errors=errors,
            warnings=warnings,
            compilation_time=time,
            size_original=0,
            size_reassembled=0
        )


def main():
    """Main function"""
    import argparse

    parser = argparse.ArgumentParser(description='Binary Reassembler v2')
    parser.add_argument('--original', required=True, help='Original binary file')
    parser.add_argument('--source', required=True, help='C source directory')
    parser.add_argument('--output', required=True, help='Output binary path')
    parser.add_argument('--arch', choices=['x86', 'x86_64', 'arm', 'arm64', 'auto'], default='auto')
    parser.add_argument('--validation-mode', choices=['checksum', 'smoke_test', 'sandboxed', 'none'],
                        default='smoke_test', help='Validation strategy')
    parser.add_argument('--validation-config', type=Path, help='Validation config JSON file')
    parser.add_argument('--no-docs', action='store_true', help='Disable documentation generation')
    parser.add_argument('--comment-style', choices=['minimal', 'detailed', 'verbose'], 
                        default='detailed', help='Documentation comment style')
    parser.add_argument('--no-build-scripts', action='store_true', help='Disable build script generation')
    parser.add_argument('--no-comparison', action='store_true', help='Disable reconstruction comparison')
    args = parser.parse_args()

    # Determine architecture
    if args.arch == 'auto':
        arch = None  # Auto-detect
    else:
        arch = Architecture.from_string(args.arch)

    # Setup validation
    if args.validation_config:
        validator = BinaryValidator.load_config(args.validation_config)
        val_config = validator.config
    else:
        val_config = ValidationConfig(mode=ValidationMode[args.validation_mode.upper()])

    # Setup documentation
    doc_config = DocumentationConfig(
        generate_comments=not args.no_docs,
        generate_build_scripts=not args.no_build_scripts,
        generate_readme=not args.no_docs,
        generate_makefile=not args.no_build_scripts,
        comment_style=args.comment_style,
        enable_comparison=not args.no_comparison,
        generate_comparison_report=not args.no_comparison
    )

    # Create reassembler
    try:
        reassembler = BinaryReassemblerV2(
            Path(args.original),
            arch,
            val_config,
            doc_config
        )
    except RuntimeError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    # Reassemble
    result = reassembler.reassemble_from_c(Path(args.source), Path(args.output))

    # Print results
    print(f"\n{'=' * 60}")
    print(f"Reassembly: {'SUCCESS' if result.success else 'FAILED'}")
    print(f"{'=' * 60}")
    print(f"Compilation time: {result.compilation_time:.2f}s")
    print(f"Original size: {result.size_original} bytes")
    print(f"Reassembled size: {result.size_reassembled} bytes")

    if result.warnings:
        print(f"\nWarnings ({len(result.warnings)}):")
        for warning in result.warnings[:5]:  # Show first 5
            print(f"  - {warning}")
        if len(result.warnings) > 5:
            print(f"  ... and {len(result.warnings) - 5} more")

    if result.errors:
        print(f"\nErrors ({len(result.errors)}):")
        for error in result.errors[:5]:
            print(f"  - {error}")
        if len(result.errors) > 5:
            print(f"  ... and {len(result.errors) - 5} more")

    if result.validation_results:
        print(f"\nValidation:")
        val = result.validation_results
        print(f"  Mode: {val.get('mode')}")
        if val.get('tests_run'):
            print(f"  Tests: {val.get('tests_passed')}/{val.get('tests_run')} passed")

    if result.documentation_generated or result.build_scripts_generated:
        print(f"\nDocumentation & Build Support:")
        if result.documentation_generated:
            print(f"  Documentation files: {len(result.documentation_generated)}")
            for doc_file in result.documentation_generated:
                print(f"    - {doc_file.name}")
        if result.build_scripts_generated:
            print(f"  Build scripts: {len(result.build_scripts_generated)}")
            for build_file in result.build_scripts_generated:
                print(f"    - {build_file.name}")
        if result.dependencies_identified:
            print(f"  Dependencies identified: {', '.join(sorted(result.dependencies_identified))}")

    if result.comparison_result:
        print(f"\nReconstruction Comparison:")
        comp = result.comparison_result
        print(f"  Overall accuracy: {comp.metrics.overall_accuracy:.2%} ({comp.metrics.accuracy_level.value})")
        print(f"  Binary similarity: {comp.metrics.binary_similarity:.2%}")
        print(f"  Functional equivalence: {comp.metrics.functional_equivalence:.2%}")
        print(f"  Behavioral match: {comp.metrics.behavioral_match:.2%}")
        if comp.recommendations:
            print(f"  Key recommendations: {len(comp.recommendations)} items")

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
