#!/usr/bin/env python3
"""
REVENG Compilation Tester
==========================

Tests compilation of generated C code during the pipeline.

Features:
- Detects available compilers (MSVC, MinGW, GCC, Clang)
- Attempts compilation with platform-aware flags
- Parses compiler errors with line numbers
- Returns structured results for debugging
- Supports incremental testing (per-file or full build)
"""

import logging
import subprocess
import platform
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import json

logger = logging.getLogger(__name__)


class CompilationTester:
    """Test compilation of generated C code"""

    def __init__(self):
        """Initialize compilation tester"""
        self.platform = platform.system()
        self.compilers = self._detect_compilers()
        self.default_compiler = self._select_default_compiler()

    def _detect_compilers(self) -> Dict[str, Optional[str]]:
        """Detect available compilers"""
        compilers = {
            'msvc': None,
            'mingw': None,
            'gcc': None,
            'clang': None
        }

        # Check MSVC (Windows only)
        if self.platform == 'Windows':
            try:
                result = subprocess.run(
                    ['cl'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if 'Microsoft' in result.stderr or 'Microsoft' in result.stdout:
                    compilers['msvc'] = 'cl'
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Check MinGW (Windows only)
        if self.platform == 'Windows':
            try:
                result = subprocess.run(
                    ['gcc', '--version'],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if 'MinGW' in result.stdout or 'mingw' in result.stdout:
                    compilers['mingw'] = 'gcc'
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Check GCC (Linux/macOS)
        try:
            result = subprocess.run(
                ['gcc', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0 and 'gcc' in result.stdout.lower():
                compilers['gcc'] = 'gcc'
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Check Clang
        try:
            result = subprocess.run(
                ['clang', '--version'],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                compilers['clang'] = 'clang'
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        return compilers

    def _select_default_compiler(self) -> Optional[str]:
        """Select default compiler for this platform"""
        if self.platform == 'Windows':
            # Prefer MSVC, then MinGW
            if self.compilers['msvc']:
                return 'msvc'
            elif self.compilers['mingw']:
                return 'mingw'
        else:
            # Prefer GCC, then Clang
            if self.compilers['gcc']:
                return 'gcc'
            elif self.compilers['clang']:
                return 'clang'

        return None

    def test_single_file(
        self,
        source_file: Path,
        compiler: Optional[str] = None,
        output_dir: Optional[Path] = None
    ) -> Dict:
        """
        Test compilation of a single C file

        Returns:
            Dict with status, compiler_output, errors, warnings
        """
        compiler = compiler or self.default_compiler
        if not compiler:
            return {
                'status': 'error',
                'error': 'No compiler available',
                'compilers_detected': self.compilers
            }

        # Prepare output directory
        if not output_dir:
            output_dir = source_file.parent / "build"
        output_dir.mkdir(exist_ok=True)

        # Output file
        output_file = output_dir / f"{source_file.stem}.o"

        # Build compile command
        compile_cmd = self._build_compile_command(
            compiler,
            source_file,
            output_file,
            compile_only=True
        )

        # Run compilation
        try:
            result = subprocess.run(
                compile_cmd,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=source_file.parent
            )

            # Parse output
            errors, warnings = self._parse_compiler_output(
                result.stdout + result.stderr,
                compiler
            )

            return {
                'status': 'success' if result.returncode == 0 else 'failed',
                'compiler': compiler,
                'source_file': str(source_file),
                'output_file': str(output_file),
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'errors': errors,
                'warnings': warnings,
                'error_count': len(errors),
                'warning_count': len(warnings)
            }

        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'compiler': compiler,
                'source_file': str(source_file),
                'error': 'Compilation timed out after 30 seconds'
            }
        except Exception as e:
            return {
                'status': 'error',
                'compiler': compiler,
                'source_file': str(source_file),
                'error': str(e)
            }

    def test_directory(
        self,
        source_dir: Path,
        compiler: Optional[str] = None,
        output_dir: Optional[Path] = None,
        max_files: int = 0
    ) -> Dict:
        """
        Test compilation of all C files in a directory

        Args:
            source_dir: Directory containing C source files
            compiler: Compiler to use (auto-detected if None)
            output_dir: Output directory for compiled objects
            max_files: Maximum files to test (0 = all)

        Returns:
            Dict with overall results and per-file results
        """
        compiler = compiler or self.default_compiler
        if not compiler:
            return {
                'status': 'error',
                'error': 'No compiler available',
                'compilers_detected': self.compilers
            }

        # Find all C files
        c_files = list(source_dir.glob('**/*.c'))
        if max_files > 0:
            c_files = c_files[:max_files]

        if not c_files:
            return {
                'status': 'error',
                'error': f'No C files found in {source_dir}'
            }

        # Test each file
        results = []
        success_count = 0
        failed_count = 0
        total_errors = 0
        total_warnings = 0

        for c_file in c_files:
            file_result = self.test_single_file(c_file, compiler, output_dir)
            results.append(file_result)

            if file_result['status'] == 'success':
                success_count += 1
            else:
                failed_count += 1

            total_errors += file_result.get('error_count', 0)
            total_warnings += file_result.get('warning_count', 0)

        return {
            'status': 'success' if failed_count == 0 else 'partial',
            'compiler': compiler,
            'source_dir': str(source_dir),
            'total_files': len(c_files),
            'success_count': success_count,
            'failed_count': failed_count,
            'total_errors': total_errors,
            'total_warnings': total_warnings,
            'results': results
        }

    def test_link(
        self,
        object_files: List[Path],
        output_binary: Path,
        compiler: Optional[str] = None
    ) -> Dict:
        """
        Test linking of compiled object files

        Returns:
            Dict with status, linker_output, errors
        """
        compiler = compiler or self.default_compiler
        if not compiler:
            return {
                'status': 'error',
                'error': 'No compiler available'
            }

        # Build link command
        link_cmd = self._build_link_command(
            compiler,
            object_files,
            output_binary
        )

        # Run linking
        try:
            result = subprocess.run(
                link_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )

            # Parse output
            errors, warnings = self._parse_compiler_output(
                result.stdout + result.stderr,
                compiler
            )

            return {
                'status': 'success' if result.returncode == 0 else 'failed',
                'compiler': compiler,
                'output_binary': str(output_binary),
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'errors': errors,
                'warnings': warnings,
                'error_count': len(errors),
                'warning_count': len(warnings)
            }

        except subprocess.TimeoutExpired:
            return {
                'status': 'timeout',
                'error': 'Linking timed out after 60 seconds'
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }

    def _build_compile_command(
        self,
        compiler: str,
        source_file: Path,
        output_file: Path,
        compile_only: bool = True
    ) -> List[str]:
        """Build compile command for compiler"""
        if compiler == 'msvc':
            cmd = ['cl', '/c', str(source_file), f'/Fo{output_file}']
        elif compiler in ['mingw', 'gcc', 'clang']:
            cmd = [
                self.compilers[compiler],
                '-c',
                str(source_file),
                '-o', str(output_file)
            ]

            # Platform-aware flags
            if self.platform != 'Windows':
                cmd.insert(1, '-fPIC')

        else:
            raise ValueError(f"Unknown compiler: {compiler}")

        return cmd

    def _build_link_command(
        self,
        compiler: str,
        object_files: List[Path],
        output_binary: Path
    ) -> List[str]:
        """Build link command for compiler"""
        if compiler == 'msvc':
            cmd = ['link', '/OUT:' + str(output_binary)] + [str(f) for f in object_files]
        elif compiler in ['mingw', 'gcc', 'clang']:
            cmd = [
                self.compilers[compiler],
                '-o', str(output_binary)
            ] + [str(f) for f in object_files]

            # Add shared library flag if needed
            if output_binary.suffix in ['.so', '.dylib', '.dll']:
                cmd.insert(1, '-shared')
        else:
            raise ValueError(f"Unknown compiler: {compiler}")

        return cmd

    def _parse_compiler_output(
        self,
        output: str,
        compiler: str
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Parse compiler output to extract errors and warnings

        Returns:
            (errors, warnings) as lists of dicts with file, line, message
        """
        errors = []
        warnings = []

        # GCC/Clang/MinGW format: file.c:line:col: error: message
        # MSVC format: file.c(line): error C1234: message
        if compiler in ['gcc', 'clang', 'mingw']:
            # GCC/Clang format
            error_pattern = re.compile(
                r'([^:]+):(\d+):(\d+):\s*(error|warning):\s*(.+)',
                re.IGNORECASE
            )
        else:
            # MSVC format
            error_pattern = re.compile(
                r'([^(]+)\((\d+)\):\s*(error|warning)\s*[A-Z]*\d+:\s*(.+)',
                re.IGNORECASE
            )

        for line in output.split('\n'):
            match = error_pattern.match(line.strip())
            if match:
                if compiler in ['gcc', 'clang', 'mingw']:
                    file_path, line_num, col, level, message = match.groups()
                    entry = {
                        'file': file_path,
                        'line': int(line_num),
                        'column': int(col),
                        'message': message
                    }
                else:
                    file_path, line_num, level, message = match.groups()
                    entry = {
                        'file': file_path,
                        'line': int(line_num),
                        'message': message
                    }

                if 'error' in level.lower():
                    errors.append(entry)
                else:
                    warnings.append(entry)

        return errors, warnings

    def save_report(self, report: Dict, output_path: Path):
        """Save compilation test report to JSON"""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Compilation test report saved to {output_path}")


# Example usage
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    tester = CompilationTester()

    print("=" * 60)
    print("COMPILATION TESTER")
    print("=" * 60)
    print(f"Platform: {tester.platform}")
    print(f"Compilers detected:")
    for name, cmd in tester.compilers.items():
        status = f"[OK] {cmd}" if cmd else "[MISSING]"
        print(f"  {name}: {status}")
    print(f"Default compiler: {tester.default_compiler}")
    print()

    if len(sys.argv) >= 2:
        target = Path(sys.argv[1])

        if target.is_file() and target.suffix == '.c':
            # Test single file
            print(f"Testing single file: {target}")
            print()
            result = tester.test_single_file(target)
            print(f"Status: {result['status']}")
            print(f"Errors: {result.get('error_count', 0)}")
            print(f"Warnings: {result.get('warning_count', 0)}")

            if result.get('errors'):
                print("\nErrors:")
                for error in result['errors'][:5]:
                    print(f"  {error['file']}:{error['line']}: {error['message']}")

        elif target.is_dir():
            # Test directory
            print(f"Testing directory: {target}")
            print()
            result = tester.test_directory(target)
            print(f"Status: {result['status']}")
            print(f"Files tested: {result['total_files']}")
            print(f"Success: {result['success_count']}")
            print(f"Failed: {result['failed_count']}")
            print(f"Total errors: {result['total_errors']}")
            print(f"Total warnings: {result['total_warnings']}")

            # Save report
            report_path = Path("compilation_test_report.json")
            tester.save_report(result, report_path)
            print(f"\nFull report saved to: {report_path}")

        else:
            print(f"Error: {target} is not a C file or directory")
    else:
        print("Usage:")
        print("  python compilation_tester.py file.c       # Test single file")
        print("  python compilation_tester.py src_dir/     # Test directory")

    print("=" * 60)
