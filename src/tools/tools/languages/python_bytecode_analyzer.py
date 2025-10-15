#!/usr/bin/env python3
"""
REVENG Python Bytecode Analyzer
================================

Analyzes Python bytecode files (.pyc, .pyo) and decompiles to Python source.

Features:
- Python bytecode detection (magic numbers)
- Version detection (Python 2.7, 3.x)
- Decompilation using uncompyle6, decompyle3, pycdc
- AST analysis
- Obfuscation detection (PyArmor, Cython, Nuitka)
- Dependency extraction

Requires:
- uncompyle6 (Python 2.7-3.8)
- decompyle3 (Python 3.7-3.9)
- pycdc (fallback decompiler)
"""

import os
import re
import json
import logging
import marshal
import struct
import dis
import importlib.util
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict
import subprocess

logger = logging.getLogger(__name__)


# Python magic numbers for version detection
PYTHON_MAGIC_NUMBERS = {
    # Python 2.x
    62211: '2.7',
    # Python 3.x
    3390: '3.6',
    3391: '3.6',
    3392: '3.6',
    3393: '3.6',
    3394: '3.7',
    3400: '3.7',
    3401: '3.7',
    3410: '3.8',
    3411: '3.8',
    3412: '3.8',
    3413: '3.8',
    3420: '3.9',
    3421: '3.9',
    3422: '3.9',
    3423: '3.9',
    3424: '3.9',
    3425: '3.9',
    3430: '3.10',
    3431: '3.10',
    3432: '3.10',
    3433: '3.10',
    3434: '3.10',
    3435: '3.10',
    3450: '3.11',
    3451: '3.11',
    3452: '3.11',
    3453: '3.11',
    3454: '3.11',
    3455: '3.11',
    3460: '3.11',
    3461: '3.11',
    3462: '3.11',
    3463: '3.11',
    3464: '3.11',
    3465: '3.11',
    3470: '3.12',
    3471: '3.12',
    3472: '3.12',
    3473: '3.12',
    3474: '3.12',
    3475: '3.12',
    3476: '3.12',
    3477: '3.12',
    3478: '3.12',
    3479: '3.12',
    3480: '3.12',
    3481: '3.12',
    3482: '3.12',
    3483: '3.12',
    3484: '3.12',
    3485: '3.12',
    3486: '3.12',
    3487: '3.12',
    3488: '3.12',
    3489: '3.12',
    3490: '3.12',
    3491: '3.12',
    3492: '3.12',
    3493: '3.12',
    3494: '3.12',
}


@dataclass
class PythonBytecodeInfo:
    """Information about Python bytecode file"""
    file_path: str
    magic_number: int
    python_version: str
    timestamp: int
    file_size: int
    is_obfuscated: bool
    obfuscator: Optional[str]
    imports: List[str]
    functions: List[str]
    classes: List[str]


@dataclass
class DecompilationResult:
    """Result from Python decompilation"""
    bytecode_file: str
    decompiled_file: Optional[str]
    decompiler_used: str
    success: bool
    error: Optional[str]
    source_code: Optional[str]
    metadata: Dict[str, Any]


class PythonBytecodeDetector:
    """
    Detects Python bytecode files and extracts metadata

    Python .pyc format:
    - Magic number (4 bytes) - identifies Python version
    - Timestamp (4 bytes) - compilation time
    - File size (4 bytes) - optional, depends on version
    - Code object (marshalled)
    """

    @staticmethod
    def detect(file_path: str) -> Tuple[bool, Optional[PythonBytecodeInfo]]:
        """Detect if file is Python bytecode"""
        try:
            with open(file_path, 'rb') as f:
                # Read magic number
                magic_bytes = f.read(4)
                if len(magic_bytes) < 4:
                    return False, None

                magic = struct.unpack('<H', magic_bytes[:2])[0]

                # Check if it's a known Python magic number
                python_version = PYTHON_MAGIC_NUMBERS.get(magic)
                if not python_version:
                    return False, None

                # Read timestamp
                timestamp = struct.unpack('<I', f.read(4))[0]

                # File size (Python 3.3+)
                file_size = 0
                if python_version >= '3.3':
                    file_size = struct.unpack('<I', f.read(4))[0]

                # Try to read code object
                try:
                    code = marshal.load(f)
                    imports, functions, classes = PythonBytecodeDetector._analyze_code_object(code)
                except Exception as e:
                    logger.warning(f"Failed to read code object: {e}")
                    imports, functions, classes = [], [], []

                # Detect obfuscation
                is_obfuscated, obfuscator = PythonBytecodeDetector._detect_obfuscation(file_path)

                info = PythonBytecodeInfo(
                    file_path=file_path,
                    magic_number=magic,
                    python_version=python_version,
                    timestamp=timestamp,
                    file_size=file_size or os.path.getsize(file_path),
                    is_obfuscated=is_obfuscated,
                    obfuscator=obfuscator,
                    imports=imports,
                    functions=functions,
                    classes=classes
                )

                return True, info

        except Exception as e:
            logger.warning(f"Failed to detect Python bytecode: {e}")
            return False, None

    @staticmethod
    def _analyze_code_object(code) -> Tuple[List[str], List[str], List[str]]:
        """Analyze Python code object to extract metadata"""
        imports = []
        functions = []
        classes = []

        try:
            # Get all constants (may include imported module names)
            if hasattr(code, 'co_consts'):
                for const in code.co_consts:
                    if isinstance(const, str):
                        imports.append(const)

            # Get function names
            if hasattr(code, 'co_names'):
                for name in code.co_names:
                    if name[0].isupper():  # Heuristic: classes start with uppercase
                        classes.append(name)
                    else:
                        functions.append(name)

            # Recursively analyze nested code objects
            if hasattr(code, 'co_consts'):
                for const in code.co_consts:
                    if hasattr(const, 'co_code'):
                        nested_imports, nested_funcs, nested_classes = PythonBytecodeDetector._analyze_code_object(const)
                        imports.extend(nested_imports)
                        functions.extend(nested_funcs)
                        classes.extend(nested_classes)

        except Exception as e:
            logger.warning(f"Failed to analyze code object: {e}")

        return imports[:50], functions[:50], classes[:50]

    @staticmethod
    def _detect_obfuscation(file_path: str) -> Tuple[bool, Optional[str]]:
        """Detect if bytecode is obfuscated"""
        try:
            # Check for PyArmor (common Python obfuscator)
            if 'pyarmor' in file_path.lower():
                return True, 'PyArmor'

            # Check for Nuitka (Python-to-C compiler)
            if file_path.endswith('.pyd') or file_path.endswith('.so'):
                return True, 'Nuitka/Cython'

            # Read file content to check for markers
            with open(file_path, 'rb') as f:
                content = f.read(1024)  # First 1KB

                if b'pyarmor' in content.lower():
                    return True, 'PyArmor'

                if b'__pyarmor__' in content:
                    return True, 'PyArmor'

                if b'nuitka' in content.lower():
                    return True, 'Nuitka'

        except Exception:
            pass

        return False, None


class PythonDecompiler:
    """
    Decompiles Python bytecode using multiple decompilers

    Decompilers (in priority order):
    1. uncompyle6 - Best for Python 2.7-3.8
    2. decompyle3 - Good for Python 3.7-3.9
    3. pycdc - Fallback for newer versions
    """

    def __init__(self):
        self.uncompyle6_available = self._check_tool('uncompyle6')
        self.decompyle3_available = self._check_tool('decompyle3')
        self.pycdc_available = self._check_tool('pycdc')

    def _check_tool(self, tool_name: str) -> bool:
        """Check if decompiler tool is available"""
        try:
            result = subprocess.run([tool_name, '--version'], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False

    def decompile(self, pyc_file: str, output_file: str, python_version: str) -> DecompilationResult:
        """Decompile Python bytecode file"""
        logger.info(f"Decompiling {pyc_file} (Python {python_version})")

        # Try decompilers in order
        decompilers = []

        # uncompyle6 for Python <= 3.8
        if self.uncompyle6_available and python_version <= '3.8':
            decompilers.append(('uncompyle6', self._run_uncompyle6))

        # decompyle3 for Python 3.7-3.9
        if self.decompyle3_available and '3.7' <= python_version <= '3.9':
            decompilers.append(('decompyle3', self._run_decompyle3))

        # pycdc as fallback
        if self.pycdc_available:
            decompilers.append(('pycdc', self._run_pycdc))

        # Try each decompiler
        for decompiler_name, decompiler_func in decompilers:
            try:
                success, source_code = decompiler_func(pyc_file, output_file)
                if success:
                    return DecompilationResult(
                        bytecode_file=pyc_file,
                        decompiled_file=output_file,
                        decompiler_used=decompiler_name,
                        success=True,
                        error=None,
                        source_code=source_code,
                        metadata={'python_version': python_version}
                    )
            except Exception as e:
                logger.warning(f"{decompiler_name} failed: {e}")
                continue

        # All decompilers failed
        return DecompilationResult(
            bytecode_file=pyc_file,
            decompiled_file=None,
            decompiler_used='none',
            success=False,
            error='All decompilers failed',
            source_code=None,
            metadata={}
        )

    def _run_uncompyle6(self, pyc_file: str, output_file: str) -> Tuple[bool, Optional[str]]:
        """Run uncompyle6 decompiler"""
        cmd = ['uncompyle6', '-o', output_file, pyc_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            source_code = Path(output_file).read_text(encoding='utf-8', errors='ignore')
            return True, source_code

        return False, None

    def _run_decompyle3(self, pyc_file: str, output_file: str) -> Tuple[bool, Optional[str]]:
        """Run decompyle3 decompiler"""
        cmd = ['decompyle3', '-o', output_file, pyc_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            source_code = Path(output_file).read_text(encoding='utf-8', errors='ignore')
            return True, source_code

        return False, None

    def _run_pycdc(self, pyc_file: str, output_file: str) -> Tuple[bool, Optional[str]]:
        """Run pycdc decompiler"""
        cmd = ['pycdc', pyc_file]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if result.returncode == 0:
            source_code = result.stdout
            Path(output_file).write_text(source_code, encoding='utf-8')
            return True, source_code

        return False, None


class PythonBytecodeAnalyzer:
    """
    Main Python bytecode analyzer

    Workflow:
    1. Detect Python bytecode
    2. Extract metadata
    3. Decompile to Python source
    4. Analyze source code
    5. Generate report
    """

    def __init__(self, output_dir: str = "python_analysis"):
        self.output_dir = Path(output_dir)
        self.detector = PythonBytecodeDetector()
        self.decompiler = PythonDecompiler()

    def analyze(self, pyc_file: str) -> DecompilationResult:
        """Analyze Python bytecode file"""
        logger.info(f"Analyzing Python bytecode: {pyc_file}")

        # Step 1: Detect bytecode
        is_python, info = self.detector.detect(pyc_file)
        if not is_python:
            return DecompilationResult(
                bytecode_file=pyc_file,
                decompiled_file=None,
                decompiler_used='none',
                success=False,
                error='Not a Python bytecode file',
                source_code=None,
                metadata={}
            )

        # Create output directory
        pyc_name = Path(pyc_file).stem
        output_subdir = self.output_dir / pyc_name
        output_subdir.mkdir(parents=True, exist_ok=True)

        # Step 2: Decompile
        output_py = output_subdir / f"{pyc_name}.py"
        result = self.decompiler.decompile(pyc_file, str(output_py), info.python_version)

        # Step 3: Add metadata
        result.metadata.update({
            'python_version': info.python_version,
            'magic_number': info.magic_number,
            'is_obfuscated': info.is_obfuscated,
            'obfuscator': info.obfuscator,
            'imports': info.imports,
            'functions': info.functions,
            'classes': info.classes,
        })

        # Step 4: Generate report
        self._generate_report(info, result, output_subdir)

        return result

    def analyze_directory(self, directory: str) -> List[DecompilationResult]:
        """Analyze all .pyc files in directory"""
        results = []

        for pyc_file in Path(directory).rglob('*.pyc'):
            result = self.analyze(str(pyc_file))
            results.append(result)

        # Generate summary
        self._generate_summary(results)

        return results

    def _generate_report(self, info: PythonBytecodeInfo, result: DecompilationResult, output_dir: Path):
        """Generate analysis report"""
        report = {
            'bytecode_file': info.file_path,
            'python_version': info.python_version,
            'magic_number': info.magic_number,
            'is_obfuscated': info.is_obfuscated,
            'obfuscator': info.obfuscator,
            'decompilation_success': result.success,
            'decompiler_used': result.decompiler_used,
            'imports': info.imports,
            'functions': info.functions,
            'classes': info.classes,
        }

        # Save JSON
        report_file = output_dir / 'analysis_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        # Generate Markdown
        md_content = f"""# Python Bytecode Analysis Report

**File**: {Path(info.file_path).name}
**Python Version**: {info.python_version}
**Magic Number**: {info.magic_number}

## Obfuscation

**Obfuscated**: {info.is_obfuscated}
**Obfuscator**: {info.obfuscator or 'None detected'}

## Decompilation

**Success**: {result.success}
**Decompiler**: {result.decompiler_used}
{f"**Error**: {result.error}" if result.error else ""}

## Metadata

**Imports**: {len(info.imports)}
**Functions**: {len(info.functions)}
**Classes**: {len(info.classes)}

### Detected Imports
{chr(10).join(f'- {imp}' for imp in info.imports[:20])}

### Detected Functions
{chr(10).join(f'- {func}' for func in info.functions[:20])}

### Detected Classes
{chr(10).join(f'- {cls}' for cls in info.classes[:20])}
"""

        md_file = output_dir / 'ANALYSIS.md'
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_content)

        logger.info(f"Generated report: {report_file}")

        # Print summary
        print("\n" + "="*60)
        print("PYTHON BYTECODE ANALYSIS COMPLETE")
        print("="*60)
        print(f"File: {Path(info.file_path).name}")
        print(f"Python Version: {info.python_version}")
        print(f"Obfuscated: {info.is_obfuscated}")
        if info.is_obfuscated:
            print(f"Obfuscator: {info.obfuscator}")
        print(f"Decompilation: {'Success' if result.success else 'Failed'}")
        if result.success:
            print(f"Decompiler: {result.decompiler_used}")
        print(f"\nOutput: {output_dir}")
        print("="*60)

    def _generate_summary(self, results: List[DecompilationResult]):
        """Generate summary for batch analysis"""
        summary = {
            'total_files': len(results),
            'successful_decompilations': sum(1 for r in results if r.success),
            'failed_decompilations': sum(1 for r in results if not r.success),
            'results': [asdict(r) for r in results]
        }

        summary_file = self.output_dir / 'summary.json'
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2)

        print(f"\nBatch analysis complete: {summary['successful_decompilations']}/{len(results)} files decompiled")


def main():
    """CLI interface for Python bytecode analysis"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Analyze Python bytecode files (.pyc, .pyo) and decompile to source'
    )
    parser.add_argument('input', help='Path to .pyc file or directory')
    parser.add_argument('-o', '--output', default='python_analysis',
                       help='Output directory for analysis results')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose logging')

    args = parser.parse_args()

    # Configure logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    analyzer = PythonBytecodeAnalyzer(output_dir=args.output)

    input_path = Path(args.input)
    if input_path.is_file():
        result = analyzer.analyze(str(input_path))
        if not result.success:
            print(f"Error: {result.error}")
            return 1
    elif input_path.is_dir():
        analyzer.analyze_directory(str(input_path))
    else:
        print(f"Error: {args.input} is not a valid file or directory")
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
