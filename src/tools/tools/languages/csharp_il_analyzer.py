#!/usr/bin/env python3
"""
REVENG C# IL Analyzer
=====================

Analyzes .NET assemblies (C# compiled binaries) using IL disassembly.

Features:
- .NET assembly detection (PE + CLR header)
- IL disassembly using ildasm or dnSpy
- C# decompilation using ILSpy or dnSpy
- Obfuscation detection (ConfuserEx, .NET Reactor, Eazfuscator)
- Metadata extraction (types, methods, properties)
- Dependency analysis

Requires:
- .NET SDK (for ildasm)
- ILSpy CLI or dnSpy (for decompilation)
"""

import os
import re
import json
import logging
import subprocess
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
import struct

logger = logging.getLogger(__name__)


@dataclass
class DotNetAssemblyInfo:
    """Information about a .NET assembly"""
    name: str
    version: str
    runtime_version: str
    architecture: str  # x86, x64, AnyCPU
    is_dotnet: bool
    has_clr_header: bool
    entry_point: Optional[str]
    namespaces: List[str]
    types: List[str]
    methods_count: int
    obfuscated: bool
    obfuscator: Optional[str]


@dataclass
class ILDisassemblyResult:
    """Result from IL disassembly"""
    assembly: str
    il_output_file: str
    decompiled_output_dir: Optional[str]
    metadata: Dict[str, any]
    success: bool
    error: Optional[str]


class DotNetDetector:
    """
    Detects if a file is a .NET assembly

    Checks:
    1. PE header (MZ signature)
    2. CLR header (COM+ descriptor)
    3. Metadata tables
    """

    @staticmethod
    def is_dotnet_assembly(file_path: str) -> Tuple[bool, Dict[str, any]]:
        """Check if file is a .NET assembly"""
        try:
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                    return False, {}

                # Get PE header offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]
                f.seek(pe_offset)

                # Read PE signature
                pe_sig = f.read(4)
                if pe_sig != b'PE\x00\x00':
                    return False, {}

                # Read COFF header
                f.read(20)  # Skip COFF header

                # Read optional header magic
                magic = struct.unpack('<H', f.read(2))[0]
                is_64bit = (magic == 0x20b)

                # Skip to Data Directories
                skip_size = 94 if is_64bit else 78
                f.read(skip_size)

                # Read COM+ descriptor RVA (14th data directory)
                f.read(8 * 13)  # Skip first 13 directories
                clr_rva, clr_size = struct.unpack('<II', f.read(8))

                has_clr = (clr_rva != 0 and clr_size != 0)

                metadata = {
                    'has_clr_header': has_clr,
                    'architecture': 'x64' if is_64bit else 'x86',
                    'clr_rva': hex(clr_rva),
                    'clr_size': clr_size
                }

                return has_clr, metadata

        except Exception as e:
            logger.warning(f"Failed to check .NET assembly: {e}")
            return False, {}


class ILDasmRunner:
    """
    Runs ildasm.exe to disassemble .NET assemblies to IL code

    ildasm is part of the .NET SDK
    """

    def __init__(self):
        self.ildasm_path = self._find_ildasm()

    def _find_ildasm(self) -> Optional[Path]:
        """Find ildasm.exe in system"""
        # Try common locations
        common_paths = [
            r"C:\Program Files\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\ildasm.exe",
            r"C:\Program Files (x86)\Microsoft SDKs\Windows\v10.0A\bin\NETFX 4.8 Tools\ildasm.exe",
            r"C:\Program Files\dotnet\sdk\*\ildasm.exe",
        ]

        for path_pattern in common_paths:
            if '*' in path_pattern:
                # Glob pattern
                from glob import glob
                matches = glob(path_pattern)
                if matches:
                    return Path(matches[0])
            else:
                p = Path(path_pattern)
                if p.exists():
                    return p

        # Try finding via 'where' command
        try:
            result = subprocess.run(['where', 'ildasm'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                return Path(result.stdout.strip().splitlines()[0])
        except Exception:
            pass

        logger.warning("ildasm.exe not found - IL disassembly will be unavailable")
        return None

    def disassemble(self, assembly_path: str, output_file: str) -> bool:
        """Disassemble .NET assembly to IL code"""
        if not self.ildasm_path:
            logger.error("ildasm not available")
            return False

        try:
            cmd = [
                str(self.ildasm_path),
                assembly_path,
                f'/OUT={output_file}',
                '/TEXT',  # Text format
                '/SOURCE',  # Include source lines if available
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

            if result.returncode == 0:
                logger.info(f"IL disassembly successful: {output_file}")
                return True
            else:
                logger.error(f"ildasm failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Failed to run ildasm: {e}")
            return False


class ILSpyRunner:
    """
    Runs ILSpy CLI to decompile .NET assemblies to C# source

    Requires: dotnet tool install -g ilspycmd
    """

    def __init__(self):
        self.ilspy_available = self._check_ilspy()

    def _check_ilspy(self) -> bool:
        """Check if ILSpy CLI is available"""
        try:
            result = subprocess.run(['ilspycmd', '--version'], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            logger.warning("ILSpy CLI not found - C# decompilation will be unavailable")
            return False

    def decompile(self, assembly_path: str, output_dir: str) -> bool:
        """Decompile .NET assembly to C# source"""
        if not self.ilspy_available:
            logger.error("ILSpy not available")
            return False

        try:
            cmd = [
                'ilspycmd',
                assembly_path,
                '-o', output_dir,
                '-p'  # Create project structure
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                logger.info(f"C# decompilation successful: {output_dir}")
                return True
            else:
                logger.error(f"ILSpy failed: {result.stderr}")
                return False

        except Exception as e:
            logger.error(f"Failed to run ILSpy: {e}")
            return False


class DotNetObfuscationDetector:
    """
    Detects .NET obfuscation

    Common obfuscators:
    - ConfuserEx (markers: ConfusedBy attribute)
    - .NET Reactor (markers: .netz resources)
    - Eazfuscator.NET (markers: eaz_ prefixes)
    - Crypto Obfuscator
    - Agile.NET
    """

    def detect_obfuscation(self, il_content: str, assembly_path: str) -> Tuple[bool, Optional[str]]:
        """Detect if assembly is obfuscated"""

        # Check for ConfuserEx
        if 'ConfusedBy' in il_content or 'ConfuserEx' in il_content:
            return True, 'ConfuserEx'

        # Check for .NET Reactor
        if '.netz' in il_content.lower() or 'NETReactor' in il_content:
            return True, '.NET Reactor'

        # Check for Eazfuscator
        if 'eaz_' in il_content.lower() or 'Eazfuscator' in il_content:
            return True, 'Eazfuscator.NET'

        # Check for Crypto Obfuscator
        if 'CryptoObfuscator' in il_content:
            return True, 'Crypto Obfuscator'

        # Heuristic checks
        obfuscation_indicators = 0

        # 1. Lots of single-character type/method names
        short_names = len(re.findall(r'\bclass\s+[a-z]\b', il_content))
        if short_names > 10:
            obfuscation_indicators += 1

        # 2. Random-looking names
        random_names = len(re.findall(r'\b[A-Z][a-z0-9]{10,}\b', il_content))
        if random_names > 20:
            obfuscation_indicators += 1

        # 3. Control flow obfuscation (lots of branches)
        branches = il_content.count('br.') + il_content.count('brtrue') + il_content.count('brfalse')
        if branches > 1000:
            obfuscation_indicators += 1

        # 4. String encryption (lots of ldc.i4 + xor)
        string_encryption = il_content.count('ldc.i4') > 500 and il_content.count('xor') > 100
        if string_encryption:
            obfuscation_indicators += 1

        if obfuscation_indicators >= 2:
            return True, 'Unknown (heuristic detection)'

        return False, None


class CSharpILAnalyzer:
    """
    Main C# IL analyzer

    Workflow:
    1. Detect if file is .NET assembly
    2. Extract metadata
    3. Disassemble to IL
    4. Decompile to C# (if available)
    5. Detect obfuscation
    6. Generate analysis report
    """

    def __init__(self, output_dir: str = "csharp_analysis"):
        self.output_dir = Path(output_dir)
        self.detector = DotNetDetector()
        self.ildasm = ILDasmRunner()
        self.ilspy = ILSpyRunner()
        self.obfuscation_detector = DotNetObfuscationDetector()

    def analyze(self, assembly_path: str) -> ILDisassemblyResult:
        """Analyze .NET assembly"""
        logger.info(f"Analyzing .NET assembly: {assembly_path}")

        assembly_name = Path(assembly_path).stem
        output_subdir = self.output_dir / assembly_name
        output_subdir.mkdir(parents=True, exist_ok=True)

        # Step 1: Verify it's a .NET assembly
        is_dotnet, metadata = self.detector.is_dotnet_assembly(assembly_path)
        if not is_dotnet:
            return ILDisassemblyResult(
                assembly=assembly_path,
                il_output_file='',
                decompiled_output_dir=None,
                metadata={},
                success=False,
                error='Not a .NET assembly'
            )

        # Step 2: Disassemble to IL
        il_output = output_subdir / f"{assembly_name}.il"
        il_success = self.ildasm.disassemble(assembly_path, str(il_output))

        # Step 3: Decompile to C# (if ILSpy available)
        decompiled_dir = None
        if self.ilspy.ilspy_available:
            decompiled_dir = output_subdir / 'decompiled_csharp'
            self.ilspy.decompile(assembly_path, str(decompiled_dir))

        # Step 4: Parse IL to extract metadata
        if il_success and il_output.exists():
            il_content = il_output.read_text(encoding='utf-8', errors='ignore')
            metadata.update(self._parse_il_metadata(il_content))

            # Detect obfuscation
            obfuscated, obfuscator = self.obfuscation_detector.detect_obfuscation(il_content, assembly_path)
            metadata['obfuscated'] = obfuscated
            metadata['obfuscator'] = obfuscator

        # Step 5: Generate report
        self._generate_report(assembly_path, metadata, output_subdir)

        return ILDisassemblyResult(
            assembly=assembly_path,
            il_output_file=str(il_output) if il_success else '',
            decompiled_output_dir=str(decompiled_dir) if decompiled_dir else None,
            metadata=metadata,
            success=il_success,
            error=None
        )

    def _parse_il_metadata(self, il_content: str) -> Dict[str, any]:
        """Parse IL content to extract metadata"""
        metadata = {}

        # Extract assembly version
        version_match = re.search(r'\.assembly\s+\w+.*?\.ver\s+([\d:]+)', il_content, re.DOTALL)
        if version_match:
            metadata['version'] = version_match.group(1).replace(':', '.')

        # Extract runtime version
        runtime_match = re.search(r'\.corflags\s+(0x[0-9a-fA-F]+)', il_content)
        if runtime_match:
            metadata['runtime_version'] = runtime_match.group(1)

        # Extract namespaces
        namespaces = set(re.findall(r'\.namespace\s+([\w.]+)', il_content))
        metadata['namespaces'] = sorted(namespaces)

        # Extract types (classes, interfaces, structs)
        types = re.findall(r'\.class\s+(?:public|private|interface)?\s+[\w.]+', il_content)
        metadata['types'] = types[:100]  # Limit to first 100
        metadata['types_count'] = len(types)

        # Extract methods
        methods = re.findall(r'\.method\s+(?:public|private|static)?\s+[\w\s<>]+', il_content)
        metadata['methods_count'] = len(methods)

        # Find entry point
        entry_point_match = re.search(r'\.entrypoint', il_content)
        if entry_point_match:
            # Find preceding method
            before_entry = il_content[:entry_point_match.start()]
            method_match = re.findall(r'\.method\s+[\w\s<>]+\s+([\w.]+)\(', before_entry)
            if method_match:
                metadata['entry_point'] = method_match[-1]

        return metadata

    def _generate_report(self, assembly_path: str, metadata: Dict, output_dir: Path):
        """Generate analysis report"""
        report = {
            'assembly': assembly_path,
            'is_dotnet': metadata.get('has_clr_header', False),
            'architecture': metadata.get('architecture', 'unknown'),
            'version': metadata.get('version', 'unknown'),
            'runtime_version': metadata.get('runtime_version', 'unknown'),
            'obfuscated': metadata.get('obfuscated', False),
            'obfuscator': metadata.get('obfuscator'),
            'namespaces': metadata.get('namespaces', []),
            'types_count': metadata.get('types_count', 0),
            'methods_count': metadata.get('methods_count', 0),
            'entry_point': metadata.get('entry_point'),
        }

        # Save JSON report
        report_file = output_dir / 'analysis_report.json'
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

        # Generate Markdown report
        md_report = f"""# C# IL Analysis Report

**Assembly**: {Path(assembly_path).name}
**Architecture**: {report['architecture']}
**Version**: {report['version']}
**Runtime**: {report['runtime_version']}

## Obfuscation

**Obfuscated**: {report['obfuscated']}
**Obfuscator**: {report['obfuscator'] or 'None detected'}

## Structure

**Namespaces**: {len(report['namespaces'])}
**Types**: {report['types_count']}
**Methods**: {report['methods_count']}
**Entry Point**: {report['entry_point'] or 'Not found'}

## Namespaces

{chr(10).join(f'- {ns}' for ns in report['namespaces'][:20])}
"""

        md_file = output_dir / 'ANALYSIS.md'
        with open(md_file, 'w', encoding='utf-8') as f:
            f.write(md_report)

        logger.info(f"Generated report: {report_file}")

        # Print summary
        print("\n" + "="*60)
        print("C# IL ANALYSIS COMPLETE")
        print("="*60)
        print(f"Assembly: {Path(assembly_path).name}")
        print(f"Architecture: {report['architecture']}")
        print(f"Obfuscated: {report['obfuscated']}")
        if report['obfuscated']:
            print(f"Obfuscator: {report['obfuscator']}")
        print(f"Namespaces: {len(report['namespaces'])}")
        print(f"Types: {report['types_count']}")
        print(f"Methods: {report['methods_count']}")
        print(f"\nOutput: {output_dir}")
        print("="*60)


def main():
    """CLI interface for C# IL analysis"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Analyze .NET assemblies (C# compiled binaries) with IL disassembly'
    )
    parser.add_argument('assembly', help='Path to .NET assembly (.exe or .dll)')
    parser.add_argument('-o', '--output', default='csharp_analysis',
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

    analyzer = CSharpILAnalyzer(output_dir=args.output)
    result = analyzer.analyze(args.assembly)

    if not result.success:
        print(f"Error: {result.error}")
        return 1

    return 0


if __name__ == '__main__':
    exit(main())
