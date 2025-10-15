#!/usr/bin/env python3
"""
REVENG Enhanced Language Detector
=================================

Automatically detects binary and bytecode file types for multi-language support.

Supports:
- Native binaries (PE, ELF, Mach-O)
- Java bytecode (.class, .jar, .war, .ear)
- .NET assemblies (.exe, .dll with IL)
- Python bytecode (.pyc, .pyo)
- JavaScript (packed/minified .js, Node.js applications)
- WebAssembly (.wasm files)
- Electron applications (app.asar, resources)
- Additional formats for AI-Enhanced Universal Analysis
"""

import os
import json
import struct
import zipfile
from pathlib import Path
from typing import Optional, Dict, List
from dataclasses import dataclass
import logging
import re

logger = logging.getLogger(__name__)


@dataclass
class FileTypeInfo:
    """Information about detected file type"""
    language: str
    format: str
    confidence: float
    details: Dict[str, any]


class LanguageDetector:
    """
    Detect file type and programming language from binary/bytecode files

    Detection strategy:
    1. Magic bytes (file signatures)
    2. File extension
    3. File structure analysis
    4. Heuristic patterns
    """

    # Magic bytes for various file formats
    MAGIC_BYTES = {
        # Native binaries
        'PE': [b'MZ'],  # PE/COFF executables (Windows)
        'ELF': [b'\x7fELF'],  # ELF executables (Linux/Unix)
        'MACH_O_32': [b'\xfe\xed\xfa\xce'],  # Mach-O 32-bit
        'MACH_O_64': [b'\xfe\xed\xfa\xcf'],  # Mach-O 64-bit

        # Java bytecode
        'JAVA_CLASS': [b'\xca\xfe\xba\xbe'],  # Java .class file
        'ZIP': [b'PK\x03\x04'],  # ZIP (used by JAR/WAR/EAR)

        # .NET
        'DOTNET_PE': [b'MZ'],  # .NET assemblies start with PE header

        # Python bytecode
        'PYTHON_PYC': [
            b'\x42\x0d\x0d\x0a',  # Python 3.8+
            b'\x55\x0d\x0d\x0a',  # Python 3.7
            b'\x33\x0d\x0d\x0a',  # Python 3.6
        ],

        # WebAssembly
        'WASM': [b'\x00asm'],  # WebAssembly magic bytes

        # Electron ASAR
        'ASAR': [b'{"files":', b'{"files" :'],  # ASAR archive header patterns
    }

    def __init__(self):
        """Initialize language detector"""
        self.detection_cache = {}

    def detect(self, file_path: str) -> FileTypeInfo:
        """
        Detect file type and language

        Args:
            file_path: Path to file to analyze

        Returns:
            FileTypeInfo with detection results
        """
        file_path = Path(file_path)

        # Check cache
        cache_key = str(file_path.absolute())
        if cache_key in self.detection_cache:
            return self.detection_cache[cache_key]

        if not file_path.exists():
            return FileTypeInfo(
                language='unknown',
                format='unknown',
                confidence=0.0,
                details={'error': 'File not found'}
            )

        # Try detection methods in order
        result = (
            self._detect_by_magic_bytes(file_path) or
            self._detect_by_extension(file_path) or
            self._detect_by_structure(file_path) or
            self._detect_javascript_nodejs(file_path) or
            self._detect_electron_app(file_path) or
            FileTypeInfo(
                language='unknown',
                format='unknown',
                confidence=0.0,
                details={'method': 'all_methods_failed'}
            )
        )

        # Cache result
        self.detection_cache[cache_key] = result
        logger.info(f"Detected {file_path.name} as {result.language}/{result.format} (confidence: {result.confidence:.2f})")

        return result

    def _detect_by_magic_bytes(self, file_path: Path) -> Optional[FileTypeInfo]:
        """Detect file type by magic bytes"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(256)  # Read first 256 bytes

            # Check Java .class file
            if header.startswith(b'\xca\xfe\xba\xbe'):
                return FileTypeInfo(
                    language='java',
                    format='class',
                    confidence=1.0,
                    details={
                        'method': 'magic_bytes',
                        'signature': 'CAFEBABE'
                    }
                )

            # Check ZIP (potential JAR/WAR/EAR)
            if header.startswith(b'PK\x03\x04'):
                # Try to determine if it's a JAR
                if self._is_java_archive(file_path):
                    return FileTypeInfo(
                        language='java',
                        format='jar',
                        confidence=0.95,
                        details={
                            'method': 'magic_bytes_plus_structure',
                            'signature': 'ZIP'
                        }
                    )
                else:
                    # Generic ZIP, might be other archive
                    return FileTypeInfo(
                        language='unknown',
                        format='zip',
                        confidence=0.5,
                        details={'method': 'magic_bytes'}
                    )

            # Check ELF
            if header.startswith(b'\x7fELF'):
                return FileTypeInfo(
                    language='native',
                    format='elf',
                    confidence=1.0,
                    details={
                        'method': 'magic_bytes',
                        'signature': 'ELF'
                    }
                )

            # Check PE (Windows)
            if header.startswith(b'MZ'):
                # Check if it's .NET assembly
                if self._is_dotnet_assembly(file_path):
                    return FileTypeInfo(
                        language='csharp',
                        format='dotnet_assembly',
                        confidence=0.9,
                        details={
                            'method': 'magic_bytes_plus_structure',
                            'signature': 'PE+CLR'
                        }
                    )
                else:
                    return FileTypeInfo(
                        language='native',
                        format='pe',
                        confidence=1.0,
                        details={
                            'method': 'magic_bytes',
                            'signature': 'MZ'
                        }
                    )

            # Check Mach-O
            if header[:4] in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf']:
                return FileTypeInfo(
                    language='native',
                    format='mach_o',
                    confidence=1.0,
                    details={
                        'method': 'magic_bytes',
                        'signature': 'FEEDFACE/FEEDFACF'
                    }
                )

            # Check Python bytecode
            for pyc_magic in self.MAGIC_BYTES['PYTHON_PYC']:
                if header.startswith(pyc_magic):
                    return FileTypeInfo(
                        language='python',
                        format='pyc',
                        confidence=0.95,
                        details={
                            'method': 'magic_bytes',
                            'signature': pyc_magic.hex()
                        }
                    )

            # Check WebAssembly
            if header.startswith(b'\x00asm'):
                version = struct.unpack('<I', header[4:8])[0] if len(header) >= 8 else 0
                return FileTypeInfo(
                    language='webassembly',
                    format='wasm',
                    confidence=1.0,
                    details={
                        'method': 'magic_bytes',
                        'signature': '00asm',
                        'version': version
                    }
                )

            # Check ASAR (Electron app archive)
            header_str = header.decode('utf-8', errors='ignore')
            if header_str.startswith('{"files":') or header_str.startswith('{"files" :'):
                return FileTypeInfo(
                    language='javascript',
                    format='electron_asar',
                    confidence=0.9,
                    details={
                        'method': 'magic_bytes',
                        'signature': 'ASAR_JSON'
                    }
                )

        except Exception as e:
            logger.warning(f"Error reading magic bytes from {file_path}: {e}")

        return None

    def _detect_by_extension(self, file_path: Path) -> Optional[FileTypeInfo]:
        """Detect file type by extension"""
        ext = file_path.suffix.lower()

        # Java extensions
        if ext == '.class':
            return FileTypeInfo(
                language='java',
                format='class',
                confidence=0.8,
                details={'method': 'extension'}
            )

        if ext in ['.jar', '.war', '.ear']:
            return FileTypeInfo(
                language='java',
                format=ext[1:],  # jar/war/ear
                confidence=0.85,
                details={'method': 'extension'}
            )

        # Native binary extensions
        if ext in ['.exe', '.dll']:
            return FileTypeInfo(
                language='native',  # Could be native or .NET
                format='pe',
                confidence=0.6,
                details={'method': 'extension', 'note': 'could_be_dotnet'}
            )

        if ext in ['.so', '.dylib']:
            return FileTypeInfo(
                language='native',
                format='elf' if ext == '.so' else 'mach_o',
                confidence=0.7,
                details={'method': 'extension'}
            )

        if ext == '.elf':
            return FileTypeInfo(
                language='native',
                format='elf',
                confidence=0.8,
                details={'method': 'extension'}
            )

        # Python bytecode
        if ext in ['.pyc', '.pyo']:
            return FileTypeInfo(
                language='python',
                format='pyc',
                confidence=0.85,
                details={'method': 'extension'}
            )

        # JavaScript and Node.js
        if ext == '.js':
            return FileTypeInfo(
                language='javascript',
                format='js',
                confidence=0.5,  # Low confidence - need to check if minified
                details={'method': 'extension'}
            )

        # WebAssembly
        if ext == '.wasm':
            return FileTypeInfo(
                language='webassembly',
                format='wasm',
                confidence=0.9,
                details={'method': 'extension'}
            )

        # Electron ASAR
        if ext == '.asar':
            return FileTypeInfo(
                language='javascript',
                format='electron_asar',
                confidence=0.85,
                details={'method': 'extension'}
            )

        # Node.js package - but we need to analyze content to determine if it's Electron
        # This will be handled by _detect_javascript_nodejs method

        return None

    def _detect_by_structure(self, file_path: Path) -> Optional[FileTypeInfo]:
        """Detect file type by analyzing file structure"""
        # This is a fallback method for ambiguous cases
        # Currently minimal implementation
        return None

    def _detect_javascript_nodejs(self, file_path: Path) -> Optional[FileTypeInfo]:
        """Detect JavaScript and Node.js applications"""
        try:
            # Check for package.json (Node.js project)
            if file_path.name == 'package.json':
                with open(file_path, 'r', encoding='utf-8') as f:
                    package_data = json.load(f)
                
                # Determine if it's an Electron app
                dependencies = package_data.get('dependencies', {})
                dev_dependencies = package_data.get('devDependencies', {})
                all_deps = {**dependencies, **dev_dependencies}
                
                if 'electron' in all_deps:
                    return FileTypeInfo(
                        language='javascript',
                        format='electron_app',
                        confidence=0.95,
                        details={
                            'method': 'package_json_analysis',
                            'electron_version': all_deps.get('electron', 'unknown'),
                            'main_entry': package_data.get('main', 'index.js')
                        }
                    )
                else:
                    return FileTypeInfo(
                        language='javascript',
                        format='nodejs_app',
                        confidence=0.9,
                        details={
                            'method': 'package_json_analysis',
                            'main_entry': package_data.get('main', 'index.js'),
                            'scripts': list(package_data.get('scripts', {}).keys())
                        }
                    )

            # Check for JavaScript files with Node.js patterns
            if file_path.suffix.lower() == '.js':
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(1024)  # Read first 1KB
                
                # Look for Node.js patterns
                nodejs_patterns = [
                    r'require\s*\(',
                    r'module\.exports',
                    r'exports\.',
                    r'process\.env',
                    r'__dirname',
                    r'__filename'
                ]
                
                nodejs_matches = sum(1 for pattern in nodejs_patterns if re.search(pattern, content))
                
                # Look for minification patterns
                minified_indicators = [
                    len(content.split('\n')) < 10 and len(content) > 500,  # Few lines but long
                    re.search(r'[a-zA-Z]\s*=\s*function\s*\([a-zA-Z,]*\)\s*{', content),  # Minified functions
                    content.count(';') > content.count('\n') * 3  # Many semicolons per line
                ]
                
                is_minified = sum(minified_indicators) >= 2
                
                if nodejs_matches >= 2:
                    return FileTypeInfo(
                        language='javascript',
                        format='nodejs_script',
                        confidence=0.8,
                        details={
                            'method': 'content_analysis',
                            'nodejs_patterns': nodejs_matches,
                            'minified': is_minified
                        }
                    )
                elif is_minified:
                    return FileTypeInfo(
                        language='javascript',
                        format='minified_js',
                        confidence=0.7,
                        details={
                            'method': 'content_analysis',
                            'minified': True
                        }
                    )

        except Exception as e:
            logger.debug(f"Error detecting JavaScript/Node.js: {e}")

        return None

    def _detect_electron_app(self, file_path: Path) -> Optional[FileTypeInfo]:
        """Detect Electron applications"""
        try:
            # Check for app.asar file
            if file_path.name == 'app.asar':
                return FileTypeInfo(
                    language='javascript',
                    format='electron_asar',
                    confidence=0.95,
                    details={
                        'method': 'filename_analysis',
                        'asar_file': True
                    }
                )

            # Check for Electron directory structure
            parent_dir = file_path.parent
            
            # Look for Electron app indicators in the directory
            electron_indicators = [
                'app.asar',
                'resources',
                'electron.exe',
                'electron',
                'package.json'
            ]
            
            found_indicators = []
            for indicator in electron_indicators:
                if (parent_dir / indicator).exists():
                    found_indicators.append(indicator)

            # Check for resources directory with app.asar
            resources_dir = parent_dir / 'resources'
            if resources_dir.exists() and (resources_dir / 'app.asar').exists():
                return FileTypeInfo(
                    language='javascript',
                    format='electron_app',
                    confidence=0.9,
                    details={
                        'method': 'directory_structure',
                        'indicators_found': found_indicators,
                        'has_asar': True
                    }
                )

            # If we found multiple Electron indicators
            if len(found_indicators) >= 2:
                return FileTypeInfo(
                    language='javascript',
                    format='electron_app',
                    confidence=0.7,
                    details={
                        'method': 'directory_structure',
                        'indicators_found': found_indicators
                    }
                )

        except Exception as e:
            logger.debug(f"Error detecting Electron app: {e}")

        return None

    def _is_java_archive(self, file_path: Path) -> bool:
        """Check if ZIP file is a Java archive (JAR/WAR/EAR)"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zf:
                # JAR files contain META-INF/MANIFEST.MF
                if 'META-INF/MANIFEST.MF' in zf.namelist():
                    return True

                # Or contain .class files
                for name in zf.namelist():
                    if name.endswith('.class'):
                        return True
        except Exception as e:
            logger.debug(f"Error checking Java archive: {e}")

        return False

    def _is_dotnet_assembly(self, file_path: Path) -> bool:
        """Check if PE file is a .NET assembly"""
        try:
            with open(file_path, 'rb') as f:
                # Read DOS header
                dos_header = f.read(64)
                if len(dos_header) < 64:
                    return False

                # Get PE header offset
                pe_offset = struct.unpack('<I', dos_header[60:64])[0]

                # Read PE header
                f.seek(pe_offset)
                pe_sig = f.read(4)

                if pe_sig != b'PE\x00\x00':
                    return False

                # Read COFF header
                f.read(20)  # Skip COFF header

                # Read optional header magic
                magic = struct.unpack('<H', f.read(2))[0]

                # Skip to data directories
                if magic == 0x10b:  # PE32
                    f.seek(pe_offset + 24 + 92, 0)
                elif magic == 0x20b:  # PE32+
                    f.seek(pe_offset + 24 + 108, 0)
                else:
                    return False

                # Read number of data directories
                num_dirs = struct.unpack('<I', f.read(4))[0]

                # CLR Runtime Header is at index 14
                if num_dirs > 14:
                    f.seek(pe_offset + (24 + (108 if magic == 0x20b else 92) + 4 + (14 * 8)), 0)
                    clr_header_rva = struct.unpack('<I', f.read(4))[0]

                    # If CLR header RVA is non-zero, it's a .NET assembly
                    return clr_header_rva != 0

        except Exception as e:
            logger.debug(f"Error checking .NET assembly: {e}")

        return False

    def get_language_category(self, file_type_info: FileTypeInfo) -> str:
        """
        Get broad category for file type

        Returns:
            'native_binary', 'java_bytecode', 'dotnet_assembly', 'python_bytecode', etc.
        """
        if file_type_info.language == 'java':
            return 'java_bytecode'
        elif file_type_info.language == 'native':
            return 'native_binary'
        elif file_type_info.language == 'csharp':
            return 'dotnet_assembly'
        elif file_type_info.language == 'python':
            return 'python_bytecode'
        elif file_type_info.language == 'javascript':
            if file_type_info.format in ['electron_app', 'electron_asar']:
                return 'electron_application'
            elif file_type_info.format in ['nodejs_app', 'nodejs_script', 'nodejs_package']:
                return 'nodejs_application'
            else:
                return 'javascript'
        elif file_type_info.language == 'webassembly':
            return 'webassembly'
        else:
            return 'unknown'

    def supports_enhanced_analysis(self, file_type_info: FileTypeInfo) -> bool:
        """
        Check if file type supports AI-Enhanced Universal Analysis
        
        Returns:
            True if the file type is supported by enhanced analysis modules
        """
        supported_languages = [
            'java', 'native', 'csharp', 'python', 
            'javascript', 'webassembly'
        ]
        return file_type_info.language in supported_languages

    def get_analysis_priority(self, file_type_info: FileTypeInfo) -> str:
        """
        Get analysis priority for the file type
        
        Returns:
            'high', 'medium', 'low' based on security relevance
        """
        # High priority: Native binaries, .NET assemblies (potential malware/corporate apps)
        if file_type_info.language in ['native', 'csharp']:
            return 'high'
        
        # Medium priority: Java, Python, Electron (common enterprise applications)
        elif file_type_info.language in ['java', 'python'] or \
             file_type_info.format in ['electron_app', 'electron_asar']:
            return 'medium'
        
        # Lower priority: JavaScript, WebAssembly
        elif file_type_info.language in ['javascript', 'webassembly']:
            return 'low'
        
        else:
            return 'low'


def main():
    """Test language detector"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python language_detector.py <file_path>")
        sys.exit(1)

    detector = LanguageDetector()
    file_info = detector.detect(sys.argv[1])

    print(f"File: {sys.argv[1]}")
    print(f"Language: {file_info.language}")
    print(f"Format: {file_info.format}")
    print(f"Confidence: {file_info.confidence:.2%}")
    print(f"Details: {file_info.details}")
    print(f"Category: {detector.get_language_category(file_info)}")


if __name__ == '__main__':
    main()
