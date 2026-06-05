"""
Local Disassembler - Capstone-based fallback when Ghidra is unavailable

This module provides basic disassembly capabilities using Capstone when
the Ghidra Analysis Server is not running. It's a lightweight fallback
that doesn't require any external servers.

Limitations compared to Ghidra:
- No decompilation (just disassembly)
- No cross-references
- No control flow graphs
- Basic function detection only

Author: REVENG Team
Version: 4.0.0
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Try to import capstone
try:
    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs

    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False
    logger.warning("Capstone not available. Install with: pip install capstone")

# Try to import pefile for PE analysis
try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    logger.warning("pefile not available. Install with: pip install pefile")

# Try to import pyelftools for ELF analysis
try:
    from elftools.elf.elffile import ELFFile

    ELFTOOLS_AVAILABLE = True
except ImportError:
    ELFTOOLS_AVAILABLE = False
    logger.warning("pyelftools not available. Install with: pip install pyelftools")


@dataclass
class DisassemblyResult:
    """Result of local disassembly analysis."""

    success: bool = False
    binary_path: str = ""
    binary_format: str = "unknown"
    architecture: str = "unknown"
    bits: int = 0
    entry_point: int = 0
    functions: List[Dict[str, Any]] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    exports: List[str] = field(default_factory=list)
    sections: List[Dict[str, Any]] = field(default_factory=list)
    disassembly: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    error: Optional[str] = None
    warning: Optional[str] = None


class LocalDisassembler:
    """
    Capstone-based local disassembler for basic binary analysis.

    This is a fallback when Ghidra Analysis Server is not available.
    It provides basic disassembly and string extraction without
    decompilation or advanced analysis.
    """

    def __init__(self):
        """Initialize the local disassembler."""
        self.cs = None
        self._check_dependencies()

    def _check_dependencies(self) -> Tuple[bool, List[str]]:
        """Check if required dependencies are available."""
        missing = []
        if not CAPSTONE_AVAILABLE:
            missing.append("capstone")
        if not PEFILE_AVAILABLE:
            missing.append("pefile")
        if not ELFTOOLS_AVAILABLE:
            missing.append("pyelftools")

        return len(missing) == 0, missing

    def analyze_binary(self, binary_path: str) -> DisassemblyResult:
        """
        Perform local disassembly analysis on a binary.

        Args:
            binary_path: Path to the binary file

        Returns:
            DisassemblyResult with analysis data
        """
        result = DisassemblyResult(binary_path=binary_path)

        path = Path(binary_path)
        if not path.exists():
            result.error = f"Binary not found: {binary_path}"
            return result

        # Read binary data
        try:
            with open(binary_path, "rb") as f:
                data = f.read()
        except Exception as e:
            result.error = f"Failed to read binary: {e}"
            return result

        # Detect binary format
        if data[:2] == b"MZ":
            result.binary_format = "PE"
            return self._analyze_pe(binary_path, data, result)
        elif data[:4] == b"\x7fELF":
            result.binary_format = "ELF"
            return self._analyze_elf(binary_path, data, result)
        elif data[:4] in [
            b"\xfe\xed\xfa\xce",
            b"\xfe\xed\xfa\xcf",
            b"\xce\xfa\xed\xfe",
            b"\xcf\xfa\xed\xfe",
        ]:
            result.binary_format = "Mach-O"
            return self._analyze_macho(binary_path, data, result)
        else:
            result.error = "Unknown binary format"
            result.warning = "Only PE, ELF, and Mach-O formats are supported"
            return result

    def _analyze_pe(
        self, binary_path: str, data: bytes, result: DisassemblyResult
    ) -> DisassemblyResult:
        """Analyze a PE (Windows) binary."""
        if not PEFILE_AVAILABLE:
            result.error = "pefile not available. Install with: pip install pefile"
            return result

        if not CAPSTONE_AVAILABLE:
            result.error = "Capstone not available. Install with: pip install capstone"
            return result

        try:
            pe = pefile.PE(binary_path)

            # Determine architecture
            if pe.FILE_HEADER.Machine == 0x8664:
                result.architecture = "x86_64"
                result.bits = 64
                self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
            else:
                result.architecture = "x86"
                result.bits = 32
                self.cs = Cs(CS_ARCH_X86, CS_MODE_32)

            # Get entry point
            result.entry_point = (
                pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
            )

            # Extract sections
            for section in pe.sections:
                section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                result.sections.append(
                    {
                        "name": section_name,
                        "virtual_address": hex(section.VirtualAddress),
                        "virtual_size": section.Misc_VirtualSize,
                        "raw_size": section.SizeOfRawData,
                        "characteristics": hex(section.Characteristics),
                    }
                )

            # Extract imports
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode("utf-8", errors="ignore")
                    for imp in entry.imports:
                        if imp.name:
                            func_name = imp.name.decode("utf-8", errors="ignore")
                            result.imports.append(f"{dll_name}!{func_name}")

            # Extract exports
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    if exp.name:
                        result.exports.append(exp.name.decode("utf-8", errors="ignore"))

            # Extract strings (basic)
            result.strings = self._extract_strings(data)

            # Disassemble code section
            for section in pe.sections:
                if section.Characteristics & 0x20000000:  # IMAGE_SCN_MEM_EXECUTE
                    section_name = section.Name.decode("utf-8", errors="ignore").strip("\x00")
                    section_data = section.get_data()
                    base_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress

                    instructions = []
                    for insn in self.cs.disasm(
                        section_data[: min(len(section_data), 10000)], base_addr
                    ):
                        instructions.append(
                            {
                                "address": hex(insn.address),
                                "mnemonic": insn.mnemonic,
                                "op_str": insn.op_str,
                                "bytes": insn.bytes.hex(),
                            }
                        )

                    result.disassembly[section_name] = instructions

                    # Basic function detection (call targets)
                    for insn in instructions:
                        if insn["mnemonic"] == "call":
                            result.functions.append(
                                {
                                    "name": f"sub_{insn['op_str']}",
                                    "address": insn["op_str"],
                                    "detected_by": "call_target",
                                }
                            )

            result.success = True
            result.warning = (
                "Local analysis only - no decompilation. For full analysis, start Ghidra server."
            )

        except Exception as e:
            result.error = f"PE analysis failed: {e}"

        return result

    def _analyze_elf(
        self, binary_path: str, data: bytes, result: DisassemblyResult
    ) -> DisassemblyResult:
        """Analyze an ELF (Linux) binary."""
        if not ELFTOOLS_AVAILABLE:
            result.error = "pyelftools not available. Install with: pip install pyelftools"
            return result

        if not CAPSTONE_AVAILABLE:
            result.error = "Capstone not available. Install with: pip install capstone"
            return result

        try:
            with open(binary_path, "rb") as f:
                elf = ELFFile(f)

                # Determine architecture
                if elf.elfclass == 64:
                    result.architecture = "x86_64"
                    result.bits = 64
                    self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
                else:
                    result.architecture = "x86"
                    result.bits = 32
                    self.cs = Cs(CS_ARCH_X86, CS_MODE_32)

                # Get entry point
                result.entry_point = elf.header.e_entry

                # Extract sections
                for section in elf.iter_sections():
                    result.sections.append(
                        {
                            "name": section.name,
                            "address": hex(section["sh_addr"]),
                            "size": section["sh_size"],
                            "type": section["sh_type"],
                        }
                    )

                # Extract strings
                result.strings = self._extract_strings(data)

                # Disassemble .text section
                text_section = elf.get_section_by_name(".text")
                if text_section:
                    section_data = text_section.data()
                    base_addr = text_section["sh_addr"]

                    instructions = []
                    for insn in self.cs.disasm(
                        section_data[: min(len(section_data), 10000)], base_addr
                    ):
                        instructions.append(
                            {
                                "address": hex(insn.address),
                                "mnemonic": insn.mnemonic,
                                "op_str": insn.op_str,
                                "bytes": insn.bytes.hex(),
                            }
                        )

                    result.disassembly[".text"] = instructions

                result.success = True
                result.warning = "Local analysis only - no decompilation. For full analysis, start Ghidra server."

        except Exception as e:
            result.error = f"ELF analysis failed: {e}"

        return result

    def _analyze_macho(
        self, binary_path: str, data: bytes, result: DisassemblyResult
    ) -> DisassemblyResult:
        """Analyze a Mach-O (macOS) binary."""
        # Basic Mach-O support - extract strings and basic info
        result.warning = "Mach-O support is limited. For full analysis, start Ghidra server."
        result.strings = self._extract_strings(data)
        result.success = True
        return result

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract printable strings from binary data."""
        strings = []
        current = ""

        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current += chr(byte)
            else:
                if len(current) >= min_length:
                    strings.append(current)
                current = ""

        if len(current) >= min_length:
            strings.append(current)

        # Limit to first 1000 strings
        return strings[:1000]

    def to_ghidra_format(self, result: DisassemblyResult) -> Dict[str, Any]:
        """
        Convert local analysis result to Ghidra-compatible format.

        This allows the rest of the pipeline to work with local analysis
        results in the same way as Ghidra results.
        """
        return {
            "analysis_complete": result.success,
            "analysis_mode": "local_capstone",
            "functions": result.functions,
            "decompiled_code": {},  # No decompilation available locally
            "strings": result.strings,
            "imports": result.imports,
            "exports": result.exports,
            "sections": result.sections,
            "metadata": {
                "binary_path": result.binary_path,
                "format": result.binary_format,
                "architecture": result.architecture,
                "bits": result.bits,
                "entry_point": hex(result.entry_point) if result.entry_point else "0x0",
            },
            "disassembly": result.disassembly,
            "xrefs": {},  # No xrefs available locally
            "warning": result.warning or "Local analysis - decompilation requires Ghidra server",
        }


def get_local_disassembler() -> Optional[LocalDisassembler]:
    """Get a local disassembler instance if dependencies are available."""
    deps_ok, missing = LocalDisassembler()._check_dependencies()

    if not CAPSTONE_AVAILABLE:
        logger.warning(
            "Local disassembly fallback not available. " "Install capstone: pip install capstone"
        )
        return None

    return LocalDisassembler()
