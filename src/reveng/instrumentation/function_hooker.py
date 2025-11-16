"""
Function Hooker

Advanced function hooking and manipulation capabilities.
"""

import logging
from typing import Dict, List, Optional, Callable, Any, Tuple
from dataclasses import dataclass
from enum import Enum


class HookStrategy(Enum):
    """Hook implementation strategies"""
    INLINE = "inline"                   # Inline code modification
    IAT = "iat"                        # Import Address Table hooking
    TRAMPOLINE = "trampoline"          # Trampoline/detour
    VTABLE = "vtable"                  # Virtual table hooking
    GOT_PLT = "got_plt"                # GOT/PLT hooking (Linux)


@dataclass
class FunctionSignature:
    """Function signature information"""
    name: str
    address: int
    module: Optional[str] = None
    return_type: Optional[str] = None
    parameters: Optional[List[str]] = None
    calling_convention: str = "cdecl"


@dataclass
class HookInfo:
    """Hook installation information"""
    function: FunctionSignature
    strategy: HookStrategy
    original_bytes: Optional[bytes] = None
    trampoline_address: Optional[int] = None
    active: bool = False


class FunctionHooker:
    """
    Advanced function hooking engine.

    Provides multiple hooking strategies for different scenarios:
    - Inline hooks for individual functions
    - IAT hooks for imported functions
    - Trampoline hooks for non-invasive hooking
    - vtable hooks for C++ objects
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.hooks: Dict[str, HookInfo] = {}
        self.trampolines: Dict[int, bytes] = {}

    def hook_function(self, function_name: str, address: int,
                     callback: Callable,
                     strategy: HookStrategy = HookStrategy.INLINE) -> bool:
        """
        Hook a function with specified strategy.

        Args:
            function_name: Name of function
            address: Function address
            callback: Hook callback
            strategy: Hooking strategy

        Returns:
            True if successful
        """
        if function_name in self.hooks:
            self.logger.warning(f"Function already hooked: {function_name}")
            return False

        signature = FunctionSignature(name=function_name, address=address)

        if strategy == HookStrategy.INLINE:
            success = self._install_inline_hook(signature, callback)
        elif strategy == HookStrategy.IAT:
            success = self._install_iat_hook(signature, callback)
        elif strategy == HookStrategy.TRAMPOLINE:
            success = self._install_trampoline_hook(signature, callback)
        elif strategy == HookStrategy.VTABLE:
            success = self._install_vtable_hook(signature, callback)
        elif strategy == HookStrategy.GOT_PLT:
            success = self._install_got_plt_hook(signature, callback)
        else:
            self.logger.error(f"Unknown strategy: {strategy}")
            return False

        if success:
            hook_info = HookInfo(
                function=signature,
                strategy=strategy,
                active=True
            )
            self.hooks[function_name] = hook_info
            self.logger.info(f"Hooked function: {function_name} @ 0x{address:x}")

        return success

    def _install_inline_hook(self, signature: FunctionSignature,
                           callback: Callable) -> bool:
        """
        Install inline hook by overwriting function prologue.

        Classic technique: overwrite first bytes with JMP to our code.
        """
        try:
            # In real implementation:
            # 1. Calculate JMP offset to callback
            # 2. Save original bytes
            # 3. Write JMP instruction
            # 4. Flush instruction cache

            self.logger.debug(f"Installing inline hook for {signature.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to install inline hook: {e}")
            return False

    def _install_iat_hook(self, signature: FunctionSignature,
                        callback: Callable) -> bool:
        """
        Hook via Import Address Table modification.

        Windows-specific: modify the IAT entry to point to our code.
        """
        try:
            # In real implementation:
            # 1. Find IAT entry for this import
            # 2. Change memory protection to writable
            # 3. Replace entry with callback address
            # 4. Restore protection

            self.logger.debug(f"Installing IAT hook for {signature.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to install IAT hook: {e}")
            return False

    def _install_trampoline_hook(self, signature: FunctionSignature,
                                callback: Callable) -> bool:
        """
        Install trampoline/detour hook.

        Non-invasive technique using an intermediate trampoline.
        """
        try:
            # In real implementation:
            # 1. Allocate trampoline memory
            # 2. Copy original function prologue to trampoline
            # 3. Add JMP back to original function
            # 4. Replace function start with JMP to callback
            # 5. Callback can call trampoline for original behavior

            self.logger.debug(f"Installing trampoline hook for {signature.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to install trampoline hook: {e}")
            return False

    def _install_vtable_hook(self, signature: FunctionSignature,
                           callback: Callable) -> bool:
        """
        Hook C++ virtual function via vtable modification.
        """
        try:
            # In real implementation:
            # 1. Locate object vtable
            # 2. Find function pointer in vtable
            # 3. Replace with callback address

            self.logger.debug(f"Installing vtable hook for {signature.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to install vtable hook: {e}")
            return False

    def _install_got_plt_hook(self, signature: FunctionSignature,
                            callback: Callable) -> bool:
        """
        Hook via GOT/PLT modification (Linux/ELF).
        """
        try:
            # In real implementation:
            # 1. Find GOT entry for this symbol
            # 2. Change memory protection
            # 3. Replace entry with callback address

            self.logger.debug(f"Installing GOT/PLT hook for {signature.name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to install GOT/PLT hook: {e}")
            return False

    def unhook_function(self, function_name: str) -> bool:
        """
        Remove a function hook.

        Args:
            function_name: Name of hooked function

        Returns:
            True if successful
        """
        if function_name not in self.hooks:
            return False

        hook_info = self.hooks[function_name]

        try:
            # Restore original bytes
            if hook_info.original_bytes:
                # Write original bytes back
                pass

            # Clean up trampoline
            if hook_info.trampoline_address:
                if hook_info.trampoline_address in self.trampolines:
                    del self.trampolines[hook_info.trampoline_address]

            hook_info.active = False
            del self.hooks[function_name]

            self.logger.info(f"Unhooked function: {function_name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to unhook: {e}")
            return False

    def hook_api_set(self, api_names: List[str],
                    callback: Callable,
                    module: Optional[str] = None) -> int:
        """
        Hook multiple API functions at once.

        Args:
            api_names: List of API function names
            callback: Shared callback
            module: Optional module name filter

        Returns:
            Number of successfully hooked functions
        """
        count = 0

        for api_name in api_names:
            # In real implementation, resolve address from module
            # For now, use placeholder
            address = 0x12345678

            if self.hook_function(api_name, address, callback):
                count += 1

        self.logger.info(f"Hooked {count}/{len(api_names)} API functions")
        return count

    def hook_crypto_apis(self, callback: Callable) -> int:
        """
        Hook common cryptographic APIs.

        Args:
            callback: Hook callback

        Returns:
            Number of hooked functions
        """
        crypto_apis = [
            # Windows Crypto API
            "CryptEncrypt", "CryptDecrypt",
            "CryptGenKey", "CryptDeriveKey",
            "CryptHashData",

            # OpenSSL
            "AES_encrypt", "AES_decrypt",
            "RSA_public_encrypt", "RSA_private_decrypt",
            "EVP_EncryptInit", "EVP_DecryptInit",

            # BCrypt (Windows)
            "BCryptEncrypt", "BCryptDecrypt",
            "BCryptGenerateSymmetricKey",
        ]

        return self.hook_api_set(crypto_apis, callback)

    def hook_network_apis(self, callback: Callable) -> int:
        """
        Hook common network APIs.

        Args:
            callback: Hook callback

        Returns:
            Number of hooked functions
        """
        network_apis = [
            # Windows Socket API
            "send", "recv", "sendto", "recvfrom",
            "WSASend", "WSARecv",
            "connect", "bind", "listen", "accept",

            # HTTP APIs
            "HttpSendRequest", "InternetReadFile",
            "WinHttpSendRequest", "WinHttpReadData",

            # SSL/TLS
            "SSL_read", "SSL_write",
            "PR_Read", "PR_Write",  # NSS
        ]

        return self.hook_api_set(network_apis, callback)

    def hook_file_apis(self, callback: Callable) -> int:
        """
        Hook common file I/O APIs.

        Args:
            callback: Hook callback

        Returns:
            Number of hooked functions
        """
        file_apis = [
            # Windows File API
            "CreateFileA", "CreateFileW",
            "ReadFile", "WriteFile",
            "DeleteFileA", "DeleteFileW",

            # POSIX
            "open", "read", "write", "close",
            "fopen", "fread", "fwrite", "fclose",
        ]

        return self.hook_api_set(file_apis, callback)

    def hook_registry_apis(self, callback: Callable) -> int:
        """
        Hook Windows Registry APIs.

        Args:
            callback: Hook callback

        Returns:
            Number of hooked functions
        """
        registry_apis = [
            "RegOpenKeyExA", "RegOpenKeyExW",
            "RegQueryValueExA", "RegQueryValueExW",
            "RegSetValueExA", "RegSetValueExW",
            "RegDeleteValueA", "RegDeleteValueW",
        ]

        return self.hook_api_set(registry_apis, callback)

    def get_hook_status(self) -> Dict[str, Any]:
        """Get status of all hooks"""
        return {
            'total_hooks': len(self.hooks),
            'active_hooks': sum(1 for h in self.hooks.values() if h.active),
            'hooks': {
                name: {
                    'address': f"0x{info.function.address:x}",
                    'strategy': info.strategy.value,
                    'active': info.active
                }
                for name, info in self.hooks.items()
            }
        }

    def unhook_all(self):
        """Remove all hooks"""
        for function_name in list(self.hooks.keys()):
            self.unhook_function(function_name)


# Pre-defined hook sets for common scenarios
MALWARE_ANALYSIS_HOOKS = [
    # Process/Thread
    "CreateProcessA", "CreateProcessW",
    "CreateThread", "CreateRemoteThread",

    # File Operations
    "CreateFileA", "CreateFileW",
    "DeleteFileA", "WriteFile",

    # Registry
    "RegSetValueExA", "RegSetValueExW",

    # Network
    "send", "recv", "connect",
    "InternetOpenUrlA", "HttpSendRequestA",
]

ANTI_ANALYSIS_DETECTION_HOOKS = [
    # Debugger Detection
    "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent",
    "NtQueryInformationProcess",

    # VM Detection
    "GetSystemFirmwareTable",

    # Timing
    "GetTickCount", "QueryPerformanceCounter",
]

CREDENTIAL_THEFT_HOOKS = [
    # Windows Credentials
    "LsaEnumerateLogonSessions",
    "CredReadA", "CredReadW",

    # Browser Credentials
    "CryptUnprotectData",  # DPAPI

    # Network Credentials
    "HttpQueryInfoA", "InternetReadFile",
]
