"""
Environmental Keying Module

Detects analysis environments (VMs, sandboxes, debuggers) to prevent
automated analysis and evade detection.

Modern malware uses environmental keying to:
1. Detect if it's being analyzed
2. Only execute payload in target environment
3. Evade automated sandboxes
"""

import os
import sys
import logging
import platform
import socket
import time
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from enum import Enum
import hashlib

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    logging.warning("psutil not available. Install: pip install psutil")

if sys.platform == "win32":
    import ctypes
    import winreg


class EnvironmentType(Enum):
    """Types of analysis environments"""
    BARE_METAL = "bare_metal"
    VIRTUAL_MACHINE = "virtual_machine"
    SANDBOX = "sandbox"
    DEBUGGER = "debugger"
    EMULATOR = "emulator"


@dataclass
class EnvironmentCheck:
    """Single environment check result"""
    check_name: str
    category: str
    detected: bool
    confidence: float  # 0.0 to 1.0
    evidence: List[str]


@dataclass
class EnvironmentProfile:
    """Complete environment analysis"""
    environment_type: EnvironmentType
    confidence: float
    checks: List[EnvironmentCheck]
    is_analysis_env: bool
    risk_score: float  # 0.0 (safe) to 100.0 (definitely analysis)


class EnvironmentalKeying:
    """
    Environmental detection and keying engine.

    Performs comprehensive environment analysis to detect:
    - Virtual machines (VMware, VirtualBox, Hyper-V, QEMU)
    - Sandboxes (Cuckoo, Joe Sandbox, Any.Run, etc.)
    - Debuggers (WinDbg, x64dbg, IDA, Ghidra, etc.)
    - Analysis tools (Process Monitor, Wireshark, Fiddler, etc.)

    Example:
        >>> keying = EnvironmentalKeying()
        >>> profile = keying.analyze_environment()
        >>> if profile.is_analysis_env:
        >>>     print("Analysis environment detected!")
        >>>     exit(0)
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.checks: List[EnvironmentCheck] = []

    def analyze_environment(self) -> EnvironmentProfile:
        """
        Perform comprehensive environment analysis.

        Returns:
            EnvironmentProfile with all detection results
        """
        self.checks.clear()

        # Run all checks
        self._check_virtual_machine()
        self._check_sandbox_artifacts()
        self._check_debugger()
        self._check_analysis_tools()
        self._check_hardware_anomalies()
        self._check_network_indicators()
        self._check_timing_anomalies()
        self._check_user_interaction()

        # Calculate risk score
        risk_score = self._calculate_risk_score()

        # Determine environment type
        env_type, confidence = self._determine_environment_type()

        # Is it an analysis environment?
        is_analysis = risk_score > 50.0

        profile = EnvironmentProfile(
            environment_type=env_type,
            confidence=confidence,
            checks=self.checks.copy(),
            is_analysis_env=is_analysis,
            risk_score=risk_score
        )

        return profile

    # ========== VM DETECTION ==========

    def _check_virtual_machine(self):
        """Check for VM indicators"""
        evidence = []
        detected = False

        # Check CPU info
        if "hypervisor" in platform.processor().lower():
            evidence.append("Hypervisor flag in CPU")
            detected = True

        if sys.platform == "win32":
            # Check for VM registry keys
            vm_reg_keys = [
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxGuest"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxMouse"),
                (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\VBoxSF"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\VMware, Inc.\VMware Tools"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Oracle\VirtualBox Guest Additions"),
            ]

            for hkey, path in vm_reg_keys:
                try:
                    winreg.OpenKey(hkey, path)
                    evidence.append(f"VM Registry: {path}")
                    detected = True
                except WindowsError:
                    pass

            # Check for VM files
            vm_files = [
                r"C:\Windows\System32\drivers\vboxguest.sys",
                r"C:\Windows\System32\drivers\vboxmouse.sys",
                r"C:\Windows\System32\drivers\vmhgfs.sys",
                r"C:\Windows\System32\drivers\vmmouse.sys",
            ]

            for file_path in vm_files:
                if os.path.exists(file_path):
                    evidence.append(f"VM Driver: {file_path}")
                    detected = True

            # Check for VM processes
            if PSUTIL_AVAILABLE:
                vm_processes = [
                    "vboxservice.exe",
                    "vboxtray.exe",
                    "vmtoolsd.exe",
                    "vmwaretray.exe",
                    "vmwareuser.exe",
                ]

                for proc in psutil.process_iter(['name']):
                    if proc.info['name'].lower() in vm_processes:
                        evidence.append(f"VM Process: {proc.info['name']}")
                        detected = True

        # Check MAC address for VM vendors
        if self._check_vm_mac_address():
            evidence.append("VM vendor MAC address")
            detected = True

        self.checks.append(EnvironmentCheck(
            check_name="Virtual Machine Detection",
            category="VM",
            detected=detected,
            confidence=0.9 if detected else 0.1,
            evidence=evidence
        ))

    def _check_vm_mac_address(self) -> bool:
        """Check if MAC address belongs to VM vendor"""
        vm_mac_prefixes = [
            "00:05:69",  # VMware
            "00:0C:29",  # VMware
            "00:1C:14",  # VMware
            "00:50:56",  # VMware
            "08:00:27",  # VirtualBox
            "00:15:5D",  # Hyper-V
            "00:16:3E",  # Xen
        ]

        if not PSUTIL_AVAILABLE:
            return False

        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK:  # MAC address
                        mac = addr.address.upper()
                        for prefix in vm_mac_prefixes:
                            if mac.startswith(prefix):
                                return True
        except:
            pass

        return False

    # ========== SANDBOX DETECTION ==========

    def _check_sandbox_artifacts(self):
        """Check for sandbox artifacts"""
        evidence = []
        detected = False

        # Check hostname
        hostname = socket.gethostname().lower()
        sandbox_hostnames = [
            'sandbox', 'malware', 'virus', 'sample', 'test',
            'cuckoo', 'analysis', 'vmware', 'vbox', 'honeypot',
            'joe', 'triage', 'reverse', 'anyrun'
        ]

        for name in sandbox_hostnames:
            if name in hostname:
                evidence.append(f"Suspicious hostname: {hostname}")
                detected = True
                break

        # Check username
        username = os.environ.get('USERNAME', '').lower()
        sandbox_usernames = [
            'sandbox', 'malware', 'virus', 'sample',
            'john', 'admin', 'user', 'test'
        ]

        for name in sandbox_usernames:
            if name == username:
                evidence.append(f"Suspicious username: {username}")
                detected = True
                break

        # Check for low resources (common in sandboxes)
        if PSUTIL_AVAILABLE:
            # Less than 2GB RAM
            if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:
                evidence.append("Low RAM (< 2GB)")
                detected = True

            # Less than 2 CPU cores
            if psutil.cpu_count() < 2:
                evidence.append("Low CPU count (< 2)")
                detected = True

            # Less than 50GB disk
            try:
                if psutil.disk_usage('/').total < 50 * 1024 * 1024 * 1024:
                    evidence.append("Low disk space (< 50GB)")
                    detected = True
            except:
                pass

        # Check for recently created system
        if sys.platform == "win32":
            try:
                # Check Windows installation date
                import subprocess
                result = subprocess.run(
                    ["systeminfo"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                # Sandboxes often have very recent install dates
                if "Original Install Date" in result.stdout:
                    evidence.append("Potentially fresh Windows install")
                    # Could parse date and check if < 30 days old

            except:
                pass

        self.checks.append(EnvironmentCheck(
            check_name="Sandbox Artifacts",
            category="Sandbox",
            detected=detected,
            confidence=0.8 if detected else 0.2,
            evidence=evidence
        ))

    # ========== DEBUGGER DETECTION ==========

    def _check_debugger(self):
        """Check for debugger presence"""
        evidence = []
        detected = False

        if sys.platform == "win32":
            kernel32 = ctypes.windll.kernel32

            # IsDebuggerPresent
            if kernel32.IsDebuggerPresent():
                evidence.append("IsDebuggerPresent() = True")
                detected = True

            # CheckRemoteDebuggerPresent
            debugger_present = ctypes.c_bool()
            kernel32.CheckRemoteDebuggerPresent(
                kernel32.GetCurrentProcess(),
                ctypes.byref(debugger_present)
            )

            if debugger_present.value:
                evidence.append("CheckRemoteDebuggerPresent() = True")
                detected = True

            # Check PEB BeingDebugged flag
            if self._check_peb_debugged():
                evidence.append("PEB.BeingDebugged = 1")
                detected = True

        # Check for debugger processes
        if PSUTIL_AVAILABLE:
            debugger_processes = [
                'ollydbg.exe', 'x64dbg.exe', 'x32dbg.exe',
                'windbg.exe', 'idaq.exe', 'idaq64.exe',
                'idaw.exe', 'idaw64.exe', 'scylla.exe',
                'protection_id.exe', 'charles.exe',
                'wireshark.exe', 'fiddler.exe', 'httpdebugger.exe'
            ]

            for proc in psutil.process_iter(['name']):
                if proc.info['name'].lower() in debugger_processes:
                    evidence.append(f"Debugger process: {proc.info['name']}")
                    detected = True

        self.checks.append(EnvironmentCheck(
            check_name="Debugger Detection",
            category="Debugger",
            detected=detected,
            confidence=0.95 if detected else 0.05,
            evidence=evidence
        ))

    def _check_peb_debugged(self) -> bool:
        """Check PEB.BeingDebugged flag (Windows)"""
        if sys.platform != "win32":
            return False

        try:
            # Get PEB address (x64)
            import ctypes
            peb = ctypes.c_ulonglong()
            ntdll = ctypes.windll.ntdll

            # NtQueryInformationProcess to get PEB
            process_basic_info = (ctypes.c_ulonglong * 6)()
            ntdll.NtQueryInformationProcess(
                ctypes.windll.kernel32.GetCurrentProcess(),
                0,  # ProcessBasicInformation
                ctypes.byref(process_basic_info),
                ctypes.sizeof(process_basic_info),
                None
            )

            peb_addr = process_basic_info[1]

            # Read BeingDebugged byte at PEB+2
            being_debugged = ctypes.c_byte()
            ctypes.windll.kernel32.ReadProcessMemory(
                ctypes.windll.kernel32.GetCurrentProcess(),
                ctypes.c_void_p(peb_addr + 2),
                ctypes.byref(being_debugged),
                1,
                None
            )

            return being_debugged.value != 0

        except:
            return False

    # ========== ANALYSIS TOOLS ==========

    def _check_analysis_tools(self):
        """Check for analysis tools"""
        evidence = []
        detected = False

        if not PSUTIL_AVAILABLE:
            return

        analysis_tools = [
            # Disassemblers
            'ghidra.exe', 'ida.exe', 'ida64.exe',
            'binaryninja.exe', 'hopper.exe',

            # Debuggers
            'ollydbg.exe', 'x64dbg.exe', 'windbg.exe',

            # System monitors
            'procmon.exe', 'procmon64.exe',
            'procexp.exe', 'procexp64.exe',
            'processhacker.exe',

            # Network monitors
            'wireshark.exe', 'fiddler.exe', 'charles.exe',
            'mitmproxy.exe', 'burpsuite.exe',

            # PE tools
            'pestudio.exe', 'pe-bear.exe', 'exeinfope.exe',

            # Sandboxes
            'cuckoo.exe', 'fakenet.exe',
        ]

        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in analysis_tools:
                evidence.append(f"Analysis tool: {proc.info['name']}")
                detected = True

        self.checks.append(EnvironmentCheck(
            check_name="Analysis Tools",
            category="Tools",
            detected=detected,
            confidence=0.9 if detected else 0.1,
            evidence=evidence
        ))

    # ========== HARDWARE ANOMALIES ==========

    def _check_hardware_anomalies(self):
        """Check for suspicious hardware"""
        evidence = []
        detected = False

        if sys.platform == "win32":
            # Check for VM GPUs
            evil_gpus = [
                'ASPEED Graphics',
                'VirtualBox Graphics',
                'VMware SVGA',
                'Microsoft Basic Display',
            ]

            try:
                import subprocess
                result = subprocess.run(
                    ["wmic", "path", "win32_VideoController", "get", "name"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                for gpu in evil_gpus:
                    if gpu.lower() in result.stdout.lower():
                        evidence.append(f"VM GPU: {gpu}")
                        detected = True

            except:
                pass

        self.checks.append(EnvironmentCheck(
            check_name="Hardware Anomalies",
            category="Hardware",
            detected=detected,
            confidence=0.7 if detected else 0.3,
            evidence=evidence
        ))

    # ========== NETWORK INDICATORS ==========

    def _check_network_indicators(self):
        """Check for analysis network indicators"""
        evidence = []
        detected = False

        try:
            # Check IP address
            import requests
            response = requests.get('https://api.ipify.org', timeout=5)
            public_ip = response.text

            # Check against known analysis service IP ranges
            # (This is a simplified check)
            analysis_ip_prefixes = [
                '192.0.2.',    # TEST-NET-1
                '198.51.100.', # TEST-NET-2
                '203.0.113.',  # TEST-NET-3
            ]

            for prefix in analysis_ip_prefixes:
                if public_ip.startswith(prefix):
                    evidence.append(f"Analysis IP range: {public_ip}")
                    detected = True

        except:
            pass

        self.checks.append(EnvironmentCheck(
            check_name="Network Indicators",
            category="Network",
            detected=detected,
            confidence=0.6 if detected else 0.4,
            evidence=evidence
        ))

    # ========== TIMING ANOMALIES ==========

    def _check_timing_anomalies(self):
        """Check for timing-based analysis detection"""
        evidence = []
        detected = False

        # CPU cycle timing (detect if running too fast/slow)
        start = time.perf_counter()
        dummy_operation = sum(range(1000000))
        end = time.perf_counter()

        elapsed = end - start

        # If extremely fast or slow, might be emulated
        if elapsed < 0.001 or elapsed > 1.0:
            evidence.append(f"Anomalous timing: {elapsed:.6f}s")
            detected = True

        # Check sleep accuracy
        start = time.perf_counter()
        time.sleep(0.1)
        end = time.perf_counter()

        sleep_actual = end - start

        # If sleep is skipped (common in sandboxes)
        if sleep_actual < 0.05:
            evidence.append(f"Sleep skipped: {sleep_actual:.6f}s")
            detected = True

        self.checks.append(EnvironmentCheck(
            check_name="Timing Anomalies",
            category="Timing",
            detected=detected,
            confidence=0.5 if detected else 0.5,
            evidence=evidence
        ))

    # ========== USER INTERACTION ==========

    def _check_user_interaction(self):
        """Check for signs of real user activity"""
        evidence = []
        detected = False  # Detected = NOT a real user

        if sys.platform == "win32":
            # Check uptime (fresh systems are suspicious)
            try:
                import subprocess
                result = subprocess.run(
                    ["wmic", "os", "get", "lastbootuptime"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )

                # Parse and check if system booted very recently
                # (Sandboxes often have very short uptimes)

            except:
                pass

            # Check for cursor movement (no movement = automated)
            # Check for recent file access patterns
            # etc.

        self.checks.append(EnvironmentCheck(
            check_name="User Interaction",
            category="User",
            detected=detected,
            confidence=0.4,
            evidence=evidence
        ))

    # ========== SCORING ==========

    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score"""
        if not self.checks:
            return 0.0

        total_weight = 0.0
        weighted_sum = 0.0

        for check in self.checks:
            if check.detected:
                weight = check.confidence
                weighted_sum += weight * 100.0
                total_weight += weight

        if total_weight == 0:
            return 0.0

        return weighted_sum / total_weight

    def _determine_environment_type(self) -> Tuple[EnvironmentType, float]:
        """Determine the environment type"""
        vm_score = 0.0
        sandbox_score = 0.0
        debugger_score = 0.0

        for check in self.checks:
            if not check.detected:
                continue

            if check.category == "VM":
                vm_score = max(vm_score, check.confidence)
            elif check.category == "Sandbox":
                sandbox_score = max(sandbox_score, check.confidence)
            elif check.category == "Debugger":
                debugger_score = max(debugger_score, check.confidence)

        # Determine type by highest score
        max_score = max(vm_score, sandbox_score, debugger_score)

        if max_score == 0:
            return EnvironmentType.BARE_METAL, 0.9

        if max_score == vm_score:
            return EnvironmentType.VIRTUAL_MACHINE, vm_score
        elif max_score == sandbox_score:
            return EnvironmentType.SANDBOX, sandbox_score
        else:
            return EnvironmentType.DEBUGGER, debugger_score


# Pre-defined environment profiles for keying
KNOWN_SANDBOXES = {
    "cuckoo": {
        "indicators": ["CUCKOO", "agent.py", "analyzer.py"],
        "description": "Cuckoo Sandbox"
    },
    "joe_sandbox": {
        "indicators": ["JoeBox", "joe", "sample"],
        "description": "Joe Sandbox"
    },
    "any_run": {
        "indicators": ["anyrun", "analysis"],
        "description": "Any.Run"
    },
}
