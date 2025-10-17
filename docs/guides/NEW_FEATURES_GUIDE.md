# REVENG New Features Guide

This guide covers the new features added to REVENG v2.2.0, transforming it into a world-class AI-powered reverse engineering platform.

## Table of Contents

1. [Installation](#installation)
2. [Natural Language Interface](#natural-language-interface)
3. [Instant Triage Mode](#instant-triage-mode)
4. [VirusTotal Integration](#virustotal-integration)
5. [YARA Rule Generation & Scanning](#yara-rule-generation--scanning)
6. [Binary Diffing](#binary-diffing)
7. [Patch Analysis](#patch-analysis)
8. [Packer Detection & Unpacking](#packer-detection--unpacking)
9. [AI Code Quality Enhancement](#ai-code-quality-enhancement)

---

## Installation

### Core Installation
```bash
# Install REVENG with core dependencies
pip install -r requirements.txt
```

### Optional Features
```bash
# Install all optional feature dependencies
pip install -r requirements-optional.txt

# Or install specific features only:
pip install vt-py         # VirusTotal integration
pip install yara-python   # YARA rules
pip install ollama        # AI features
```

### AI Setup (Ollama)
```bash
# Install Ollama from https://ollama.ai
# Then pull a model:
ollama pull llama3        # General purpose
ollama pull codellama     # Better for code analysis

# Start Ollama server:
ollama serve
```

### VirusTotal Setup
```bash
# Get API key from https://www.virustotal.com/gui/my-apikey
# Set environment variable:
export VT_API_KEY=your_api_key_here

# Or pass directly in commands:
reveng vt-lookup malware.exe --api-key YOUR_KEY
```

---

## Natural Language Interface

Ask questions about binaries in plain English using AI.

### Basic Usage
```bash
# Ask what a binary does
reveng ask "What does this binary do?" malware.exe

# Find specific functions
reveng ask "Show me all network functions" sample.dll

# Check for threats
reveng ask "Is this dangerous?" suspicious.exe

# Extract IOCs
reveng ask "Extract all IP addresses and domains" malware.bin
```

### With Previous Analysis Results
```bash
# First, run full analysis
reveng analyze malware.exe --output-dir analysis_results

# Then query the results
reveng ask "What encryption does this use?" \
  --analysis-results analysis_results/analysis.json
```

### Example Queries
- "What does this binary do?"
- "Find all crypto functions"
- "Is this malware?"
- "What anti-analysis techniques are used?"
- "Extract IOCs"
- "Show me network communication code"
- "Does this use encryption?"

### How It Works
1. Parses your natural language question
2. Identifies intent (explain, find, assess, etc.)
3. Analyzes binary or loads existing results
4. Uses LLM to generate human-readable answer
5. Falls back to heuristics if Ollama unavailable

---

## Instant Triage Mode

Rapid <30 second threat assessment for incident response.

### Basic Usage
```bash
# Triage a single file
reveng triage suspicious.exe

# Triage multiple files in batch
reveng triage --bulk *.exe *.dll

# JSON output for automation
reveng triage malware.exe --format json

# Markdown report
reveng triage malware.exe --format markdown
```

### Example Output
```
Instant Triage Report
============================================================

File: suspicious.exe
SHA256: abc123...

THREAT ASSESSMENT
------------------
Threat Score: 85/100 (HIGH)
Priority: CRITICAL
Classification: Likely Malware

CAPABILITIES DETECTED
---------------------
✓ Network Communication (HTTP/HTTPS)
✓ Registry Modification
✓ Process Injection
✓ Anti-Analysis Techniques
✓ Data Exfiltration
✓ Persistence Mechanisms

INDICATORS OF COMPROMISE (IOCs)
--------------------------------
IP Addresses:
  - 192.168.1.100:8080
  - 10.0.0.50

Domains:
  - malicious-c2.example.com

File Operations:
  - Creates: C:\Windows\Temp\payload.dll
  - Modifies: HKLM\Software\Microsoft\Windows\CurrentVersion\Run

THREAT HYPOTHESIS
-----------------
Based on observed capabilities, this binary appears to be a remote
access trojan (RAT) with keylogging and data exfiltration capabilities.
The network communication patterns suggest C2 beaconing behavior.

RECOMMENDED ACTIONS
-------------------
1. Isolate system from network immediately
2. Perform full forensic analysis
3. Check for lateral movement
4. Review network logs for C2 communication
```

### Threat Scoring Algorithm
- **Entropy Analysis**: High entropy = likely packed (+30)
- **Capabilities**: Each capability adds points
  - Network: +10
  - File Operations: +5
  - Registry: +10
  - Process Manipulation: +15
  - Persistence: +20
  - Crypto: +15
  - Evasion: +25
  - Data Theft: +30
- **IOC Count**: More IOCs = higher threat

---

## VirusTotal Integration

Enrich analysis with VirusTotal threat intelligence.

### Lookup File Hash
```bash
# Lookup by file path (calculates hash)
reveng vt-lookup malware.exe

# Lookup by hash directly
reveng vt-lookup abc123def456...

# With API key override
reveng vt-lookup malware.exe --api-key YOUR_KEY
```

### Submit File for Analysis
```bash
# Submit and get analysis ID
reveng vt-submit malware.exe

# Submit and wait for results
reveng vt-submit malware.exe --wait
```

### Example Output
```markdown
# VirusTotal Enrichment Report

**Detection Ratio:** 45/72 engines flagged as malicious

## Malware Families
- TrickBot (confidence: 0.95)
- Emotet variant (confidence: 0.82)

## Sandbox Verdicts
- JoeSandbox: Malicious (score: 95/100)
- Cuckoo: Trojan.Generic
- CAPE: Banking Trojan

## YARA Matches
- banker_emotet_variant
- persistence_registry_run_key
- anti_vm_techniques

## Behavioral IOCs
IP Addresses:
  - 192.168.1.100:8080 (C2 server)
  - 10.0.0.50:443 (Data exfil)

Domains:
  - malicious-c2.example.com
  - update.suspicious-domain.net

File Operations:
  - Creates: %TEMP%\payload.dll
  - Drops: %APPDATA%\config.dat

Network Communication:
  - HTTP POST to /api/bot/register
  - HTTPS beacon every 60 seconds
```

### Use Cases
- Quick malware family identification
- IOC extraction for threat hunting
- Validate analysis findings
- Enrich incident response reports

---

## YARA Rule Generation & Scanning

Automatically generate YARA rules from binaries and scan for threats.

### Generate YARA Rule
```bash
# Generate from binary
reveng generate-yara malware.exe

# With custom rule name
reveng generate-yara malware.exe --rule-name TrickBot_Variant

# Save to file
reveng generate-yara malware.exe --output rules/trickbot.yar

# Use previous analysis for better rules
reveng generate-yara malware.exe \
  --analysis-results analysis_results/analysis.json
```

### Example Generated Rule
```yara
rule Malware_Sample_abc123 {
    meta:
        description = "Auto-generated rule for malware.exe"
        author = "REVENG"
        date = "2025-01-16"
        hash = "abc123def456..."

    strings:
        $s1 = "malicious-c2.example.com" ascii wide
        $s2 = "Mozilla/5.0 (Windows NT 10.0)" ascii
        $s3 = { 48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? }
        $s4 = { E8 ?? ?? ?? ?? 48 89 C3 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 500KB and
        3 of them
}
```

### Scan with YARA Rules
```bash
# Scan with rules directory
reveng scan-yara suspicious.exe --rules-dir yara_rules/

# Scan with single rule file
reveng scan-yara suspicious.exe --rule-file malware.yar
```

### Example Scan Output
```
Found 3 YARA rule matches:

Rule: TrickBot_Variant_2024
  Tags: banker, trojan, trickbot
  Strings matched: 8
  Metadata: {'author': 'REVENG', 'severity': 'high'}

Rule: Generic_Packer_UPX
  Tags: packer, upx
  Strings matched: 4
  Metadata: {'confidence': 'high'}

Rule: Persistence_Registry_RunKey
  Tags: persistence, registry
  Strings matched: 2
  Metadata: {'technique': 'T1547.001'}
```

---

## Binary Diffing

Compare two binary versions to identify changes at the function level.

### Basic Usage
```bash
# Compare two binaries
reveng diff program_v1.exe program_v2.exe

# Deep analysis with detailed comparison
reveng diff program_v1.exe program_v2.exe --deep

# JSON output for automation
reveng diff old.dll new.dll --format json

# Markdown report
reveng diff old.dll new.dll --format markdown
```

### Example Output
```markdown
# Binary Diff Report

**Binary 1:** program_v1.exe (SHA256: abc123...)
**Binary 2:** program_v2.exe (SHA256: def456...)

## Summary
- **Similarity Score:** 87.5%
- **Unchanged Functions:** 145
- **Modified Functions:** 12
- **New Functions:** 5
- **Deleted Functions:** 2

## Modified Functions

### 1. authenticate_user (92% similar)
- Size changed: 256 → 312 bytes
- Likely changes: Additional validation logic

### 2. encrypt_data (78% similar)
- Size changed: 512 → 598 bytes
- Likely changes: Enhanced encryption algorithm

### 3. send_network_request (85% similar)
- Size changed: 384 → 401 bytes
- Likely changes: Protocol changes

## New Functions
- validate_certificate (156 bytes)
- check_license_server (224 bytes)
- log_security_event (128 bytes)

## Deleted Functions
- deprecated_legacy_auth (192 bytes)
- old_encryption_method (448 bytes)
```

### Use Cases
- **Patch Analysis**: Identify what changed in security updates
- **Malware Variants**: Compare malware samples to find differences
- **Software Evolution**: Track code changes across versions
- **Backdoor Detection**: Find unauthorized modifications

---

## Patch Analysis

Analyze security patches to identify fixed vulnerabilities.

### Basic Usage
```bash
# Analyze a security patch
reveng patch-analysis vulnerable_v1.exe patched_v2.exe

# With CVE identifier
reveng patch-analysis old.dll new.dll --cve CVE-2024-1234

# JSON output
reveng patch-analysis old.exe new.exe --format json
```

### Example Output
```markdown
# Security Patch Analysis

**CVE:** CVE-2024-1234
**Unpatched:** vulnerable_v1.exe
**Patched:** patched_v2.exe

## Identified Vulnerabilities

### Vulnerability #1: Buffer Overflow
**Function:** process_user_input
**Severity:** Critical (9.8/10)
**Exploitability:** High (8.5/10)

**Description:**
The unpatched version lacks bounds checking when processing user input,
allowing an attacker to overflow a stack buffer and achieve arbitrary
code execution.

**Patch Details:**
- Added length validation before memcpy operation
- Implemented bounds checking on input buffer
- Added buffer size: 256 → 512 bytes

**Code Changes:**
```c
// Unpatched (vulnerable):
memcpy(buffer, user_input, input_length);

// Patched (fixed):
if (input_length > MAX_BUFFER_SIZE) {
    return ERROR_BUFFER_OVERFLOW;
}
memcpy(buffer, user_input, input_length);
```

**Exploitation Scenario:**
An attacker could send a crafted input larger than the buffer size,
overwriting the return address to redirect execution to malicious code.

### Vulnerability #2: Integer Overflow
**Function:** allocate_memory
**Severity:** High (7.5/10)
**Exploitability:** Medium (6.0/10)

**Description:**
Integer overflow in size calculation could lead to undersized buffer
allocation, resulting in heap corruption.

**Patch Details:**
- Added overflow check before allocation
- Implemented safe integer multiplication

---

## Packer Detection & Unpacking

Detect if binaries are packed/obfuscated and attempt to unpack them.

### Detect Packer
```bash
# Detect packer
reveng detect-packer suspicious.exe

# JSON output
reveng detect-packer suspicious.exe --format json

# Markdown report
reveng detect-packer suspicious.exe --format markdown
```

### Example Detection Output
```
Packed: True
Packer: UPX
Confidence: 95.0%
Entropy: 7.82

Indicators:
  - High entropy detected (7.82 > 7.5 threshold)
  - UPX signature found in PE header
  - Unusual section name: UPX0
  - Suspicious PE characteristics
```

### Unpack Binary
```bash
# Auto-detect and unpack
reveng unpack packed.exe

# Specify output path
reveng unpack packed.exe --output unpacked.exe

# Force specific unpacking method
reveng unpack packed.exe --method specialized  # Known packers (UPX, etc.)
reveng unpack packed.exe --method generic      # Generic unpacking
reveng unpack packed.exe --method auto         # Try both (default)
```

### Example Unpacking Output
```markdown
# Unpacking Report

**Status:** ✅ SUCCESS
**Method:** upx

## Packer Detection
- **Packed:** True
- **Packer:** UPX
- **Confidence:** 95.0%
- **Entropy:** 7.82

**Indicators:**
- High entropy detected (7.82 > 7.5 threshold)
- UPX signature found in PE header
- Unusual section name: UPX0

## Hashes
- **Original:** abc123def456...
- **Unpacked:** 789ghi012jkl...

**Unpacked File:** malware_unpacked.exe
```

### Supported Packers
- **UPX**: Full unpacking support (requires upx tool)
- **MPRESS**: Detection only (unpacking planned)
- **Themida**: Detection only
- **VMProtect**: Detection only
- **ASPack**: Detection only
- **PECompact**: Detection only
- **Generic**: Heuristic detection via entropy

---

## AI Code Quality Enhancement

Transform raw decompiled code into readable, documented code using AI.

### Basic Usage
```bash
# Enhance decompiled code
reveng enhance-code decompiled_function.c

# Specify function name for better context
reveng enhance-code function.c --function-name decrypt_config

# Custom output path
reveng enhance-code messy.c --output clean.c
```

### Before Enhancement
```c
int sub_401000(int a1, char *a2, int a3) {
    int v4;
    char *v5;
    int v6;

    v4 = a1 + 0x10;
    v5 = a2;
    v6 = 0;

    while (*v5) {
        v6 = (v6 << 5) + v6 + *v5;
        v5++;
    }

    if (v6 == v4) {
        return a3;
    }
    return 0;
}
```

### After Enhancement
```c
// Original function: sub_401000
// Suggested name: verify_string_hash
// Improvements: Renamed 6 variables, Added 4 comments

/* Verify string hash against expected value */
int verify_string_hash(int expected_base, char *input_string, int success_value) {
    int expected_hash;
    char *current_char;
    int computed_hash;

    /* Calculate expected hash from base */
    expected_hash = expected_base + 0x10;
    current_char = input_string;
    computed_hash = 0;

    /* Compute DJB2 hash of input string */
    while (*current_char) {
        computed_hash = (computed_hash << 5) + computed_hash + *current_char;
        current_char++;
    }

    /* Return success value if hash matches */
    if (computed_hash == expected_hash) {
        return success_value;
    }
    return 0;
}
```

### Features
- **Semantic Variable Renaming**: `var_1` → `connection_socket`
- **Function Name Suggestions**: `sub_401000` → `decrypt_config`
- **AI-Generated Comments**: Explains purpose and logic
- **Type Inference**: Identifies actual variable purposes
- **Heuristic Fallback**: Works without AI (basic renaming)

---

## Quick Reference

### Command Cheat Sheet
```bash
# AI Features (require Ollama)
reveng ask "question" binary.exe
reveng triage binary.exe
reveng enhance-code code.c

# Threat Intelligence (require VirusTotal API key)
reveng vt-lookup binary.exe
reveng vt-submit binary.exe

# YARA (require yara-python)
reveng generate-yara binary.exe
reveng scan-yara binary.exe --rules-dir rules/

# Binary Analysis (built-in, no dependencies)
reveng diff old.exe new.exe
reveng patch-analysis vulnerable.exe patched.exe
reveng detect-packer binary.exe
reveng unpack packed.exe

# Original REVENG
reveng analyze binary.exe
reveng serve
```

### Common Workflows

#### Malware Analysis Workflow
```bash
# 1. Quick triage
reveng triage malware.exe

# 2. Check VirusTotal
reveng vt-lookup malware.exe

# 3. Detect packing
reveng detect-packer malware.exe

# 4. Unpack if needed
reveng unpack malware.exe

# 5. Full analysis
reveng analyze malware_unpacked.exe

# 6. Ask specific questions
reveng ask "What persistence mechanisms are used?" malware.exe

# 7. Generate YARA rule
reveng generate-yara malware.exe --output rules/new_threat.yar
```

#### Patch Analysis Workflow
```bash
# 1. Diff the binaries
reveng diff vulnerable.dll patched.dll

# 2. Analyze security fixes
reveng patch-analysis vulnerable.dll patched.dll --cve CVE-2024-1234

# 3. Generate YARA rule for vulnerability
reveng generate-yara vulnerable.dll --rule-name CVE_2024_1234

# 4. Scan for similar vulnerabilities
reveng scan-yara other_binary.exe --rule-file cve_2024_1234.yar
```

---

## Troubleshooting

### Ollama Not Available
```bash
# Install Ollama
# Visit: https://ollama.ai

# Pull a model
ollama pull llama3

# Start Ollama server
ollama serve

# Verify
python -c "import ollama; print('OK')"
```

### VirusTotal API Errors
```bash
# Check API key is set
echo $VT_API_KEY

# Or use --api-key flag
reveng vt-lookup file.exe --api-key YOUR_KEY

# Rate limits: Free tier = 4 requests/minute
# Wait 60 seconds between requests if rate limited
```

### YARA Build Errors
```bash
# Linux
sudo apt install libyara-dev
pip install yara-python

# macOS
brew install yara
pip install yara-python

# Windows
# Download YARA from https://github.com/VirusTotal/yara/releases
# Add to PATH, then:
pip install yara-python
```

---

## Performance Tips

1. **Instant Triage**: Completes in <30 seconds, perfect for incident response
2. **VirusTotal**: Free tier limited to 4 requests/minute
3. **YARA Generation**: Faster with pre-computed analysis results
4. **Binary Diffing**: Use `--deep` only for critical analysis (slower)
5. **AI Features**: Local Ollama much faster than cloud APIs

---

## Next Steps

1. **Read Full Documentation**: See `WORLD_CLASS_ROADMAP.md` for future features
2. **Join Community**: Contribute at https://github.com/oimiragieo/reveng-main
3. **Report Issues**: Open GitHub issues for bugs or feature requests
4. **Share YARA Rules**: Contribute rules to the community

---

## Credits

REVENG Development Team
Version: 2.2.0
License: MIT
