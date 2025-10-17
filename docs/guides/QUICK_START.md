# REVENG v2.2.0 Quick Start Guide

## Installation

```bash
# 1. Install core dependencies
pip install -r requirements.txt

# 2. Install optional features (recommended)
pip install -r requirements-optional.txt

# 3. Set up Ollama for AI features (optional)
# Download from https://ollama.ai
ollama pull llama3
ollama serve

# 4. Set up VirusTotal (optional)
export VT_API_KEY=your_api_key_here
```

## Instant Examples

### 1. Quick Threat Assessment (30 seconds)
```bash
reveng triage suspicious.exe
```

**Output:**
```
Instant Triage Report
============================================================
File: suspicious.exe
Threat Score: 85/100 (HIGH)
Priority: CRITICAL
Classification: Likely Malware

Capabilities: Network, Registry, Process Injection, Anti-Analysis
IOCs: 3 IPs, 2 domains, 5 file operations
```

### 2. Ask Questions About a Binary
```bash
reveng ask "What does this binary do?" malware.exe
```

**Output:**
```
This binary appears to be a remote access trojan (RAT) that:
- Establishes C2 communication via HTTP
- Exfiltrates system information
- Implements persistence via registry Run key
- Contains anti-VM detection mechanisms
```

### 3. Check VirusTotal
```bash
reveng vt-lookup malware.exe
```

**Output:**
```
Detection Ratio: 45/72 engines flagged as malicious
Malware Families: TrickBot (0.95), Emotet variant (0.82)
IOCs: 3 IP addresses, 2 domains, 4 file operations
```

### 4. Generate YARA Rule
```bash
reveng generate-yara malware.exe --output rules/threat.yar
```

**Output:**
```
YARA rule saved to: rules/threat.yar

rule Malware_Sample_abc123 {
    meta:
        description = "Auto-generated rule"
        hash = "abc123..."
    strings:
        $s1 = "malicious-c2.example.com"
        $s2 = { 48 8B 05 ?? ?? ?? ?? }
    condition:
        uint16(0) == 0x5A4D and 2 of them
}
```

### 5. Compare Binary Versions
```bash
reveng diff old_version.exe new_version.exe
```

**Output:**
```
Binary Diff Report
============================================================
Similarity: 87.5%
Modified Functions: 12
New Functions: 5
Deleted Functions: 2

Key Changes:
- authenticate_user (92% similar) - Added validation
- encrypt_data (78% similar) - Enhanced algorithm
```

### 6. Detect Packing
```bash
reveng detect-packer suspicious.exe
```

**Output:**
```
Packed: True
Packer: UPX
Confidence: 95.0%
Entropy: 7.82
```

### 7. Unpack Binary
```bash
reveng unpack packed.exe
```

**Output:**
```
Unpacking Report
Status: ✅ SUCCESS
Method: upx
Unpacked File: packed_unpacked.exe
```

### 8. Analyze Security Patch
```bash
reveng patch-analysis vulnerable.dll patched.dll --cve CVE-2024-1234
```

**Output:**
```
Security Patch Analysis
CVE: CVE-2024-1234

Vulnerability #1: Buffer Overflow
Function: process_user_input
Severity: Critical (9.8/10)

Patch Details:
- Added bounds checking
- Implemented input validation
```

### 9. Enhance Decompiled Code
```bash
reveng enhance-code messy_function.c
```

**Output:**
```
Enhanced code saved to: messy_function_enhanced.c

Improvements applied:
  - Renamed 6 variables (var_1 → connection_socket)
  - Suggested function name: verify_string_hash
  - Added 4 comments
```

### 10. Scan with YARA Rules
```bash
reveng scan-yara binary.exe --rules-dir yara_rules/
```

**Output:**
```
Found 3 YARA rule matches:

Rule: TrickBot_Variant_2024
  Tags: banker, trojan
  Strings matched: 8
```

## Common Workflows

### Malware Analysis Pipeline
```bash
# 1. Quick triage
reveng triage malware.exe

# 2. VirusTotal check
reveng vt-lookup malware.exe

# 3. Detect/unpack
reveng detect-packer malware.exe
reveng unpack malware.exe

# 4. Full analysis
reveng analyze malware_unpacked.exe

# 5. Generate detection rule
reveng generate-yara malware_unpacked.exe --output rules/threat.yar

# 6. Ask specific questions
reveng ask "What persistence mechanisms are used?" malware_unpacked.exe
```

### Incident Response
```bash
# Batch triage all suspicious files
reveng triage --bulk /quarantine/*.exe --format json > results.json

# Generate YARA rules for threats
reveng generate-yara threat1.exe --output rules/threat1.yar
reveng generate-yara threat2.exe --output rules/threat2.yar

# Scan environment
reveng scan-yara /system32/*.dll --rules-dir rules/
```

### Patch Analysis
```bash
# Compare versions
reveng diff old.dll new.dll --deep

# Analyze security fixes
reveng patch-analysis old.dll new.dll --cve CVE-2024-1234

# Generate detection rule
reveng generate-yara old.dll --rule-name CVE_2024_1234_Exploit
```

## Command Reference

| Command | Purpose | Speed |
|---------|---------|-------|
| `triage` | Instant threat assessment | <30 sec |
| `ask` | Natural language queries | ~20 sec |
| `vt-lookup` | VirusTotal intelligence | ~2 sec |
| `vt-submit` | Submit to VirusTotal | ~5 sec |
| `generate-yara` | Create detection rule | ~10 sec |
| `scan-yara` | Scan with YARA | <5 sec |
| `diff` | Compare binaries | ~20 sec |
| `patch-analysis` | Analyze patches | ~30 sec |
| `detect-packer` | Detect packing | <5 sec |
| `unpack` | Unpack binary | ~10 sec |
| `enhance-code` | Improve code quality | ~40 sec |

## Output Formats

Most commands support multiple output formats:

```bash
# JSON (for automation)
reveng triage malware.exe --format json

# Markdown (for reports)
reveng diff old.exe new.exe --format markdown

# Text (for CLI)
reveng detect-packer binary.exe --format text
```

## Environment Variables

```bash
# VirusTotal API key
export VT_API_KEY=your_key_here

# Ollama server (if not default)
export OLLAMA_HOST=http://localhost:11434
```

## Troubleshooting

### Ollama Not Available
```bash
# Install Ollama: https://ollama.ai
ollama pull llama3
ollama serve

# Verify
python -c "import ollama; print('OK')"
```

### VirusTotal Rate Limit
```bash
# Free tier: 4 requests/minute
# Wait 60 seconds between requests
```

### YARA Not Found
```bash
# Linux
sudo apt install libyara-dev
pip install yara-python

# macOS
brew install yara
pip install yara-python
```

## Next Steps

1. **Read Full Guide**: See [NEW_FEATURES_GUIDE.md](NEW_FEATURES_GUIDE.md) for detailed documentation
2. **Explore Roadmap**: See [WORLD_CLASS_ROADMAP.md](WORLD_CLASS_ROADMAP.md) for future features
3. **Implementation Details**: See [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) for technical details

## Help

```bash
# Global help
reveng --help

# Command-specific help
reveng triage --help
reveng ask --help
reveng diff --help
```

---

**Version:** 2.2.0
**License:** MIT
**Repository:** https://github.com/oimiragieo/reveng-main
