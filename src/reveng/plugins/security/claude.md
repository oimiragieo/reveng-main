# Plugins - Security

## Overview

Security plugins provide threat detection, malware analysis, and security assessment capabilities. These plugins implement advanced security analysis techniques including pattern matching, behavioral analysis, and ML-based threat detection.

**Location:** `/home/user/reveng-main/src/reveng/plugins/security/`

## Files in This Directory

### `malware_detection_plugin.py` (24233 lines)
Comprehensive malware detection and analysis plugin.

**MalwareDetectionPlugin:**
- **Category:** SECURITY
- **Priority:** CRITICAL
- **Dependencies:** ML models, signature databases

**Detection Methods:**
1. **Signature-based** - Pattern matching against known malware
2. **Heuristic-based** - Behavioral analysis and anomaly detection
3. **ML-based** - Machine learning classification
4. **Static analysis** - Code pattern analysis
5. **Dynamic analysis** - Runtime behavior monitoring (planned)

**Features:**
- Multi-engine malware scanning
- Threat classification
- Indicator extraction
- Risk scoring
- Family identification
- YARA rule matching
- Sandbox integration (planned)

**Output:**
- Threat score (0-100)
- Malware family identification
- Behavioral indicators
- Attack vectors
- Recommended actions

**Usage:**
```python
from reveng.plugins.security import MalwareDetectionPlugin

plugin = MalwareDetectionPlugin()
result = plugin.analyze(context)

if result['is_malicious']:
    print(f"⚠️ Malware detected!")
    print(f"Threat Score: {result['threat_score']}/100")
    print(f"Family: {result['malware_family']}")
    print(f"Indicators: {len(result['indicators'])}")
```

## Architecture

### Detection Pipeline

```
Binary Input
  ↓
Signature Scanning
  ├─> Known malware? → Report
  └─> Unknown → Continue
  ↓
Heuristic Analysis
  ├─> Suspicious? → Flag
  └─> Clean? → Continue
  ↓
ML Classification
  ├─> Malicious? → Report
  └─> Benign? → Continue
  ↓
Final Risk Score
  └─> Generate Report
```

### Multi-Engine Detection

```
MalwareDetectionPlugin
  ├─> Signature Engine
  │   ├─> Hash matching
  │   ├─> YARA rules
  │   └─> Pattern matching
  │
  ├─> Heuristic Engine
  │   ├─> Behavior analysis
  │   ├─> Anomaly detection
  │   └─> Entropy analysis
  │
  └─> ML Engine
      ├─> Feature extraction
      ├─> Model inference
      └─> Classification
```

## Key Concepts

### 1. Threat Scoring

Malware detection uses multi-factor threat scoring:

```python
threat_score = (
    signature_score * 0.4 +
    heuristic_score * 0.3 +
    ml_score * 0.3
)

is_malicious = threat_score >= 70  # Threshold
```

### 2. Indicator Extraction

Plugins extract Indicators of Compromise (IoCs):

- IP addresses
- Domain names
- File hashes
- Registry keys
- Mutexes
- File paths

### 3. Family Classification

Malware is classified into known families:

- Ransomware
- Trojan
- Worm
- Rootkit
- Backdoor
- Spyware
- Adware

## Usage Examples

### Example 1: Basic Malware Scan

```python
from reveng.plugins.security import MalwareDetectionPlugin
from reveng.plugins.base import PluginContext

plugin = MalwareDetectionPlugin()
context = PluginContext(binary_path="suspicious.exe")

if plugin.initialize(context):
    result = plugin.analyze(context)

    print(f"Threat Score: {result['threat_score']}/100")
    print(f"Malicious: {result['is_malicious']}")

    if result['is_malicious']:
        print(f"Family: {result['malware_family']}")
        print(f"Type: {result['malware_type']}")
```

### Example 2: Detailed Threat Analysis

```python
result = plugin.analyze(context)

# Analysis breakdown
print("\nDetection Engines:")
print(f"  Signature: {result['signature_match']}")
print(f"  Heuristic: {result['heuristic_score']}/100")
print(f"  ML: {result['ml_score']}/100")

# Indicators
print(f"\nIndicators of Compromise:")
for indicator in result['indicators']:
    print(f"  - {indicator['type']}: {indicator['value']}")

# Behavior
print(f"\nSuspicious Behaviors:")
for behavior in result['behaviors']:
    print(f"  - {behavior}")
```

### Example 3: Batch Scanning

```python
from pathlib import Path

plugin = MalwareDetectionPlugin()
samples_dir = Path("/samples/")

for binary_path in samples_dir.glob("*.exe"):
    context = PluginContext(binary_path=str(binary_path))
    result = plugin.analyze(context)

    if result['is_malicious']:
        print(f"⚠️ {binary_path.name}: {result['malware_family']}")
    else:
        print(f"✓ {binary_path.name}: Clean")
```

## Configuration

### Plugin Options

```python
context = PluginContext(
    binary_path="file.exe",
    options={
        "use_ml": True,
        "use_yara": True,
        "extract_strings": True,
        "deep_scan": True,
        "timeout": 300
    }
)
```

### YARA Rules

Configure custom YARA rules:

```python
context.options["yara_rules"] = [
    "/path/to/custom_rules.yar",
    "/path/to/malware_rules.yar"
]
```

## Testing

### Unit Tests

```python
import pytest
from reveng.plugins.security import MalwareDetectionPlugin

def test_malware_detection():
    plugin = MalwareDetectionPlugin()
    context = PluginContext(binary_path="known_malware.exe")

    result = plugin.analyze(context)

    assert result['is_malicious'] is True
    assert result['threat_score'] >= 70
    assert 'malware_family' in result

def test_clean_file():
    plugin = MalwareDetectionPlugin()
    context = PluginContext(binary_path="clean.exe")

    result = plugin.analyze(context)

    assert result['is_malicious'] is False
    assert result['threat_score'] < 30
```

## Related Modules

### Internal Dependencies
- `/home/user/reveng-main/src/reveng/plugins/` - Plugin framework
- `/home/user/reveng-main/src/reveng/ml/` - ML models for detection
- `/home/user/reveng-main/src/reveng/malware/` - Malware analysis utilities

### External Dependencies
- YARA rules
- ML models (trained classifiers)
- Signature databases

## Notes

**Best Practices:**
1. Use multi-engine detection for accuracy
2. Keep signatures and models updated
3. Validate results with manual analysis
4. Use appropriate threat thresholds

**Security Considerations:**
- Analyze samples in isolated environment
- Limit resource usage (CPU, memory, time)
- Validate all inputs
- Handle evasion techniques

**Future Enhancements:**
- [ ] Dynamic analysis integration
- [ ] Sandbox automation
- [ ] Cloud threat intelligence
- [ ] Automated reporting
- [ ] Behavioral monitoring

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
