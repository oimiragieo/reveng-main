# Tools - Threat Intel

## Overview

Threat intelligence integration tools for enriching analysis with threat data from various sources including VirusTotal, MISP, and custom feeds.

**Location:** `/home/user/reveng-main/src/reveng/tools/threat_intel/`

**File Count:** 4 Python files

## Key Capabilities

### Threat Intelligence Sources
- VirusTotal integration
- MISP integration
- Custom threat feeds
- YARA rule feeds
- IOC databases

### Intelligence Enrichment
- Hash lookups
- Domain/IP reputation
- Malware family identification
- Attribution data
- Campaign tracking

### Threat Correlation
- Cross-reference analysis
- Related malware detection
- Attack pattern matching
- Threat actor profiling

## Usage Examples

### Example 1: VirusTotal Lookup

```python
from reveng.tools.threat_intel import VirusTotalClient

vt = VirusTotalClient(api_key="your-key")
result = vt.lookup_file("/path/to/binary.exe")

print(f"Detections: {result['positives']}/{result['total']}")
print(f"SHA256: {result['sha256']}")
print(f"First seen: {result['first_seen']}")
```

### Example 2: Enrich with Threat Intel

```python
from reveng.tools.threat_intel import ThreatIntelEnricher

enricher = ThreatIntelEnricher()
enriched = enricher.enrich(
    binary="/path/to/malware.exe",
    sources=["virustotal", "misp"]
)

print(f"Malware family: {enriched['family']}")
print(f"Threat actor: {enriched['actor']}")
print(f"Campaign: {enriched['campaign']}")
print(f"IOCs: {len(enriched['iocs'])}")
```

### Example 3: MISP Integration

```python
from reveng.tools.threat_intel import MISPClient

misp = MISPClient(url="https://misp.local", api_key="key")
events = misp.search_by_hash(sha256="...")

for event in events:
    print(f"Event: {event['title']}")
    print(f"Tags: {event['tags']}")
```

## Related Modules

- `/home/user/reveng-main/src/reveng/malware/` - Malware analysis
- `/home/user/reveng-main/src/reveng/security/` - Security features

---

**Status:** Implemented ✅

**Maintainer:** REVENG Development Team
