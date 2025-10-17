# REVENG AI API Reference

Complete API reference for the AI-optimized Python interface for REVENG.

## Overview

The REVENG AI API (`REVENG_AI_API`) provides a clean, type-hinted programmatic interface specifically designed for AI agents (Claude, GPT, etc.) to control REVENG and perform binary analysis tasks.

## Installation

```python
from reveng.ai_api import REVENG_AI_API, TriageResult, NLResponse

# Initialize API
api = REVENG_AI_API(use_ollama=True, ollama_model='auto')
```

## Core Classes

### REVENG_AI_API

Main API class for AI agents.

#### Constructor

```python
api = REVENG_AI_API(
    use_ollama: bool = True,          # Enable local LLM via Ollama
    ollama_model: str = 'auto',       # Ollama model ('auto', 'llama3', 'mistral')
    output_dir: Optional[str] = None  # Custom output directory
)
```

#### Methods

##### triage_binary()

Fast (<30 second) triage to determine threat level.

```python
result: TriageResult = api.triage_binary(
    binary_path: str,              # Path to binary file
    include_reasoning: bool = True  # Include detailed reasoning
)
```

**Returns:** `TriageResult` with:
- `threat_level` (str): ThreatLevel enum value
- `threat_score` (int): 0-100
- `is_malicious` (bool): Quick yes/no assessment
- `confidence` (float): 0.0-1.0
- `detected_capabilities` (List[str]): Capabilities found
- `recommended_action` (str): Recommended next steps
- `analysis_time_ms` (int): Analysis time in milliseconds
- `metadata` (Dict): Additional context

**Example:**
```python
triage = api.triage_binary("suspicious.exe")
if triage.is_malicious:
    print(f"THREAT: {triage.threat_level} (score: {triage.threat_score})")
    print(f"Capabilities: {', '.join(triage.detected_capabilities)}")
    print(f"Action: {triage.recommended_action}")
```

##### ask()

Natural language query about a binary.

```python
response: NLResponse = api.ask(
    question: str,                              # Natural language question
    binary_path: Optional[str] = None,          # Path to binary
    analysis_results: Optional[Dict] = None     # Pre-existing analysis
)
```

**Returns:** `NLResponse` with:
- `answer` (str): Natural language answer
- `confidence` (float): 0.0-1.0
- `intent` (str): Detected query intent
- `sources` (List[str]): Data sources used
- `metadata` (Dict): Additional context

**Example:**
```python
response = api.ask("What does this binary do?", "malware.exe")
print(f"Answer: {response.answer}")
print(f"Confidence: {response.confidence:.2f}")
print(f"Sources: {', '.join(response.sources)}")
```

##### get_crypto_details()

Extract cryptography-related details.

```python
crypto: CryptoDetails = api.get_crypto_details(
    binary_path: str,
    analysis_results: Optional[Dict] = None
)
```

**Returns:** `CryptoDetails` with:
- `algorithms` (List[str]): Detected algorithms (AES, RSA, MD5, SHA, etc.)
- `key_operations` (List[str]): Key generation/management operations
- `confidence` (float): 0.0-1.0
- `suspicious_patterns` (List[str]): Weak algorithms, hardcoded keys
- `notes` (str): Additional details

**Example:**
```python
crypto = api.get_crypto_details("ransomware.exe")
if 'MD5' in crypto.algorithms:
    print("WARNING: Uses weak MD5 algorithm")
for pattern in crypto.suspicious_patterns:
    print(f"SUSPICIOUS: {pattern}")
```

##### get_network_details()

Extract network-related details.

```python
network: NetworkDetails = api.get_network_details(
    binary_path: str,
    analysis_results: Optional[Dict] = None
)
```

**Returns:** `NetworkDetails` with:
- `protocols` (List[str]): Network protocols (HTTP, TCP, UDP, etc.)
- `endpoints` (List[str]): IPs, domains, URLs
- `ports` (List[int]): Port numbers
- `c2_indicators` (List[str]): C2 infrastructure indicators
- `confidence` (float): 0.0-1.0
- `notes` (str): Additional details

**Example:**
```python
network = api.get_network_details("trojan.exe")
print(f"Protocols: {', '.join(network.protocols)}")
print(f"Endpoints: {len(network.endpoints)} found")
print(f"C2 Indicators: {', '.join(network.c2_indicators)}")
```

##### get_translation_hints()

Generate C-to-Python translation hints for decompiled code.

```python
hints: TranslationGuide = api.get_translation_hints(
    code_path: str,                    # Path to C source file
    output_format: str = 'structured'  # 'structured', 'markdown', or 'json'
)
```

**Returns:** `TranslationGuide` (structured) or `str` (markdown/json) with:
- `hints` (List[Dict]): Translation hints for each Windows API call
- `complexity` (str): 'simple', 'moderate', or 'complex'
- `imports_needed` (List[str]): Required Python imports
- `summary` (Dict): High-level translation summary
- `statistics` (Dict): Coverage and complexity metrics

**Example:**
```python
# Structured output
hints = api.get_translation_hints("decompiled_code.c")
print(f"Complexity: {hints.complexity}")
print(f"Required imports: {', '.join(hints.imports_needed)}")
print(f"Total hints: {len(hints.hints)}")

# Markdown guide
guide_md = api.get_translation_hints("code.c", output_format='markdown')
with open('TRANSLATION_GUIDE.md', 'w') as f:
    f.write(guide_md)
```

##### analyze_binary()

Comprehensive binary analysis.

```python
results: Dict = api.analyze_binary(
    binary_path: str,
    mode: AnalysisMode = AnalysisMode.STANDARD,  # QUICK, STANDARD, DEEP, REBUILD
    save_results: bool = True
)
```

**Returns:** Dictionary with:
- `triage` (Dict): Triage results
- `full_analysis` (Dict): Complete analysis results
- `translation_hints` (List[Dict]): Translation hints (if mode=REBUILD)

**Example:**
```python
# Quick triage only
results = api.analyze_binary("test.exe", mode=AnalysisMode.QUICK)

# Full analysis with translation hints for rebuild
results = api.analyze_binary("malware.exe", mode=AnalysisMode.REBUILD)
print(f"Threat score: {results['triage']['threat_score']}")
if 'translation_hints' in results:
    print(f"Translation hints for {len(results['translation_hints'])} files")
```

##### explain_binary()

Get comprehensive explanation of binary.

```python
response: NLResponse = api.explain_binary(
    binary_path: str,
    detail_level: str = 'standard'  # 'brief', 'standard', or 'detailed'
)
```

**Example:**
```python
# Brief explanation (2-3 sentences)
brief = api.explain_binary("file.exe", detail_level='brief')

# Detailed technical explanation
detailed = api.explain_binary("file.exe", detail_level='detailed')
print(detailed.answer)
```

##### find_vulnerabilities()

Find potential vulnerabilities.

```python
response: NLResponse = api.find_vulnerabilities(
    binary_path: str,
    vuln_types: Optional[List[str]] = None  # e.g., ['buffer overflow', 'sql injection']
)
```

**Example:**
```python
# Find all vulnerabilities
vulns = api.find_vulnerabilities("app.exe")
print(vulns.answer)

# Find specific vulnerability types
vulns = api.find_vulnerabilities("app.exe", vuln_types=['buffer overflow'])
```

##### extract_iocs()

Extract indicators of compromise.

```python
response: NLResponse = api.extract_iocs(
    binary_path: str,
    ioc_types: Optional[List[str]] = None  # e.g., ['ip', 'domain', 'url', 'hash']
)
```

**Example:**
```python
# Extract all IOCs
iocs = api.extract_iocs("malware.exe")

# Extract specific IOC types
iocs = api.extract_iocs("malware.exe", ioc_types=['ip', 'domain'])
print(iocs.answer)
```

##### compare_binaries()

Compare two binaries.

```python
comparison: Dict = api.compare_binaries(
    binary1_path: str,
    binary2_path: str
)
```

**Returns:** Dictionary with:
- `binary1` (Dict): Threat score, capabilities
- `binary2` (Dict): Threat score, capabilities
- `similarity` (Dict): Common capabilities, unique capabilities, threat score difference

**Example:**
```python
comp = api.compare_binaries("version1.exe", "version2.exe")
print(f"Threat score diff: {comp['similarity']['threat_score_diff']}")
print(f"Common capabilities: {comp['similarity']['common_capabilities']}")
print(f"Unique to v1: {comp['similarity']['unique_to_binary1']}")
```

## Data Classes

### TriageResult

```python
@dataclass
class TriageResult:
    threat_level: str
    threat_score: int
    is_malicious: bool
    confidence: float
    detected_capabilities: List[str]
    recommended_action: str
    analysis_time_ms: int
    metadata: Dict[str, Any]

    def to_dict(self) -> dict
    def to_json(self) -> str
```

### NLResponse

```python
@dataclass
class NLResponse:
    answer: str
    confidence: float
    intent: str
    sources: List[str]
    metadata: Optional[Dict[str, Any]]

    def to_dict(self) -> dict
    def to_json(self) -> str
```

### CryptoDetails

```python
@dataclass
class CryptoDetails:
    algorithms: List[str]
    key_operations: List[str]
    confidence: float
    suspicious_patterns: List[str]
    notes: str

    def to_dict(self) -> dict
```

### NetworkDetails

```python
@dataclass
class NetworkDetails:
    protocols: List[str]
    endpoints: List[str]
    ports: List[int]
    c2_indicators: List[str]
    confidence: float
    notes: str

    def to_dict(self) -> dict
```

### TranslationGuide

```python
@dataclass
class TranslationGuide:
    hints: List[Dict[str, Any]]
    complexity: str
    imports_needed: List[str]
    summary: Dict[str, Any]
    statistics: Dict[str, Any]

    def to_dict(self) -> dict
    def to_markdown(self) -> str
```

## Enums

### AnalysisMode

```python
class AnalysisMode(Enum):
    QUICK = "quick"         # Triage only (fastest)
    STANDARD = "standard"   # Standard analysis
    DEEP = "deep"           # Full analysis with all features
    REBUILD = "rebuild"     # Analysis + translation hints
```

## Convenience Functions

### quick_triage()

```python
from reveng.ai_api import quick_triage

result = quick_triage("binary.exe")
```

### quick_ask()

```python
from reveng.ai_api import quick_ask

answer = quick_ask("What does this do?", "binary.exe")  # Returns just string
```

## Complete Example

```python
from reveng.ai_api import REVENG_AI_API, AnalysisMode

# Initialize API
api = REVENG_AI_API()

# Step 1: Quick triage
triage = api.triage_binary("suspicious.exe")
print(f"Threat: {triage.threat_level} ({triage.threat_score}/100)")
print(f"Malicious: {triage.is_malicious}")

if triage.threat_score >= 60:
    # Step 2: Deep analysis for high-risk binaries
    results = api.analyze_binary("suspicious.exe", mode=AnalysisMode.DEEP)

    # Step 3: Ask specific questions
    capabilities = api.ask("What can this malware do?")
    print(f"Capabilities: {capabilities.answer}")

    # Step 4: Extract IOCs
    iocs = api.extract_iocs("suspicious.exe")
    print(f"IOCs: {iocs.answer}")

    # Step 5: Find vulnerabilities
    vulns = api.find_vulnerabilities("suspicious.exe")
    print(f"Vulnerabilities: {vulns.answer}")

    # Step 6: Get crypto details
    crypto = api.get_crypto_details("suspicious.exe")
    if crypto.suspicious_patterns:
        print(f"Crypto issues: {', '.join(crypto.suspicious_patterns)}")

else:
    print("Low threat, standard monitoring recommended")
```

## Best Practices

1. **Always start with triage** - Fast and cheap, helps decide next steps
2. **Use confidence scores** - All responses include confidence metrics
3. **Leverage natural language** - Ask questions in plain English
4. **Check sources** - NLResponse includes data sources used
5. **Handle errors** - Check confidence scores and metadata for errors
6. **Reuse analysis** - Pass `analysis_results` to avoid re-analyzing
7. **Choose appropriate mode** - Use QUICK for triage, REBUILD for code translation

## Error Handling

All methods return structured responses with confidence scores. Check confidence before trusting results:

```python
response = api.ask("Find network functions", "binary.exe")

if response.confidence >= 0.7:
    print(f"High confidence: {response.answer}")
elif response.confidence >= 0.4:
    print(f"Medium confidence: {response.answer}")
    print("Manual verification recommended")
else:
    print(f"Low confidence: {response.answer}")
    print("Results may be unreliable")

# Check for errors in metadata
if 'error' in response.metadata:
    print(f"Error occurred: {response.metadata['error']}")
```

## Performance Tips

- **Triage first**: ~10-30 seconds
- **Standard analysis**: ~2-5 minutes
- **Deep analysis**: ~5-15 minutes
- **Translation hints**: <1 second per file
- **Natural language queries**: <2 seconds (with Ollama)

## See Also

- [Translation Hints Guide](../guides/AI_AGENT_DESIGN_ANALYSIS.md)
- [Natural Language Interface](../guides/NEW_FEATURES_GUIDE.md)
- [Quick Start](../guides/QUICK_START.md)
