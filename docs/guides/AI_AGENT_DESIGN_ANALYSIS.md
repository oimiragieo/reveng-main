# REVENG as an AI Agent Tool: Design Analysis

## Design Philosophy

**REVENG is designed for AI agents (like Claude) to use as a reverse engineering assistant**, where:
- **REVENG does:** Low-level binary analysis, decompilation, intelligence extraction
- **AI Agent does:** High-level reasoning, code translation, synthesis, decision-making

The human user says: "Reverse engineer this binary and rebuild in Python"
The AI agent (Claude) uses REVENG as its analysis tool to accomplish this.

---

## Current AI Agent Capabilities: How Claude Would Use REVENG

### ✅ What Works Excellently for AI Agents

#### 1. **CLI Commands are AI-Friendly**

**AI Agent Workflow:**
```python
# Claude's internal reasoning:
# "User wants to understand binary.exe. Let me use REVENG systematically."

# Step 1: Quick triage
run_command("reveng triage binary.exe --format json")
# Parse JSON output → understand threat level, capabilities

# Step 2: Ask specific questions
run_command('reveng ask "What does this binary do?" binary.exe')
# Get natural language explanation

# Step 3: Deep analysis
run_command("reveng analyze binary.exe --output-dir analysis")
# Get structured analysis results

# Step 4: Extract specifics
run_command('reveng ask "What encryption is used?" binary.exe --analysis-results analysis/analysis.json')
# Get crypto details

# Step 5: Enhance critical code
run_command("reveng enhance-code analysis/decompiled/crypto.c --output enhanced/crypto.c")
# Get readable code
```

**Why This Works:**
- ✅ All commands have JSON output options
- ✅ Structured, parseable data
- ✅ Predictable command syntax
- ✅ Clear input/output contracts

---

#### 2. **Natural Language Interface is Perfect for AI Agents**

**Claude can ask domain-specific questions:**
```bash
# Instead of parsing raw disassembly, Claude asks:
reveng ask "What crypto algorithm is used in function sub_401000?" binary.exe
reveng ask "Find all network communication code" binary.exe
reveng ask "What persistence mechanisms are implemented?" binary.exe
reveng ask "Extract all IOCs" binary.exe
```

**Why This is Brilliant for AI:**
- ✅ AI agent doesn't need to parse assembly
- ✅ AI agent gets semantic answers
- ✅ Can ask follow-up questions iteratively
- ✅ Natural language → Natural language (AI's native domain)

**Example AI Agent Workflow:**
```
User: "Reverse engineer this malware"
Claude thinks: "I need to understand it first"
  ↓
Claude: reveng ask "What does this binary do?" malware.exe
REVENG: "This is a credential stealer that..."
  ↓
Claude thinks: "I need crypto details"
  ↓
Claude: reveng ask "What encryption is used?" malware.exe
REVENG: "AES-256-CBC with key derived from SHA256('seed')"
  ↓
Claude thinks: "Now I can write Python code"
  ↓
Claude writes Python crypto code using those exact details
```

---

#### 3. **Structured JSON Output Enables Programmatic Processing**

**All commands support JSON:**
```bash
reveng triage binary.exe --format json
reveng diff old.exe new.exe --format json
reveng detect-packer binary.exe --format json
```

**AI Agent can parse and reason:**
```python
# Claude's pseudo-logic:
result = json.loads(run_command("reveng triage binary.exe --format json"))

if result['threat_score'] > 80:
    # High threat - need detailed analysis
    run_deep_analysis()

if 'network' in result['capabilities']:
    # Ask about network behavior
    network_details = ask_reveng("How does network communication work?")

if 'crypto' in result['capabilities']:
    # Extract crypto details for Python implementation
    crypto_details = ask_reveng("What crypto algorithms are used?")
```

**Why This is Powerful:**
- ✅ AI can make decisions based on analysis results
- ✅ AI can branch workflows dynamically
- ✅ AI can extract specific fields programmatically
- ✅ No need to parse human-readable text

---

#### 4. **Code Enhancement Bridges RE → Implementation Gap**

**Current Flow:**
```bash
# REVENG decompiles to messy C
reveng analyze binary.exe

# AI gets this:
int sub_401000(int a1, char *a2) {
    int v4; char *v5; int v6;
    v4 = a1 + 0x10;
    // ... cryptic code
}

# AI enhances it:
reveng enhance-code decompiled/sub_401000.c

# AI now gets this:
int verify_string_hash(int expected_base, char *input_string) {
    int expected_hash;
    char *current_char;
    int computed_hash;

    /* Calculate expected hash from base */
    expected_hash = expected_base + 0x10;
    // ... readable code with comments
}

# AI can now translate to Python much easier!
```

**Why This Works:**
- ✅ Enhanced code is MUCH easier for AI to understand
- ✅ Semantic variable names help AI infer purpose
- ✅ Comments guide AI translation
- ✅ Function names hint at functionality

---

### ✅ Complete AI Agent Workflow Example

**User Request:** "Reverse engineer malware.exe and rebuild in Python"

**Claude's Autonomous Workflow Using REVENG:**

```python
def autonomous_reverse_engineer_and_rebuild(binary_path: str, target_lang: str = "python"):
    """
    AI Agent uses REVENG to autonomously RE and rebuild binary

    This is Claude's internal logic when user says:
    "Reverse engineer binary.exe and rebuild in Python"
    """

    # PHASE 1: UNDERSTAND THE BINARY
    print("[Claude] Let me analyze this binary first...")

    # Quick triage
    triage = json.loads(run_bash("reveng triage {binary_path} --format json"))
    print(f"[Claude] Threat score: {triage['threat_score']}")
    print(f"[Claude] Capabilities: {', '.join(triage['capabilities'])}")

    # High-level understanding
    overview = run_bash(f'reveng ask "What does this binary do?" {binary_path}')
    print(f"[Claude] Overview: {overview}")

    # PHASE 2: DEEP ANALYSIS
    print("[Claude] Running deep analysis...")
    run_bash(f"reveng analyze {binary_path} --output-dir analysis")

    # PHASE 3: EXTRACT KEY DETAILS
    print("[Claude] Extracting implementation details...")

    # Ask specific questions based on capabilities
    if 'crypto' in triage['capabilities']:
        crypto_info = run_bash(f'reveng ask "What crypto algorithms are used and what are the keys?" {binary_path}')
        print(f"[Claude] Crypto: {crypto_info}")

    if 'network' in triage['capabilities']:
        network_info = run_bash(f'reveng ask "How does network communication work? Include URLs, protocols, and data formats" {binary_path}')
        print(f"[Claude] Network: {network_info}")

    if 'persistence' in triage['capabilities']:
        persistence_info = run_bash(f'reveng ask "What persistence mechanisms are used?" {binary_path}')
        print(f"[Claude] Persistence: {persistence_info}")

    # PHASE 4: ENHANCE CODE FOR READABILITY
    print("[Claude] Enhancing decompiled code...")
    decompiled_files = glob("analysis/decompiled/*.c")

    for c_file in decompiled_files:
        run_bash(f"reveng enhance-code {c_file} --output enhanced/{basename(c_file)}")

    # PHASE 5: TRANSLATE TO PYTHON (This is where AI does the work)
    print("[Claude] Now I'll translate to Python using the enhanced code...")

    # Read enhanced C files
    enhanced_files = glob("enhanced/*.c")
    python_modules = []

    for c_file in enhanced_files:
        c_code = read_file(c_file)

        # Claude uses LLM knowledge to translate C → Python
        # This is AI reasoning, not automation
        python_code = claude_translate_c_to_python(
            c_code=c_code,
            crypto_details=crypto_info,
            network_details=network_info,
            target_lang="python"
        )

        # Write Python module
        module_name = basename(c_file).replace('.c', '.py')
        write_file(f"rebuild/{module_name}", python_code)
        python_modules.append(module_name)

    # PHASE 6: CREATE MAIN ORCHESTRATION
    print("[Claude] Creating main orchestration...")

    # Claude synthesizes main.py based on understanding
    main_code = claude_generate_main_module(
        modules=python_modules,
        overview=overview,
        capabilities=triage['capabilities']
    )

    write_file("rebuild/main.py", main_code)

    # PHASE 7: DOCUMENT THE REBUILD
    print("[Claude] Generating documentation...")

    doc = f"""
    # {binary_path} Rebuild

    ## Original Binary Analysis
    {overview}

    ## Capabilities
    {json.dumps(triage['capabilities'], indent=2)}

    ## Implementation Details

    ### Crypto
    {crypto_info if 'crypto' in triage['capabilities'] else 'N/A'}

    ### Network
    {network_info if 'network' in triage['capabilities'] else 'N/A'}

    ## Python Modules
    {', '.join(python_modules)}

    ## Usage
    ```python
    from main import MalwareRebuild
    malware = MalwareRebuild()
    malware.run()
    ```
    """

    write_file("rebuild/README.md", doc)

    print("[Claude] ✅ Rebuild complete!")
    print("[Claude] Output directory: rebuild/")
    print(f"[Claude] Created {len(python_modules)} Python modules")

    return "rebuild/"

def claude_translate_c_to_python(c_code, crypto_details, network_details, target_lang):
    """
    This is Claude's internal LLM reasoning to translate C → Python

    Claude uses:
    - Enhanced C code (readable, commented)
    - Extracted intelligence (crypto keys, URLs, etc.)
    - Domain knowledge of C ↔ Python mappings
    - Understanding of common patterns
    """

    # Parse enhanced C code
    functions = parse_c_functions(c_code)

    python_code = "# Auto-generated from enhanced C code\n\n"

    for func in functions:
        # Claude's reasoning:
        # 1. Understand function purpose (from name + comments)
        # 2. Map C types to Python types
        # 3. Replace Windows API with Python equivalents
        # 4. Preserve logic flow
        # 5. Use extracted intelligence (keys, URLs)

        python_func = translate_function(
            c_function=func,
            crypto_keys=crypto_details,
            network_urls=network_details
        )

        python_code += python_func + "\n\n"

    return python_code
```

---

## ✅ Current Strengths for AI Agents

### 1. **Excellent Information Extraction**
- ✅ JSON output for programmatic parsing
- ✅ Natural language Q&A for semantic understanding
- ✅ Structured analysis results
- ✅ IOC extraction
- ✅ Capability detection

### 2. **AI-Friendly Commands**
- ✅ Clear, predictable syntax
- ✅ Consistent output formats
- ✅ Composable workflow
- ✅ No interactive prompts (fully scriptable)

### 3. **Enhanced Code Quality**
- ✅ Readable C code (much easier to translate)
- ✅ Semantic variable names
- ✅ Helpful comments
- ✅ Function purpose identification

### 4. **Iterative Question Answering**
- ✅ AI can ask follow-up questions
- ✅ Refine understanding progressively
- ✅ Extract specific details on demand

---

## ❌ Gaps for AI Agent Workflows

### 🔴 Gap #1: No Programmatic API (Only CLI)

**Current:**
```bash
# AI must shell out to CLI
result = subprocess.run(["reveng", "ask", "question", "binary.exe"], capture_output=True)
```

**Better for AI Agents:**
```python
# Python API for direct integration
from reveng import REVENGAnalyzer

analyzer = REVENGAnalyzer("binary.exe")
result = analyzer.triage()
answer = analyzer.ask("What does this do?")
enhanced_code = analyzer.enhance_code("function.c")
```

**Why This Matters:**
- AI agents prefer programmatic APIs over CLI
- Better error handling
- Type hints for AI code generation
- In-process execution (faster)
- No subprocess overhead

---

### 🔴 Gap #2: No Code Translation Examples in Output

**Current:**
```bash
reveng enhance-code crypto.c
# Outputs: Enhanced C code (still C!)
```

**Better for AI Agents:**
```bash
reveng enhance-code crypto.c --include-translation-hints python
# Outputs: Enhanced C + inline Python translation suggestions

/* Original C code */
HANDLE hFile = CreateFileW(L"config.dat", GENERIC_READ, ...);

/* Enhanced C code with translation hints */
// Python equivalent: with open("config.dat", "rb") as f:
HANDLE file_handle = CreateFileW(
    config_path,  // Python: use pathlib.Path
    GENERIC_READ,  // Python: mode='rb'
    ...
);
```

**Why This Matters:**
- Guides AI translation directly
- Reduces ambiguity
- Provides Python library suggestions
- Maps Windows API → Python stdlib

---

### 🔴 Gap #3: No Structured Code Representation

**Current:**
```bash
reveng analyze binary.exe
# Outputs: C code in text files
```

**Better for AI Agents:**
```bash
reveng analyze binary.exe --format json --include-ast
# Outputs: JSON with AST representation

{
  "functions": [
    {
      "name": "decrypt_config",
      "address": "0x401000",
      "signature": "int decrypt_config(void)",
      "ast": {
        "type": "function",
        "body": [
          {
            "type": "variable_declaration",
            "name": "encrypted_data",
            "ctype": "char[256]"
          },
          {
            "type": "function_call",
            "name": "AES_decrypt",
            "args": ["encrypted_data", "key", "output"]
          }
        ]
      },
      "intelligence": {
        "crypto_algorithm": "AES-256-CBC",
        "key_location": "0x5040",
        "key_value": "4B657953656372657453656564..."
      }
    }
  ]
}
```

**Why This Matters:**
- AI can parse structure programmatically
- AI can extract specific elements (loops, calls, etc.)
- AI can reason about code structure
- Easier to template-based translation

---

### 🔴 Gap #4: No Multi-Step Workflow Orchestration

**Current:**
```bash
# AI must manually orchestrate
reveng triage binary.exe
reveng analyze binary.exe
reveng ask "..." binary.exe
reveng enhance-code file1.c
reveng enhance-code file2.c
# ... many manual steps
```

**Better for AI Agents:**
```bash
# Single command for complete workflow
reveng full-rebuild binary.exe \
  --target python \
  --output rebuild/ \
  --strategy autonomous

# REVENG would:
# 1. Triage
# 2. Deep analysis
# 3. Enhance all code
# 4. Extract all intelligence
# 5. Generate structured output for AI translation
# 6. Provide translation templates
```

**Why This Matters:**
- Reduces AI orchestration complexity
- Consistent workflow
- Optimized for end-to-end rebuilds
- Single command = simpler for users

---

### 🔴 Gap #5: No Translation Templates/Patterns

**Current:**
AI must know all C→Python mappings from scratch.

**Better for AI Agents:**
```bash
reveng get-translation-patterns --source c --target python

# Outputs JSON with common patterns:
{
  "file_operations": {
    "c_pattern": "HANDLE h = CreateFileW(...); ReadFile(h, buf, size, ...);",
    "python_pattern": "with open(path, 'rb') as f: data = f.read()"
  },
  "crypto": {
    "c_pattern": "AES_set_decrypt_key(key, 256, &aes_key); AES_cbc_encrypt(...);",
    "python_pattern": "from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes\ncipher = Cipher(algorithms.AES(key), modes.CBC(iv))\ndecryptor = cipher.decryptor()\nplaintext = decryptor.update(ciphertext)"
  },
  "network": {
    "c_pattern": "WinHttpOpen(...); WinHttpConnect(...); WinHttpSendRequest(...);",
    "python_pattern": "import requests\nresponse = requests.post(url, data=payload)"
  }
}
```

**Why This Matters:**
- AI doesn't need to memorize all mappings
- Consistent translation patterns
- Reduces hallucination risk
- Faster AI translation

---

### 🟡 Gap #6: No Confidence Scores in NL Interface

**Current:**
```bash
reveng ask "What crypto is used?" binary.exe
# Output: "This uses AES-256-CBC encryption"
# But is this certain or a guess?
```

**Better for AI Agents:**
```bash
reveng ask "What crypto is used?" binary.exe --format json

{
  "answer": "This uses AES-256-CBC encryption",
  "confidence": 0.95,  # High confidence based on API calls found
  "evidence": [
    "Found BCryptEncrypt API call at 0x402000",
    "Key size is 32 bytes (256 bits)",
    "CBC mode indicated by IV usage"
  ],
  "uncertainty": null
}
```

**Why This Matters:**
- AI can assess answer reliability
- AI can decide if manual verification needed
- AI can ask follow-up questions for low confidence
- Better decision-making

---

## 🎯 Design Improvements for AI Agent Integration

### Priority 1: Python API (Highest Impact)

```python
# Create src/reveng/api.py

from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass

@dataclass
class TriageResult:
    threat_score: int
    priority: str
    classification: str
    capabilities: List[str]
    iocs: Dict[str, List[str]]

class REVENGAnalyzer:
    """Python API for REVENG

    Designed for AI agents to use programmatically.
    """

    def __init__(self, binary_path: str):
        self.binary_path = Path(binary_path)
        self.analysis_dir: Optional[Path] = None

    def triage(self) -> TriageResult:
        """Perform instant triage"""
        from .tools.tools.ai_enhanced import InstantTriageEngine
        engine = InstantTriageEngine()
        result = engine.triage(str(self.binary_path))
        return result

    def ask(self, question: str, analysis_results: Optional[Dict] = None) -> str:
        """Ask natural language question"""
        from .tools.tools.ai_enhanced import NaturalLanguageInterface
        nl = NaturalLanguageInterface()
        return nl.query(question, str(self.binary_path), analysis_results)

    def analyze(self, output_dir: Optional[str] = None) -> Dict[str, Any]:
        """Run full analysis"""
        from .analyzer import REVENGAnalyzer as CoreAnalyzer
        analyzer = CoreAnalyzer(str(self.binary_path))
        success = analyzer.analyze_binary()

        if success:
            self.analysis_dir = Path(output_dir or analyzer.output_dir)
            return self.load_analysis_results()
        return {}

    def enhance_code(self, code_path: str) -> str:
        """Enhance decompiled code"""
        from .tools.tools.ai_enhanced import AICodeQualityEnhancer

        with open(code_path) as f:
            code = f.read()

        enhancer = AICodeQualityEnhancer()
        result = enhancer.enhance_function(code)
        return result.enhanced_code

    def get_crypto_details(self) -> Dict[str, Any]:
        """Extract crypto implementation details"""
        answer = self.ask("What crypto algorithms are used? Include keys, IVs, and modes.")
        # Parse and structure the answer
        return {
            'algorithm': self._extract_algorithm(answer),
            'keys': self._extract_keys(answer),
            'mode': self._extract_mode(answer)
        }

    def get_network_details(self) -> Dict[str, Any]:
        """Extract network implementation details"""
        answer = self.ask("How does network communication work? Include URLs, protocols, headers.")
        return {
            'urls': self._extract_urls(answer),
            'protocol': self._extract_protocol(answer),
            'headers': self._extract_headers(answer)
        }

    def get_translation_hints(self, c_code: str, target_lang: str = "python") -> Dict[str, str]:
        """Get hints for translating C code to target language

        Returns mapping of C constructs to target language equivalents
        """
        # Analyze C code and provide translation suggestions
        hints = {}

        # Detect Windows API calls
        if "CreateFileW" in c_code:
            hints["CreateFileW"] = "open(path, 'rb')" if target_lang == "python" else None

        if "WinHttpOpen" in c_code:
            hints["WinHttpOpen"] = "requests.Session()" if target_lang == "python" else None

        # More sophisticated analysis...
        return hints

# Usage by AI agent:
"""
analyzer = REVENGAnalyzer("malware.exe")

# Quick triage
triage = analyzer.triage()
if triage.threat_score > 80:
    # Deep analysis needed
    results = analyzer.analyze()

# Extract details for Python rebuild
crypto = analyzer.get_crypto_details()
network = analyzer.get_network_details()

# Enhance code
enhanced = analyzer.enhance_code("analysis/decompiled/crypto.c")

# Get translation hints
hints = analyzer.get_translation_hints(enhanced, target_lang="python")

# AI can now translate with all the context
"""
```

---

### Priority 2: Structured Output Format

Add `--output-format structured` that provides complete analysis in single JSON:

```json
{
  "metadata": {
    "binary": "malware.exe",
    "sha256": "abc123...",
    "analysis_time": "2025-01-16T10:30:00Z"
  },
  "triage": {
    "threat_score": 92,
    "capabilities": ["network", "crypto", "persistence"]
  },
  "functions": [
    {
      "address": "0x401000",
      "name": "decrypt_config",
      "original_name": "sub_401000",
      "signature": "int decrypt_config(void)",
      "c_code": "int decrypt_config(void) { ... }",
      "enhanced_code": "/* Decrypt configuration */ int decrypt_config(void) { ... }",
      "translation_hints": {
        "python": {
          "suggested_imports": ["cryptography.hazmat.primitives.ciphers"],
          "api_mappings": {
            "AES_decrypt": "Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()"
          }
        }
      },
      "intelligence": {
        "crypto_algorithm": "AES-256-CBC",
        "key": "4B657953656372657453656564...",
        "iv": "000102030405060708090a0b0c0d0e0f"
      }
    }
  ],
  "iocs": {
    "urls": ["https://evil.com/api/upload"],
    "ips": ["192.168.1.100"],
    "file_paths": ["C:\\config.dat"],
    "registry_keys": ["HKCU\\Software\\...\\Run"]
  }
}
```

AI agent gets EVERYTHING in one structured format, ready for programmatic processing.

---

### Priority 3: Add Translation Templates

```bash
reveng translate-template crypto.c --target python --output crypto.py.template

# Generates template with placeholders:
```

```python
# crypto.py
# Auto-generated template from crypto.c
# Fill in implementation details

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib

class CryptoModule:
    """
    Original function: decrypt_config at 0x401000
    Purpose: {{ EXTRACTED_PURPOSE }}
    """

    def __init__(self):
        # Key derivation from static analysis
        # Original: {{ ORIGINAL_KEY_DERIVATION }}
        seed = b"{{ EXTRACTED_SEED }}"
        self.key = hashlib.sha256(seed).digest()

        # IV from offset {{ IV_OFFSET }}
        self.iv = bytes.fromhex("{{ EXTRACTED_IV }}")

    def decrypt_config(self) -> dict:
        """
        {{ FUNCTION_DESCRIPTION }}

        Original logic:
        {{ C_CODE_LOGIC }}
        """
        # TODO: Translate C logic to Python
        # Hint: {{ TRANSLATION_HINT }}
        pass
```

AI agent fills in placeholders using extracted intelligence.

---

## ✅ Conclusion: Current Design Assessment

### Excellent Foundation for AI Agents

**Current REVENG is 80% optimized for AI agent usage:**

#### Strong Points:
1. ✅ **JSON output** - AI can parse programmatically
2. ✅ **Natural language Q&A** - AI's native interface
3. ✅ **Code enhancement** - Makes translation easier
4. ✅ **Structured workflows** - Predictable, composable
5. ✅ **Intelligence extraction** - Keys, URLs, IOCs
6. ✅ **No interactive prompts** - Fully scriptable

#### Remaining Gaps:
1. ❌ **No Python API** - Only CLI (adds overhead)
2. ❌ **No translation hints** - AI must guess mappings
3. ❌ **No AST/structured code** - Only text C files
4. ❌ **No complete rebuild workflow** - Many manual steps
5. ❌ **No confidence scores** - AI can't assess reliability

---

### Recommended Next Steps

**To make REVENG perfect for AI agents:**

1. **Add Python API** (Priority 1)
   - `from reveng import REVENGAnalyzer`
   - Direct function calls, no subprocess
   - Type hints for AI code generation

2. **Add Translation Hints** (Priority 2)
   - Include Python equivalents in enhanced code
   - API mapping database (CreateFileW → open())
   - Common pattern templates

3. **Add Structured Output** (Priority 3)
   - Single JSON with complete analysis
   - AST representation of code
   - Intelligence embedded per-function

4. **Add Confidence Scores** (Priority 4)
   - Every NL answer includes confidence
   - Evidence citations
   - Uncertainty flagging

5. **Add Rebuild Workflow** (Priority 5)
   - `reveng full-rebuild` command
   - Orchestrates entire pipeline
   - Generates translation templates

---

## Real-World AI Agent Usage Today

**How Claude Would Use Current REVENG:**

```python
# User: "Reverse engineer malware.exe and rebuild in Python"

# Claude's thought process:
"I'll use REVENG to do the heavy lifting, then translate manually"

# Step 1: Understanding
triage = run_bash("reveng triage malware.exe --format json")
overview = run_bash('reveng ask "What does this do?" malware.exe')

# Step 2: Deep analysis
run_bash("reveng analyze malware.exe --output-dir analysis")

# Step 3: Extract details
crypto = run_bash('reveng ask "What crypto is used? Include keys." malware.exe')
network = run_bash('reveng ask "Network details? Include URLs." malware.exe')

# Step 4: Enhance code
for c_file in glob("analysis/decompiled/*.c"):
    run_bash(f"reveng enhance-code {c_file}")

# Step 5: Translate (MANUAL - Claude's LLM does this)
for enhanced_c in glob("enhanced/*.c"):
    c_code = read_file(enhanced_c)

    # Claude's internal reasoning translates C → Python
    # Uses: enhanced code, crypto details, network details
    python_code = claude_translate(c_code, crypto, network)

    write_file(f"rebuild/{basename(enhanced_c, '.c')}.py", python_code)

# Step 6: Document
write_documentation(overview, triage, "rebuild/README.md")

# Result: Complete Python rebuild
```

**This works today!** REVENG provides excellent support for AI agents, with some manual translation work remaining.

---

## Vision: Ideal AI Agent Integration

**What perfect integration would look like:**

```python
# Single Python API call
from reveng import REVENGRebuild

rebuilder = REVENGRebuild("malware.exe")
rebuilder.rebuild(
    target_language="python",
    output_dir="rebuild/",
    ai_assisted=True  # Uses LLM for translation
)

# REVENG + AI handles everything:
# 1. Analysis
# 2. Enhancement
# 3. Translation template generation
# 4. AI fills templates
# 5. Generates tests
# 6. Creates documentation
```

**Result:** Complete Python rebuild with 95% automation, AI agent only reviews/validates.

This is the **ultimate vision** - REVENG as the perfect AI agent tool!
