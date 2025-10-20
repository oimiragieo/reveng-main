# REVENG Technical Implementation Roadmap
## Detailed Engineering Plan for Killer Features

**Purpose:** This document provides detailed technical specifications and implementation guidance for transforming REVENG into the #1 AI-powered reverse engineering platform.

---

## 🎯 Phase 0: Critical Bug Fixes (Week 1-2)

### Bug Fix #1: Path Resolution (CRITICAL)

**File:** `src/reveng/analyzer.py`

**Current Problem:**
```python
# Line 430, 618, 656, 712, 746, 779, 1022
script_path = "src/tools/tools/core/ai_recompiler_converter.py"  # WRONG
```

**Fix:**
```python
# Use Path resolution relative to package root
from pathlib import Path

class REVENGAnalyzer:
    def __init__(self):
        # Get package root
        self.package_root = Path(__file__).parent.parent.parent
        self.tools_dir = self.package_root / "src" / "reveng" / "tools"

    def get_tool_path(self, tool_name: str) -> Path:
        """Resolve tool path correctly"""
        return self.tools_dir / "core" / f"{tool_name}.py"

# Usage
script_path = str(self.get_tool_path("ai_recompiler_converter"))
```

**Testing:**
```python
def test_tool_paths():
    """Verify all tool paths resolve correctly"""
    analyzer = REVENGAnalyzer()
    tools = [
        "ai_recompiler_converter",
        "optimal_binary_analysis",
        "ai_source_inspector",
        "human_readable_converter_fixed",
        "deobfuscation_tool",
        "implementation_tool",
        "binary_reassembler_v2"
    ]

    for tool in tools:
        path = analyzer.get_tool_path(tool)
        assert path.exists(), f"Tool not found: {path}"
        assert path.is_file(), f"Not a file: {path}"
```

---

### Bug Fix #2: Import Errors (CRITICAL)

**Problem:** Relative imports fail when running as script

**Current:**
```python
# In analyzer.py
from ..tools.languages.language_detector import LanguageDetector  # FAILS
```

**Solution 1: Use Absolute Imports (Recommended)**
```python
# Change all relative imports to absolute
from reveng.tools.languages.language_detector import LanguageDetector
from reveng.tools.ai.ollama_analyzer import OllamaAnalyzer
from reveng.tools.enterprise.corporate_exposure import CorporateExposureDetector
```

**Solution 2: Fix sys.path in Entry Points**
```python
# In reveng_analyzer.py (legacy CLI)
import sys
from pathlib import Path

# Add src/ to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root / "src"))

# Now can import
from reveng.analyzer import REVENGAnalyzer
```

**Migration Script:**
```python
# scripts/fix_imports.py
import re
from pathlib import Path

def fix_imports(file_path: Path):
    """Convert relative imports to absolute imports"""
    content = file_path.read_text()

    # Pattern: from ..module import X
    # Replace: from reveng.module import X
    patterns = [
        (r'from \.\.tools\.', 'from reveng.tools.'),
        (r'from \.\.ml\.', 'from reveng.ml.'),
        (r'from \.\.web\.', 'from reveng.web.'),
    ]

    for pattern, replacement in patterns:
        content = re.sub(pattern, replacement, content)

    file_path.write_text(content)

# Apply to all Python files
for py_file in Path("src/reveng").rglob("*.py"):
    fix_imports(py_file)
```

---

### Bug Fix #3: CLI Logger (CRITICAL)

**File:** `src/reveng/__main__.py` or `src/reveng/cli.py`

**Problem:**
```python
logger = get_logger()  # Missing required argument
```

**Fix:**
```python
# Find the get_logger() call around line 51
# Change to:
logger = get_logger(__name__)

# Or if using custom logging:
import logging
logger = logging.getLogger("reveng.cli")
```

**Complete Logging Setup:**
```python
# src/reveng/logging_config.py
import logging
import sys
from pathlib import Path

def setup_logging(name: str = "reveng", level: str = "INFO",
                  log_file: Path = None) -> logging.Logger:
    """
    Centralized logging configuration

    Usage:
        logger = setup_logging(__name__)
        logger.info("Starting analysis...")
    """
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper()))

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_format = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s'
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger

# Use everywhere
# src/reveng/cli.py
from reveng.logging_config import setup_logging
logger = setup_logging(__name__)
```

---

## 🚀 Phase 1: Killer Feature #1 - ChatRE (Conversational RE)

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    ChatRE Interface                     │
│         (Web UI / CLI / Python API)                     │
└────────────────┬────────────────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────────────────┐
│              Conversation Manager                        │
│  ├─ Multi-turn context management                       │
│  ├─ Intent classification                               │
│  ├─ Response generation                                 │
│  └─ Memory and state tracking                           │
└────────────────┬────────────────────────────────────────┘
                 │
        ┌────────┴────────┐
        │                 │
┌───────▼──────┐  ┌──────▼────────┐
│ Binary       │  │  AI Provider  │
│ Analysis     │  │  (Claude,     │
│ Cache        │  │   GPT-4,      │
│              │  │   Ollama)     │
└──────────────┘  └───────────────┘
```

### Implementation

#### 1. Core Conversation Manager

```python
# src/reveng/chat/conversation_manager.py
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import json

class ExpertiseLevel(Enum):
    BEGINNER = "beginner"
    INTERMEDIATE = "intermediate"
    EXPERT = "expert"

class Intent(Enum):
    ANALYZE_FUNCTION = "analyze_function"
    FIND_VULNERABILITIES = "find_vulnerabilities"
    EXPLAIN_CODE = "explain_code"
    EXTRACT_IOCS = "extract_iocs"
    COMPARE_BINARIES = "compare_binaries"
    GENERATE_YARA = "generate_yara"
    IDENTIFY_MALWARE = "identify_malware"
    PATCH_BINARY = "patch_binary"
    UNKNOWN = "unknown"

@dataclass
class Message:
    """Single message in conversation"""
    role: str  # "user" or "assistant"
    content: str
    timestamp: str
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ConversationContext:
    """Full conversation state"""
    binary_path: str
    analysis_results: Dict[str, Any]
    conversation_history: List[Message] = field(default_factory=list)
    expertise_level: ExpertiseLevel = ExpertiseLevel.INTERMEDIATE
    active_function: Optional[str] = None
    discovered_iocs: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ChatResponse:
    """Response to user query"""
    answer: str
    confidence: float
    intent: Intent
    suggested_followups: List[str]
    structured_data: Optional[Dict[str, Any]] = None
    sources: List[str] = field(default_factory=list)

class ConversationManager:
    """
    Manages multi-turn conversations about binary analysis

    Example:
        manager = ConversationManager("malware.exe")

        response = manager.chat("What does this binary do?")
        print(response.answer)

        # Follow-up question with context
        response = manager.chat("Show me the network functions")
        print(response.answer)
    """

    def __init__(self, binary_path: str, ai_provider: str = "claude"):
        self.context = ConversationContext(binary_path=binary_path)
        self.ai_provider = self._init_ai_provider(ai_provider)
        self.analyzer = None  # Lazy load

    def _init_ai_provider(self, provider: str):
        """Initialize AI provider"""
        if provider == "claude":
            from reveng.chat.providers import ClaudeProvider
            return ClaudeProvider()
        elif provider == "gpt4":
            from reveng.chat.providers import GPT4Provider
            return GPT4Provider()
        elif provider == "ollama":
            from reveng.chat.providers import OllamaProvider
            return OllamaProvider()
        else:
            raise ValueError(f"Unknown provider: {provider}")

    def chat(self, user_message: str) -> ChatResponse:
        """
        Process user message and return AI response

        Workflow:
        1. Classify intent
        2. Retrieve relevant analysis data
        3. Build context-aware prompt
        4. Query AI provider
        5. Parse and structure response
        6. Update conversation state
        """
        # Add user message to history
        self.context.conversation_history.append(
            Message(role="user", content=user_message, timestamp=self._get_timestamp())
        )

        # Classify intent
        intent = self._classify_intent(user_message)

        # Get relevant analysis data
        relevant_data = self._get_relevant_data(intent)

        # Build context-aware prompt
        prompt = self._build_prompt(user_message, intent, relevant_data)

        # Query AI
        ai_response = self.ai_provider.query(prompt, self.context)

        # Parse response
        response = self._parse_response(ai_response, intent)

        # Update conversation state
        self.context.conversation_history.append(
            Message(role="assistant", content=response.answer, timestamp=self._get_timestamp())
        )

        return response

    def _classify_intent(self, message: str) -> Intent:
        """
        Classify user intent using pattern matching + AI

        Examples:
            "What does this do?" → EXPLAIN_CODE
            "Find vulnerabilities" → FIND_VULNERABILITIES
            "Show network functions" → ANALYZE_FUNCTION
            "Is this malware?" → IDENTIFY_MALWARE
        """
        message_lower = message.lower()

        # Quick pattern matching first
        patterns = {
            Intent.FIND_VULNERABILITIES: ["vulnerability", "vuln", "security issue", "bug"],
            Intent.EXTRACT_IOCS: ["ioc", "indicator", "domain", "ip address"],
            Intent.EXPLAIN_CODE: ["what does", "explain", "how does", "what is"],
            Intent.GENERATE_YARA: ["yara", "signature", "detection rule"],
            Intent.IDENTIFY_MALWARE: ["malware", "virus", "trojan", "ransomware"],
        }

        for intent, keywords in patterns.items():
            if any(kw in message_lower for kw in keywords):
                return intent

        # Fall back to AI classification if patterns don't match
        return self._ai_classify_intent(message)

    def _ai_classify_intent(self, message: str) -> Intent:
        """Use AI to classify ambiguous intents"""
        prompt = f"""
        Classify the intent of this reverse engineering question:

        Question: "{message}"

        Possible intents:
        - analyze_function: User wants to understand specific functions
        - find_vulnerabilities: User wants security analysis
        - explain_code: User wants code explanation
        - extract_iocs: User wants IOCs, domains, IPs
        - identify_malware: User wants malware classification
        - generate_yara: User wants YARA rule
        - patch_binary: User wants to modify binary
        - compare_binaries: User wants binary comparison

        Return only the intent name.
        """

        response = self.ai_provider.quick_query(prompt)
        try:
            return Intent(response.strip().lower())
        except ValueError:
            return Intent.UNKNOWN

    def _get_relevant_data(self, intent: Intent) -> Dict[str, Any]:
        """
        Retrieve analysis data relevant to user's intent

        Smart data loading: only load what's needed
        """
        # Lazy load analyzer if not done yet
        if self.analyzer is None:
            from reveng.ai_api import REVENG_AI_API
            self.analyzer = REVENG_AI_API()
            # Run quick triage first (30 seconds)
            self.context.analysis_results["triage"] = self.analyzer.triage_binary(
                self.context.binary_path
            )

        relevant_data = {}

        if intent == Intent.FIND_VULNERABILITIES:
            # Load vulnerability scan results
            if "vulnerabilities" not in self.context.analysis_results:
                relevant_data["vulnerabilities"] = self._scan_vulnerabilities()
            else:
                relevant_data["vulnerabilities"] = self.context.analysis_results["vulnerabilities"]

        elif intent == Intent.EXTRACT_IOCS:
            # Load IOC extraction
            if "iocs" not in self.context.analysis_results:
                relevant_data["iocs"] = self._extract_iocs()
            else:
                relevant_data["iocs"] = self.context.analysis_results["iocs"]

        elif intent == Intent.IDENTIFY_MALWARE:
            # Load malware classification
            relevant_data["triage"] = self.context.analysis_results.get("triage")
            if "malware_classification" not in self.context.analysis_results:
                relevant_data["malware"] = self._classify_malware()

        elif intent == Intent.ANALYZE_FUNCTION:
            # Load function analysis
            if "functions" not in self.context.analysis_results:
                relevant_data["functions"] = self._analyze_functions()

        # Always include triage summary for context
        relevant_data["triage_summary"] = self.context.analysis_results.get("triage")

        return relevant_data

    def _build_prompt(self, user_message: str, intent: Intent,
                     relevant_data: Dict[str, Any]) -> str:
        """
        Build context-aware prompt for AI provider

        Includes:
        - Conversation history (last N messages)
        - Relevant analysis data
        - User's expertise level
        - Current focus (if any)
        """
        # Get conversation context (last 5 messages)
        recent_history = self.context.conversation_history[-10:]
        conversation_context = "\n".join([
            f"{msg.role.upper()}: {msg.content}"
            for msg in recent_history
        ])

        # Format relevant data
        data_context = json.dumps(relevant_data, indent=2)

        # Build expertise-aware prompt
        expertise_instructions = {
            ExpertiseLevel.BEGINNER: "Explain in simple terms. Avoid jargon. Use analogies.",
            ExpertiseLevel.INTERMEDIATE: "Balance technical depth with clarity.",
            ExpertiseLevel.EXPERT: "Use technical terminology. Be precise and detailed."
        }

        prompt = f"""
You are an AI reverse engineering assistant helping analyze a binary.

BINARY: {self.context.binary_path}

EXPERTISE LEVEL: {self.context.expertise_level.value}
INSTRUCTIONS: {expertise_instructions[self.context.expertise_level]}

CONVERSATION HISTORY:
{conversation_context}

RELEVANT ANALYSIS DATA:
{data_context}

USER QUESTION: {user_message}

Provide a helpful, accurate response based on the analysis data.
Include confidence scores for any claims.
Cite specific evidence (addresses, strings, API calls, etc.).
Suggest 2-3 relevant follow-up questions the user might ask.

If you're uncertain, say so. Never make up information.
"""

        return prompt

    def _parse_response(self, ai_response: str, intent: Intent) -> ChatResponse:
        """
        Parse AI response into structured format

        Extract:
        - Main answer
        - Confidence score
        - Follow-up suggestions
        - Structured data (addresses, IOCs, etc.)
        """
        # TODO: More sophisticated parsing
        # For now, basic extraction

        # Try to extract confidence from response
        confidence = self._extract_confidence(ai_response)

        # Extract suggested follow-ups
        followups = self._extract_followups(ai_response)

        # Extract structured data (addresses, hashes, etc.)
        structured_data = self._extract_structured_data(ai_response, intent)

        return ChatResponse(
            answer=ai_response,
            confidence=confidence,
            intent=intent,
            suggested_followups=followups,
            structured_data=structured_data,
            sources=self._extract_sources(ai_response)
        )

    def set_expertise_level(self, level: ExpertiseLevel):
        """Adjust response complexity for user's expertise"""
        self.context.expertise_level = level

    def focus_on_function(self, function_address: str):
        """Set analysis focus to specific function"""
        self.context.active_function = function_address

    def export_conversation(self, format: str = "markdown") -> str:
        """
        Export conversation as professional report

        Formats: markdown, html, pdf, json
        """
        if format == "markdown":
            return self._export_markdown()
        elif format == "json":
            return self._export_json()
        elif format == "html":
            return self._export_html()
        else:
            raise ValueError(f"Unknown format: {format}")

    def _export_markdown(self) -> str:
        """Export as markdown report"""
        md = f"# Reverse Engineering Analysis Session\n\n"
        md += f"**Binary:** {self.context.binary_path}\n\n"
        md += f"**Date:** {self._get_timestamp()}\n\n"
        md += "## Conversation\n\n"

        for msg in self.context.conversation_history:
            md += f"### {msg.role.upper()}\n{msg.content}\n\n"

        # Add discovered IOCs
        if self.context.discovered_iocs:
            md += "## Indicators of Compromise\n\n"
            for ioc in self.context.discovered_iocs:
                md += f"- `{ioc}`\n"

        return md
```

#### 2. AI Provider Implementations

```python
# src/reveng/chat/providers/__init__.py
from abc import ABC, abstractmethod
from typing import Dict, Any

class AIProvider(ABC):
    """Base class for AI providers"""

    @abstractmethod
    def query(self, prompt: str, context: Any) -> str:
        """Send query to AI and get response"""
        pass

    @abstractmethod
    def quick_query(self, prompt: str) -> str:
        """Fast query without full context (for intent classification)"""
        pass

# src/reveng/chat/providers/claude_provider.py
from anthropic import Anthropic
import os

class ClaudeProvider(AIProvider):
    """
    Claude API provider

    Strengths:
    - 200K context window (can fit entire binary analysis)
    - Excellent reasoning and code understanding
    - Good at explaining complex topics
    """

    def __init__(self):
        api_key = os.getenv("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("ANTHROPIC_API_KEY not set")

        self.client = Anthropic(api_key=api_key)
        self.model = "claude-3-5-sonnet-20241022"

    def query(self, prompt: str, context: Any) -> str:
        """Full context query"""
        response = self.client.messages.create(
            model=self.model,
            max_tokens=4096,
            temperature=0.1,  # Lower for more consistent analysis
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )

        return response.content[0].text

    def quick_query(self, prompt: str) -> str:
        """Fast query for intent classification"""
        response = self.client.messages.create(
            model="claude-3-haiku-20240307",  # Faster, cheaper model
            max_tokens=100,
            temperature=0.0,
            messages=[{
                "role": "user",
                "content": prompt
            }]
        )

        return response.content[0].text

# src/reveng/chat/providers/ollama_provider.py
import ollama

class OllamaProvider(AIProvider):
    """
    Ollama local LLM provider

    Strengths:
    - Privacy-preserving (runs locally)
    - Free (no API costs)
    - Fast for local analysis

    Models:
    - qwen2.5-coder:32b (best for code)
    - deepseek-coder-v2 (alternative)
    - llama3.1:70b (general purpose)
    """

    def __init__(self, model: str = "qwen2.5-coder:32b"):
        self.model = model
        self.client = ollama.Client()

    def query(self, prompt: str, context: Any) -> str:
        """Full context query"""
        response = self.client.chat(
            model=self.model,
            messages=[{
                "role": "user",
                "content": prompt
            }],
            options={
                "temperature": 0.1,
                "num_ctx": 32768  # Use full context window
            }
        )

        return response['message']['content']

    def quick_query(self, prompt: str) -> str:
        """Fast query"""
        response = self.client.chat(
            model="llama3.1:8b",  # Smaller, faster model
            messages=[{
                "role": "user",
                "content": prompt
            }],
            options={
                "temperature": 0.0,
                "num_ctx": 2048
            }
        )

        return response['message']['content']
```

#### 3. CLI Integration

```python
# src/reveng/cli/chat.py
import click
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from reveng.chat.conversation_manager import ConversationManager, ExpertiseLevel

console = Console()

@click.command()
@click.argument('binary_path', type=click.Path(exists=True))
@click.option('--provider', default='claude', type=click.Choice(['claude', 'gpt4', 'ollama']))
@click.option('--expertise', default='intermediate', type=click.Choice(['beginner', 'intermediate', 'expert']))
def chat(binary_path: str, provider: str, expertise: str):
    """
    Start interactive chat session with binary

    Example:
        reveng chat malware.exe
        reveng chat --provider ollama suspicious.dll
    """
    console.print(Panel.fit(
        "[bold blue]REVENG ChatRE[/bold blue]\n"
        f"Binary: {binary_path}\n"
        f"AI Provider: {provider}\n"
        f"Expertise Level: {expertise}",
        title="Welcome"
    ))

    # Initialize conversation
    manager = ConversationManager(binary_path, ai_provider=provider)
    manager.set_expertise_level(ExpertiseLevel(expertise))

    console.print("\n[green]Running initial analysis...[/green]")

    # Initial greeting
    greeting_response = manager.chat("Hello! What can you tell me about this binary?")
    console.print(Markdown(greeting_response.answer))

    # Interactive loop
    console.print("\n[yellow]Type your questions (or 'quit' to exit)[/yellow]\n")

    while True:
        try:
            # Get user input
            user_input = console.input("[bold cyan]You:[/bold cyan] ")

            if user_input.lower() in ['quit', 'exit', 'q']:
                console.print("[green]Exporting conversation...[/green]")
                report = manager.export_conversation("markdown")
                with open(f"{binary_path}.chat.md", "w") as f:
                    f.write(report)
                console.print(f"[green]Saved to {binary_path}.chat.md[/green]")
                break

            if not user_input.strip():
                continue

            # Get AI response
            console.print("[dim]Thinking...[/dim]")
            response = manager.chat(user_input)

            # Display response
            console.print(f"\n[bold magenta]REVENG:[/bold magenta]")
            console.print(Markdown(response.answer))

            # Show suggested follow-ups
            if response.suggested_followups:
                console.print("\n[dim]Suggested follow-ups:[/dim]")
                for i, followup in enumerate(response.suggested_followups, 1):
                    console.print(f"  {i}. {followup}")

            console.print()  # Blank line

        except KeyboardInterrupt:
            console.print("\n[yellow]Interrupted. Type 'quit' to exit properly.[/yellow]")
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")

if __name__ == "__main__":
    chat()
```

#### 4. Usage Example

```bash
# Start chat session
$ reveng chat malware.exe

╭─────────────────────────────────╮
│      REVENG ChatRE             │
│ Binary: malware.exe            │
│ AI Provider: claude             │
│ Expertise Level: intermediate   │
╰─────────────────────────────────╯

Running initial analysis...

**REVENG:** Based on my initial analysis, this appears to be a
ransomware binary with the following characteristics:

1. **File Encryption Capabilities** (Confidence: 98%)
   - Uses ChaCha20 algorithm (detected at 0x401234)
   - Targets document, image, and database files
   - Evidence: CryptGenRandom calls, recursive directory enumeration

2. **Network Communication** (Confidence: 95%)
   - Connects to C2 server: hxxp://evil[.]com:8443
   - Uses custom protocol over TLS
   - Evidence: WinHTTP API usage, hardcoded domain string

3. **Persistence Mechanism** (Confidence: 92%)
   - Creates registry run key
   - Copies itself to %APPDATA%
   - Evidence: RegCreateKeyEx function calls

Would you like me to analyze any specific aspect in detail?

Type your questions (or 'quit' to exit)

You: Show me the encryption function in detail

Thinking...

**REVENG:** The encryption function is located at address **0x401234**.
Here's a detailed analysis:

... [detailed explanation] ...

You: Can you generate a YARA rule to detect this?

Thinking...

**REVENG:** Based on the analysis, here's a YARA rule to detect
this ransomware family:

```yara
rule Ransomware_Sample_ChaCha20 {
    meta:
        description = "Detects ransomware using ChaCha20 encryption"
        confidence = "high"
        generated_by = "REVENG AI"

    strings:
        $api1 = "CryptGenRandom" ascii
        $api2 = "CryptAcquireContext" ascii
        $c2 = "evil.com:8443" ascii
        $crypto_const = { 61 70 78 65 }  # ChaCha20 constant "apxe"

    condition:
        uint16(0) == 0x5A4D and  // MZ header
        all of ($api*) and
        $c2 and
        $crypto_const
}
```

This rule has a **92% confidence** of detecting similar samples.

Suggested follow-ups:
  1. How can I decrypt files encrypted by this ransomware?
  2. Are there any known decryption tools?
  3. What other IOCs should I look for?

You: quit

Exporting conversation...
Saved to malware.exe.chat.md
```

---

This is just the beginning! I'll create more technical specifications if you'd like for:
- **Automated Patching** (Killer Feature #2)
- **Cross-Binary Intelligence** (Killer Feature #3)
- **Real-Time Collaboration** (Killer Feature #4)
- **Web Interface Architecture**
- **Scalability & Infrastructure**

Would you like me to continue with the other killer features?
