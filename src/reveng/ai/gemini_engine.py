"""
Gemini AI Engine - Advanced Reasoning and Code Analysis

This module provides Google Gemini integration for:
- Advanced code reconstruction
- Security vulnerability analysis
- Natural language code understanding
- Automated exploit generation

Author: REVENG Team
Version: 3.0.0
"""

import asyncio
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class GeminiEngine:
    """
    Google Gemini integration for advanced AI-powered analysis.

    This class provides high-level methods for:
    - Code reconstruction from decompiled output
    - Security vulnerability detection
    - Exploit generation
    - Natural language queries
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-pro",
        temperature: float = 0.7,
        max_retries: int = 3,
    ):
        """
        Initialize Gemini Engine.

        Args:
            api_key: Google AI API key (or from GEMINI_API_KEY env var)
            model: Model to use (gemini-pro, gemini-pro-vision)
            temperature: Sampling temperature (0.0-1.0)
            max_retries: Maximum number of retries for API calls
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries

        # Try to import google-generativeai
        try:
            import google.generativeai as genai

            self.genai = genai
            if self.api_key:
                genai.configure(api_key=self.api_key)
                self.client = genai.GenerativeModel(model)
                logger.info(f"✅ Gemini Engine initialized with model: {model}")
            else:
                self.client = None
                logger.warning(
                    "⚠️ Gemini API key not found. Set GEMINI_API_KEY environment variable."
                )
        except ImportError:
            self.genai = None
            self.client = None
            logger.warning(
                "⚠️ google-generativeai not installed. Install with: pip install google-generativeai"
            )

    def is_available(self) -> bool:
        """Check if Gemini is available."""
        return self.client is not None

    async def reconstruct_function(
        self,
        decompiled_code: str,
        function_name: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Reconstruct a function from decompiled code.

        Args:
            decompiled_code: Decompiled C code from Ghidra
            function_name: Name of the function
            context: Additional context (imports, strings, etc.)

        Returns:
            dict: Reconstructed code with metadata:
                - source_code: Cleaned, readable source code
                - language: Detected or target language
                - confidence: Confidence score (0.0-1.0)
                - variables: List of identified variables
                - calls: External function calls
        """
        if not self.is_available():
            logger.error("Gemini not available")
            return {
                "source_code": decompiled_code,
                "language": "c",
                "confidence": 0.0,
                "error": "Gemini not available",
            }

        prompt = self._create_reconstruction_prompt(
            decompiled_code, function_name, context
        )

        try:
            response = await self._generate_async(prompt)
            return self._parse_reconstruction_response(response, decompiled_code)
        except Exception as e:
            logger.error(f"Gemini reconstruction failed: {e}")
            return {
                "source_code": decompiled_code,
                "language": "c",
                "confidence": 0.0,
                "error": str(e),
            }

    async def analyze_security(
        self, source_code: str, binary_metadata: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Analyze source code for security vulnerabilities.

        Args:
            source_code: Source code to analyze
            binary_metadata: Additional binary metadata

        Returns:
            list: List of detected vulnerabilities:
                - type: Vulnerability type (buffer_overflow, use_after_free, etc.)
                - severity: Severity level (critical, high, medium, low)
                - location: Code location
                - description: Human-readable description
                - cwe: CWE identifier
                - exploit_available: Boolean
        """
        if not self.is_available():
            logger.error("Gemini not available")
            return []

        prompt = self._create_security_prompt(source_code, binary_metadata)

        try:
            response = await self._generate_async(prompt)
            return self._parse_security_response(response)
        except Exception as e:
            logger.error(f"Gemini security analysis failed: {e}")
            return []

    async def generate_exploit(
        self, vulnerability: Dict[str, Any], source_code: str
    ) -> Optional[Dict[str, Any]]:
        """
        Generate proof-of-concept exploit for a vulnerability.

        Args:
            vulnerability: Vulnerability details from analyze_security()
            source_code: Vulnerable source code

        Returns:
            dict or None: Exploit details:
                - exploit_code: Working exploit code
                - language: Exploit language (python, c, etc.)
                - description: How the exploit works
                - mitigation: How to fix the vulnerability
        """
        if not self.is_available():
            logger.error("Gemini not available")
            return None

        prompt = self._create_exploit_prompt(vulnerability, source_code)

        try:
            response = await self._generate_async(prompt)
            return self._parse_exploit_response(response)
        except Exception as e:
            logger.error(f"Gemini exploit generation failed: {e}")
            return None

    async def ask_question(
        self, question: str, context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Answer natural language questions about binary analysis.

        Args:
            question: User's question
            context: Analysis context (functions, strings, etc.)

        Returns:
            dict: Answer with metadata:
                - answer: Natural language answer
                - confidence: Confidence score
                - citations: Referenced code locations
        """
        if not self.is_available():
            logger.error("Gemini not available")
            return {
                "answer": "Gemini not available",
                "confidence": 0.0,
                "error": "Gemini not configured",
            }

        prompt = self._create_question_prompt(question, context)

        try:
            response = await self._generate_async(prompt)
            return self._parse_question_response(response)
        except Exception as e:
            logger.error(f"Gemini question answering failed: {e}")
            return {
                "answer": f"Error: {str(e)}",
                "confidence": 0.0,
                "error": str(e),
            }

    async def _generate_async(self, prompt: str) -> str:
        """
        Generate response from Gemini (async).

        Args:
            prompt: Input prompt

        Returns:
            str: Generated text
        """
        # Run in thread pool since genai is synchronous
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None, lambda: self.client.generate_content(prompt)
        )
        return response.text

    def _create_reconstruction_prompt(
        self,
        decompiled_code: str,
        function_name: str,
        context: Optional[Dict[str, Any]],
    ) -> str:
        """Create prompt for code reconstruction."""
        context_str = ""
        if context:
            if "imports" in context:
                context_str += (
                    f"\n\nImported functions:\n{', '.join(context['imports'][:20])}"
                )
            if "strings" in context:
                context_str += (
                    f"\n\nString constants:\n{', '.join(context['strings'][:20])}"
                )

        return f"""You are an expert reverse engineer. Reconstruct the following decompiled function into clean, readable source code.

Function: {function_name}

Decompiled code (from Ghidra):
```c
{decompiled_code}
```
{context_str}

Tasks:
1. Clean up variable names (replace var1, var2 with meaningful names)
2. Identify the programming language (C, C++, or suggest Python equivalent)
3. Restore proper function signatures
4. Add comments explaining complex logic
5. Identify potential security vulnerabilities

Output format (JSON):
{{
  "source_code": "reconstructed code here",
  "language": "c|cpp|python",
  "confidence": 0.95,
  "variables": [{{"original": "var1", "suggested": "buffer_size"}}],
  "calls": ["strcpy", "malloc"],
  "security_notes": ["potential buffer overflow at line 5"]
}}
"""

    def _create_security_prompt(
        self, source_code: str, binary_metadata: Optional[Dict[str, Any]]
    ) -> str:
        """Create prompt for security analysis."""
        metadata_str = ""
        if binary_metadata:
            metadata_str = f"\n\nBinary metadata:\n{binary_metadata}"

        return f"""You are a security researcher. Analyze this code for vulnerabilities.

Source code:
```c
{source_code}
```
{metadata_str}

Find ALL security vulnerabilities including:
- Buffer overflows (strcpy, gets, sprintf without bounds)
- Use-after-free
- Double free
- Integer overflows
- Format string vulnerabilities
- Command injection
- SQL injection
- Path traversal
- Race conditions (TOCTOU)
- Unsafe deserialization

Output format (JSON array):
[
  {{
    "type": "buffer_overflow",
    "severity": "critical",
    "location": "line 23: strcpy(buffer, user_input)",
    "description": "strcpy used without bounds checking",
    "cwe": "CWE-120",
    "exploit_available": true,
    "cvss_score": 9.8
  }}
]
"""

    def _create_exploit_prompt(
        self, vulnerability: Dict[str, Any], source_code: str
    ) -> str:
        """Create prompt for exploit generation."""
        return f"""You are a security researcher creating a proof-of-concept exploit for educational purposes.

Vulnerability:
Type: {vulnerability.get('type')}
Severity: {vulnerability.get('severity')}
Location: {vulnerability.get('location')}
Description: {vulnerability.get('description')}

Vulnerable code:
```c
{source_code}
```

Create a working proof-of-concept exploit demonstrating this vulnerability.

Output format (JSON):
{{
  "exploit_code": "#!/usr/bin/env python3\\n# PoC code here",
  "language": "python",
  "description": "This exploit demonstrates...",
  "steps": ["1. Allocate buffer", "2. Overflow buffer", "3. Execute shellcode"],
  "mitigation": "Use strncpy instead of strcpy with proper bounds checking",
  "disclaimer": "FOR EDUCATIONAL PURPOSES ONLY"
}}
"""

    def _create_question_prompt(self, question: str, context: Dict[str, Any]) -> str:
        """Create prompt for question answering."""
        return f"""You are a reverse engineering expert. Answer this question about the binary analysis.

Question: {question}

Analysis context:
- Functions: {len(context.get('functions', []))} found
- Strings: {len(context.get('strings', []))} found
- Imports: {len(context.get('imports', []))} found

Sample functions:
{self._format_functions(context.get('functions', [])[:5])}

Sample strings:
{self._format_strings(context.get('strings', [])[:10])}

Provide a detailed, technical answer with specific code references.

Output format (JSON):
{{
  "answer": "detailed answer here",
  "confidence": 0.95,
  "citations": ["function main at 0x401000", "string 'password' at 0x404000"]
}}
"""

    def _format_functions(self, functions: List[Dict[str, Any]]) -> str:
        """Format functions for prompt."""
        result = []
        for func in functions[:5]:
            result.append(
                f"- {func.get('name', 'unknown')} at {func.get('entry_point', '?')}"
            )
        return "\n".join(result)

    def _format_strings(self, strings: List[str]) -> str:
        """Format strings for prompt."""
        return "\n".join([f"- {s[:50]}" for s in strings[:10]])

    def _parse_reconstruction_response(
        self, response: str, original_code: str
    ) -> Dict[str, Any]:
        """Parse reconstruction response."""
        try:
            # Try to parse JSON response
            import json

            # Extract JSON from markdown code blocks if present
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()

            data = json.loads(response)
            return data
        except Exception as e:
            logger.warning(f"Failed to parse Gemini response as JSON: {e}")
            # Return original code with low confidence
            return {
                "source_code": original_code,
                "language": "c",
                "confidence": 0.0,
                "error": f"Parse error: {str(e)}",
            }

    def _parse_security_response(self, response: str) -> List[Dict[str, Any]]:
        """Parse security analysis response."""
        try:
            import json

            # Extract JSON from markdown code blocks if present
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()

            data = json.loads(response)
            return data if isinstance(data, list) else [data]
        except Exception as e:
            logger.warning(f"Failed to parse security response: {e}")
            return []

    def _parse_exploit_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse exploit generation response."""
        try:
            import json

            # Extract JSON from markdown code blocks if present
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()

            data = json.loads(response)
            return data
        except Exception as e:
            logger.warning(f"Failed to parse exploit response: {e}")
            return None

    def _parse_question_response(self, response: str) -> Dict[str, Any]:
        """Parse question answering response."""
        try:
            import json

            # Extract JSON from markdown code blocks if present
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end].strip()

            data = json.loads(response)
            return data
        except Exception as e:
            logger.warning(f"Failed to parse question response: {e}")
            # Return plain text response
            return {"answer": response, "confidence": 0.5, "citations": []}


# Convenience functions for quick usage
async def reconstruct_code(decompiled_code: str, function_name: str = "unknown") -> str:
    """Quick function to reconstruct code using Gemini."""
    engine = GeminiEngine()
    if not engine.is_available():
        return decompiled_code

    result = await engine.reconstruct_function(decompiled_code, function_name)
    return result.get("source_code", decompiled_code)


async def find_vulnerabilities(source_code: str) -> List[Dict[str, Any]]:
    """Quick function to find vulnerabilities using Gemini."""
    engine = GeminiEngine()
    if not engine.is_available():
        return []

    return await engine.analyze_security(source_code)
