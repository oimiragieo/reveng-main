#!/usr/bin/env python3
"""
REVENG OpenAI Integration
==========================

Integrates OpenAI GPT for AI-powered code analysis with:
- Lazy import (does not fail if openai is not installed)
- Exponential backoff on rate-limit and connection errors
- Same AnalysisResult interface as OllamaAnalyzer (drop-in replacement)
- Structured logging via stdlib logging

Supported models:
  - gpt-4o          (primary)
  - gpt-4o          (fallback)
"""

import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from .ollama_analyzer import AnalysisResult

logger = logging.getLogger(__name__)

_INSTALL_HINT = (
    "The 'openai' package is required for OpenAIAnalyzer. "
    "Install it with: pip install reveng[ai]"
)


def _extract_code_block(text: str) -> str:
    """Extract the first code block from a markdown-fenced response, or return as-is."""
    if "```" not in text:
        return text.strip()
    parts = text.split("```")
    for i in range(1, len(parts), 2):
        content = parts[i]
        newline_pos = content.find("\n")
        if newline_pos != -1:
            content = content[newline_pos + 1 :]
        stripped = content.strip()
        if stripped:
            return stripped
    return text.strip()


def _import_openai():
    """Lazy-import openai and raise a clear error when absent."""
    try:
        import openai  # noqa: PLC0415

        return openai
    except ImportError as exc:
        raise ImportError(_INSTALL_HINT) from exc


class OpenAIAnalyzer:
    """
    OpenAI GPT-powered code analysis.

    Drop-in replacement for OllamaAnalyzer; implements the same
    ``analyze_function`` / ``generate_implementation`` interface.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model_id: str = "gpt-4o",
        max_tokens: int = 8192,
        temperature: float = 0.2,
        timeout_seconds: int = 120,
    ):
        """
        Initialize OpenAIAnalyzer.

        Args:
            api_key: OpenAI API key.  Defaults to ``OPENAI_API_KEY`` env var.
            model_id: Model to use (default: ``gpt-4o``).
            max_tokens: Maximum tokens in the response (default: 8192).
            temperature: Sampling temperature (default: 0.2 for consistent analysis).
            timeout_seconds: HTTP request timeout in seconds (default: 120).
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model_id = model_id
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds

        logger.info(
            "OpenAIAnalyzer ready: model=%s max_tokens=%d temperature=%.2f timeout=%ds",
            self.model_id,
            self.max_tokens,
            self.temperature,
            self.timeout_seconds,
        )

    # ------------------------------------------------------------------
    # Public interface (mirrors OllamaAnalyzer)
    # ------------------------------------------------------------------

    def analyze_function(
        self,
        function_code: str,
        function_name: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> AnalysisResult:
        """
        Analyze a C function using GPT.

        Args:
            function_code: Decompiled C code of the function.
            function_name: Current (mangled) function name.
            context: Optional extras: strings, imports, callers.

        Returns:
            AnalysisResult populated from GPT's response.
        """
        prompt = self._build_analysis_prompt(function_code, function_name, context)

        try:
            response_text = self._call_openai(prompt)
            return self._parse_analysis_response(response_text)
        except Exception as exc:
            logger.error("OpenAI analysis failed for %s: %s", function_name, exc)
            return self._fallback_analysis(function_name, function_code)

    def generate_implementation(self, function_spec: Dict[str, Any], language: str = "c") -> str:
        """
        Generate a function implementation from a specification dict.

        Args:
            function_spec: Dict with ``name``, ``purpose``, ``parameters``, ``return_type``.
            language: Target language (c, python, javascript).

        Returns:
            Generated source code as a string.
        """
        prompt = (
            f"Generate a {language.upper()} implementation for this function.\n\n"
            f"Specification:\n"
            f"- Name: {function_spec.get('name')}\n"
            f"- Purpose: {function_spec.get('purpose')}\n"
            f"- Return type: {function_spec.get('return_type', 'int')}\n"
            f"- Parameters: {function_spec.get('parameters', [])}\n\n"
            "Requirements:\n"
            "- Include error handling\n"
            "- Add comments\n"
            f"- Use modern {language} best practices\n"
            "- Make it cross-platform (no OS-specific code)\n\n"
            "Generate ONLY the function code, no explanations."
        )

        try:
            response_text = self._call_openai(prompt)
            return _extract_code_block(response_text)
        except Exception as exc:
            logger.error("OpenAI code generation failed: %s", exc)
            return self._generate_stub(function_spec, language)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_analysis_prompt(
        self,
        function_code: str,
        function_name: str,
        context: Optional[Dict[str, Any]],
    ) -> str:
        """Compose the analysis prompt."""
        context_info = ""
        if context:
            if context.get("strings"):
                context_info += f"\nString references: {', '.join(context['strings'][:5])}"
            if context.get("imports"):
                context_info += f"\nImported functions: {', '.join(context['imports'][:5])}"
            if context.get("callers"):
                context_info += f"\nCalled by: {', '.join(context['callers'][:3])}"

        return (
            "Analyze this C function from a reverse-engineered binary.\n\n"
            f"Function name: {function_name}"
            f"{context_info}\n\n"
            "Code:\n"
            "```c\n"
            f"{function_code[:1000]}\n"
            "```\n\n"
            "Provide a JSON response with:\n"
            '1. "purpose": One-sentence description of what this function does\n'
            '2. "category": One of [Memory, FileIO, Network, JavaScript, Utility, Error, Crypto, Security, Unknown]\n'
            '3. "complexity": One of [Low, Medium, High, VeryHigh]\n'
            '4. "security_concerns": List of potential security issues (empty if none)\n'
            '5. "suggested_name": Better name following C conventions (or null if current is good)\n'
            '6. "confidence": Float 0.0-1.0 indicating confidence in analysis\n'
            '7. "reasoning": Brief explanation of your analysis\n\n'
            "Respond with ONLY valid JSON, no other text."
        )

    def _call_openai(
        self,
        prompt: str,
        max_retries: int = 3,
        backoff_delays: tuple = (2, 4, 8),
    ) -> str:
        """
        Send a message to the OpenAI Chat Completions API with exponential backoff.

        Retries on:
          - ``openai.RateLimitError``
          - ``openai.APIConnectionError``

        Args:
            prompt: The user-turn text to send.
            max_retries: Maximum number of attempts (default: 3).
            backoff_delays: Sleep durations between attempts (default: 2/4/8 seconds).

        Returns:
            The text content of the first choice message.

        Raises:
            ImportError: When the ``openai`` package is not installed.
            Exception: Re-raised after exhausting all retries.
        """
        openai = _import_openai()

        client = openai.OpenAI(
            api_key=self.api_key,
            timeout=float(self.timeout_seconds),
        )

        last_exc: Optional[Exception] = None

        for attempt in range(max_retries):
            try:
                response = client.chat.completions.create(
                    model=self.model_id,
                    max_tokens=self.max_tokens,
                    temperature=self.temperature,
                    messages=[{"role": "user", "content": prompt}],
                )
                # Extract text from the first choice
                choice = response.choices[0]
                content = choice.message.content
                if content is None:
                    raise ValueError("OpenAI response contained no message content")

                usage = response.usage
                tokens_used = (usage.prompt_tokens + usage.completion_tokens) if usage else 0
                logger.debug(
                    "OpenAI call succeeded on attempt %d/%d " "(tokens_used=%d, model=%s)",
                    attempt + 1,
                    max_retries,
                    tokens_used,
                    self.model_id,
                )
                return content

            except openai.RateLimitError as exc:
                last_exc = exc
                delay = backoff_delays[min(attempt, len(backoff_delays) - 1)]
                logger.warning(
                    "OpenAI rate-limit hit (attempt %d/%d). Sleeping %ds.",
                    attempt + 1,
                    max_retries,
                    delay,
                )
                if attempt < max_retries - 1:
                    time.sleep(delay)

            except openai.APIConnectionError as exc:
                last_exc = exc
                delay = backoff_delays[min(attempt, len(backoff_delays) - 1)]
                logger.warning(
                    "OpenAI connection error (attempt %d/%d): %s. Sleeping %ds.",
                    attempt + 1,
                    max_retries,
                    exc,
                    delay,
                )
                if attempt < max_retries - 1:
                    time.sleep(delay)

            except Exception as exc:
                logger.error("OpenAI API error: %s", exc)
                raise

        raise RuntimeError(f"OpenAI call failed after {max_retries} attempts") from last_exc

    def _parse_analysis_response(self, response: str) -> AnalysisResult:
        """Parse GPT's JSON response into an AnalysisResult."""
        try:
            json_text = response
            if "```json" in response:
                json_text = response.split("```json")[1].split("```")[0]
            elif "```" in response:
                json_text = response.split("```")[1].split("```")[0]

            data = json.loads(json_text.strip())

            return AnalysisResult(
                purpose=data.get("purpose", "Unknown purpose"),
                category=data.get("category", "Unknown"),
                complexity=data.get("complexity", "Medium"),
                security_concerns=data.get("security_concerns", []),
                suggested_name=data.get("suggested_name"),
                confidence=float(data.get("confidence", 0.5)),
                reasoning=data.get("reasoning", "No reasoning provided"),
            )

        except Exception as exc:
            logger.error("Failed to parse OpenAI response: %s", exc)
            logger.debug("Raw response (first 300 chars): %s", response[:300])
            return self._extract_from_text(response)

    def _extract_from_text(self, response: str) -> AnalysisResult:
        """Fallback: extract analysis from free-form text."""
        category = "Unknown"
        response_lower = response.lower()
        if "memory" in response_lower or "alloc" in response_lower:
            category = "Memory"
        elif "file" in response_lower or "i/o" in response_lower:
            category = "FileIO"
        elif "network" in response_lower or "socket" in response_lower:
            category = "Network"
        elif "javascript" in response_lower or " js " in response_lower:
            category = "JavaScript"
        elif "error" in response_lower or "exception" in response_lower:
            category = "Error"

        sentences = response.split(".")
        purpose = sentences[0].strip() if sentences else "Unknown"

        return AnalysisResult(
            purpose=purpose,
            category=category,
            complexity="Medium",
            security_concerns=[],
            suggested_name=None,
            confidence=0.3,
            reasoning="Extracted from free-form text (JSON parse failed)",
        )

    def _fallback_analysis(self, function_name: str, function_code: str) -> AnalysisResult:
        """Minimal heuristic analysis used when the API call fails entirely."""
        code_lower = function_code.lower()
        category = "Unknown"
        if "malloc" in code_lower or "free" in code_lower:
            category = "Memory"
        elif "fopen" in code_lower or "fread" in code_lower:
            category = "FileIO"
        elif "socket" in code_lower or "connect" in code_lower:
            category = "Network"

        return AnalysisResult(
            purpose=f"Function {function_name}",
            category=category,
            complexity="Medium",
            security_concerns=[],
            suggested_name=None,
            confidence=0.2,
            reasoning="Fallback heuristic analysis (OpenAI API unavailable)",
        )

    @staticmethod
    def _generate_stub(function_spec: Dict[str, Any], language: str) -> str:
        """Emit a bare stub when code generation fails."""
        name = function_spec.get("name", "unknown")
        return_type = function_spec.get("return_type", "int")
        if language == "c":
            return f"{return_type} {name}() {{\n    // TODO: Implement {name}\n    return 0;\n}}"
        if language == "python":
            return f"def {name}():\n    # TODO: Implement {name}\n    pass"
        if language == "javascript":
            return f"function {name}() {{\n    // TODO: Implement {name}\n    return null;\n}}"
        return f"// {name} stub"
