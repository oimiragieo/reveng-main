"""
LLM-Powered Deobfuscation Engine

Uses GPT-4, Claude, or other LLMs to understand and deobfuscate malware:
- Control flow unflattening
- String deobfuscation
- Dead code removal
- Variable renaming
- Comment generation
- Malware behavior explanation

Handles advanced obfuscation:
- Control flow flattening (switch-based dispatchers)
- Opaque predicates
- Junk code injection
- String encryption
- API hashing
"""

import logging
import os
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """LLM providers"""

    OPENAI_GPT4 = "openai_gpt4"
    ANTHROPIC_CLAUDE = "anthropic_claude"
    LOCAL_MODEL = "local_model"


class ObfuscationTechnique(Enum):
    """Detected obfuscation techniques"""

    CONTROL_FLOW_FLATTENING = "control_flow_flattening"
    OPAQUE_PREDICATES = "opaque_predicates"
    JUNK_CODE = "junk_code"
    STRING_ENCRYPTION = "string_encryption"
    API_HASHING = "api_hashing"
    DEAD_CODE = "dead_code"
    VIRTUALIZATION = "virtualization"


@dataclass
class DeobfuscationResult:
    """Result from deobfuscation"""

    success: bool
    original_code: str
    deobfuscated_code: str
    techniques_detected: List[ObfuscationTechnique]
    explanation: str
    confidence: float
    error: Optional[str] = None


class LLMDeobfuscator:
    """
    LLM-powered deobfuscation engine

    Uses large language models to:
    1. Identify obfuscation techniques
    2. Generate deobfuscated code
    3. Explain malware behavior
    4. Rename variables meaningfully
    """

    def __init__(
        self,
        provider: LLMProvider = LLMProvider.OPENAI_GPT4,
        api_key: Optional[str] = None,
    ):
        self.provider = provider
        self.api_key = (
            api_key or os.getenv("OPENAI_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
        )

    async def deobfuscate_function(
        self, code: str, language: str = "c", context: Optional[str] = None
    ) -> DeobfuscationResult:
        """
        Deobfuscate a function using LLM

        Args:
            code: Obfuscated code
            language: Programming language
            context: Additional context about the malware

        Returns:
            DeobfuscationResult with cleaned code
        """
        logger.info("Deobfuscating code with LLM...")

        # Detect obfuscation techniques
        techniques = self._detect_obfuscation(code)

        logger.info(f"Detected techniques: {[t.value for t in techniques]}")

        # Build prompt for LLM
        prompt = self._build_deobfuscation_prompt(code, language, techniques, context)

        # Query LLM
        try:
            if self.provider == LLMProvider.OPENAI_GPT4:
                response = await self._query_openai(prompt)
            elif self.provider == LLMProvider.ANTHROPIC_CLAUDE:
                response = await self._query_anthropic(prompt)
            else:
                response = await self._query_local_model(prompt)

            # Parse response
            deobfuscated = self._parse_llm_response(response)

            # Calculate confidence based on response
            confidence = self._estimate_confidence(code, deobfuscated, response)

            return DeobfuscationResult(
                success=True,
                original_code=code,
                deobfuscated_code=deobfuscated["code"],
                techniques_detected=techniques,
                explanation=deobfuscated["explanation"],
                confidence=confidence,
            )

        except Exception as e:
            logger.error(f"Deobfuscation failed: {e}")
            return DeobfuscationResult(
                success=False,
                original_code=code,
                deobfuscated_code="",
                techniques_detected=techniques,
                explanation="",
                confidence=0.0,
                error=str(e),
            )

    def _detect_obfuscation(self, code: str) -> List[ObfuscationTechnique]:
        """Detect obfuscation techniques in code"""
        techniques = []

        # Control flow flattening: switch statement with state variable
        if "switch" in code and "state" in code.lower():
            techniques.append(ObfuscationTechnique.CONTROL_FLOW_FLATTENING)

        # Opaque predicates: always true/false conditions
        if any(pattern in code for pattern in ["== 0", "!= 0", "& 1"]):
            techniques.append(ObfuscationTechnique.OPAQUE_PREDICATES)

        # String encryption: XOR patterns, decryption loops
        if "xor" in code.lower() or "^" in code:
            techniques.append(ObfuscationTechnique.STRING_ENCRYPTION)

        # API hashing: hash computations with API calls
        if "hash" in code.lower() or ("GetProcAddress" in code and "0x" in code):
            techniques.append(ObfuscationTechnique.API_HASHING)

        # Dead code: unreachable code, always-false conditions
        if "if (0)" in code or "if (false)" in code:
            techniques.append(ObfuscationTechnique.DEAD_CODE)

        # Junk code: many nop-equivalent instructions
        lines = code.split("\n")
        junk_indicators = sum(
            1
            for line in lines
            if any(
                pattern in line
                for pattern in ["nop", "mov eax, eax", "xor eax, eax; xor eax, eax"]
            )
        )
        if junk_indicators > len(lines) * 0.2:
            techniques.append(ObfuscationTechnique.JUNK_CODE)

        return techniques

    def _build_deobfuscation_prompt(
        self,
        code: str,
        language: str,
        techniques: List[ObfuscationTechnique],
        context: Optional[str],
    ) -> str:
        """Build prompt for LLM deobfuscation"""
        prompt = f"""You are a malware analysis expert. Deobfuscate the following {language} code.

Detected obfuscation techniques:
{chr(10).join(f"- {t.value}" for t in techniques)}

"""

        if context:
            prompt += f"Context: {context}\n\n"

        prompt += f"""Original code:
```{language}
{code}
```

Please provide:
1. Deobfuscated code with meaningful variable names
2. Explanation of what the code does
3. Identification of any malicious behavior

Format your response as JSON:
{{
  "code": "deobfuscated code here",
  "explanation": "explanation here",
  "malicious_behaviors": ["behavior1", "behavior2"]
}}
"""

        return prompt

    async def _query_openai(self, prompt: str) -> str:
        """Query OpenAI GPT-4"""
        try:
            import openai

            if not self.api_key:
                raise ValueError("OpenAI API key not provided")

            openai.api_key = self.api_key

            response = await openai.ChatCompletion.acreate(
                model="gpt-4-turbo-preview",
                messages=[
                    {
                        "role": "system",
                        "content": "You are a malware analysis and reverse engineering expert.",
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.1,  # Low temperature for consistent output
                max_tokens=4000,
            )

            return response.choices[0].message.content

        except ImportError:
            logger.error("openai package not installed")
            raise

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise

    async def _query_anthropic(self, prompt: str) -> str:
        """Query Anthropic Claude"""
        try:
            import anthropic

            if not self.api_key:
                raise ValueError("Anthropic API key not provided")

            client = anthropic.Anthropic(api_key=self.api_key)

            message = client.messages.create(
                model="claude-3-opus-20240229",
                max_tokens=4000,
                temperature=0.1,
                messages=[{"role": "user", "content": prompt}],
            )

            return message.content[0].text

        except ImportError:
            logger.error("anthropic package not installed")
            raise

        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise

    async def _query_local_model(self, prompt: str) -> str:
        """Query local model (e.g., LLaMA)"""
        logger.warning("Local model not implemented, using placeholder")

        # Placeholder response
        return json.dumps(
            {
                "code": "// Deobfuscated code would be here",
                "explanation": "Local model deobfuscation not implemented",
                "malicious_behaviors": [],
            }
        )

    def _parse_llm_response(self, response: str) -> Dict:
        """Parse LLM response"""
        try:
            # Try to parse as JSON
            # LLM might wrap in markdown code blocks
            if "```json" in response:
                # Extract JSON from markdown
                start = response.find("```json") + 7
                end = response.find("```", start)
                json_str = response[start:end].strip()
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                json_str = response[start:end].strip()
            else:
                json_str = response.strip()

            data = json.loads(json_str)

            # Ensure required fields
            if "code" not in data:
                data["code"] = ""
            if "explanation" not in data:
                data["explanation"] = "No explanation provided"

            return data

        except json.JSONDecodeError:
            logger.warning("Could not parse LLM response as JSON")

            # Fallback: treat entire response as explanation
            return {"code": "", "explanation": response, "malicious_behaviors": []}

    def _estimate_confidence(
        self, original: str, deobfuscated: Dict, raw_response: str
    ) -> float:
        """Estimate confidence in deobfuscation"""
        confidence = 0.5

        # Higher confidence if response includes code
        if deobfuscated.get("code"):
            confidence += 0.2

        # Higher confidence if explanation is detailed
        if len(deobfuscated.get("explanation", "")) > 100:
            confidence += 0.1

        # Higher confidence if malicious behaviors identified
        if deobfuscated.get("malicious_behaviors"):
            confidence += 0.1

        # Lower confidence if response seems uncertain
        uncertain_phrases = ["might", "possibly", "not sure", "unclear"]
        if any(phrase in raw_response.lower() for phrase in uncertain_phrases):
            confidence -= 0.2

        return min(1.0, max(0.0, confidence))

    async def unflatten_control_flow(self, code: str) -> str:
        """
        Specifically handle control flow flattening

        Control flow flattening transforms:
        ```
        if (x) { A(); } else { B(); }
        C();
        ```

        Into:
        ```
        state = 0;
        while(1) {
          switch(state) {
            case 0: if (x) state = 1; else state = 2; break;
            case 1: A(); state = 3; break;
            case 2: B(); state = 3; break;
            case 3: C(); return;
          }
        }
        ```
        """
        logger.info("Unflattening control flow...")

        # Build specialized prompt
        prompt = f"""Unflatten the control flow in this code. It uses a switch-based dispatcher to obfuscate the original control flow.

Code:
```c
{code}
```

Convert this back to natural control flow with if/else statements and loops.
"""

        try:
            if self.provider == LLMProvider.OPENAI_GPT4:
                response = await self._query_openai(prompt)
            else:
                response = await self._query_anthropic(prompt)

            # Extract code from response
            if "```" in response:
                start = response.find("```") + 3
                # Skip language identifier
                if response[start : start + 1] == "c":
                    start += 1
                end = response.find("```", start)
                unflattened = response[start:end].strip()
            else:
                unflattened = response.strip()

            logger.info("Control flow unflattened")
            return unflattened

        except Exception as e:
            logger.error(f"Control flow unflattening failed: {e}")
            return code

    async def deobfuscate_strings(
        self, encrypted_strings: List[Tuple[str, bytes]]
    ) -> Dict[str, str]:
        """
        Deobfuscate encrypted strings

        Args:
            encrypted_strings: List of (name, encrypted_data) tuples

        Returns:
            Dict mapping name to decrypted string
        """
        logger.info(f"Deobfuscating {len(encrypted_strings)} strings...")

        decrypted = {}

        for name, data in encrypted_strings:
            # Try common decryption methods
            # XOR with single byte
            for key in range(256):
                try:
                    candidate = bytes([b ^ key for b in data])
                    if candidate.decode("utf-8").isprintable():
                        decrypted[name] = candidate.decode("utf-8")
                        break
                except:
                    continue

            # Try XOR with repeating key
            # (Would add more sophisticated methods)

        logger.info(f"Decrypted {len(decrypted)} strings")
        return decrypted

    def export_report(self, result: DeobfuscationResult, output_path: str) -> None:
        """Export deobfuscation report"""
        report = {
            "success": result.success,
            "techniques_detected": [t.value for t in result.techniques_detected],
            "confidence": result.confidence,
            "explanation": result.explanation,
            "original_code": result.original_code,
            "deobfuscated_code": result.deobfuscated_code,
        }

        if result.error:
            report["error"] = result.error

        with open(output_path, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Deobfuscation report saved to: {output_path}")
