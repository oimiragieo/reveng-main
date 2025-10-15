#!/usr/bin/env python3
"""
REVENG Ollama Integration
==========================

Integrates Ollama for local LLM analysis with open-source models:
- Dynamic model selection from available models
- Function purpose analysis
- Code generation
- Security vulnerability detection
- Rename suggestions
- Documentation generation

Supported models: phi, llama3, mistral, codellama, deepseek-coder, etc.
"""

import json
import logging
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import requests
import time

logger = logging.getLogger(__name__)


@dataclass
class OllamaModel:
    """Ollama model information"""
    name: str
    size: str
    modified: str
    parameter_size: str
    quantization: str


@dataclass
class AnalysisResult:
    """LLM analysis result"""
    purpose: str
    category: str
    complexity: str
    security_concerns: List[str]
    suggested_name: Optional[str]
    confidence: float
    reasoning: str


class OllamaAnalyzer:
    """Ollama-powered code analysis"""

    def __init__(
        self,
        model_name: Optional[str] = None,
        ollama_host: str = "http://localhost:11434",
        timeout: int = 60,
        temperature: float = 0.1,
        max_tokens: int = 500
    ):
        """
        Initialize Ollama analyzer

        Args:
            model_name: Model to use (None = auto-select best available)
            ollama_host: Ollama API endpoint
            timeout: Request timeout in seconds (default: 60)
            temperature: LLM temperature for sampling (default: 0.1 for consistent analysis)
            max_tokens: Maximum tokens to generate (default: 500)
        """
        self.ollama_host = ollama_host
        self.timeout = timeout
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.available_models = self._get_available_models()

        if model_name:
            self.model_name = model_name
        else:
            self.model_name = self._select_best_model()

        logger.info(f"Ollama analyzer initialized with model: {self.model_name}")
        logger.info(f"Config: timeout={timeout}s, temperature={temperature}, max_tokens={max_tokens}")
        logger.info(f"Available models: {len(self.available_models)}")

    def _get_available_models(self) -> List[OllamaModel]:
        """Get list of available Ollama models"""
        try:
            # Try API first
            response = requests.get(f"{self.ollama_host}/api/tags", timeout=5)
            if response.status_code == 200:
                data = response.json()
                models = []

                for model_info in data.get('models', []):
                    models.append(OllamaModel(
                        name=model_info['name'],
                        size=model_info.get('size', 'unknown'),
                        modified=model_info.get('modified_at', 'unknown'),
                        parameter_size=model_info.get('details', {}).get('parameter_size', 'unknown'),
                        quantization=model_info.get('details', {}).get('quantization_level', 'unknown')
                    ))

                return models

        except Exception as e:
            logger.warning(f"Failed to get models via API: {e}")

        # Fallback: Try CLI
        try:
            result = subprocess.run(
                ['ollama', 'list'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                models = []
                lines = result.stdout.strip().split('\n')[1:]  # Skip header

                for line in lines:
                    parts = line.split()
                    if len(parts) >= 3:
                        models.append(OllamaModel(
                            name=parts[0],
                            size=parts[1] if len(parts) > 1 else 'unknown',
                            modified=parts[2] if len(parts) > 2 else 'unknown',
                            parameter_size='unknown',
                            quantization='unknown'
                        ))

                return models

        except Exception as e:
            logger.error(f"Failed to get models via CLI: {e}")

        return []

    def _select_best_model(self) -> str:
        """Automatically select best available model for code analysis"""
        if not self.available_models:
            logger.warning("No Ollama models found - install with: ollama pull phi")
            return "phi"  # Default fallback

        # Preference order for code analysis
        preferred_models = [
            'deepseek-coder',
            'codellama',
            'phi3',
            'phi',
            'llama3.1',
            'llama3',
            'mistral',
            'qwen2.5-coder'
        ]

        # Find first matching model
        for preferred in preferred_models:
            for model in self.available_models:
                if preferred in model.name.lower():
                    logger.info(f"Auto-selected model: {model.name}")
                    return model.name

        # Use first available model
        first_model = self.available_models[0].name
        logger.info(f"Using first available model: {first_model}")
        return first_model

    def list_models(self) -> List[Dict[str, str]]:
        """
        Get formatted list of available models

        Returns:
            List of dicts with model info
        """
        return [
            {
                'name': model.name,
                'size': model.size,
                'modified': model.modified,
                'parameters': model.parameter_size,
                'quantization': model.quantization
            }
            for model in self.available_models
        ]

    def analyze_function(
        self,
        function_code: str,
        function_name: str,
        context: Optional[Dict] = None
    ) -> AnalysisResult:
        """
        Analyze a function using Ollama

        Args:
            function_code: C code of the function
            function_name: Current function name
            context: Additional context (imports, xrefs, etc.)

        Returns:
            AnalysisResult with LLM analysis
        """
        prompt = self._build_analysis_prompt(function_code, function_name, context)

        try:
            response = self._call_ollama(prompt)
            result = self._parse_analysis_response(response)
            return result

        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return self._fallback_analysis(function_name, function_code)

    def _build_analysis_prompt(
        self,
        function_code: str,
        function_name: str,
        context: Optional[Dict]
    ) -> str:
        """Build analysis prompt for LLM"""

        context_info = ""
        if context:
            if context.get('strings'):
                context_info += f"\nString references: {', '.join(context['strings'][:5])}"
            if context.get('imports'):
                context_info += f"\nImported functions: {', '.join(context['imports'][:5])}"
            if context.get('callers'):
                context_info += f"\nCalled by: {', '.join(context['callers'][:3])}"

        prompt = f"""Analyze this C function from a reverse-engineered binary.

Function name: {function_name}
{context_info}

Code:
```c
{function_code[:1000]}
```

Provide a JSON response with:
1. "purpose": One-sentence description of what this function does
2. "category": One of [Memory, FileIO, Network, JavaScript, Utility, Error, Crypto, Security, Unknown]
3. "complexity": One of [Low, Medium, High, VeryHigh]
4. "security_concerns": List of potential security issues (empty if none)
5. "suggested_name": Better name following C conventions (or null if current is good)
6. "confidence": Float 0.0-1.0 indicating confidence in analysis
7. "reasoning": Brief explanation of your analysis

Respond with ONLY valid JSON, no other text."""

        return prompt

    def _call_ollama(self, prompt: str, max_retries: int = 3) -> str:
        """
        Call Ollama API with retry logic

        Args:
            prompt: Prompt to send
            max_retries: Maximum retry attempts

        Returns:
            Model response text
        """
        for attempt in range(max_retries):
            try:
                response = requests.post(
                    f"{self.ollama_host}/api/generate",
                    json={
                        "model": self.model_name,
                        "prompt": prompt,
                        "stream": False,
                        "options": {
                            "temperature": self.temperature,
                            "top_p": 0.9,
                            "num_predict": self.max_tokens
                        }
                    },
                    timeout=self.timeout
                )

                if response.status_code == 200:
                    data = response.json()
                    return data.get('response', '')
                else:
                    logger.warning(f"Ollama returned status {response.status_code}")

            except requests.exceptions.Timeout:
                logger.warning(f"Timeout on attempt {attempt + 1}/{max_retries}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)  # Exponential backoff

            except Exception as e:
                logger.error(f"Ollama call failed: {e}")
                if attempt < max_retries - 1:
                    time.sleep(1)

        raise Exception("Failed to call Ollama after retries")

    def _parse_analysis_response(self, response: str) -> AnalysisResult:
        """Parse LLM response into AnalysisResult"""
        try:
            # Extract JSON from response (might have extra text)
            json_match = response
            if '```json' in response:
                json_match = response.split('```json')[1].split('```')[0]
            elif '```' in response:
                json_match = response.split('```')[1].split('```')[0]

            # Clean up common issues
            json_match = json_match.strip()

            data = json.loads(json_match)

            return AnalysisResult(
                purpose=data.get('purpose', 'Unknown purpose'),
                category=data.get('category', 'Unknown'),
                complexity=data.get('complexity', 'Medium'),
                security_concerns=data.get('security_concerns', []),
                suggested_name=data.get('suggested_name'),
                confidence=float(data.get('confidence', 0.5)),
                reasoning=data.get('reasoning', 'No reasoning provided')
            )

        except Exception as e:
            logger.error(f"Failed to parse response: {e}")
            logger.debug(f"Response was: {response[:200]}")

            # Try to extract information from free-form text
            return self._extract_from_text(response)

    def _extract_from_text(self, response: str) -> AnalysisResult:
        """Extract analysis from free-form text response"""
        # Simple keyword extraction
        purpose = "Unknown"
        category = "Unknown"
        complexity = "Medium"

        response_lower = response.lower()

        # Detect category
        if 'memory' in response_lower or 'alloc' in response_lower:
            category = "Memory"
        elif 'file' in response_lower or 'i/o' in response_lower:
            category = "FileIO"
        elif 'network' in response_lower or 'socket' in response_lower:
            category = "Network"
        elif 'javascript' in response_lower or 'js' in response_lower:
            category = "JavaScript"
        elif 'error' in response_lower or 'exception' in response_lower:
            category = "Error"

        # Extract first sentence as purpose
        sentences = response.split('.')
        if sentences:
            purpose = sentences[0].strip()

        return AnalysisResult(
            purpose=purpose,
            category=category,
            complexity=complexity,
            security_concerns=[],
            suggested_name=None,
            confidence=0.3,
            reasoning="Extracted from free-form text"
        )

    def _fallback_analysis(
        self,
        function_name: str,
        function_code: str
    ) -> AnalysisResult:
        """Fallback analysis when Ollama unavailable"""
        # Simple heuristic analysis
        code_lower = function_code.lower()

        category = "Unknown"
        if 'malloc' in code_lower or 'free' in code_lower:
            category = "Memory"
        elif 'fopen' in code_lower or 'fread' in code_lower:
            category = "FileIO"
        elif 'socket' in code_lower or 'connect' in code_lower:
            category = "Network"

        return AnalysisResult(
            purpose=f"Function {function_name}",
            category=category,
            complexity="Medium",
            security_concerns=[],
            suggested_name=None,
            confidence=0.2,
            reasoning="Fallback heuristic analysis (Ollama unavailable)"
        )

    def generate_implementation(
        self,
        function_spec: Dict[str, Any],
        language: str = "c"
    ) -> str:
        """
        Generate function implementation from specification

        Args:
            function_spec: Dict with name, purpose, parameters, return_type
            language: Target language (c, cpp, python, javascript)

        Returns:
            Generated code
        """
        prompt = f"""Generate a {language.upper()} implementation for this function.

Specification:
- Name: {function_spec.get('name')}
- Purpose: {function_spec.get('purpose')}
- Return type: {function_spec.get('return_type', 'int')}
- Parameters: {function_spec.get('parameters', [])}

Requirements:
- Include error handling
- Add comments
- Use modern {language} best practices
- Make it cross-platform (no OS-specific code)

Generate ONLY the function code, no explanations."""

        try:
            response = self._call_ollama(prompt)

            # Extract code block
            if '```' in response:
                code_blocks = response.split('```')
                for i, block in enumerate(code_blocks):
                    if language in block or (i > 0 and i % 2 == 1):
                        code = code_blocks[i + 1] if language in block else block
                        return code.strip()

            return response.strip()

        except Exception as e:
            logger.error(f"Code generation failed: {e}")
            return self._generate_stub(function_spec, language)

    def _generate_stub(self, function_spec: Dict, language: str) -> str:
        """Generate basic stub when LLM unavailable"""
        name = function_spec.get('name', 'unknown')
        return_type = function_spec.get('return_type', 'int')

        if language == 'c':
            return f"""{return_type} {name}() {{
    // TODO: Implement {name}
    return 0;
}}"""
        elif language == 'python':
            return f"""def {name}():
    # TODO: Implement {name}
    pass"""
        elif language == 'javascript':
            return f"""function {name}() {{
    // TODO: Implement {name}
    return null;
}}"""

        return f"// {name} stub"

    def analyze_security(self, function_code: str) -> List[str]:
        """
        Analyze function for security vulnerabilities

        Returns:
            List of security concerns
        """
        prompt = f"""Analyze this C code for security vulnerabilities:

```c
{function_code[:1000]}
```

Identify specific vulnerabilities such as:
- Buffer overflows
- Integer overflows/underflows
- Use-after-free
- NULL pointer dereferences
- Format string vulnerabilities
- Race conditions
- Injection vulnerabilities

Respond with a JSON array of vulnerability descriptions. If no vulnerabilities, return empty array [].
Example: ["Buffer overflow in strcpy at line 5", "Integer overflow in size calculation"]"""

        try:
            response = self._call_ollama(prompt)

            # Extract JSON array
            if '[' in response and ']' in response:
                start = response.index('[')
                end = response.rindex(']') + 1
                json_str = response[start:end]
                return json.loads(json_str)

            return []

        except Exception as e:
            logger.error(f"Security analysis failed: {e}")
            return []

    def batch_analyze(
        self,
        functions: List[Dict[str, str]],
        progress_callback: Optional[callable] = None
    ) -> List[AnalysisResult]:
        """
        Analyze multiple functions in batch

        Args:
            functions: List of dicts with 'name' and 'code'
            progress_callback: Optional callback(current, total)

        Returns:
            List of AnalysisResults
        """
        results = []
        total = len(functions)

        for i, func in enumerate(functions):
            if progress_callback:
                progress_callback(i + 1, total)

            result = self.analyze_function(
                func['code'],
                func['name'],
                func.get('context')
            )
            results.append(result)

        return results


# CLI interface
if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    analyzer = OllamaAnalyzer()

    print("=" * 70)
    print("REVENG OLLAMA ANALYZER")
    print("=" * 70)
    print()

    # List available models
    print("Available Models:")
    print("-" * 70)
    models = analyzer.list_models()

    if models:
        for i, model in enumerate(models, 1):
            print(f"{i}. {model['name']}")
            print(f"   Size: {model['size']}, Parameters: {model['parameters']}")
        print()
        print(f"Selected model: {analyzer.model_name}")
    else:
        print("No models found!")
        print("Install a model with: ollama pull phi")
        print("Or: ollama pull codellama")
        sys.exit(1)

    print()

    # Test analysis
    if len(sys.argv) >= 2:
        test_file = Path(sys.argv[1])

        if test_file.exists():
            print(f"Analyzing: {test_file}")
            print("-" * 70)

            with open(test_file, 'r', encoding='utf-8') as f:
                code = f.read()

            result = analyzer.analyze_function(code, test_file.stem)

            print(f"Purpose: {result.purpose}")
            print(f"Category: {result.category}")
            print(f"Complexity: {result.complexity}")
            print(f"Confidence: {result.confidence:.2f}")

            if result.suggested_name:
                print(f"Suggested name: {result.suggested_name}")

            if result.security_concerns:
                print(f"Security concerns: {len(result.security_concerns)}")
                for concern in result.security_concerns:
                    print(f"  - {concern}")

            print(f"\nReasoning: {result.reasoning}")

    else:
        print("Usage:")
        print("  python ollama_analyzer.py <file.c>")
        print()
        print("Example:")
        print("  python ollama_analyzer.py deobfuscated_app/memory/memory_alloc.c")

    print("=" * 70)
