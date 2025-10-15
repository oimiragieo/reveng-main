#!/usr/bin/env python3
"""
REVENG AI-Enhanced Java Analyzer
=================================

Uses LLMs (Ollama/OpenAI/Anthropic) to analyze decompiled Java code and provide:
- Function purpose and behavior analysis
- Security vulnerability detection
- Obfuscation pattern identification
- Original intent inference
- Suggested variable/method names for deobfuscation

Integrates with existing Ollama infrastructure and extends it for Java analysis.
"""

import os
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class JavaAIAnalysisResult:
    """Result from AI analysis of Java code"""
    class_name: str
    function_purpose: str
    security_issues: List[str]
    obfuscation_patterns: List[str]
    original_intent: str
    suggested_names: Dict[str, str]  # old_name -> suggested_name
    confidence: float
    model_used: str


class JavaAIAnalyzer:
    """
    AI-enhanced analyzer for decompiled Java code

    Uses LLMs to understand obfuscated code and suggest improvements
    """

    def __init__(self, ai_provider: str = 'ollama', model: str = 'auto'):
        """
        Initialize AI analyzer

        Args:
            ai_provider: 'ollama', 'openai', or 'anthropic'
            model: Model name or 'auto' for best available
        """
        self.ai_provider = ai_provider
        self.model = model
        self.ai_available = False
        self.ai_client = None

        # Try to initialize AI client
        self._initialize_ai_client()

    def _initialize_ai_client(self):
        """Initialize AI client based on provider"""
        try:
            if self.ai_provider == 'ollama':
                self._init_ollama()
            elif self.ai_provider == 'openai':
                self._init_openai()
            elif self.ai_provider == 'anthropic':
                self._init_anthropic()
            else:
                logger.warning(f"Unknown AI provider: {self.ai_provider}")

        except ImportError as e:
            logger.warning(f"AI client not available: {e}")
            self.ai_available = False
        except Exception as e:
            logger.warning(f"AI initialization failed: {e}")
            self.ai_available = False

    def _init_ollama(self):
        """Initialize Ollama client"""
        try:
            from tools.ollama_analyzer import OllamaAnalyzer
            from tools.config_manager import get_config

            # Get config
            config = get_config()
            ai_config = config.get_ai_config()

            # Check if Ollama is enabled
            if not ai_config.enable_ai or ai_config.provider != 'ollama':
                logger.info("Ollama not enabled in configuration")
                return

            # Create Ollama client
            self.ai_client = OllamaAnalyzer(
                host=ai_config.ollama_host,
                model=ai_config.ollama_model if ai_config.ollama_model != 'auto' else None
            )

            self.ai_available = True
            logger.info(f"Ollama client initialized: {ai_config.ollama_model}")

        except Exception as e:
            logger.warning(f"Ollama initialization failed: {e}")

    def _init_openai(self):
        """Initialize OpenAI client"""
        # Placeholder for OpenAI implementation
        logger.warning("OpenAI support not yet implemented")

    def _init_anthropic(self):
        """Initialize Anthropic client"""
        # Placeholder for Anthropic implementation
        logger.warning("Anthropic support not yet implemented")

    def analyze_java_class(self, class_name: str, java_source: str) -> Optional[JavaAIAnalysisResult]:
        """
        Analyze decompiled Java class with AI

        Args:
            class_name: Name of the class
            java_source: Decompiled Java source code

        Returns:
            JavaAIAnalysisResult or None if AI unavailable
        """
        if not self.ai_available:
            logger.warning("AI not available - returning None")
            return None

        try:
            # Build analysis prompt
            prompt = self._build_analysis_prompt(class_name, java_source)

            # Query AI
            response = self._query_ai(prompt)

            # Parse response
            result = self._parse_ai_response(class_name, response)

            return result

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return None

    def _build_analysis_prompt(self, class_name: str, java_source: str) -> str:
        """Build AI prompt for Java code analysis"""
        # Truncate source if too long (model context limits)
        max_source_length = 4000  # Leave room for prompt and response
        truncated_source = java_source[:max_source_length]
        if len(java_source) > max_source_length:
            truncated_source += "\n\n... (truncated)"

        prompt = f"""Analyze this decompiled Java class and provide insights:

Class Name: {class_name}

Source Code:
```java
{truncated_source}
```

Please provide a JSON response with the following structure:
{{
    "function_purpose": "Brief description of what this class does",
    "security_issues": ["List of potential security vulnerabilities"],
    "obfuscation_patterns": ["List of obfuscation techniques detected"],
    "original_intent": "What you think this class was meant to do before obfuscation",
    "suggested_names": {{
        "a": "suggestedVariableName",
        "b": "anotherVariableName"
    }},
    "confidence": 0.85
}}

Focus on:
1. Identifying the class's primary purpose
2. Detecting security issues (SQL injection, XSS, insecure crypto, etc.)
3. Recognizing obfuscation patterns (ProGuard, Allatori, etc.)
4. Inferring original variable/method names from context
5. Providing a confidence score (0.0 to 1.0)

Return ONLY valid JSON, no additional text.
"""
        return prompt

    def _query_ai(self, prompt: str) -> str:
        """Query AI with prompt"""
        if self.ai_provider == 'ollama':
            return self._query_ollama(prompt)
        elif self.ai_provider == 'openai':
            return self._query_openai(prompt)
        elif self.ai_provider == 'anthropic':
            return self._query_anthropic(prompt)
        else:
            raise ValueError(f"Unknown AI provider: {self.ai_provider}")

    def _query_ollama(self, prompt: str) -> str:
        """Query Ollama"""
        import requests

        from tools.config_manager import get_config
        config = get_config()
        ai_config = config.get_ai_config()

        url = f"{ai_config.ollama_host}/api/generate"
        payload = {
            "model": ai_config.ollama_model if ai_config.ollama_model != 'auto' else 'deepseek-coder',
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": ai_config.ollama_temperature,
                "num_predict": ai_config.ollama_max_tokens
            }
        }

        response = requests.post(url, json=payload, timeout=ai_config.ollama_timeout)
        response.raise_for_status()

        result = response.json()
        return result.get('response', '')

    def _query_openai(self, prompt: str) -> str:
        """Query OpenAI (placeholder)"""
        raise NotImplementedError("OpenAI support not yet implemented")

    def _query_anthropic(self, prompt: str) -> str:
        """Query Anthropic (placeholder)"""
        raise NotImplementedError("Anthropic support not yet implemented")

    def _parse_ai_response(self, class_name: str, response: str) -> JavaAIAnalysisResult:
        """Parse AI response into structured result"""
        try:
            # Try to extract JSON from response
            # Some models may include additional text
            json_start = response.find('{')
            json_end = response.rfind('}') + 1

            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                data = json.loads(json_str)
            else:
                # Fallback: try parsing entire response
                data = json.loads(response)

            # Create result
            return JavaAIAnalysisResult(
                class_name=class_name,
                function_purpose=data.get('function_purpose', 'Unknown'),
                security_issues=data.get('security_issues', []),
                obfuscation_patterns=data.get('obfuscation_patterns', []),
                original_intent=data.get('original_intent', 'Unknown'),
                suggested_names=data.get('suggested_names', {}),
                confidence=float(data.get('confidence', 0.5)),
                model_used=self.model
            )

        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response as JSON: {e}")
            logger.debug(f"Response was: {response[:500]}")

            # Return fallback result
            return JavaAIAnalysisResult(
                class_name=class_name,
                function_purpose="AI analysis failed - JSON parse error",
                security_issues=[],
                obfuscation_patterns=[],
                original_intent="Unknown",
                suggested_names={},
                confidence=0.0,
                model_used=self.model
            )

    def analyze_batch(self, classes: Dict[str, str], max_classes: int = 10) -> List[JavaAIAnalysisResult]:
        """
        Analyze multiple Java classes in batch

        Args:
            classes: Dict of class_name -> java_source
            max_classes: Maximum number of classes to analyze (limit for performance)

        Returns:
            List of analysis results
        """
        results = []

        # Limit to max_classes
        items = list(classes.items())[:max_classes]

        for class_name, java_source in items:
            logger.info(f"AI analyzing {class_name}...")

            result = self.analyze_java_class(class_name, java_source)

            if result:
                results.append(result)
            else:
                logger.warning(f"AI analysis failed for {class_name}")

        return results

    def save_results(self, results: List[JavaAIAnalysisResult], output_file: Path):
        """Save AI analysis results to JSON file"""
        output_data = {
            'ai_provider': self.ai_provider,
            'model': self.model,
            'total_classes': len(results),
            'results': [asdict(r) for r in results]
        }

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2)

        logger.info(f"Saved AI analysis results to {output_file}")


def main():
    """Test AI analyzer"""
    import argparse

    parser = argparse.ArgumentParser(description='REVENG AI-Enhanced Java Analyzer')
    parser.add_argument('java_file', help='Path to Java source file')
    parser.add_argument('--provider', default='ollama', choices=['ollama', 'openai', 'anthropic'])
    parser.add_argument('--model', default='auto', help='Model name or auto')
    parser.add_argument('-o', '--output', help='Output JSON file')

    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Read Java source
    with open(args.java_file, 'r', encoding='utf-8') as f:
        java_source = f.read()

    class_name = Path(args.java_file).stem

    # Analyze
    analyzer = JavaAIAnalyzer(ai_provider=args.provider, model=args.model)

    if not analyzer.ai_available:
        print("ERROR: AI not available")
        print(f"Provider: {args.provider}")
        print("Make sure Ollama is running: ollama serve")
        return 1

    print(f"Analyzing {class_name} with {args.provider}...")
    result = analyzer.analyze_java_class(class_name, java_source)

    if result:
        print("\n=== AI Analysis Results ===")
        print(f"Class: {result.class_name}")
        print(f"Purpose: {result.function_purpose}")
        print(f"Security Issues: {', '.join(result.security_issues) if result.security_issues else 'None detected'}")
        print(f"Obfuscation: {', '.join(result.obfuscation_patterns) if result.obfuscation_patterns else 'None detected'}")
        print(f"Original Intent: {result.original_intent}")
        print(f"Suggested Names: {len(result.suggested_names)} suggestions")
        print(f"Confidence: {result.confidence:.2%}")
        print(f"Model: {result.model_used}")

        if result.suggested_names:
            print("\nSuggested Name Improvements:")
            for old, new in result.suggested_names.items():
                print(f"  {old} → {new}")

        # Save if requested
        if args.output:
            analyzer.save_results([result], Path(args.output))
            print(f"\nSaved to: {args.output}")

    else:
        print("ERROR: AI analysis failed")
        return 1

    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
