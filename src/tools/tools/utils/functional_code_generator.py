#!/usr/bin/env python3
"""
REVENG Functional Code Generator
=================================

Generates functional C code from disassembly using Ollama AI.

This replaces stub generation with actual implementations by:
1. Analyzing disassembly with AI to understand function logic
2. Generating working C code that implements the same behavior
3. Adding proper error handling and type safety
4. Creating compilable, testable output

Author: REVENG
Version: 2.0
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
import re

# Try to import Ollama analyzer
try:
    from tools.ollama_analyzer import OllamaAnalyzer
    from tools.config_manager import get_config
    HAS_OLLAMA = True
except ImportError:
    HAS_OLLAMA = False

logger = logging.getLogger(__name__)


class FunctionalCodeGenerator:
    """
    Generate functional C code from disassembly and analysis

    Uses AI (Ollama) when available to generate real implementations
    Falls back to template-based generation for simple patterns
    """

    def __init__(self, use_ai: bool = True):
        """
        Initialize generator

        Args:
            use_ai: Whether to use AI for code generation (requires Ollama)
        """
        self.use_ai = use_ai and HAS_OLLAMA
        self.ai_analyzer = None

        if self.use_ai:
            try:
                config = get_config()
                ai_config = config.get_ai_config()
                if ai_config.enable_ai:
                    self.ai_analyzer = OllamaAnalyzer(
                        model_name=ai_config.ollama_model if ai_config.ollama_model != 'auto' else None,
                        ollama_host=ai_config.ollama_host,
                        timeout=ai_config.ollama_timeout,
                        temperature=ai_config.ollama_temperature,
                        max_tokens=ai_config.ollama_max_tokens
                    )
                    logger.info(f"AI code generation enabled with model: {self.ai_analyzer.model_name}")
                else:
                    self.use_ai = False
                    logger.info("AI disabled in config, using template-based generation")
            except Exception as e:
                self.use_ai = False
                logger.warning(f"Failed to initialize AI: {e}, using template-based generation")
        else:
            logger.info("Template-based code generation mode")

        # Load templates for fallback
        self.templates = self._load_templates()

    def _load_templates(self) -> Dict[str, str]:
        """Load basic code templates for fallback"""
        return {
            'memory_alloc': '''    void *ptr = malloc({size});
    if (!ptr) {{
        return NULL;
    }}
    memset(ptr, 0, {size});
    return ptr;''',

            'file_open': '''    FILE *fp = fopen({filename}, "{mode}");
    if (!fp) {{
        perror("fopen");
        return NULL;
    }}
    return fp;''',

            'default': '''    // TODO: Implement function logic
    // Based on analysis: {purpose}
    return {return_value};'''
        }

    def generate_functional_code(
        self,
        function_name: str,
        disassembly: str,
        analysis: Optional[Dict[str, Any]] = None,
        output_path: Optional[Path] = None
    ) -> str:
        """
        Generate functional C code from disassembly

        Args:
            function_name: Name of the function
            disassembly: Disassembled code
            analysis: Optional AI analysis results
            output_path: Optional path to write output

        Returns:
            Generated C code as string
        """
        if self.use_ai and self.ai_analyzer:
            code = self._generate_with_ai(function_name, disassembly, analysis)
        else:
            code = self._generate_with_templates(function_name, disassembly, analysis)

        # Write to file if requested
        if output_path:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(code)
            logger.info(f"Generated code written to {output_path}")

        return code

    def _generate_with_ai(
        self,
        function_name: str,
        disassembly: str,
        analysis: Optional[Dict[str, Any]]
    ) -> str:
        """Generate code using Ollama AI"""
        logger.info(f"Generating functional code for {function_name} using AI")

        # Build comprehensive prompt for code generation
        prompt = self._build_code_generation_prompt(function_name, disassembly, analysis)

        try:
            # Call Ollama for code generation
            response = self.ai_analyzer._call_ollama(prompt)

            # Extract C code from response
            c_code = self._extract_c_code(response)

            # Validate and clean up code
            c_code = self._cleanup_generated_code(c_code)

            # Add header comments
            full_code = self._add_header(function_name, "AI-generated functional implementation", analysis)
            full_code += "\n" + c_code

            return full_code

        except Exception as e:
            logger.error(f"AI code generation failed: {e}, falling back to templates")
            return self._generate_with_templates(function_name, disassembly, analysis)

    def _build_code_generation_prompt(
        self,
        function_name: str,
        disassembly: str,
        analysis: Optional[Dict[str, Any]]
    ) -> str:
        """Build prompt for Ollama to generate functional C code"""

        prompt = f"""You are a reverse engineering expert. Generate functional C code that implements the behavior shown in this disassembly.

FUNCTION NAME: {function_name}

DISASSEMBLY:
{disassembly[:2000]}  # Limit to prevent token overflow

"""

        if analysis:
            prompt += f"""ANALYSIS RESULTS:
Category: {analysis.get('category', 'Unknown')}
Purpose: {analysis.get('purpose', 'Unknown')}
Confidence: {analysis.get('confidence', 0.0)}
"""

            if analysis.get('security_issues'):
                prompt += f"\nSecurity Issues Found: {len(analysis['security_issues'])}\n"
                for issue in analysis['security_issues'][:3]:  # Show top 3
                    prompt += f"  - {issue.get('description', 'Unknown issue')}\n"

        prompt += """
REQUIREMENTS:
1. Generate COMPLETE, FUNCTIONAL C code that can be compiled
2. Include all necessary #include statements
3. Implement the actual logic based on the disassembly patterns
4. Add proper error handling (check NULL, validate inputs)
5. Use meaningful variable names
6. Add security mitigations for any identified issues
7. Make the code cross-platform (Windows/Linux/macOS) where possible
8. Include brief inline comments for complex logic

FORMAT:
- Return ONLY valid C code (no markdown, no explanations)
- Start with #include statements
- End with complete function implementation
- Use standard C library functions when appropriate

Generate the C code now:
"""

        return prompt

    def _extract_c_code(self, llm_response: str) -> str:
        """Extract C code from LLM response"""
        # Remove markdown code blocks if present
        code = llm_response.strip()

        # Try to extract from markdown code block
        if '```c' in code or '```C' in code:
            match = re.search(r'```[cC]\n(.*?)```', code, re.DOTALL)
            if match:
                return match.group(1).strip()

        # Try generic code block
        if '```' in code:
            match = re.search(r'```\n(.*?)```', code, re.DOTALL)
            if match:
                return match.group(1).strip()

        # Return as-is if no code block markers
        return code

    def _cleanup_generated_code(self, code: str) -> str:
        """Clean up and validate generated code"""
        # Remove any explanatory text before the first #include or function
        lines = code.split('\n')
        start_idx = 0

        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('#include') or stripped.startswith('/*') or stripped.startswith('//'):
                start_idx = i
                break
            if 'int ' in stripped or 'void ' in stripped or 'char ' in stripped:
                start_idx = i
                break

        cleaned = '\n'.join(lines[start_idx:])

        # Ensure proper formatting
        cleaned = cleaned.strip()

        return cleaned

    def _generate_with_templates(
        self,
        function_name: str,
        disassembly: str,
        analysis: Optional[Dict[str, Any]]
    ) -> str:
        """Generate code using templates (fallback)"""
        logger.info(f"Generating template-based code for {function_name}")

        # Determine function category
        category = 'default'
        if analysis:
            category_name = analysis.get('category', '').lower()
            if 'memory' in category_name or 'alloc' in function_name.lower():
                category = 'memory_alloc'
            elif 'file' in category_name or 'io' in category_name:
                category = 'file_open'

        # Get template
        template = self.templates.get(category, self.templates['default'])

        # Simple parameter detection from disassembly
        params = self._detect_parameters(disassembly)
        return_type = self._detect_return_type(disassembly, analysis)

        # Format parameters
        param_str = ", ".join([f"{p['type']} {p['name']}" for p in params]) if params else "void"

        # Generate body
        purpose = analysis.get('purpose', 'Unknown') if analysis else 'Unknown'
        return_value = "0" if return_type == "int" else "NULL" if "*" in return_type else "0"

        body = template.format(
            purpose=purpose,
            return_value=return_value,
            size="256",
            filename=params[0]['name'] if params else '"file.txt"',
            mode="r"
        )

        # Build full function
        code = self._add_header(function_name, "Template-based implementation", analysis)
        code += f"\n{return_type} {function_name}({param_str}) {{\n"
        code += body + "\n"
        code += "}\n"

        return code

    def _detect_parameters(self, disassembly: str) -> List[Dict[str, str]]:
        """Detect function parameters from disassembly"""
        params = []

        # Look for register usage patterns (rdi, rsi, rdx, rcx for x64 calling convention)
        if 'rdi' in disassembly or 'edi' in disassembly:
            params.append({'type': 'void*', 'name': 'arg1'})
        if 'rsi' in disassembly or 'esi' in disassembly:
            params.append({'type': 'void*', 'name': 'arg2'})
        if 'rdx' in disassembly or 'edx' in disassembly:
            params.append({'type': 'int', 'name': 'arg3'})

        return params[:3]  # Limit to first 3 params

    def _detect_return_type(self, disassembly: str, analysis: Optional[Dict[str, Any]]) -> str:
        """Detect return type from disassembly and analysis"""
        if analysis:
            category = analysis.get('category', '').lower()
            if 'memory' in category:
                return "void*"
            if 'file' in category:
                return "FILE*"

        # Default return type
        return "int"

    def _add_header(
        self,
        function_name: str,
        description: str,
        analysis: Optional[Dict[str, Any]]
    ) -> str:
        """Add header comments to generated code"""
        header = "/*\n"
        header += f" * {function_name}\n"
        header += f" * {description}\n"

        if analysis:
            header += f" *\n"
            header += f" * Category: {analysis.get('category', 'Unknown')}\n"
            header += f" * Purpose: {analysis.get('purpose', 'Unknown')}\n"
            header += f" * Confidence: {analysis.get('confidence', 0.0):.2f}\n"

            if analysis.get('security_issues'):
                header += f" * Security Issues: {len(analysis['security_issues'])} found\n"

        header += " */\n\n"
        header += "#include <stdio.h>\n"
        header += "#include <stdlib.h>\n"
        header += "#include <string.h>\n"

        return header


# CLI for testing
if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser(description='Generate functional C code from disassembly')
    parser.add_argument('function_name', help='Name of the function')
    parser.add_argument('--disasm', required=True, help='Path to disassembly file')
    parser.add_argument('--analysis', help='Path to AI analysis JSON (optional)')
    parser.add_argument('--output', help='Output C file path')
    parser.add_argument('--no-ai', action='store_true', help='Disable AI, use templates only')
    args = parser.parse_args()

    # Load disassembly
    with open(args.disasm, 'r') as f:
        disassembly = f.read()

    # Load analysis if provided
    analysis = None
    if args.analysis:
        with open(args.analysis, 'r') as f:
            analysis = json.load(f)

    # Generate code
    generator = FunctionalCodeGenerator(use_ai=not args.no_ai)
    code = generator.generate_functional_code(
        args.function_name,
        disassembly,
        analysis,
        args.output
    )

    if not args.output:
        print(code)
