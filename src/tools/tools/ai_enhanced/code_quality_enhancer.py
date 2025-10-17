"""
AI Code Quality Enhancer for REVENG

Transforms raw decompiled code into readable, documented code using AI.
Features:
- Semantic variable renaming (var_1 → connection_socket)
- Function renaming (sub_401000 → decrypt_config)
- AI-generated comments and documentation
- Type inference
- Control flow reconstruction
"""

import logging
import re
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class CodeEnhancement:
    """Enhanced code result"""
    original_code: str
    enhanced_code: str
    variable_renamings: Dict[str, str]
    suggested_function_name: str
    comments_added: int
    improvements: List[str]


class AICodeQualityEnhancer:
    """
    AI-powered code quality enhancement for decompiled code.

    Uses LLM to make decompiled code human-readable through:
    - Semantic renaming
    - Documentation generation
    - Code structure improvement
    """

    def __init__(self, model: str = 'auto', use_ollama: bool = True):
        """
        Initialize code quality enhancer.

        Args:
            model: LLM model to use
            use_ollama: Whether to use Ollama for enhancement
        """
        self.use_ollama = use_ollama and OLLAMA_AVAILABLE
        self.model = model

        if self.use_ollama:
            if model == 'auto':
                self.model = self._detect_model()
            logger.info(f"Code enhancer using model: {self.model}")
        else:
            logger.warning("Ollama not available, using basic heuristics")

    def _detect_model(self) -> str:
        """Detect available Ollama model"""
        try:
            models = ollama.list()
            if models and 'models' in models:
                available = [m['name'] for m in models['models']]
                # Prefer code-focused models
                for preferred in ['codellama', 'llama3', 'mistral']:
                    for model in available:
                        if preferred in model.lower():
                            return model
                if available:
                    return available[0]
        except Exception:
            pass
        return 'llama3'

    def enhance_function(
        self,
        function_code: str,
        function_name: str = "unknown",
        context: Optional[Dict[str, Any]] = None
    ) -> CodeEnhancement:
        """
        Enhance a single function's code quality.

        Args:
            function_code: Raw decompiled function code
            function_name: Current function name
            context: Optional context about the binary/analysis

        Returns:
            Enhanced code with improvements
        """
        if not self.use_ollama:
            return self._fallback_enhancement(function_code, function_name)

        logger.info(f"Enhancing function: {function_name}")

        # Step 1: Variable renaming
        variable_renamings = self._ai_rename_variables(function_code, function_name)

        # Step 2: Apply renamings
        renamed_code = self._apply_renamings(function_code, variable_renamings)

        # Step 3: Add comments
        commented_code = self._add_ai_comments(renamed_code, function_name)

        # Step 4: Suggest function name
        suggested_name = self._suggest_function_name(commented_code, function_name)

        # Step 5: Count improvements
        improvements = []
        if variable_renamings:
            improvements.append(f"Renamed {len(variable_renamings)} variables")
        if suggested_name != function_name:
            improvements.append(f"Suggested better name: {suggested_name}")

        comment_count = commented_code.count('/*') + commented_code.count('//')
        if comment_count > 0:
            improvements.append(f"Added {comment_count} comments")

        return CodeEnhancement(
            original_code=function_code,
            enhanced_code=commented_code,
            variable_renamings=variable_renamings,
            suggested_function_name=suggested_name,
            comments_added=comment_count,
            improvements=improvements
        )

    def _ai_rename_variables(
        self,
        function_code: str,
        function_name: str
    ) -> Dict[str, str]:
        """Use AI to suggest semantic variable names"""
        # Extract variables that need renaming (var_X, a1, etc.)
        var_pattern = r'\b(var_\d+|a\d+|v\d+|dword_[0-9A-F]+)\b'
        variables = set(re.findall(var_pattern, function_code))

        if not variables:
            return {}

        # Limit to most important variables (top 10)
        variables = list(variables)[:10]

        prompt = f"""Analyze this decompiled function and suggest semantic names for variables.

Function: {function_name}

Code:
{function_code[:1500]}  # Limit code length

Variables to rename: {', '.join(variables)}

For each variable, suggest a meaningful name based on how it's used.
Return ONLY valid JSON in this exact format:
{{
  "var_1": "suggested_name",
  "var_2": "other_name"
}}

Rules:
- Use snake_case
- Be descriptive but concise
- Infer type/purpose from usage
- No special characters except underscore"""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}],
                options={'temperature': 0.3}  # Low temperature for consistency
            )

            content = response['message']['content']

            # Extract JSON from response
            json_match = re.search(r'\{[^}]+\}', content, re.DOTALL)
            if json_match:
                suggestions = json.loads(json_match.group())
                # Validate suggestions
                validated = {}
                for old_name, new_name in suggestions.items():
                    if old_name in variables:
                        # Clean up suggestion
                        new_name = re.sub(r'[^a-zA-Z0-9_]', '', new_name)
                        if new_name and new_name != old_name:
                            validated[old_name] = new_name

                logger.info(f"AI suggested {len(validated)} variable renamings")
                return validated

        except Exception as e:
            logger.error(f"AI variable renaming failed: {e}")

        return {}

    def _apply_renamings(
        self,
        code: str,
        renamings: Dict[str, str]
    ) -> str:
        """Apply variable renamings to code"""
        renamed_code = code

        # Sort by length (longest first) to avoid partial replacements
        sorted_renamings = sorted(
            renamings.items(),
            key=lambda x: len(x[0]),
            reverse=True
        )

        for old_name, new_name in sorted_renamings:
            # Use word boundaries to avoid partial matches
            pattern = r'\b' + re.escape(old_name) + r'\b'
            renamed_code = re.sub(pattern, new_name, renamed_code)

        return renamed_code

    def _add_ai_comments(
        self,
        code: str,
        function_name: str
    ) -> str:
        """Add AI-generated inline comments"""
        prompt = f"""Add helpful inline comments to this decompiled code.

Function: {function_name}

Code:
{code[:2000]}

Add concise /* ... */ comments before key sections to explain what they do.
Return the code with comments added. Keep existing code unchanged.
Focus on explaining:
- Purpose of code blocks
- What variables represent
- Important operations

Return ONLY the code with comments, no explanations."""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}],
                options={'temperature': 0.3}
            )

            commented = response['message']['content']

            # Extract code from response (remove markdown if present)
            code_match = re.search(r'```(?:c|cpp)?\n(.*?)\n```', commented, re.DOTALL)
            if code_match:
                commented = code_match.group(1)

            return commented

        except Exception as e:
            logger.error(f"AI commenting failed: {e}")
            return code

    def _suggest_function_name(
        self,
        code: str,
        current_name: str
    ) -> str:
        """Suggest better function name based on code analysis"""
        # Skip if already has good name
        if not re.match(r'(sub|func|FUN)_[0-9a-fA-F]+', current_name):
            return current_name

        prompt = f"""Based on this function code, suggest a descriptive function name.

Current name: {current_name}

Code:
{code[:1000]}

Suggest a better name that describes what this function does.
Return ONLY the function name (snake_case, no special characters).
Examples: decrypt_config, send_http_request, check_debugger"""

        try:
            response = ollama.chat(
                model=self.model,
                messages=[{'role': 'user', 'content': prompt}],
                options={'temperature': 0.3, 'num_predict': 20}
            )

            suggestion = response['message']['content'].strip()

            # Clean up suggestion
            suggestion = re.sub(r'[^a-zA-Z0-9_]', '', suggestion)

            # Validate format
            if suggestion and re.match(r'^[a-z][a-z0-9_]*$', suggestion):
                logger.info(f"Suggested function name: {suggestion}")
                return suggestion

        except Exception as e:
            logger.error(f"Function name suggestion failed: {e}")

        return current_name

    def _fallback_enhancement(
        self,
        code: str,
        function_name: str
    ) -> CodeEnhancement:
        """Fallback enhancement without AI"""
        logger.info("Using fallback heuristic enhancement (no AI)")

        # Simple heuristic renaming
        renamings = {}

        # Rename common patterns
        heuristic_patterns = {
            r'\bv\d+\b': 'variable',
            r'\ba\d+\b': 'arg',
            r'\bdword_[0-9A-F]+\b': 'data_ptr'
        }

        enhanced_code = code
        for pattern, base_name in heuristic_patterns.items():
            matches = re.findall(pattern, code)
            for idx, match in enumerate(set(matches)):
                new_name = f"{base_name}_{idx}"
                renamings[match] = new_name
                enhanced_code = re.sub(
                    r'\b' + re.escape(match) + r'\b',
                    new_name,
                    enhanced_code
                )

        return CodeEnhancement(
            original_code=code,
            enhanced_code=enhanced_code,
            variable_renamings=renamings,
            suggested_function_name=function_name,
            comments_added=0,
            improvements=[f"Applied heuristic renaming to {len(renamings)} variables"]
        )

    def enhance_all_functions(
        self,
        functions: Dict[str, str],
        output_dir: Optional[str] = None
    ) -> Dict[str, CodeEnhancement]:
        """
        Enhance all functions in a binary.

        Args:
            functions: Dict mapping function_name -> code
            output_dir: Optional directory to save enhanced code

        Returns:
            Dict mapping function_name -> CodeEnhancement
        """
        enhancements = {}

        logger.info(f"Enhancing {len(functions)} functions...")

        for func_name, func_code in functions.items():
            try:
                enhancement = self.enhance_function(func_code, func_name)
                enhancements[func_name] = enhancement

                # Save to file if output directory provided
                if output_dir:
                    output_path = Path(output_dir) / f"{enhancement.suggested_function_name}.c"
                    output_path.parent.mkdir(parents=True, exist_ok=True)

                    with open(output_path, 'w') as f:
                        f.write(f"// Original: {func_name}\n")
                        f.write(f"// Enhancements: {', '.join(enhancement.improvements)}\n\n")
                        f.write(enhancement.enhanced_code)

            except Exception as e:
                logger.error(f"Failed to enhance {func_name}: {e}")

        logger.info(f"Enhanced {len(enhancements)}/{len(functions)} functions")

        return enhancements

    def generate_summary_report(
        self,
        enhancements: Dict[str, CodeEnhancement]
    ) -> str:
        """Generate summary report of enhancements"""
        total_vars_renamed = sum(
            len(e.variable_renamings) for e in enhancements.values()
        )
        total_comments = sum(
            e.comments_added for e in enhancements.values()
        )
        functions_renamed = sum(
            1 for e in enhancements.values()
            if e.suggested_function_name != "unknown"
        )

        report = f"Code Quality Enhancement Summary\n"
        report += f"{'=' * 60}\n\n"
        report += f"Functions Enhanced: {len(enhancements)}\n"
        report += f"Variables Renamed: {total_vars_renamed}\n"
        report += f"Comments Added: {total_comments}\n"
        report += f"Functions Renamed: {functions_renamed}\n\n"

        report += f"Top Enhancements:\n"
        # Show functions with most improvements
        sorted_enhancements = sorted(
            enhancements.items(),
            key=lambda x: len(x[1].variable_renamings),
            reverse=True
        )

        for func_name, enhancement in sorted_enhancements[:10]:
            report += f"  {func_name}:\n"
            for improvement in enhancement.improvements:
                report += f"    - {improvement}\n"

        return report


# Convenience function
def enhance_code(function_code: str, function_name: str = "unknown") -> CodeEnhancement:
    """Quick code enhancement"""
    enhancer = AICodeQualityEnhancer()
    return enhancer.enhance_function(function_code, function_name)
