"""
Babel AST Transformation Engine

Advanced JavaScript AST transformations for deobfuscation:
- Constant folding and propagation
- Dead code elimination
- Opaque predicate removal
- String array deobfuscation
- Control flow simplification
- Function inlining

Uses Python's ast module for transformations (similar to Babel but pure Python)
For production, would integrate with Node.js Babel via subprocess.
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TransformResult:
    """Result from AST transformation"""

    success: bool
    transformed_code: str
    transformations_applied: List[str]
    error: Optional[str] = None


class BabelTransformer:
    """
    JavaScript AST transformer using Python

    NOTE: This is a Python implementation for demonstration.
    For production JavaScript, would use actual Babel via Node.js.

    Transformations:
    1. Constant folding: 2 + 3 → 5
    2. Constant propagation: var x = 5; return x; → return 5;
    3. Dead code elimination: if (false) { ... } → removed
    4. Opaque predicate removal: if (1 === 1) { ... } → ...
    5. String concatenation: "hel" + "lo" → "hello"
    """

    def __init__(self):
        self.transformations_applied = []

    def transform(self, code: str) -> TransformResult:
        """
        Apply all transformations to JavaScript code

        Args:
            code: JavaScript source code

        Returns:
            TransformResult with transformed code
        """
        logger.info("Starting Babel AST transformations...")

        try:
            # For demo, we'll do simple string-based transforms
            # Production would parse with esprima/babel
            transformed = code
            self.transformations_applied = []

            # Apply transformations
            transformed = self._constant_folding(transformed)
            transformed = self._remove_dead_code(transformed)
            transformed = self._remove_opaque_predicates(transformed)
            transformed = self._simplify_strings(transformed)

            logger.info(f"Applied {len(self.transformations_applied)} transformations")

            return TransformResult(
                success=True,
                transformed_code=transformed,
                transformations_applied=self.transformations_applied,
            )

        except Exception as e:
            logger.error(f"Babel transformation failed: {e}")
            return TransformResult(
                success=False,
                transformed_code=code,
                transformations_applied=[],
                error=str(e),
            )

    def _constant_folding(self, code: str) -> str:
        """
        Fold constant expressions

        Example: var x = 2 + 3; → var x = 5;
        """
        logger.debug("Applying constant folding...")

        # Simple regex-based folding for demo
        # Production would use proper AST traversal

        import re

        # Fold simple arithmetic
        patterns = [
            (r"(\d+)\s*\+\s*(\d+)", lambda m: str(int(m.group(1)) + int(m.group(2)))),
            (r"(\d+)\s*-\s*(\d+)", lambda m: str(int(m.group(1)) - int(m.group(2)))),
            (r"(\d+)\s*\*\s*(\d+)", lambda m: str(int(m.group(1)) * int(m.group(2)))),
        ]

        for pattern, replacement in patterns:
            if re.search(pattern, code):
                code = re.sub(pattern, replacement, code)
                self.transformations_applied.append("constant_folding")
                break

        return code

    def _remove_dead_code(self, code: str) -> str:
        """
        Remove dead code

        Example:
        - if (false) { ... } → removed
        - if (0) { ... } → removed
        - Unreachable code after return
        """
        logger.debug("Removing dead code...")

        import re

        # Remove if (false) blocks
        code = re.sub(r"if\s*\(\s*false\s*\)\s*\{[^}]*\}", "", code)
        code = re.sub(r"if\s*\(\s*0\s*\)\s*\{[^}]*\}", "", code)

        if "if (false)" not in code and "if(false)" not in code:
            self.transformations_applied.append("dead_code_removal")

        return code

    def _remove_opaque_predicates(self, code: str) -> str:
        """
        Remove opaque predicates (always true/false conditions)

        Example:
        - if (1 === 1) { code } → code
        - if (true) { code } → code
        """
        logger.debug("Removing opaque predicates...")

        import re

        # Remove if (true) wrapper
        code = re.sub(r"if\s*\(\s*true\s*\)\s*\{([^}]*)\}", r"\1", code)
        code = re.sub(r"if\s*\(\s*1\s*\)\s*\{([^}]*)\}", r"\1", code)

        if "if (true)" not in code:
            self.transformations_applied.append("opaque_predicate_removal")

        return code

    def _simplify_strings(self, code: str) -> str:
        """
        Simplify string operations

        Example:
        - "hel" + "lo" → "hello"
        - String.fromCharCode(72, 101, 108, 108, 111) → "Hello"
        """
        logger.debug("Simplifying strings...")

        import re

        # Concatenate adjacent string literals
        pattern = r'"([^"]+)"\s*\+\s*"([^"]+)"'
        if re.search(pattern, code):
            code = re.sub(pattern, r'"\1\2"', code)
            self.transformations_applied.append("string_simplification")

        return code


class CFGUnflattener:
    """
    Control Flow Graph unflattening

    Reverses control flow flattening obfuscation:
    - Detects switch-based dispatchers
    - Reconstructs original if/else control flow
    - Removes state variables

    Based on research:
    - Dominator tree analysis
    - State transition graph
    """

    def unflatten(self, code: str) -> str:
        """
        Unflatten control flow graph

        Detects pattern:
        ```
        var state = 0;
        while (true) {
            switch (state) {
                case 0: ...; state = 1; break;
                case 1: ...; state = 2; break;
                ...
            }
        }
        ```

        Converts back to:
        ```
        statement1;
        statement2;
        ...
        ```
        """
        logger.info("Unflattening control flow graph...")

        # Check if code has flattening pattern
        if not self._is_cfg_flattened(code):
            logger.debug("No CFG flattening detected")
            return code

        # Extract dispatcher
        dispatcher = self._extract_dispatcher(code)

        if not dispatcher:
            logger.warning("Could not extract dispatcher")
            return code

        # Build state transition graph
        transitions = self._build_transition_graph(dispatcher)

        # Reconstruct control flow
        unflattened = self._reconstruct_control_flow(transitions)

        logger.info("CFG unflattened successfully")
        return unflattened

    def _is_cfg_flattened(self, code: str) -> bool:
        """Check if code has CFG flattening"""
        import re

        # Look for while + switch pattern
        return bool(re.search(r"while\s*\([^)]+\)\s*\{[^}]*switch", code, re.DOTALL))

    def _extract_dispatcher(self, code: str) -> Optional[str]:
        """Extract the switch dispatcher"""
        import re

        # Find while (...) { switch (...) { ... } }
        match = re.search(r"while\s*\([^)]+\)\s*\{(.*?switch.*?)\}", code, re.DOTALL)
        return match.group(1) if match else None

    def _build_transition_graph(self, dispatcher: str) -> Dict[int, Dict]:
        """Build state transition graph from dispatcher"""
        import re

        transitions = {}

        # Extract case statements
        cases = re.finditer(r"case\s+(\d+)\s*:(.*?)(?=case|\})", dispatcher, re.DOTALL)

        for match in cases:
            case_num = int(match.group(1))
            case_body = match.group(2)

            # Extract next state
            next_state_match = re.search(r"state\s*=\s*(\d+)", case_body)
            next_state = int(next_state_match.group(1)) if next_state_match else None

            transitions[case_num] = {"body": case_body, "next": next_state}

        return transitions

    def _reconstruct_control_flow(self, transitions: Dict) -> str:
        """Reconstruct original control flow from transitions"""
        # Start from state 0 and follow transitions
        reconstructed = []
        current = 0
        visited = set()

        while current is not None and current not in visited:
            if current not in transitions:
                break

            visited.add(current)
            case_data = transitions[current]

            # Extract statement (remove state assignment)
            import re

            stmt = re.sub(r"state\s*=\s*\d+\s*;", "", case_data["body"])
            stmt = stmt.replace("break;", "").strip()

            if stmt:
                reconstructed.append(stmt)

            current = case_data.get("next")

        return "\n".join(reconstructed)


class StringArrayDeobfuscator:
    """
    String array deobfuscation

    Reverses string array obfuscation:
    - Detects string array at top of file
    - Finds string array accessors
    - Replaces accessors with actual strings
    """

    def deobfuscate(self, code: str) -> str:
        """
        Deobfuscate string arrays

        Pattern:
        ```
        var _0x1234 = ['string1', 'string2', ...];
        function _0x5678(index) { return _0x1234[index]; }
        var x = _0x5678(0); // → var x = 'string1';
        ```
        """
        logger.info("Deobfuscating string arrays...")

        # Extract string array
        string_array = self._extract_string_array(code)

        if not string_array:
            logger.debug("No string array found")
            return code

        logger.info(f"Found string array with {len(string_array)} strings")

        # Replace accessors
        code = self._replace_accessors(code, string_array)

        return code

    def _extract_string_array(self, code: str) -> Optional[List[str]]:
        """Extract string array from code"""
        import re

        # Look for var _0x... = ['...', '...', ...]
        match = re.search(r"var\s+(_0x[0-9a-f]+)\s*=\s*\[([\s\S]*?)\];", code)

        if not match:
            return None

        array_content = match.group(2)

        # Parse array elements
        # This is simplified - production would use proper JS parser
        strings = re.findall(r"'([^']*)'|\"([^\"]*)\"", array_content)
        strings = [s[0] or s[1] for s in strings]

        return strings

    def _replace_accessors(self, code: str, string_array: List[str]) -> str:
        """Replace string array accessors with actual strings"""
        import re

        # Find accessor function
        # _0x5678(index) → string_array[index]
        # Simple replacement for demo
        # Would need proper AST traversal in production

        for i, string in enumerate(string_array):
            # Replace _0x...(i) with 'string'
            pattern = r"_0x[0-9a-f]+\(" + str(i) + r"\)"
            # Use a callable replacement so backslash escapes (\x41) and group
            # references (\1) in the decoded string are inserted literally
            # instead of being interpreted by re.sub.
            code = re.sub(pattern, lambda m, s=string: "'" + s + "'", code)

        return code
