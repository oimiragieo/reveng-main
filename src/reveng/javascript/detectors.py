"""
JavaScript Obfuscation Detection

Automatically detects obfuscation types by analyzing code patterns.
Used to guide the deobfuscation pipeline.
"""

import re
import logging
from typing import List
from dataclasses import dataclass
from .deobfuscator import ObfuscationType

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result from obfuscation detection"""

    obfuscation_types: List[ObfuscationType]
    confidence: float
    details: dict


class ObfuscationDetector:
    """
    Detects JavaScript obfuscation types

    Uses pattern matching to identify:
    - Minification (short variable names, no whitespace)
    - Packing (eval-based)
    - Bundling (webpack/browserify signatures)
    - obfuscator.io patterns
    - Control flow flattening
    - String encryption
    """

    def detect(self, code: str) -> DetectionResult:
        """
        Detect obfuscation types in JavaScript code

        Args:
            code: JavaScript source code

        Returns:
            DetectionResult with detected obfuscation types
        """
        types = []
        details = {}

        # Check for minification
        if self._is_minified(code):
            types.append(ObfuscationType.MINIFIED)
            details["minified"] = True

        # Check for packing (eval-based)
        if self._is_packed(code):
            types.append(ObfuscationType.PACKED)
            details["packed"] = True

        # Check for webpack
        if self._is_webpack(code):
            types.append(ObfuscationType.WEBPACK)
            details["webpack"] = True

        # Check for browserify
        if self._is_browserify(code):
            types.append(ObfuscationType.BROWSERIFY)
            details["browserify"] = True

        # Check for obfuscator.io
        if self._is_obfuscator_io(code):
            types.append(ObfuscationType.OBFUSCATOR_IO)
            details["obfuscator_io"] = True

        # Check for control flow flattening
        if self._is_cfg_flattened(code):
            types.append(ObfuscationType.CFG_FLATTENED)
            details["cfg_flattened"] = True

        # Check for JSFuck
        if self._is_jsfuck(code):
            types.append(ObfuscationType.JSFUCK)
            details["jsfuck"] = True

        # Check for string encryption
        if self._is_string_encrypted(code):
            types.append(ObfuscationType.STRING_ENCRYPTED)
            details["string_encrypted"] = True

        # Calculate confidence
        confidence = min(1.0, len(types) * 0.2 + 0.4)

        if not types:
            types.append(ObfuscationType.MINIFIED)  # Default assumption

        return DetectionResult(
            obfuscation_types=types, confidence=confidence, details=details
        )

    def _is_minified(self, code: str) -> bool:
        """Check if code is minified"""
        # Indicators of minification:
        # - Very long lines
        # - Short variable names (a, b, c, d...)
        # - No whitespace after operators

        lines = code.split("\n")

        # Check for very long lines
        avg_line_length = sum(len(line) for line in lines) / max(len(lines), 1)
        if avg_line_length > 200:
            return True

        # Check for single-line code
        if len(lines) < 10 and len(code) > 500:
            return True

        # Check for short variable names
        short_vars = len(re.findall(r"\b[a-z]\b", code))
        if short_vars > 20:
            return True

        return False

    def _is_packed(self, code: str) -> bool:
        """Check for eval-based packing"""
        # Common packing patterns:
        # - eval(function(p,a,c,k,e,d)...)
        # - Large base64/hex strings with eval

        if "eval" in code and "function(p,a,c,k,e,d)" in code:
            return True

        if "eval" in code and re.search(r"\\x[0-9a-f]{2}", code):
            return True

        return False

    def _is_webpack(self, code: str) -> bool:
        """Check for webpack bundling"""
        # Webpack signatures:
        # - __webpack_require__
        # - webpackJsonp
        # - /******/ pattern

        webpack_patterns = [
            "__webpack_require__",
            "webpackJsonp",
            "__webpack_exports__",
            r"/\*{6}/",  # Comment block separator
        ]

        for pattern in webpack_patterns:
            if re.search(pattern, code):
                return True

        return False

    def _is_browserify(self, code: str) -> bool:
        """Check for browserify bundling"""
        # Browserify patterns:
        # - require('...')
        # - module.exports
        # - (function(){...}())

        browserify_patterns = [
            r"\(function\(\)\{",
            r"module\.exports",
            r'require\(["\']',
        ]

        matches = 0
        for pattern in browserify_patterns:
            if re.search(pattern, code):
                matches += 1

        return matches >= 2

    def _is_obfuscator_io(self, code: str) -> bool:
        """Check for obfuscator.io obfuscation"""
        # obfuscator.io patterns:
        # - _0x... variable names
        # - String array at top
        # - Hex-encoded strings

        obfuscator_patterns = [
            r"_0x[0-9a-f]{4,}",  # Hex variable names
            r"var\s+_0x[0-9a-f]+\s*=\s*\[",  # String array
            r"\\x[0-9a-f]{2}",  # Hex-encoded chars
        ]

        matches = 0
        for pattern in obfuscator_patterns:
            if re.search(pattern, code):
                matches += 1

        return matches >= 2

    def _is_cfg_flattened(self, code: str) -> bool:
        """Check for control flow flattening"""
        # CFG flattening pattern:
        # - while(true) { switch(state) { ... } }
        # - Large switch statements with state variable

        # Look for while + switch pattern
        if re.search(r"while\s*\(\s*(!!\[\]|true|0x1)\s*\)", code):
            if "switch" in code:
                return True

        # Look for large switch statements
        switch_cases = len(re.findall(r"case\s+", code))
        if switch_cases > 10:
            return True

        return False

    def _is_jsfuck(self, code: str) -> bool:
        """Check for JSFuck obfuscation"""
        # JSFuck uses only: []!+()
        # If code is >90% these characters, it's JSFuck

        allowed_chars = set("[]!+()")
        code_chars = set(c for c in code if not c.isspace())

        if not code_chars:
            return False

        jsfuck_ratio = len(code_chars & allowed_chars) / len(code_chars)

        return jsfuck_ratio > 0.9

    def _is_string_encrypted(self, code: str) -> bool:
        """Check for encrypted strings"""
        # Patterns indicating string encryption:
        # - XOR operations on strings
        # - Base64 decode followed by eval
        # - String.fromCharCode with calculations

        patterns = [
            r"String\.fromCharCode",
            r"atob\s*\(",  # Base64 decode
            r"\^\s*0x[0-9a-f]+",  # XOR with hex
            r"charCodeAt.*\^",  # XOR on char codes
        ]

        matches = 0
        for pattern in patterns:
            if re.search(pattern, code):
                matches += 1

        return matches >= 2
