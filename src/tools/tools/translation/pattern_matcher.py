"""
Pattern matcher for detecting Windows API calls in C code.

Analyzes decompiled C code to identify Windows API usage and extract
context for translation hints.
"""

import re
from typing import List, Optional, Set
from dataclasses import dataclass

from .api_mappings import API_MAPPINGS


@dataclass
class APICallMatch:
    """Represents a detected Windows API call in C code."""

    api_name: str
    line_number: int
    line_content: str
    function_context: Optional[str] = None
    variables_used: List[str] = None

    def __post_init__(self):
        if self.variables_used is None:
            self.variables_used = []


def detect_api_calls(code: str, api_names: Optional[Set[str]] = None) -> List[APICallMatch]:
    """
    Detect Windows API calls in C code.

    Args:
        code: C source code to analyze
        api_names: Optional set of specific API names to search for.
                  If None, searches for all APIs in API_MAPPINGS.

    Returns:
        List of APICallMatch objects for detected API calls
    """
    if api_names is None:
        # Use all APIs from mapping database
        api_names = set(API_MAPPINGS.keys())

    matches = []
    lines = code.split("\n")

    # Extract function names from code for context
    function_pattern = re.compile(r"^\s*(?:static\s+)?(?:\w+\s+)+(\w+)\s*\([^)]*\)\s*\{?")
    current_function = None

    for line_num, line in enumerate(lines, start=1):
        # Check if we're entering a new function
        func_match = function_pattern.match(line)
        if func_match:
            current_function = func_match.group(1)

        # Check for API calls in this line
        for api_name in api_names:
            # Pattern: API_name(...)
            # Handles both direct calls and calls through pointers
            pattern = rf"\b{re.escape(api_name)}\s*\("
            if re.search(pattern, line):
                # Extract variables used in the call
                variables = extract_variables_from_call(line, api_name)

                match = APICallMatch(
                    api_name=api_name,
                    line_number=line_num,
                    line_content=line.strip(),
                    function_context=current_function,
                    variables_used=variables,
                )
                matches.append(match)

    return matches


def extract_variables_from_call(line: str, api_name: str) -> List[str]:
    """
    Extract variable names used in an API call.

    Args:
        line: Line of code containing the API call
        api_name: Name of the API being called

    Returns:
        List of variable names used as arguments
    """
    # Find the API call and extract arguments
    pattern = rf"{re.escape(api_name)}\s*\(([^)]*)\)"
    match = re.search(pattern, line)

    if not match:
        return []

    args_str = match.group(1)

    # Split by commas, but be careful with nested function calls
    variables = []
    depth = 0
    current_arg = []

    for char in args_str:
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "," and depth == 0:
            arg = "".join(current_arg).strip()
            if arg:
                var_name = extract_primary_variable(arg)
                if var_name:
                    variables.append(var_name)
            current_arg = []
            continue

        current_arg.append(char)

    # Don't forget the last argument
    arg = "".join(current_arg).strip()
    if arg:
        var_name = extract_primary_variable(arg)
        if var_name:
            variables.append(var_name)

    return variables


def extract_primary_variable(arg: str) -> Optional[str]:
    """
    Extract the primary variable name from an argument expression.

    Examples:
        '&buffer' -> 'buffer'
        'lpFileName' -> 'lpFileName'
        'hFile + 10' -> 'hFile'
        'sizeof(data)' -> None (not a variable)
        'NULL' -> None

    Args:
        arg: Argument expression

    Returns:
        Primary variable name or None
    """
    # Skip constants and literals
    if arg in ("NULL", "0", "TRUE", "FALSE"):
        return None
    if arg.startswith('"') or arg.startswith("'"):
        return None
    if arg.isdigit():
        return None
    if arg.startswith("0x"):
        return None

    # Skip sizeof, cast expressions
    if arg.startswith("sizeof") or arg.startswith("("):
        return None

    # Remove address-of and dereference operators
    arg = arg.lstrip("&*")

    # Extract first identifier
    match = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)", arg)
    if match:
        return match.group(1)

    return None


def detect_api_patterns(code: str) -> dict:
    """
    Detect common Windows API usage patterns.

    Identifies higher-level patterns like:
    - File operations (open -> read -> close)
    - HTTP requests (open -> connect -> send -> receive)
    - Registry access patterns
    - Process creation patterns

    Args:
        code: C source code to analyze

    Returns:
        Dictionary mapping pattern names to detected instances
    """
    patterns = {
        "file_operations": [],
        "http_requests": [],
        "registry_access": [],
        "process_creation": [],
        "crypto_operations": [],
    }

    matches = detect_api_calls(code)

    # Group matches by function context
    by_function = {}
    for match in matches:
        func = match.function_context or "__global__"
        if func not in by_function:
            by_function[func] = []
        by_function[func].append(match)

    # Analyze each function for patterns
    for func_name, func_matches in by_function.items():
        api_names = [m.api_name for m in func_matches]

        # File operation pattern
        if any(api in api_names for api in ["CreateFileW", "CreateFileA"]):
            if any(api in api_names for api in ["ReadFile", "WriteFile"]):
                patterns["file_operations"].append(
                    {
                        "function": func_name,
                        "apis": api_names,
                        "pattern": "create -> read/write -> close",
                    }
                )

        # HTTP request pattern
        if "WinHttpOpen" in api_names or "InternetOpenW" in api_names:
            if any(api in api_names for api in ["WinHttpSendRequest", "InternetOpenUrlW"]):
                patterns["http_requests"].append(
                    {
                        "function": func_name,
                        "apis": api_names,
                        "pattern": "open -> connect -> send -> receive",
                    }
                )

        # Registry access pattern
        if "RegOpenKeyExW" in api_names:
            if any(api in api_names for api in ["RegQueryValueExW", "RegSetValueExW"]):
                patterns["registry_access"].append(
                    {
                        "function": func_name,
                        "apis": api_names,
                        "pattern": "open -> query/set -> close",
                    }
                )

        # Process creation pattern
        if "CreateProcessW" in api_names:
            patterns["process_creation"].append(
                {"function": func_name, "apis": api_names, "pattern": "create -> wait -> close"}
            )

        # Crypto operations pattern
        if "CryptAcquireContextW" in api_names:
            if any(api in api_names for api in ["CryptCreateHash", "CryptHashData"]):
                patterns["crypto_operations"].append(
                    {
                        "function": func_name,
                        "apis": api_names,
                        "pattern": "acquire -> hash -> get result",
                    }
                )

    return patterns


def get_translation_complexity(matches: List[APICallMatch]) -> str:
    """
    Estimate translation complexity based on API calls detected.

    Args:
        matches: List of detected API calls

    Returns:
        Complexity level: 'simple', 'moderate', 'complex'
    """
    if not matches:
        return "simple"

    api_count = len(matches)

    # Check for complex APIs (crypto, process manipulation)
    complex_apis = {
        "CryptAcquireContextW",
        "CryptCreateHash",
        "CreateProcessW",
        "CreateThread",
        "VirtualAlloc",
        "VirtualProtect",
    }
    has_complex_api = any(m.api_name in complex_apis for m in matches)

    if api_count <= 3 and not has_complex_api:
        return "simple"
    elif api_count <= 10 or (api_count <= 5 and has_complex_api):
        return "moderate"
    else:
        return "complex"
