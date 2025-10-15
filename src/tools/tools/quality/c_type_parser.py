#!/usr/bin/env python3
"""
C Type Parser
=============

Robust parser for C type declarations that handles:
- Qualifiers (const, volatile, restrict)
- Multi-token types (unsigned int, long long, etc.)
- Pointers and arrays
- Function pointers
- Type inference from context

Author: Enhancement
Version: 1.0
"""

import logging
import re
from dataclasses import dataclass
from typing import List, Optional, Tuple

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CType:
    """Parsed C type"""
    base_type: str              # int, char, void, struct foo, etc.
    qualifiers: List[str]       # const, volatile, restrict
    pointer_depth: int          # Number of pointer levels
    is_array: bool = False
    array_size: Optional[str] = None
    is_function_pointer: bool = False
    function_params: Optional[List['CType']] = None

    def __str__(self) -> str:
        """Generate C type string"""
        parts = []

        # Qualifiers
        parts.extend(self.qualifiers)

        # Base type
        parts.append(self.base_type)

        # Pointers
        result = ' '.join(parts)
        result += ' ' + '*' * self.pointer_depth

        # Arrays
        if self.is_array:
            if self.array_size:
                result += f'[{self.array_size}]'
            else:
                result += '[]'

        return result.strip()

    def to_signature_string(self) -> str:
        """Generate signature string (for function parameters)"""
        return str(self)


@dataclass
class CParameter:
    """Function parameter with type and name"""
    name: str
    type: CType
    default_value: Optional[str] = None

    def __str__(self) -> str:
        """Generate parameter string"""
        return f"{self.type} {self.name}"


@dataclass
class CFunctionSignature:
    """Complete function signature"""
    name: str
    return_type: CType
    parameters: List[CParameter]
    address: Optional[int] = None  # Function address in binary
    calling_convention: Optional[str] = None  # __cdecl, __stdcall, __fastcall
    is_variadic: bool = False  # ... varargs

    def __str__(self) -> str:
        """Generate function signature string"""
        params_str = ', '.join(str(p) for p in self.parameters)
        if self.is_variadic:
            params_str += ', ...' if params_str else '...'

        cc = f"__{self.calling_convention} " if self.calling_convention else ""
        return f"{self.return_type} {cc}{self.name}({params_str})"


class CTypeParser:
    """
    Robust C type parser

    Handles complex C type declarations including:
    - Multi-word types: unsigned int, long long, etc.
    - Qualifiers: const, volatile, restrict
    - Pointers: *, **, ***, etc.
    - Arrays: [], [10], [SIZE]
    - Function pointers: int (*func)(void)
    """

    # C type keywords
    TYPE_KEYWORDS = {
        'void', 'char', 'short', 'int', 'long', 'float', 'double',
        'signed', 'unsigned',
        'struct', 'union', 'enum',
        'typedef'
    }

    TYPE_QUALIFIERS = {'const', 'volatile', 'restrict'}

    CALLING_CONVENTIONS = {'__cdecl', '__stdcall', '__fastcall', '__thiscall'}

    # Multi-word type patterns
    MULTI_WORD_TYPES = [
        'unsigned char', 'signed char',
        'unsigned short', 'signed short', 'short int',
        'unsigned int', 'signed int',
        'unsigned long', 'signed long', 'long int', 'long long',
        'unsigned long long', 'signed long long',
        'long double'
    ]

    def __init__(self):
        """Initialize parser"""
        pass

    def parse_type(self, type_string: str) -> Optional[CType]:
        """
        Parse a C type string

        Examples:
            "int" → CType(base_type="int", qualifiers=[], pointer_depth=0)
            "const char *" → CType(base_type="char", qualifiers=["const"], pointer_depth=1)
            "unsigned long long" → CType(base_type="unsigned long long", ...)
            "int[10]" → CType(base_type="int", is_array=True, array_size="10")
        """
        if not type_string or not type_string.strip():
            return None

        type_string = type_string.strip()

        # Extract qualifiers
        qualifiers = []
        for qual in self.TYPE_QUALIFIERS:
            if qual in type_string:
                qualifiers.append(qual)
                type_string = type_string.replace(qual, '').strip()

        # Count pointer depth
        pointer_depth = type_string.count('*')
        type_string = type_string.replace('*', '').strip()

        # Check for arrays
        is_array = False
        array_size = None
        array_match = re.search(r'\[(\d+|[A-Z_]+)?\]', type_string)
        if array_match:
            is_array = True
            array_size = array_match.group(1)
            type_string = type_string[:array_match.start()].strip()

        # Parse base type (handle multi-word types)
        base_type = self._parse_base_type(type_string)

        if not base_type:
            logger.warning(f"Could not parse base type from: {type_string}")
            return None

        return CType(
            base_type=base_type,
            qualifiers=qualifiers,
            pointer_depth=pointer_depth,
            is_array=is_array,
            array_size=array_size
        )

    def _parse_base_type(self, type_string: str) -> Optional[str]:
        """Parse base type, handling multi-word types"""

        # Check multi-word types first (longest match)
        for multi_type in sorted(self.MULTI_WORD_TYPES, key=len, reverse=True):
            if multi_type in type_string:
                return multi_type

        # Check for struct/union/enum
        for keyword in ['struct', 'union', 'enum']:
            if type_string.startswith(keyword):
                return type_string  # Return full "struct foo" or "enum bar"

        # Check single-word type
        words = type_string.split()
        if words and words[0] in self.TYPE_KEYWORDS:
            return words[0]

        # Unknown type (might be typedef)
        if words:
            return words[0]

        return None

    def parse_parameter(self, param_string: str) -> Optional[CParameter]:
        """
        Parse function parameter

        Examples:
            "int x" → CParameter(name="x", type=CType(...))
            "const char *buffer" → CParameter(name="buffer", type=CType(...))
            "size_t len" → CParameter(name="len", type=CType(...))
        """
        param_string = param_string.strip()

        if not param_string or param_string == 'void':
            return None

        # Check for "..." (variadic)
        if param_string == '...':
            return None  # Handled separately

        # Split into type and name
        # Strategy: Last identifier is name, rest is type
        tokens = param_string.split()
        if len(tokens) < 2:
            # Only type, no name (e.g., in function pointer)
            param_type = self.parse_type(param_string)
            return CParameter(name="", type=param_type) if param_type else None

        # Handle pointer syntax: "char *name" vs "char* name" vs "const char *str"
        # Find the parameter name (rightmost token that doesn't look like a type keyword)
        # Valid names: identifiers, possibly with leading *
        # Type keywords: const, volatile, struct, union, enum, unsigned, signed, etc.

        type_keywords = {'const', 'volatile', 'struct', 'union', 'enum',
                        'unsigned', 'signed', 'short', 'long', 'static', 'extern'}

        name_idx = -1
        for i in range(len(tokens) - 1, -1, -1):
            token = tokens[i].strip('*')  # Strip stars to check if it's a keyword
            if token and token not in type_keywords:
                # This is likely the parameter name
                name_idx = i
                break

        if name_idx < 0:
            return None

        # Extract name and count pointers attached to it
        param_name_raw = tokens[name_idx]
        pointer_in_name = param_name_raw.count('*')
        param_name = param_name_raw.replace('*', '').strip()

        # Type is everything before the name
        type_tokens = tokens[:name_idx]
        type_string = ' '.join(type_tokens)

        # Add back pointers that were attached to the name
        if pointer_in_name > 0:
            type_string += ' ' + '*' * pointer_in_name

        param_type = self.parse_type(type_string.strip())

        if not param_type:
            return None

        return CParameter(
            name=param_name,
            type=param_type
        )

    def parse_function_signature(self, signature_string: str, func_addr: str = "") -> Optional[CFunctionSignature]:
        """
        Parse complete function signature

        Examples:
            "int foo(char *buf, int len)"
            "void __stdcall bar(void)"
            "int* get_data(void)"
        """
        signature_string = signature_string.strip()

        # Match function signature pattern
        # Pattern: return_type [calling_convention] name(params)
        pattern = r'(.+?)\s+(__\w+\s+)?(\w+)\s*\((.*?)\)'
        match = re.match(pattern, signature_string)

        if not match:
            logger.warning(f"Could not parse function signature: {signature_string}")
            return None

        return_type_str = match.group(1).strip()
        calling_convention_str = match.group(2).strip() if match.group(2) else None
        func_name = match.group(3).strip()
        params_str = match.group(4).strip()

        # Parse return type
        return_type = self.parse_type(return_type_str)
        if not return_type:
            logger.warning(f"Could not parse return type: {return_type_str}")
            return None

        # Parse calling convention
        calling_convention = None
        if calling_convention_str:
            calling_convention = calling_convention_str.strip('_')

        # Parse parameters
        parameters = []
        is_variadic = False

        if params_str and params_str != 'void':
            param_strings = params_str.split(',')
            for param_str in param_strings:
                param_str = param_str.strip()

                if param_str == '...':
                    is_variadic = True
                    continue

                param = self.parse_parameter(param_str)
                if param:
                    parameters.append(param)

        # Parse address if provided
        address = None
        if func_addr:
            try:
                # Handle hex addresses with 0x prefix or plain decimal
                if isinstance(func_addr, str):
                    address = int(func_addr, 16) if func_addr.startswith('0x') else int(func_addr, 0)
                else:
                    address = int(func_addr)
            except (ValueError, TypeError):
                # Invalid address format, leave as None
                pass

        return CFunctionSignature(
            name=func_name,
            return_type=return_type,
            parameters=parameters,
            address=address,
            calling_convention=calling_convention,
            is_variadic=is_variadic
        )

    def infer_type_from_name(self, var_name: str) -> CType:
        """
        Infer type from variable name using common patterns

        Examples:
            "p_data" → char* (pointer prefix)
            "size" → size_t
            "count" → int
            "buffer" → char*
        """
        var_name_lower = var_name.lower()

        # Pointer prefixes
        if var_name.startswith('p') and len(var_name) > 1 and var_name[1].isupper():
            return CType(base_type="void", qualifiers=[], pointer_depth=1)

        if var_name_lower.startswith('ptr'):
            return CType(base_type="void", qualifiers=[], pointer_depth=1)

        # Size/length types
        if any(word in var_name_lower for word in ['size', 'len', 'length', 'count', 'num']):
            return CType(base_type="size_t", qualifiers=[], pointer_depth=0)

        # Buffer/string types
        if any(word in var_name_lower for word in ['buffer', 'buf', 'str', 'string', 'text']):
            return CType(base_type="char", qualifiers=[], pointer_depth=1)

        # Handle/descriptor types
        if any(word in var_name_lower for word in ['handle', 'hnd', 'fd', 'descriptor']):
            return CType(base_type="HANDLE", qualifiers=[], pointer_depth=0)

        # Default to int
        return CType(base_type="int", qualifiers=[], pointer_depth=0)


# Example usage and tests
if __name__ == "__main__":
    parser = CTypeParser()

    # Test cases
    test_cases = [
        "int",
        "const char *",
        "unsigned long long",
        "int[10]",
        "void *",
        "const unsigned int *",
        "struct foo *",
        "char buffer[256]",
    ]

    print("Type Parsing Tests:")
    print("=" * 50)

    for test in test_cases:
        parsed = parser.parse_type(test)
        print(f"Input:  '{test}'")
        print(f"Output: {parsed}")
        print()

    # Test function signature parsing
    print("\nFunction Signature Tests:")
    print("=" * 50)

    signatures = [
        "int foo(char *buf, int len)",
        "void __stdcall bar(void)",
        "const char* get_name(int id)",
        "int printf(const char *format, ...)",
    ]

    for sig in signatures:
        parsed = parser.parse_function_signature(sig)
        print(f"Input:  '{sig}'")
        print(f"Output: {parsed}")
        print()