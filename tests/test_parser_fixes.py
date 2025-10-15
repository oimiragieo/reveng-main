#!/usr/bin/env python3
"""Test C type parser fixes for pointer parsing and address field"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent / "tools"))

from c_type_parser import CTypeParser

def test_pointer_parsing():
    """Test pointer parameter parsing fixes"""
    parser = CTypeParser()

    print("=" * 70)
    print("Testing Pointer Parameter Parsing Fixes")
    print("=" * 70)

    test_cases = [
        ("int foo(const char *str)", "const char*", "str"),
        ("void* bar(const void *ptr)", "const void*", "ptr"),
        ("int copy(const unsigned char *src, char *dst)", "const unsigned char*", "src"),
        ("int process(char buffer[256])", None, "buffer"),  # Array parameter
    ]

    for code, expected_type_contains, expected_name in test_cases:
        print(f"\nTest: {code}")
        sig = parser.parse_function_signature(code)

        if sig and len(sig.parameters) > 0:
            param = sig.parameters[0]
            print(f"  [OK] Parsed successfully")
            print(f"  Parameter name: {param.name}")
            print(f"  Parameter type: {param.type}")

            # Verify name
            if param.name == expected_name:
                print(f"  [OK] Name correct: {param.name}")
            else:
                print(f"  [FAIL] Name WRONG: expected '{expected_name}', got '{param.name}'")

            # Verify type contains expected string
            if expected_type_contains and expected_type_contains.replace('*', '').strip() in str(param.type):
                print(f"  [OK] Type contains: {expected_type_contains}")
            else:
                print(f"  Type info: {param.type}")
        else:
            print(f"  [FAIL] FAILED to parse")

def test_address_field():
    """Test address field preservation"""
    parser = CTypeParser()

    print("\n" + "=" * 70)
    print("Testing Address Field Preservation")
    print("=" * 70)

    test_cases = [
        ("int foo(void)", "0x401000", 0x401000, "hex address"),
        ("int bar(void)", "12345", 12345, "decimal address"),
        ("int baz(void)", "", None, "missing address"),
    ]

    for code, addr_input, expected_addr, desc in test_cases:
        print(f"\nTest: {code} with {desc}")
        sig = parser.parse_function_signature(code, addr_input)

        if sig:
            print(f"  [OK] Parsed successfully")
            print(f"  Address: {hex(sig.address) if sig.address else 'None'}")

            if sig.address == expected_addr:
                print(f"  [OK] Address correct: {hex(sig.address) if sig.address else 'None'}")
            else:
                print(f"  [FAIL] Address WRONG: expected {expected_addr}, got {sig.address}")
        else:
            print(f"  [FAIL] FAILED to parse")

if __name__ == "__main__":
    test_pointer_parsing()
    test_address_field()

    print("\n" + "=" * 70)
    print("Testing Complete")
    print("=" * 70)
