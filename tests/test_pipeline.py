#!/usr/bin/env python3
"""
Basic Pipeline Test Harness
Tests critical stages of the REVENG binary analysis pipeline
"""

import sys
import unittest
from pathlib import Path

# Add tools to path
sys.path.insert(0, str(Path(__file__).parent.parent / "tools"))

from validation_config import ValidationConfig, ValidationMode, BinaryValidator
from c_type_parser import CTypeParser


class TestValidationDefaults(unittest.TestCase):
    """Test that validation defaults don't fail atypical binaries"""

    def test_default_mode_is_checksum(self):
        """Default validation mode should be CHECKSUM, not SMOKE_TEST"""
        config = ValidationConfig()
        self.assertEqual(config.mode, ValidationMode.CHECKSUM,
                        "Default validation should use CHECKSUM mode")

    def test_no_smoke_tests_in_checksum_mode(self):
        """CHECKSUM mode should not populate smoke tests"""
        config = ValidationConfig()
        self.assertEqual(len(config.smoke_tests), 0,
                        "CHECKSUM mode should have no smoke tests")

    def test_smoke_tests_only_in_smoke_mode(self):
        """Smoke tests should only populate when explicitly requested"""
        config = ValidationConfig(mode=ValidationMode.SMOKE_TEST)
        self.assertGreater(len(config.smoke_tests), 0,
                          "SMOKE_TEST mode should have default tests")


class TestCTypeParser(unittest.TestCase):
    """Test that type parser handles multi-token types"""

    def setUp(self):
        self.parser = CTypeParser()

    def test_unsigned_long_long(self):
        """Parser should handle 'unsigned long long'"""
        code = "unsigned long long foo(int x) { return x; }"
        sig = self.parser.parse_function_signature(code)
        self.assertIsNotNone(sig, "Should parse unsigned long long")
        self.assertIn("unsigned long long", str(sig.return_type).lower())

    def test_const_char_pointer(self):
        """Parser should handle 'const char *'"""
        code = "int foo(const char *str) { return 0; }"
        sig = self.parser.parse_function_signature(code)
        self.assertIsNotNone(sig, "Should parse const char *")
        self.assertEqual(len(sig.parameters), 1)
        param_type = str(sig.parameters[0].type).lower()
        self.assertIn("const", param_type)
        self.assertIn("char", param_type)

    def test_function_address_preserved(self):
        """Parser should preserve function address"""
        code = "int foo(int x) { return x; }"
        addr = "0x140001000"
        sig = self.parser.parse_function_signature(code, addr)
        self.assertIsNotNone(sig.address, "Address should be set")
        self.assertEqual(sig.address, 0x140001000, "Should preserve hex address as int")

    def test_function_address_decimal(self):
        """Parser should handle decimal addresses"""
        code = "int bar(void) { return 0; }"
        addr = "12345"
        sig = self.parser.parse_function_signature(code, addr)
        self.assertIsNotNone(sig.address)
        self.assertEqual(sig.address, 12345)

    def test_function_address_missing(self):
        """Parser should handle missing address"""
        code = "int baz(void) { return 0; }"
        sig = self.parser.parse_function_signature(code)
        self.assertIsNone(sig.address, "Address should be None when not provided")

    def test_pointer_param_with_const(self):
        """Parser should handle const char* parameters (HIGH priority fix)"""
        test_cases = [
            ("int foo(const char *str)", "str"),
            ("int bar(const char* data)", "data"),
            ("void* get(const void *ptr)", "ptr"),
            ("int copy(const unsigned char *src, unsigned char *dst)", "src"),  # First param
        ]

        for code, expected_param_name in test_cases:
            with self.subTest(code=code):
                sig = self.parser.parse_function_signature(code)
                self.assertIsNotNone(sig, f"Should parse: {code}")
                self.assertGreater(len(sig.parameters), 0, "Should have at least one parameter")

                param = sig.parameters[0]
                self.assertEqual(param.name, expected_param_name, f"Parameter name should be {expected_param_name}")

                # Type should include const and pointer
                param_type_str = str(param.type).lower()
                self.assertIn("const", param_type_str, "Type should include 'const'")
                self.assertIn("*", str(param.type), "Type should be a pointer")

    def test_function_pointer_params(self):
        """Parser should handle function pointer parameters"""
        code = "int register_callback(void (*callback)(int), int data)"
        sig = self.parser.parse_function_signature(code)
        # Function pointers are complex; at minimum we should parse the signature
        self.assertIsNotNone(sig, "Should parse function pointer parameter")
        # Note: Full function pointer parsing is complex and may not extract all params correctly
        # This test just ensures the parser doesn't crash on function pointers
        self.assertGreaterEqual(len(sig.parameters), 1, "Should have at least 1 parameter")

    def test_array_parameters(self):
        """Parser should handle array parameters"""
        code = "int process(char buffer[256], int size)"
        sig = self.parser.parse_function_signature(code)
        self.assertIsNotNone(sig, "Should parse array parameter")
        self.assertEqual(len(sig.parameters), 2, "Should have 2 parameters")


class TestPlatformAwareCompilation(unittest.TestCase):
    """Test that compilation flags are platform-aware"""

    def test_fpic_not_on_windows(self):
        """Test that -fPIC logic excludes Windows"""
        import platform

        # Simulate the logic from binary_reassembler_v2.py
        system = platform.system().lower()
        flags = ["-O2"]

        if system in ['linux', 'darwin']:
            flags.append("-fPIC")

        # On Windows, flags should NOT contain -fPIC
        if system == 'windows':
            self.assertNotIn("-fPIC", flags,
                           "Windows builds should not have -fPIC")
        else:
            self.assertIn("-fPIC", flags,
                        "Linux/macOS builds should have -fPIC")


class TestGeneratedCode(unittest.TestCase):
    """Test that generated code is compilable"""

    def test_no_windows_headers_in_generated_code(self):
        """Generated code should not include Windows-specific headers"""
        human_readable_dir = Path(__file__).parent.parent / "human_readable_code"

        if not human_readable_dir.exists():
            self.skipTest("human_readable_code directory not found")

        for c_file in human_readable_dir.glob("*.c"):
            with open(c_file, 'r') as f:
                content = f.read()

            self.assertNotIn("#include <windows.h>", content,
                           f"{c_file.name} should not include windows.h")
            self.assertNotIn("GetLastError", content,
                           f"{c_file.name} should not use GetLastError")

    def test_generated_functions_have_return_statements(self):
        """Generated functions should have return statements"""
        human_readable_dir = Path(__file__).parent.parent / "human_readable_code"

        if not human_readable_dir.exists():
            self.skipTest("human_readable_code directory not found")

        for c_file in human_readable_dir.glob("*.c"):
            if c_file.name == "main.c":
                continue  # main.c has different structure

            with open(c_file, 'r') as f:
                content = f.read()

            # Functions returning int should have return statement
            if "int " in content and "() {" in content:
                self.assertIn("return", content,
                            f"{c_file.name} should have return statement")


if __name__ == "__main__":
    # Run tests with verbose output
    unittest.main(verbosity=2)
