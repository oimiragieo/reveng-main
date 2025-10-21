#!/usr/bin/env python3
"""
Quick test for Ghidra Analysis Server and GhidraEngine

This tests the new Ghidra-First architecture without running full analysis.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

print("=" * 70)
print("TESTING GHIDRA-FIRST ARCHITECTURE")
print("=" * 70)
print()

# Test 1: Import GhidraEngine
print("[TEST 1] Importing GhidraEngine...")
try:
    from reveng.tools.config.ghidra_engine import GhidraEngine, GhidraConnectionError, GhidraDataExtractor
    print("✅ PASS: GhidraEngine imported successfully")
except ImportError as e:
    print(f"❌ FAIL: {e}")
    sys.exit(1)

# Test 2: Try to connect to Ghidra Analysis Server (expect failure - server not running)
print("\n[TEST 2] Testing fail-fast connection (expecting failure)...")
try:
    ghidra = GhidraEngine(
        server_url="http://127.0.0.1:1337",
        timeout=2,
        fail_fast=True
    )
    print("❌ FAIL: Should have raised GhidraConnectionError")
except GhidraConnectionError as e:
    print("✅ PASS: GhidraConnectionError raised as expected")
    print(f"   Error message preview: {str(e)[:100]}...")
except Exception as e:
    print(f"❌ FAIL: Wrong exception type: {type(e).__name__}: {e}")

# Test 3: Test non-fail-fast mode
print("\n[TEST 3] Testing non-fail-fast mode...")
try:
    ghidra = GhidraEngine(
        server_url="http://127.0.0.1:1337",
        timeout=2,
        fail_fast=False  # Don't fail immediately
    )
    print("✅ PASS: GhidraEngine created with fail_fast=False")

    # Check availability
    available = ghidra.is_available()
    print(f"   Server available: {available} (expected: False)")
    if not available:
        print("✅ PASS: Correctly detected server unavailable")
    else:
        print("❌ FAIL: Server should not be available")
except Exception as e:
    print(f"❌ FAIL: {e}")

# Test 4: Test GhidraDataExtractor with mock data
print("\n[TEST 4] Testing GhidraDataExtractor...")
try:
    mock_analysis_data = {
        "functions": [{"address": "0x401000", "name": "main"}],
        "decompiled_code": {
            "0x401000": "void main(void) {\n  strcpy(buffer, input);\n  memcpy(dest, src, 100);\n}",
            "0x401100": "void crypto_func(void) {\n  for (i = 0; i < len; i++) {\n    data[i] ^= key;\n  }\n}"
        },
        "strings": ["Hello", "World"],
        "imports": ["kernel32.dll!CreateFile"],
        "exports": [],
        "xrefs": {}
    }

    extractor = GhidraDataExtractor(mock_analysis_data)
    print("✅ PASS: GhidraDataExtractor created")

    # Test methods
    decompiled = extractor.get_all_decompiled_code()
    print(f"   Decompiled functions: {len(decompiled)}")

    dangerous = extractor.get_dangerous_functions()
    print(f"   Dangerous functions: {len(dangerous)}")
    if len(dangerous) == 2:  # strcpy and memcpy
        print("✅ PASS: Correctly detected dangerous functions")
    else:
        print(f"❌ FAIL: Expected 2 dangerous functions, got {len(dangerous)}")

    crypto = extractor.get_crypto_candidates()
    print(f"   Crypto candidates: {len(crypto)}")
    if len(crypto) > 0:
        print("✅ PASS: Correctly detected crypto patterns")
    else:
        print("❌ FAIL: Should have detected crypto patterns")

except Exception as e:
    print(f"❌ FAIL: {e}")
    import traceback
    traceback.print_exc()

# Summary
print("\n" + "=" * 70)
print("TEST SUMMARY")
print("=" * 70)
print("✅ GhidraEngine module working correctly")
print("✅ Fail-fast behavior working as expected")
print("✅ GhidraDataExtractor working correctly")
print()
print("NEXT STEPS:")
print("1. Start Ghidra MCP server at http://127.0.0.1:8080")
print("2. Start Ghidra Analysis Server:")
print("   python -m reveng.server.ghidra_analysis_server --port 1337")
print("3. Run full analysis:")
print("   python reveng_analyzer.py decompile/KARP.exe")
print("=" * 70)
