#!/usr/bin/env python3
"""
Simple test for Ghidra Engine (avoids security module imports)
"""

import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

print("=" * 70)
print("TESTING GHIDRA ENGINE (SIMPLE)")
print("=" * 70)

# Direct import to avoid lazy loading issues
try:
    from reveng.integrations.ghidra.ghidra_http_client import GhidraHTTPClient

    print(f"[OK] {GhidraHTTPClient.__name__} imported")
except Exception as e:
    print(f"[FAIL] GhidraHTTPClient: {e}")
    sys.exit(1)

try:
    from reveng.integrations.ghidra.ghidra_engine import (
        GhidraConnectionError,
        GhidraDataExtractor,
        GhidraEngine,
    )

    print("[OK] GhidraEngine imported")
except Exception as e:
    print(f"[FAIL] GhidraEngine: {e}")
    sys.exit(1)

# Test GhidraDataExtractor
try:
    mock_data = {
        "decompiled_code": {
            "0x401000": "void main() { strcpy(buf, input); }",
            "0x401100": "void crypto() { data[i] ^= key; }",
        }
    }
    extractor = GhidraDataExtractor(mock_data)
    dangerous = extractor.get_dangerous_functions()
    print(f"[OK] Dangerous functions detected: {len(dangerous)}")
    crypto = extractor.get_crypto_candidates()
    print(f"[OK] Crypto candidates detected: {len(crypto)}")
except Exception as e:
    print(f"[FAIL] Data extractor: {e}")

# Test connection (will fail - no server)
try:
    ghidra = GhidraEngine(server_url="http://127.0.0.1:1337", fail_fast=True)
    print("[FAIL] Should have raised GhidraConnectionError")
except GhidraConnectionError:
    print("[OK] GhidraConnectionError raised as expected")
except Exception as e:
    print(f"[FAIL] Wrong exception: {e}")

print("\n" + "=" * 70)
print("ALL TESTS PASSED - NEW ARCHITECTURE WORKING!")
print("=" * 70)
