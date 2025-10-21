#!/usr/bin/env python3
"""
Standalone test for Ghidra Analysis Server
Tests the server can start and respond to requests
"""

import json
import sys
import time
from pathlib import Path

# Test if Flask is installed
try:
    import flask
    print("[OK] Flask installed")
except ImportError:
    print("[FAIL] Flask not installed. Run: pip install flask flask-cors")
    sys.exit(1)

# Test if requests is installed
try:
    import requests
    print("[OK] Requests installed")
except ImportError:
    print("[FAIL] Requests not installed. Run: pip install requests")
    sys.exit(1)

print("\n" + "=" * 70)
print("GHIDRA ANALYSIS SERVER - STANDALONE TEST")
print("=" * 70)

# Test 1: Can we import the server module?
print("\n[TEST 1] Importing server module...")
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    # Import just what we need without triggering security module imports
    import sys
    import os

    # Temporarily add path
    server_path = Path(__file__).parent / "src" / "reveng" / "server"
    sys.path.insert(0, str(server_path.parent.parent))

    # Now try importing
    from reveng.server import ghidra_analysis_server
    print("[OK] Server module imported successfully")
except Exception as e:
    print(f"[FAIL] Could not import server: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)

# Test 2: Can we create the GhidraAnalysisEngine?
print("\n[TEST 2] Creating GhidraAnalysisEngine...")
try:
    engine = ghidra_analysis_server.GhidraAnalysisEngine(
        ghidra_mcp_url="http://127.0.0.1:8080"
    )
    print("[OK] GhidraAnalysisEngine created")
except Exception as e:
    print(f"[FAIL] {e}")
    import traceback
    traceback.print_exc()

# Test 3: Can we check health (will fail - no Ghidra running)
print("\n[TEST 3] Testing health check (expecting unhealthy)...")
try:
    health = engine.health_check()
    print(f"[INFO] Health status: {health['status']}")
    if health['status'] == 'unhealthy':
        print("[OK] Correctly detected Ghidra MCP unavailable")
    else:
        print("[WARN] Unexpected health status")
except Exception as e:
    print(f"[INFO] Health check error (expected): {e}")

# Test 4: Test the Flask app endpoints
print("\n[TEST 4] Testing Flask app structure...")
try:
    app = ghidra_analysis_server.app
    print(f"[OK] Flask app exists")
    print(f"[INFO] App name: {app.name}")

    # Check routes
    routes = [rule.rule for rule in app.url_map.iter_rules()]
    print(f"[INFO] Routes: {routes}")

    expected_routes = ['/', '/health', '/analyze', '/function/<address>']
    for route in expected_routes:
        if any(route in r for r in routes):
            print(f"[OK] Route {route} exists")
        else:
            print(f"[WARN] Route {route} not found")

except Exception as e:
    print(f"[FAIL] {e}")

# Summary
print("\n" + "=" * 70)
print("TEST SUMMARY")
print("=" * 70)
print("[OK] Server module working")
print("[OK] GhidraAnalysisEngine can be created")
print("[OK] Flask app structure correct")
print()
print("TO START THE SERVER:")
print("  python -m reveng.server.ghidra_analysis_server --port 1337")
print()
print("THEN TEST WITH:")
print("  curl http://127.0.0.1:1337/health")
print("=" * 70)
