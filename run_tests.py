#!/usr/bin/env python3
"""
Comprehensive test runner for REVENG v3.0.0
Runs all tests without pytest dependency
"""

import sys
import os
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_imports():
    """Test basic imports"""
    print("Testing imports...")
    try:
        import reveng
        print(f"✓ Core module: {reveng.__version__}")
        
        from reveng import REVENGAnalyzer, analyze_binary, detect_malware
        print("✓ API imports successful")
        
        from reveng.utils.security import safe_extract_zip, safe_extract_tar
        print("✓ Security utilities imported")
        
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False

def test_cli():
    """Test CLI functionality"""
    print("Testing CLI...")
    try:
        # Test CLI help
        import subprocess
        result = subprocess.run([sys.executable, "reveng.py", "--help"], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0 and "REVENG Universal Reverse Engineering Platform" in result.stdout:
            print("✓ CLI help works")
        else:
            print(f"✗ CLI help failed: {result.stderr}")
            return False
        
        # Test module execution
        result = subprocess.run([sys.executable, "-m", "reveng", "--help"], 
                              capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print("✓ Module execution works")
        else:
            print(f"✗ Module execution failed: {result.stderr}")
            return False
        
        return True
    except Exception as e:
        print(f"✗ CLI test failed: {e}")
        return False

def test_security():
    """Test security utilities"""
    print("Testing security utilities...")
    try:
        from test_security_simple import main as run_security_tests
        return run_security_tests() == 0
    except Exception as e:
        print(f"✗ Security test failed: {e}")
        return False

def test_version():
    """Test version consistency"""
    print("Testing version consistency...")
    try:
        import reveng
        from reveng.version import get_version, get_version_info
        
        # Check version consistency
        version = reveng.__version__
        version_info = get_version_info()
        
        if version == "3.0.0" and version_info == (3, 0, 0):
            print("✓ Version consistency verified")
            return True
        else:
            print(f"✗ Version mismatch: {version} vs {version_info}")
            return False
    except Exception as e:
        print(f"✗ Version test failed: {e}")
        return False

def test_basic_functionality():
    """Test basic functionality"""
    print("Testing basic functionality...")
    try:
        from reveng import REVENGAnalyzer
        
        # Test analyzer creation
        analyzer = REVENGAnalyzer()
        print("✓ Analyzer creation successful")
        
        # Test version info
        from reveng.version import get_build_info, get_system_info
        
        build_info = get_build_info()
        system_info = get_system_info()
        
        if build_info and system_info:
            print("✓ Build and system info available")
            return True
        else:
            print("✗ Build/system info missing")
            return False
            
    except Exception as e:
        print(f"✗ Basic functionality test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("=" * 60)
    print("REVENG v3.0.0 Test Suite")
    print("=" * 60)
    
    tests = [
        ("Imports", test_imports),
        ("CLI", test_cli),
        ("Security", test_security),
        ("Version", test_version),
        ("Basic Functionality", test_basic_functionality),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n--- {test_name} ---")
        try:
            if test_func():
                passed += 1
                print(f"✓ {test_name} passed")
            else:
                print(f"✗ {test_name} failed")
        except Exception as e:
            print(f"✗ {test_name} failed with error: {e}")
    
    print("\n" + "=" * 60)
    print(f"Test Results: {passed}/{total} passed")
    
    if passed == total:
        print("✓ All tests passed!")
        print("✓ REVENG v3.0.0 is ready for publication!")
        return 0
    else:
        print("✗ Some tests failed!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
