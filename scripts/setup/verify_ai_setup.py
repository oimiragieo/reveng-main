#!/usr/bin/env python3
"""
REVENG AI Setup Verification Script

Checks all dependencies and configurations needed for AI-powered binary analysis.
Run this after installation to ensure everything is set up correctly.

Usage:
    python scripts/setup/verify_ai_setup.py
"""

import sys
import os
import subprocess
from pathlib import Path


def print_header(text):
    """Print a section header."""
    print(f"\n{'=' * 60}")
    print(f"  {text}")
    print(f"{'=' * 60}")


def print_check(name, status, message=""):
    """Print check result with status indicator."""
    icon = "✅" if status else "❌"
    print(f"{icon} {name}")
    if message:
        print(f"   {message}")


def check_python_version():
    """Check Python version >= 3.11."""
    version = sys.version_info
    version_str = f"{version.major}.{version.minor}.{version.micro}"

    if version >= (3, 11):
        print_check("Python Version", True, f"Found: Python {version_str}")
        return True
    else:
        print_check(
            "Python Version",
            False,
            f"Found: Python {version_str}, Required: 3.11+",
        )
        return False


def check_ghidra():
    """Check if Ghidra is installed and GHIDRA_INSTALL_DIR is set."""
    ghidra_dir = os.environ.get("GHIDRA_INSTALL_DIR")

    if not ghidra_dir:
        print_check(
            "Ghidra Installation",
            False,
            "GHIDRA_INSTALL_DIR environment variable not set",
        )
        print("   Set with: export GHIDRA_INSTALL_DIR=/path/to/ghidra (Linux/macOS)")
        print("   Or: setx GHIDRA_INSTALL_DIR C:\\path\\to\\ghidra (Windows)")
        return False

    if not os.path.exists(ghidra_dir):
        print_check(
            "Ghidra Installation",
            False,
            f"Directory not found: {ghidra_dir}",
        )
        return False

    # Check for ghidraRun executable
    ghidra_run_unix = os.path.join(ghidra_dir, "ghidraRun")
    ghidra_run_win = os.path.join(ghidra_dir, "ghidraRun.bat")

    if os.path.exists(ghidra_run_unix) or os.path.exists(ghidra_run_win):
        print_check("Ghidra Installation", True, f"Found: {ghidra_dir}")
        return True
    else:
        print_check(
            "Ghidra Installation",
            False,
            f"ghidraRun not found in {ghidra_dir}",
        )
        return False


def check_java():
    """Check Java version >= 21."""
    try:
        result = subprocess.run(
            ["java", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout + result.stderr

        # Parse version (e.g., "openjdk 21.0.1" or "java 21.0.1")
        if "21" in output or "java version" in output.lower():
            version_line = output.split("\n")[0]
            print_check("Java Installation", True, version_line.strip())
            return True
        else:
            print_check(
                "Java Installation",
                False,
                f"Java 21 required, found: {output.split()[0] if output else 'unknown'}",
            )
            return False

    except (subprocess.TimeoutExpired, FileNotFoundError):
        print_check("Java Installation", False, "Java not found in PATH")
        print("   Install Java 21 from https://adoptium.net")
        return False


def check_ollama():
    """Check if Ollama is installed and running."""
    # Check Python package
    try:
        import ollama

        pkg_installed = True
    except ImportError:
        print_check("Ollama Python Package", False, "pip install ollama")
        return False

    print_check("Ollama Python Package", True, "Installed")

    # Check server
    try:
        models = ollama.list()
        model_count = len(models.get("models", []))

        if model_count > 0:
            model_names = [m["name"] for m in models["models"][:3]]
            print_check(
                "Ollama Server",
                True,
                f"{model_count} models available: {', '.join(model_names)}",
            )
            return True
        else:
            print_check(
                "Ollama Server",
                False,
                "No models found. Run: ollama pull llama3",
            )
            return False

    except Exception as e:
        print_check(
            "Ollama Server",
            False,
            f"Server not reachable: {str(e)}",
        )
        print("   Start Ollama: ollama serve")
        print("   Pull model: ollama pull llama3")
        return False


def check_core_dependencies():
    """Check required Python packages."""
    required = {
        "lief": "Binary parsing and manipulation",
        "capstone": "Disassembly engine",
        "keystone": "Assembly engine",
        "ghidramcp": "Ghidra integration",
        "requests": "HTTP client",
    }

    all_ok = True
    for pkg, desc in required.items():
        try:
            __import__(pkg)
            print_check(pkg, True, desc)
        except ImportError:
            print_check(pkg, False, f"{desc} - REQUIRED")
            all_ok = False

    return all_ok


def check_optional_dependencies():
    """Check optional Python packages."""
    optional = {
        "ollama": "AI features (natural language queries)",
        "yara": "YARA rule generation/scanning",
        "vt": "VirusTotal integration",
        "pycparser": "C code parsing for translation hints",
        "black": "Code formatting",
        "pylint": "Code linting",
    }

    any_installed = False
    for pkg, desc in optional.items():
        try:
            __import__(pkg)
            print_check(pkg, True, desc)
            any_installed = True
        except ImportError:
            print(f"⚠️  {pkg} - {desc} (optional)")

    return any_installed


def check_reveng_installation():
    """Check if REVENG modules are importable."""
    try:
        # Try importing main REVENG module
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

        from reveng.ai_api import REVENG_AI_API

        print_check("REVENG AI API", True, "Module importable")

        # Try initializing (without Ollama to avoid connection check)
        api = REVENG_AI_API(use_ollama=False)
        print_check("REVENG AI API", True, "Initialized successfully")
        return True

    except Exception as e:
        print_check("REVENG AI API", False, f"Import failed: {str(e)}")
        return False


def run_test_analysis():
    """Run a quick test analysis if all checks pass."""
    print_header("Test Analysis")

    try:
        # Add src to path
        sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

        from reveng.ai_api import REVENG_AI_API, AnalysisMode

        # Create simple test binary
        test_file = Path("test_verification.bin")
        test_file.write_bytes(b"\x00" * 100)  # Dummy binary

        print("Running quick triage on test binary...")
        api = REVENG_AI_API(use_ollama=False)
        result = api.triage_binary(str(test_file))

        print_check("Test Triage", True, f"Threat score: {result.threat_score}/100")

        # Cleanup
        test_file.unlink()
        return True

    except Exception as e:
        print_check("Test Analysis", False, f"Error: {str(e)}")
        return False


def print_summary(results):
    """Print summary and recommendations."""
    print_header("Summary")

    required_checks = results["python"] and results["java"] and results["ghidra"] and results["core_deps"]

    if required_checks:
        print("\n✅ Core setup COMPLETE! REVENG is ready to use.")
    else:
        print("\n❌ Setup INCOMPLETE. Install missing requirements:")
        if not results["python"]:
            print("   • Install Python 3.11+ from https://python.org")
        if not results["java"]:
            print("   • Install Java 21 from https://adoptium.net")
        if not results["ghidra"]:
            print("   • Download Ghidra from https://github.com/NationalSecurityAgency/ghidra/releases")
        if not results["core_deps"]:
            print("   • Install dependencies: pip install -r requirements.txt")

    if not results["ollama"]:
        print("\n⚠️  Ollama not configured (optional but recommended):")
        print("   • Install: https://ollama.ai")
        print("   • Start server: ollama serve")
        print("   • Pull model: ollama pull llama3")
        print("   • Enables: Natural language queries, instant triage, code enhancement")

    if not results["optional_deps"]:
        print("\n⚠️  Optional dependencies not installed:")
        print("   • Install: pip install -r requirements-optional.txt")
        print("   • Enables: VirusTotal, YARA, translation hints, linting")

    print("\n📖 For detailed setup instructions, see:")
    print("   docs/guides/COMPLETE_SETUP_GUIDE.md")


def main():
    """Run all verification checks."""
    print_header("REVENG AI Setup Verification")

    results = {}

    # Core requirements
    print_header("Core Requirements")
    results["python"] = check_python_version()
    results["java"] = check_java()
    results["ghidra"] = check_ghidra()

    # Python dependencies
    print_header("Python Dependencies (Required)")
    results["core_deps"] = check_core_dependencies()

    print_header("Python Dependencies (Optional)")
    results["optional_deps"] = check_optional_dependencies()

    # AI components
    print_header("AI Components")
    results["ollama"] = check_ollama()

    # REVENG modules
    print_header("REVENG Modules")
    results["reveng"] = check_reveng_installation()

    # Test analysis (if all required checks pass)
    if all([results["python"], results["java"], results["ghidra"], results["core_deps"]]):
        results["test"] = run_test_analysis()
    else:
        results["test"] = False

    # Print summary
    print_summary(results)

    # Exit code
    sys.exit(0 if all([results["python"], results["core_deps"], results["reveng"]]) else 1)


if __name__ == "__main__":
    main()
