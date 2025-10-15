#!/usr/bin/env python3
"""
REVENG Java Analysis Setup Script
==================================

Automated setup and validation for Java bytecode analysis.

Steps:
1. Check Java installation
2. Install Python dependencies
3. Download decompilers
4. Compile test files
5. Run validation tests
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
from typing import Tuple, List

# ANSI colors for terminal output
class Colors:
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    END = '\033[0m'

def print_section(title: str):
    """Print section header"""
    print()
    print("=" * 70)
    print(f" {title}")
    print("=" * 70)

def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✓{Colors.END} {message}")

def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠{Colors.END} {message}")

def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}✗{Colors.END} {message}")

def print_info(message: str):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ{Colors.END} {message}")

def check_java() -> Tuple[bool, str]:
    """Check if Java is installed and get version"""
    try:
        result = subprocess.run(
            ['java', '-version'],
            capture_output=True,
            text=True,
            timeout=5
        )

        # Java version is in stderr
        version_output = result.stderr if result.stderr else result.stdout
        version_line = version_output.split('\n')[0]

        # Extract version number
        if 'version' in version_line:
            return True, version_line
        else:
            return False, "Could not parse version"

    except FileNotFoundError:
        return False, "Java not found in PATH"
    except Exception as e:
        return False, str(e)

def check_javac() -> bool:
    """Check if javac (Java compiler) is installed"""
    try:
        result = subprocess.run(
            ['javac', '-version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

def check_javap() -> bool:
    """Check if javap (Java disassembler) is installed"""
    try:
        result = subprocess.run(
            ['javap', '-version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except:
        return False

def install_python_dependencies() -> bool:
    """Install Python dependencies from requirements-java.txt"""
    print_info("Installing Python dependencies...")

    req_file = Path('requirements-java.txt')
    if not req_file.exists():
        print_error(f"requirements-java.txt not found")
        return False

    try:
        result = subprocess.run(
            [sys.executable, '-m', 'pip', 'install', '-r', str(req_file)],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0:
            print_success("Python dependencies installed")
            return True
        else:
            print_error(f"Installation failed: {result.stderr}")
            return False

    except Exception as e:
        print_error(f"Installation error: {e}")
        return False

def download_decompilers() -> Tuple[int, int]:
    """Download Java decompilers"""
    print_info("Downloading decompilers...")

    decompiler_script = Path('tools/decompilers/download_decompilers.py')
    if not decompiler_script.exists():
        print_error("Download script not found")
        return 0, 1

    try:
        result = subprocess.run(
            [sys.executable, str(decompiler_script)],
            capture_output=True,
            text=True,
            timeout=300
        )

        # Parse output to get success count
        output = result.stdout
        if 'successful' in output.lower():
            # Try to extract success count from "X/Y successful"
            for line in output.split('\n'):
                if 'successful' in line.lower() and '/' in line:
                    parts = line.split()
                    for part in parts:
                        if '/' in part:
                            try:
                                success, total = part.split('/')
                                return int(success), int(total)
                            except:
                                pass

        # Default: assume at least CFR downloaded if script succeeded
        if result.returncode == 0:
            return 1, 1
        else:
            return 0, 1

    except Exception as e:
        print_error(f"Download error: {e}")
        return 0, 1

def compile_test_files() -> List[Path]:
    """Compile test Java files to .class"""
    print_info("Compiling test files...")

    test_dir = Path('test_samples')
    if not test_dir.exists():
        print_warning("test_samples directory not found")
        return []

    java_files = list(test_dir.glob('*.java'))
    compiled = []

    for java_file in java_files:
        try:
            result = subprocess.run(
                ['javac', str(java_file)],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                class_file = java_file.with_suffix('.class')
                if class_file.exists():
                    print_success(f"Compiled {java_file.name}")
                    compiled.append(class_file)
                else:
                    print_warning(f"Compiled but .class not found: {java_file.name}")
            else:
                print_error(f"Compilation failed: {java_file.name}")
                if result.stderr:
                    print(f"  Error: {result.stderr[:200]}")

        except Exception as e:
            print_error(f"Error compiling {java_file.name}: {e}")

    return compiled

def test_language_detector(class_file: Path) -> bool:
    """Test language detector on .class file"""
    try:
        result = subprocess.run(
            [sys.executable, 'tools/language_detector.py', str(class_file)],
            capture_output=True,
            text=True,
            timeout=10
        )

        output = result.stdout + result.stderr

        # Check if detected as Java
        if 'java' in output.lower() and 'class' in output.lower():
            return True
        else:
            return False

    except Exception as e:
        print_error(f"Language detector test failed: {e}")
        return False

def test_java_analyzer(class_file: Path) -> bool:
    """Test Java analyzer on .class file"""
    try:
        result = subprocess.run(
            [sys.executable, 'tools/java_bytecode_analyzer.py', str(class_file), '-o', 'test_output'],
            capture_output=True,
            text=True,
            timeout=60
        )

        # Check if output directory was created
        output_dir = Path('test_output')
        if output_dir.exists():
            # Check for analysis JSON
            json_files = list(output_dir.glob('*_analysis.json'))
            if json_files:
                return True

        return False

    except Exception as e:
        print_error(f"Java analyzer test failed: {e}")
        return False

def cleanup_test_output():
    """Clean up test output directory"""
    test_output = Path('test_output')
    if test_output.exists():
        shutil.rmtree(test_output, ignore_errors=True)

def main():
    """Main setup function"""
    print_section("REVENG Java Analysis Setup")

    # Change to project root
    script_dir = Path(__file__).parent
    project_root = script_dir.parent
    os.chdir(project_root)

    print(f"Project root: {project_root}")

    # Track success
    checks_passed = []
    checks_failed = []

    # Step 1: Check Java
    print_section("Step 1: Check Java Installation")
    java_ok, java_version = check_java()
    if java_ok:
        print_success(f"Java found: {java_version}")
        checks_passed.append("Java runtime")
    else:
        print_error(f"Java not found: {java_version}")
        print_info("Install Java 11+ from https://adoptium.net/")
        checks_failed.append("Java runtime")

    javac_ok = check_javac()
    if javac_ok:
        print_success("javac found (Java compiler)")
        checks_passed.append("javac")
    else:
        print_warning("javac not found - cannot compile test files")
        print_info("Install JDK (not just JRE) for javac")
        checks_failed.append("javac")

    javap_ok = check_javap()
    if javap_ok:
        print_success("javap found (Java disassembler)")
        checks_passed.append("javap")
    else:
        print_warning("javap not found - will use fallback")
        checks_failed.append("javap")

    # Step 2: Install Python dependencies
    print_section("Step 2: Install Python Dependencies")
    if install_python_dependencies():
        checks_passed.append("Python dependencies")
    else:
        print_warning("Some dependencies may have failed")
        checks_failed.append("Python dependencies")

    # Step 3: Download decompilers
    print_section("Step 3: Download Java Decompilers")
    success, total = download_decompilers()
    if success > 0:
        print_success(f"Downloaded {success}/{total} decompilers")
        checks_passed.append(f"Decompilers ({success}/{total})")
    else:
        print_error("No decompilers downloaded")
        print_info("Try manual download: cd tools/decompilers && python download_decompilers.py")
        checks_failed.append("Decompilers")

    # Step 4: Compile test files
    print_section("Step 4: Compile Test Files")
    if javac_ok:
        compiled_files = compile_test_files()
        if compiled_files:
            print_success(f"Compiled {len(compiled_files)} test file(s)")
            checks_passed.append(f"Test compilation ({len(compiled_files)} files)")
        else:
            print_warning("No test files compiled")
            checks_failed.append("Test compilation")
    else:
        print_info("Skipping test compilation (javac not available)")
        compiled_files = []

    # Step 5: Validation tests
    print_section("Step 5: Validation Tests")

    if compiled_files:
        test_file = compiled_files[0]

        # Test language detector
        print_info(f"Testing language detector on {test_file.name}...")
        if test_language_detector(test_file):
            print_success("Language detector works correctly")
            checks_passed.append("Language detector")
        else:
            print_error("Language detector test failed")
            checks_failed.append("Language detector")

        # Test Java analyzer
        print_info(f"Testing Java analyzer on {test_file.name}...")
        if test_java_analyzer(test_file):
            print_success("Java analyzer works correctly")
            checks_passed.append("Java analyzer")
        else:
            print_error("Java analyzer test failed")
            checks_failed.append("Java analyzer")

        # Cleanup
        cleanup_test_output()
    else:
        print_warning("No test files available - skipping validation tests")

    # Final summary
    print_section("Setup Summary")

    print(f"\n{Colors.BOLD}Passed:{Colors.END} {len(checks_passed)}")
    for check in checks_passed:
        print(f"  {Colors.GREEN}✓{Colors.END} {check}")

    if checks_failed:
        print(f"\n{Colors.BOLD}Failed/Warning:{Colors.END} {len(checks_failed)}")
        for check in checks_failed:
            print(f"  {Colors.YELLOW}⚠{Colors.END} {check}")

    print()

    # Final verdict
    if java_ok and success > 0:
        print(f"{Colors.GREEN}{Colors.BOLD}✓ Setup Complete!{Colors.END}")
        print()
        print("Next steps:")
        print("  1. Test with a real JAR: python reveng_analyzer.py application.jar")
        print("  2. View results in: analysis_<name>/java_analysis/")
        print("  3. Check CLAUDE.md for detailed usage instructions")
        print()
        return 0
    else:
        print(f"{Colors.YELLOW}{Colors.BOLD}⚠ Setup Incomplete{Colors.END}")
        print()
        print("Required fixes:")
        if not java_ok:
            print("  - Install Java 11+: https://adoptium.net/")
        if success == 0:
            print("  - Download decompilers: cd tools/decompilers && python download_decompilers.py")
        print()
        print("See CLAUDE.md for manual setup instructions")
        print()
        return 1

if __name__ == '__main__':
    sys.exit(main())
